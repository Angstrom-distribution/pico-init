/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The fstab pass against real mounts.
 *
 * Everything that talks to the kernel runs inside a private user + mount
 * namespace, where an unprivileged process owns its own mount table and may
 * mount tmpfs, reconfigure it and change its per-mount attributes -- which is
 * the whole of the new-mount-API surface the pass uses. That makes these real
 * fsopen()/fsconfig()/fsmount()/move_mount()/fspick()/mount_setattr() calls
 * checked against the kernel's own /proc/self/mountinfo, not a mock, and
 * nothing here can touch the host's mounts. A host that refuses user
 * namespaces SKIPs (77) after the pure checks have run.
 *
 * The pure checks come first: the attribute masks, the API-mount floor table,
 * the mountinfo lookup and mkdir -p, and the lines the pass must skip without
 * ever reaching a syscall.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fstab-mount.h"
#include "fstab.h"
#include "mount-setup.h"
#include "test-util.h"

static void test_attr_masks(void) {
        FstabOptions o;
        uint64_t set, clr;

        /* A fresh mount: what the line asks for, plus the floor. */
        ASSERT_EQ_INT(fstab_options_parse("nosuid,exec,noatime", &o), 0);
        fstab_fresh_attrs(&o, 0, &set, &clr);
        ASSERT_EQ_INT(set, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOATIME);
        ASSERT_EQ_INT(clr, MOUNT_ATTR_NOEXEC | MOUNT_ATTR__ATIME);

        /* The floor beats an explicit clear: "exec" on a noexec-floored API
         * mount must not clear noexec. */
        fstab_fresh_attrs(&o, MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV, &set, &clr);
        ASSERT_EQ_INT(set, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOATIME | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV);
        ASSERT_EQ_INT(clr, MOUNT_ATTR__ATIME);
        fstab_options_done(&o);

        /* A remount resets what it is not told, the way mount(8) -o remount
         * always has -- but never the atime mode, and never the floor. */
        ASSERT_EQ_INT(fstab_options_parse("defaults", &o), 0);
        fstab_remount_attrs(&o, 0, &set, &clr);
        ASSERT_EQ_INT(set, 0);
        ASSERT_EQ_INT(clr,
                      MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC |
                                      MOUNT_ATTR_NOSYMFOLLOW);

        fstab_remount_attrs(&o, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC, &set, &clr);
        ASSERT_EQ_INT(set, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC);
        ASSERT_EQ_INT(clr, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOSYMFOLLOW);
        fstab_options_done(&o);

        /* The stock /run line against /run's own floor. */
        ASSERT_EQ_INT(fstab_options_parse("mode=0755,nodev,nosuid,strictatime", &o), 0);
        fstab_remount_attrs(&o, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, &set, &clr);
        ASSERT_EQ_INT(set, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_STRICTATIME);
        ASSERT_EQ_INT(clr, MOUNT_ATTR__ATIME | MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSYMFOLLOW);
        fstab_options_done(&o);

        /* ro survives a remount; NULL options are a bare rw. */
        ASSERT_EQ_INT(fstab_options_parse("ro", &o), 0);
        fstab_remount_attrs(&o, 0, &set, &clr);
        ASSERT_EQ_INT(set, MOUNT_ATTR_RDONLY);
        ASSERT_TRUE(!(clr & MOUNT_ATTR_RDONLY));
        fstab_options_done(&o);

        fstab_remount_attrs(NULL, 0, &set, &clr);
        ASSERT_EQ_INT(set, 0);
        ASSERT_TRUE(clr & MOUNT_ATTR_RDONLY);
        ASSERT_TRUE(!(clr & MOUNT_ATTR__ATIME));
}

static void test_api_floor(void) {
        uint64_t floor = 0;

        ASSERT_TRUE(mount_setup_api_floor("/proc", &floor));
        ASSERT_EQ_INT(floor, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC);
        ASSERT_TRUE(mount_setup_api_floor("/dev", &floor));
        ASSERT_EQ_INT(floor, MOUNT_ATTR_NOSUID);
        ASSERT_TRUE(mount_setup_api_floor("/dev/pts", &floor));
        ASSERT_EQ_INT(floor, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC);
        ASSERT_TRUE(mount_setup_api_floor("/run", &floor));
        ASSERT_EQ_INT(floor, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV);
        ASSERT_TRUE(mount_setup_api_floor("/sys/fs/cgroup", NULL));

        ASSERT_TRUE(!mount_setup_api_floor("/var/volatile", &floor));
        ASSERT_TRUE(!mount_setup_api_floor("/run/lock", &floor));
        ASSERT_TRUE(!mount_setup_api_floor(NULL, &floor));
}

static void test_is_mounted_and_mkdir(void) {
        char *dir, path[PATH_MAX], file[PATH_MAX + 16];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "mountinfo",
                                      "22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n"
                                      "garbage\n"
                                      "40 22 0:40 / /mnt/my\\040disk rw,relatime - tmpfs tmpfs rw\n"),
                      0);
        snprintf(path, sizeof(path), "%s/mountinfo", dir);

        ASSERT_EQ_INT(fstab_is_mounted(path, "/proc"), 1);
        ASSERT_EQ_INT(fstab_is_mounted(path, "/mnt/my disk"), 1);
        ASSERT_EQ_INT(fstab_is_mounted(path, "/mnt/my\\040disk"), 0);
        ASSERT_EQ_INT(fstab_is_mounted(path, "/proc/sys"), 0);
        ASSERT_EQ_INT(fstab_is_mounted(path, "/pro"), 0);
        snprintf(file, sizeof(file), "%s/missing", dir);
        ASSERT_EQ_INT(fstab_is_mounted(file, "/proc"), -ENOENT);

        snprintf(path, sizeof(path), "%s/a/b//c", dir);
        ASSERT_EQ_INT(fstab_mkdir_p(path, 0755), 0);
        snprintf(path, sizeof(path), "%s/a/b/c", dir);
        ASSERT_TRUE(access(path, F_OK) == 0);
        ASSERT_EQ_INT(fstab_mkdir_p(path, 0755), 0);

        /* An existing file is left alone (a bind mount's target), and a file
         * in the middle of the path is a real error. */
        snprintf(file, sizeof(file), "%s/mountinfo", dir);
        ASSERT_EQ_INT(fstab_mkdir_p(file, 0755), 0);
        snprintf(file, sizeof(file), "%s/mountinfo/x", dir);
        ASSERT_EQ_INT(fstab_mkdir_p(file, 0755), -ENOTDIR);
        ASSERT_EQ_INT(fstab_mkdir_p("relative/path", 0755), -EINVAL);

        test_rm_rf(dir);
        free(dir);
}

static bool never_api(const char *where, uint64_t *ret_floor) {
        (void) where;
        (void) ret_floor;
        return false;
}

static void read_file(const char *path, char *buf, size_t size) {
        FILE *f = fopen(path, "re");
        size_t n;

        ASSERT_TRUE(f != NULL);
        n = fread(buf, 1, size - 1, f);
        buf[n] = '\0';
        fclose(f);
}

/* Lines the pass must record as skipped, noauto or failed without making any
 * mount syscall -- which is why this runs unprivileged, outside the namespace. */
static void test_pass_skips(void) {
        static const char * const lines[] = {
                "/dev/root / auto defaults 1 1",
                "/dev/sda2 none swap sw 0 0",
                "srv:/export /mnt/nfs nfs4 defaults 0 0",
                "//srv/share /mnt/cifs cifs defaults 0 0",
                "/dev/sdb1 /mnt/net ext4 _netdev 0 0",
                "/dev/sdc1 /mnt/auto ext4 x-systemd.automount 0 0",
                "UUID=0123-4567 /mnt/uuid vfat defaults 0 0",
                "PARTLABEL=data /mnt/plabel ext4 defaults 0 0",
                "/img /mnt/loop ext4 loop 0 0",
                "/dev/sdd1 /mnt/card auto noauto 0 0",
                "tmpfs relative tmpfs defaults 0 0",
        };
        static const char * const want[] = {
                "/ present the root filesystem\n",
                "none skipped swap lines are not activated by pico-init\n",
                "/mnt/nfs skipped network filesystem: nothing orders it after the network\n",
                "/mnt/cifs skipped network filesystem: nothing orders it after the network\n",
                "/mnt/net skipped network filesystem: nothing orders it after the network\n",
                "/mnt/auto skipped x-systemd.automount is not supported\n",
                "/mnt/uuid skipped UUID= sources are not resolved by pico-init yet\n",
                "/mnt/plabel skipped PARTLABEL= sources are not resolved by pico-init yet\n",
                "/mnt/loop skipped loop mounts are not supported\n",
                "/mnt/card noauto -\n",
                "relative failed the mount point is not an absolute path\n",
        };
        FstabPassConfig cfg = { 0 };
        FstabTable t = { 0 };
        char *dir, record[PATH_MAX], content[4096], expect[4096] = "";
        size_t i;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(record, sizeof(record), "%s/run/pico-init/fstab", dir);

        t.entries = calloc(sizeof(lines) / sizeof(lines[0]), sizeof(FstabEntry));
        ASSERT_TRUE(t.entries != NULL);
        for (i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
                ASSERT_EQ_INT(fstab_parse_line(lines[i], &t.entries[i]), 1);
                t.n++;
                strcat(expect, want[i]);
        }

        cfg.record = record;
        cfg.api_floor = never_api;

        /* 8 skipped + 1 failed; noauto and the root line do not count. The
         * record's directory is created on the way. */
        ASSERT_EQ_INT(fstab_pass(&t, &cfg), 9);
        read_file(record, content, sizeof(content));
        ASSERT_STREQ(content, expect);
        ASSERT_EQ_INT(fstab_record_count_degraded(record), 9);

        /* An outcome already recorded -- the root check's -- is kept. */
        fstab_entry_set_outcome(&t.entries[0], FSTAB_REMOUNTED, "rw by the root check");
        t.entries[1].outcome = FSTAB_PENDING;
        ASSERT_EQ_INT(fstab_pass(&t, &cfg), 9);
        read_file(record, content, sizeof(content));
        ASSERT_TRUE(strncmp(content, "/ remounted rw by the root check\n", 33) == 0);

        fstab_table_done(&t);

        /* No fstab lines at all still leaves a record behind, empty. */
        ASSERT_EQ_INT(fstab_pass(&t, &cfg), 0);
        read_file(record, content, sizeof(content));
        ASSERT_STREQ(content, "");

        test_rm_rf(dir);
        free(dir);
}

/* --- inside a private user + mount namespace --- */

static int write_proc(const char *path, const char *s) {
        int fd = open(path, O_WRONLY | O_CLOEXEC);
        ssize_t len = (ssize_t) strlen(s);
        int r = 0;

        if (fd < 0)
                return -errno;
        if (write(fd, s, (size_t) len) != len)
                r = -errno;
        close(fd);
        return r;
}

static bool enter_namespace(void) {
        char map[64];
        uid_t uid = getuid();
        gid_t gid = getgid();

        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
                fprintf(stderr, "test-fstab-mount: unshare: %s\n", strerror(errno));
                return false;
        }

        if (write_proc("/proc/self/setgroups", "deny") < 0)
                return false;
        snprintf(map, sizeof(map), "0 %u 1", (unsigned) uid);
        if (write_proc("/proc/self/uid_map", map) < 0)
                return false;
        snprintf(map, sizeof(map), "0 %u 1", (unsigned) gid);
        if (write_proc("/proc/self/gid_map", map) < 0)
                return false;

        /* Scaffolding, not code under test: keep every mount below from
         * propagating anywhere, whatever the host's propagation is. */
        return mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0;
}

/*
 * The mountinfo line for `where`: its per-mount option field, and the
 * superblock option field after the " - type source " separator. The last
 * matching line, the mount a lookup lands on. False when not mounted.
 */
static bool mount_options(const char *where, char *vfs, size_t vfs_size, char *sb, size_t sb_size) {
        char line[4096];
        bool found = false;
        FILE *f = fopen("/proc/self/mountinfo", "re");

        ASSERT_TRUE(f != NULL);
        while (fgets(line, sizeof(line), f)) {
                char mp[PATH_MAX], opts[1024], type[64], src[PATH_MAX], sopts[1024];
                char *sep;

                if (sscanf(line, "%*s %*s %*s %*s %4095s %1023s", mp, opts) != 2)
                        continue;
                fstab_unescape(mp);
                if (strcmp(mp, where) != 0)
                        continue;

                sep = strstr(line, " - ");
                ASSERT_TRUE(sep != NULL);
                ASSERT_EQ_INT(sscanf(sep + 3, "%63s %4095s %1023s", type, src, sopts), 3);

                snprintf(vfs, vfs_size, ",%s,", opts);
                snprintf(sb, sb_size, ",%s,", sopts);
                found = true;
        }
        fclose(f);

        return found;
}

/* Whole-token membership in a ",a,b,c," list as mount_options() builds it. */
static bool has_opt(const char *list, const char *opt) {
        char tok[128];

        snprintf(tok, sizeof(tok), ",%s,", opt);
        return strstr(list, tok) != NULL;
}

static char scratch[PATH_MAX];

static void path_in(char *buf, size_t size, const char *rel) {
        int n = snprintf(buf, size, "%s/%s", scratch, rel);

        ASSERT_TRUE(n > 0 && (size_t) n < size);
}

/* Parse "<what> <rel> <type> <options>" with `rel` under the scratch tmpfs. */
static void make_entry(FstabEntry *e, const char *what, const char *rel, const char *type, const char *options) {
        char where[PATH_MAX], line[PATH_MAX * 2];

        path_in(where, sizeof(where), rel);
        snprintf(line, sizeof(line), "%s %s %s %s 0 0", what, where, type, options);
        ASSERT_EQ_INT(fstab_parse_line(line, e), 1);
}

static const char *api_path;

static bool test_api(const char *where, uint64_t *ret_floor) {
        if (!api_path || strcmp(where, api_path) != 0)
                return false;
        *ret_floor = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC;
        return true;
}

static void test_fresh_mount(void) {
        char where[PATH_MAX], vfs[1024], sb[1024], err[512];
        FstabEntry e;
        struct stat st;

        /* mkdir -p through three missing levels, then fsopen() + one
         * fsconfig() per option + fsmount() with the VFS attributes. */
        make_entry(&e, "tmpfs", "fresh/a/b", "tmpfs", "size=1m,mode=0700,nosuid,nodev,noexec,noatime,nofail");
        path_in(where, sizeof(where), "fresh/a/b");
        ASSERT_EQ_INT(fstab_mkdir_p(where, 0755), 0);
        ASSERT_EQ_INT(fstab_mount(&e, where, 0, NULL, err, sizeof(err)), 0);

        ASSERT_TRUE(mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(vfs, "rw"));
        ASSERT_TRUE(has_opt(vfs, "nosuid") && has_opt(vfs, "nodev") && has_opt(vfs, "noexec"));
        ASSERT_TRUE(has_opt(vfs, "noatime"));
        ASSERT_TRUE(has_opt(sb, "size=1024k"));
        ASSERT_TRUE(has_opt(sb, "mode=700"));
        ASSERT_TRUE(stat(where, &st) == 0 && (st.st_mode & 07777) == 0700);
        fstab_entry_done(&e);

        /* ro reaches both halves: the mount and the superblock. */
        make_entry(&e, "tmpfs", "fresh/ro", "tmpfs", "ro,size=1m");
        path_in(where, sizeof(where), "fresh/ro");
        ASSERT_EQ_INT(fstab_mkdir_p(where, 0755), 0);
        ASSERT_EQ_INT(fstab_mount(&e, where, 0, NULL, err, sizeof(err)), 0);
        ASSERT_TRUE(mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(vfs, "ro"));
        ASSERT_TRUE(has_opt(sb, "ro"));
        fstab_entry_done(&e);

        /* A floor on a fresh mount is applied even though the line never
         * asked for it. */
        make_entry(&e, "tmpfs", "fresh/floor", "tmpfs", "defaults");
        path_in(where, sizeof(where), "fresh/floor");
        ASSERT_EQ_INT(fstab_mkdir_p(where, 0755), 0);
        ASSERT_EQ_INT(fstab_mount(&e, where, MOUNT_ATTR_NOEXEC, NULL, err, sizeof(err)), 0);
        ASSERT_TRUE(mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(vfs, "noexec"));
        ASSERT_TRUE(!has_opt(vfs, "nosuid"));
        fstab_entry_done(&e);

        /* The filesystem's own complaint reaches the caller, not just an
         * errno: the step that failed and the option it failed on. */
        make_entry(&e, "tmpfs", "fresh/bad", "tmpfs", "size=1m,no_such_tmpfs_option=1");
        path_in(where, sizeof(where), "fresh/bad");
        ASSERT_EQ_INT(fstab_mkdir_p(where, 0755), 0);
        ASSERT_TRUE(fstab_mount(&e, where, 0, NULL, err, sizeof(err)) < 0);
        ASSERT_TRUE(strstr(err, "fsconfig(no_such_tmpfs_option=1)") != NULL);
        ASSERT_TRUE(!mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        fstab_entry_done(&e);

        make_entry(&e, "tmpfs", "fresh/nofs", "no_such_filesystem_type", "defaults");
        path_in(where, sizeof(where), "fresh/nofs");
        ASSERT_EQ_INT(fstab_mkdir_p(where, 0755), 0);
        ASSERT_EQ_INT(fstab_mount(&e, where, 0, NULL, err, sizeof(err)), -ENODEV);
        ASSERT_TRUE(strstr(err, "fsopen(no_such_filesystem_type)") != NULL);
        fstab_entry_done(&e);
}

static void test_auto_and_bind(void) {
        char where[PATH_MAX], src[PATH_MAX], fs[PATH_MAX], vfs[1024], sb[1024], err[512];
        FstabEntry e;

        /* "auto" walks the type list in order, skips nodev lines, and keeps
         * going past a type the kernel does not have. The list is a fixture
         * so the walk itself is what is tested. */
        path_in(fs, sizeof(fs), "filesystems");
        {
                FILE *f = fopen(fs, "we");

                ASSERT_TRUE(f != NULL);
                fputs("nodev\tproc\n\tno_such_filesystem_type\n\ttmpfs\n", f);
                fclose(f);
        }

        make_entry(&e, "tmpfs", "auto", "auto", "size=1m");
        path_in(where, sizeof(where), "auto");
        ASSERT_EQ_INT(fstab_mkdir_p(where, 0755), 0);
        ASSERT_EQ_INT(fstab_mount(&e, where, 0, fs, err, sizeof(err)), 0);
        ASSERT_TRUE(mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(sb, "size=1024k"));
        fstab_entry_done(&e);

        {
                FILE *f = fopen(fs, "we");

                ASSERT_TRUE(f != NULL);
                fputs("nodev\ttmpfs\n\tno_such_filesystem_type\n", f);
                fclose(f);
        }
        make_entry(&e, "tmpfs", "auto-none", "auto", "defaults");
        path_in(where, sizeof(where), "auto-none");
        ASSERT_EQ_INT(fstab_mkdir_p(where, 0755), 0);
        ASSERT_TRUE(fstab_mount(&e, where, 0, fs, err, sizeof(err)) < 0);
        ASSERT_TRUE(strstr(err, "no filesystem type could mount it, last: fsopen(no_such_filesystem_type)") !=
                    NULL);
        fstab_entry_done(&e);

        /* bind: open_tree() clone, attributes on the detached tree, attach. */
        path_in(src, sizeof(src), "auto");
        make_entry(&e, src, "bound", "none", "bind,ro,nosuid");
        path_in(where, sizeof(where), "bound");
        ASSERT_EQ_INT(fstab_mkdir_p(where, 0755), 0);
        ASSERT_EQ_INT(fstab_mount(&e, where, 0, NULL, err, sizeof(err)), 0);
        ASSERT_TRUE(mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(vfs, "ro") && has_opt(vfs, "nosuid"));
        /* The source keeps its own attributes; only the clone is read-only. */
        ASSERT_TRUE(mount_options(src, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(vfs, "rw") && !has_opt(vfs, "nosuid"));
        fstab_entry_done(&e);
}

static void test_remount(void) {
        char where[PATH_MAX], vfs[1024], sb[1024], err[512];
        FstabOptions o;
        FstabEntry e;

        make_entry(&e, "tmpfs", "re", "tmpfs", "ro,nosuid,size=1m");
        path_in(where, sizeof(where), "re");
        ASSERT_EQ_INT(fstab_mkdir_p(where, 0755), 0);
        ASSERT_EQ_INT(fstab_mount(&e, where, 0, NULL, err, sizeof(err)), 0);
        fstab_entry_done(&e);
        ASSERT_TRUE(mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(vfs, "ro") && has_opt(sb, "ro"));

        /*
         * The root check's case: a bare rw remount of a read-only mount must
         * make BOTH the superblock and the mount writable -- reconfigure for
         * one, mount_setattr() for the other -- and, like mount(8), reset
         * nosuid it was not told to keep.
         */
        ASSERT_EQ_INT(fstab_remount(where, NULL, 0, err, sizeof(err)), 0);
        ASSERT_TRUE(mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(vfs, "rw"));
        ASSERT_TRUE(has_opt(sb, "rw"));
        ASSERT_TRUE(!has_opt(vfs, "nosuid"));
        {
                char probe[PATH_MAX + 8];

                snprintf(probe, sizeof(probe), "%s/probe", where);
                ASSERT_EQ_INT(test_write_file(where, "probe", "x"), 0);
                ASSERT_TRUE(access(probe, F_OK) == 0);
        }

        /* Filesystem options go through the reconfigure, VFS ones through
         * mount_setattr(), and an fstab "ro" puts both back. */
        ASSERT_EQ_INT(fstab_options_parse("ro,size=2m,noexec,noatime", &o), 0);
        ASSERT_EQ_INT(fstab_remount(where, &o, 0, err, sizeof(err)), 0);
        fstab_options_done(&o);
        ASSERT_TRUE(mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(vfs, "ro") && has_opt(sb, "ro"));
        ASSERT_TRUE(has_opt(sb, "size=2048k"));
        ASSERT_TRUE(has_opt(vfs, "noexec") && has_opt(vfs, "noatime"));

        /* The atime mode survives a remount that does not name one. */
        ASSERT_EQ_INT(fstab_options_parse("rw", &o), 0);
        ASSERT_EQ_INT(fstab_remount(where, &o, 0, err, sizeof(err)), 0);
        fstab_options_done(&o);
        ASSERT_TRUE(mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(vfs, "rw") && has_opt(sb, "rw"));
        ASSERT_TRUE(has_opt(vfs, "noatime"));
        ASSERT_TRUE(!has_opt(vfs, "noexec"));

        /* A bad filesystem option fails the reconfigure and changes nothing,
         * the per-mount attributes included. */
        ASSERT_EQ_INT(fstab_options_parse("ro,no_such_tmpfs_option", &o), 0);
        ASSERT_TRUE(fstab_remount(where, &o, 0, err, sizeof(err)) < 0);
        ASSERT_TRUE(strstr(err, "fsconfig(no_such_tmpfs_option)") != NULL);
        fstab_options_done(&o);
        ASSERT_TRUE(mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(vfs, "rw") && has_opt(sb, "rw"));

        path_in(where, sizeof(where), "not-a-mount-point-at-all");
        ASSERT_TRUE(fstab_remount(where, NULL, 0, err, sizeof(err)) < 0);
        ASSERT_TRUE(strstr(err, "fspick") != NULL);
}

static void test_pass_real(void) {
        char api[PATH_MAX], deep[PATH_MAX], mid[PATH_MAX], plain[PATH_MAX], record[PATH_MAX];
        char vfs[1024], sb[1024], err[512], content[4096], line[PATH_MAX * 2];
        FstabPassConfig cfg = { 0 };
        FstabTable t = { 0 };
        struct stat a, b;
        FstabEntry pre;

        path_in(api, sizeof(api), "api");
        path_in(mid, sizeof(mid), "pass/mid");
        path_in(deep, sizeof(deep), "pass/mid/deep");
        path_in(plain, sizeof(plain), "plain");
        path_in(record, sizeof(record), "record/fstab");

        /* A stand-in for one of PID 1's own API mounts, already mounted with
         * its hardening, and a plain mount some earlier stage already made. */
        make_entry(&pre, "tmpfs", "api", "tmpfs", "nosuid,nodev,noexec,size=1m");
        ASSERT_EQ_INT(fstab_mkdir_p(api, 0755), 0);
        ASSERT_EQ_INT(fstab_mount(&pre, api, 0, NULL, err, sizeof(err)), 0);
        fstab_entry_done(&pre);
        make_entry(&pre, "tmpfs", "plain", "tmpfs", "size=1m");
        ASSERT_EQ_INT(fstab_mkdir_p(plain, 0755), 0);
        ASSERT_EQ_INT(fstab_mount(&pre, plain, 0, NULL, err, sizeof(err)), 0);
        fstab_entry_done(&pre);

        t.entries = calloc(5, sizeof(FstabEntry));
        ASSERT_TRUE(t.entries != NULL);

        /* The child is listed before its parent on purpose: file order would
         * mount the parent over it and hide it. */
        make_entry(&t.entries[t.n++], "tmpfs", "pass/mid/deep", "tmpfs", "size=1m");
        make_entry(&t.entries[t.n++], "tmpfs", "pass/mid", "tmpfs", "size=1m");
        /* fstab asks to undo the API mount's hardening and resize it. */
        make_entry(&t.entries[t.n++], "tmpfs", "api", "tmpfs", "suid,dev,exec,size=2m");
        make_entry(&t.entries[t.n++], "tmpfs", "plain", "tmpfs", "size=3m,noexec");
        snprintf(line, sizeof(line), "tmpfs %s/pass/broken tmpfs no_such_tmpfs_option 0 0", scratch);
        ASSERT_EQ_INT(fstab_parse_line(line, &t.entries[t.n++]), 1);

        api_path = api;
        cfg.api_floor = test_api;
        cfg.record = record;

        ASSERT_EQ_INT(fstab_pass(&t, &cfg), 1);

        ASSERT_EQ_INT(t.entries[0].outcome, FSTAB_MOUNTED);
        ASSERT_EQ_INT(t.entries[1].outcome, FSTAB_MOUNTED);
        ASSERT_EQ_INT(t.entries[2].outcome, FSTAB_REMOUNTED);
        ASSERT_EQ_INT(t.entries[3].outcome, FSTAB_PRESENT);
        ASSERT_EQ_INT(t.entries[4].outcome, FSTAB_FAILED);

        /* Depth order: the child is a mount point on top of its parent's
         * tmpfs, visible, rather than buried under a later parent mount. */
        ASSERT_TRUE(stat(deep, &a) == 0 && stat(mid, &b) == 0);
        ASSERT_TRUE(a.st_dev != b.st_dev);
        ASSERT_EQ_INT(fstab_is_mounted("/proc/self/mountinfo", deep), 1);

        /* The API mount: fstab's filesystem option applied, and its request
         * to clear the hardening refused -- the floor stands. */
        ASSERT_TRUE(mount_options(api, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(sb, "size=2048k"));
        ASSERT_TRUE(has_opt(vfs, "nosuid") && has_opt(vfs, "nodev") && has_opt(vfs, "noexec"));

        /* Already mounted and not PID 1's own: left exactly as it was. */
        ASSERT_TRUE(mount_options(plain, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(has_opt(sb, "size=1024k"));
        ASSERT_TRUE(!has_opt(vfs, "noexec"));

        read_file(record, content, sizeof(content));
        ASSERT_TRUE(strstr(content, " mounted tmpfs size=1m\n") != NULL);
        ASSERT_TRUE(strstr(content, "/api remounted suid,dev,exec,size=2m\n") != NULL);
        ASSERT_TRUE(strstr(content, "/plain present already mounted\n") != NULL);
        ASSERT_TRUE(strstr(content, "/pass/broken failed fsconfig(no_such_tmpfs_option)") != NULL);
        ASSERT_EQ_INT(fstab_record_count_degraded(record), 1);

        /* Run again: everything is now already there, nothing is mounted
         * twice, and the one broken line is still the one degraded line. */
        {
                size_t i;

                for (i = 0; i < t.n; i++)
                        fstab_entry_set_outcome(&t.entries[i], FSTAB_PENDING, NULL);
        }
        ASSERT_EQ_INT(fstab_pass(&t, &cfg), 1);
        ASSERT_EQ_INT(t.entries[0].outcome, FSTAB_PRESENT);
        ASSERT_EQ_INT(t.entries[1].outcome, FSTAB_PRESENT);
        ASSERT_EQ_INT(t.entries[2].outcome, FSTAB_REMOUNTED);

        fstab_table_done(&t);
        api_path = NULL;
}

int main(void) {
        char *dir;

        test_attr_masks();
        test_api_floor();
        test_is_mounted_and_mkdir();
        test_pass_skips();

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(scratch, sizeof(scratch), "%s", dir);

        if (!enter_namespace()) {
                test_rm_rf(dir);
                free(dir);
                printf("test-fstab-mount: no user namespace here, skipping the real-mount checks\n");
                return 77;
        }

        /* Everything below lives on one scratch tmpfs, so tearing it down is
         * one detach rather than an unmount per test. */
        ASSERT_TRUE(mount("tmpfs", scratch, "tmpfs", 0, "size=8m") == 0);

        test_fresh_mount();
        test_auto_and_bind();
        test_remount();
        test_pass_real();

        ASSERT_TRUE(umount2(scratch, MNT_DETACH) == 0);
        test_rm_rf(dir);
        free(dir);

        printf("test-fstab-mount: all checks passed\n");
        return 0;
}
