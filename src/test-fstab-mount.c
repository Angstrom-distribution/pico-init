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
#include <sys/swap.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "fstab-mount.h"
#include "fstab.h"
#include "mount-setup.h"
#include "test-util.h"
#include "ubi-attach.h"

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

static void test_device_mounted(void) {
        char *dir, path[PATH_MAX], where[PATH_MAX], line[PATH_MAX];
        struct stat st;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(path, sizeof(path), "%s/mountinfo", dir);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "mountinfo",
                                      "22 1 0:21 / /proc rw - proc proc rw\n"
                                      "30 1 8:2 / / rw - ext4 /dev/root rw\n"
                                      "36 30 8:17 / /mnt/my\\040card rw - vfat /dev/sdb1 rw\n"
                                      "40 30 0:45 / /data rw - btrfs /dev/sdc1 rw\n"
                                      "no separator here\n"),
                      0);

        /* By source, for nodes that are not block devices here. */
        ASSERT_EQ_INT(fstab_device_mounted(path, "/dev/sdb1", where, sizeof(where)), 1);
        ASSERT_STREQ(where, "/mnt/my card");
        /* btrfs lists an anonymous 0:N, so only the source can match. */
        ASSERT_EQ_INT(fstab_device_mounted(path, "/dev/sdc1", NULL, 0), 1);
        ASSERT_EQ_INT(fstab_device_mounted(path, "/dev/sdb", NULL, 0), 0);
        ASSERT_EQ_INT(fstab_device_mounted(path, "/dev/sdb10", NULL, 0), 0);

        /* By device number, for a real block device: whatever mountinfo
         * calls its source. Needs one to exist on this host. */
        if (stat("/dev/loop0", &st) == 0 && S_ISBLK(st.st_mode)) {
                snprintf(line,
                         sizeof(line),
                         "50 30 %u:%u / /srv rw - ext4 /dev/some-other-name rw\n",
                         major(st.st_rdev),
                         minor(st.st_rdev));
                ASSERT_EQ_INT(test_write_file(dir, "mountinfo", line), 0);
                ASSERT_EQ_INT(fstab_device_mounted(path, "/dev/loop0", where, sizeof(where)), 1);
                ASSERT_STREQ(where, "/srv");
        }

        snprintf(path, sizeof(path), "%s/missing", dir);
        ASSERT_EQ_INT(fstab_device_mounted(path, "/dev/sdb1", NULL, 0), -ENOENT);

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
                "srv:/export /mnt/nfs nfs4 defaults 0 0",
                "//srv/share /mnt/cifs cifs defaults 0 0",
                "/dev/sdb1 /mnt/net ext4 _netdev 0 0",
                "/dev/sdc1 /mnt/auto ext4 x-systemd.automount 0 0",
                "ID=usb-Card_Reader-0:0 /mnt/id vfat defaults 0 0",
                "/img /mnt/loop ext4 loop 0 0",
                "/dev/sdd1 /mnt/card auto noauto 0 0",
                "tmpfs relative tmpfs defaults 0 0",
        };
        static const char * const want[] = {
                "/ present the root filesystem\n",
                "/mnt/nfs skipped network filesystem: nothing orders it after the network\n",
                "/mnt/cifs skipped network filesystem: nothing orders it after the network\n",
                "/mnt/net skipped network filesystem: nothing orders it after the network\n",
                "/mnt/auto skipped x-systemd.automount is not supported\n",
                "/mnt/id skipped ID= sources are not supported\n",
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

        /* 6 skipped + 1 failed; noauto and the root line do not count. The
         * record's directory is created on the way. */
        ASSERT_EQ_INT(fstab_pass(&t, &cfg), 7);
        read_file(record, content, sizeof(content));
        ASSERT_STREQ(content, expect);
        ASSERT_EQ_INT(fstab_record_count_degraded(record), 7);

        /* An outcome already recorded -- the root check's -- is kept. */
        fstab_entry_set_outcome(&t.entries[0], FSTAB_REMOUNTED, "rw by the root check");
        t.entries[1].outcome = FSTAB_PENDING;
        ASSERT_EQ_INT(fstab_pass(&t, &cfg), 7);
        read_file(record, content, sizeof(content));
        ASSERT_TRUE(strncmp(content, "/ remounted rw by the root check\n", 33) == 0);

        fstab_table_done(&t);

        /* A line that would be mounted, when whether it already is cannot
         * be read: failed, never a guess that could stack a second mount. */
        {
                char line[PATH_MAX + 64], mi[PATH_MAX + 16];

                snprintf(line, sizeof(line), "tmpfs %s/m tmpfs defaults 0 0", dir);
                ASSERT_TRUE((t.entries = calloc(1, sizeof(FstabEntry))) != NULL);
                ASSERT_EQ_INT(fstab_parse_line(line, &t.entries[0]), 1);
                t.n = 1;

                snprintf(mi, sizeof(mi), "%s/no-mountinfo", dir);
                cfg.mountinfo = mi;
                ASSERT_EQ_INT(fstab_pass(&t, &cfg), 1);
                ASSERT_EQ_INT(t.entries[0].outcome, FSTAB_FAILED);
                ASSERT_STREQ(t.entries[0].reason,
                             "cannot tell whether it is mounted: No such file or directory");
                cfg.mountinfo = NULL;
                fstab_table_done(&t);
        }

        /* No fstab lines at all still leaves a record behind, empty. */
        ASSERT_EQ_INT(fstab_pass(&t, &cfg), 0);
        read_file(record, content, sizeof(content));
        ASSERT_STREQ(content, "");

        test_rm_rf(dir);
        free(dir);
}

static void test_swap_flags(void) {
        static const struct {
                const char *options;
                int ret;
                int flags;
        } cases[] = {
                {                   "sw",       0,                                                  0 },
                {                "pri=5",       0,                               SWAP_FLAG_PREFER | 5 },
                {            "pri=32767",       0,                           SWAP_FLAG_PREFER | 32767 },
                {            "pri=32768", -EINVAL,                                                  0 },
                {               "pri=-1", -EINVAL,                                                  0 },
                {                "pri=x", -EINVAL,                                                  0 },
                {                 "pri=", -EINVAL,                                                  0 },
                {              "discard",       0,                                  SWAP_FLAG_DISCARD },
                {         "discard=once",       0,                        SWAP_FLAG_DISCARD | 0x20000 },
                {        "discard=pages",       0,                        SWAP_FLAG_DISCARD | 0x40000 },
                {  "pri=3,discard=pages",       0, SWAP_FLAG_PREFER | 3 | SWAP_FLAG_DISCARD | 0x40000 },
                /* The last discard wins, as the last pri= does. */
                { "discard=once,discard",       0,                                  SWAP_FLAG_DISCARD },
                {   "pri=1,pri=2,nofail",       0,                               SWAP_FLAG_PREFER | 2 },
                /* Nothing for the kernel in these; ignored. */
                {   "defaults,x-foo=bar",       0,                                                  0 },
        };

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                FstabOptions o;
                int flags = -1, r;

                ASSERT_EQ_INT(fstab_options_parse(cases[i].options, &o), 0);
                r = fstab_swap_flags(&o, &flags);
                if (r != cases[i].ret || (r == 0 && flags != cases[i].flags)) {
                        fprintf(stderr, "%s: got %d/0x%x\n", cases[i].options, r, (unsigned) flags);
                        ASSERT_TRUE(false);
                }
                fstab_options_done(&o);
        }
}

/* What the pass asked for, in order: "m" for a mount line reaching the API
 * floor lookup, "<path> <flags>" for a swapon(). */
static char calls[4096];

static int fake_swapon(const char *path, int flags) {
        char one[PATH_MAX + 32];

        snprintf(one, sizeof(one), "%s %d;", path, flags);
        strncat(calls, one, sizeof(calls) - strlen(calls) - 1);

        if (strstr(path, "busy")) {
                errno = EBUSY;
                return -1;
        }
        if (strstr(path, "bad")) {
                errno = EINVAL;
                return -1;
        }
        return 0;
}

static bool recording_api(const char *where, uint64_t *ret_floor) {
        (void) where;
        (void) ret_floor;
        strncat(calls, "m;", sizeof(calls) - strlen(calls) - 1);
        return false;
}

static void test_pass_swap(void) {
        char *dir, sys[PATH_MAX], dev[PATH_MAX], record[PATH_MAX], want[PATH_MAX * 5], content[4096];
        char lines[10][PATH_MAX + 64];
        FstabPassConfig cfg = { 0 };
        FstabTable t = { 0 };
        size_t i;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(sys, sizeof(sys), "%s/sys", dir);
        snprintf(dev, sizeof(dev), "%s/dev", dir);
        snprintf(record, sizeof(record), "%s/record", dir);
        ASSERT_EQ_INT(test_mkdir(dir, "dev"), 0);

        /* A card that is swap from end to end, and three swap files. */
        {
                uint8_t page[4096] = { 0 };
                char path[PATH_MAX + 16];

                page[1024] = 1;
                page[1028] = 255;
                memcpy(page + 1052, "picoswap", 8);
                memcpy(page + 4086, "SWAPSPACE2", 10);
                ASSERT_EQ_INT(test_block_device(sys, "mmcblk0", NULL, 0, 2048), 0);
                snprintf(path, sizeof(path), "%s/mmcblk0", dev);
                ASSERT_EQ_INT(test_image_write(path, 1 << 20, page, sizeof(page), 0), 0);
        }
        ASSERT_EQ_INT(test_write_file(dir, "swapfile", ""), 0);
        ASSERT_EQ_INT(test_write_file(dir, "busyswap", ""), 0);
        ASSERT_EQ_INT(test_write_file(dir, "badswap", ""), 0);

        /* Swap lines first in the file, a mount line last: the mount line
         * still goes first. */
        snprintf(lines[0], sizeof(lines[0]), "%s/swapfile none swap pri=7 0 0", dir);
        snprintf(lines[1], sizeof(lines[1]), "LABEL=picoswap none swap discard 0 0");
        snprintf(lines[2], sizeof(lines[2]), "%s/busyswap none swap sw 0 0", dir);
        snprintf(lines[3], sizeof(lines[3]), "%s/badswap none swap sw 0 0", dir);
        snprintf(lines[4], sizeof(lines[4]), "%s/missing none swap sw 0 0", dir);
        snprintf(lines[5], sizeof(lines[5]), "LABEL=noswap none swap sw 0 0");
        snprintf(lines[6], sizeof(lines[6]), "LABEL=noswap2 none swap nofail 0 0");
        snprintf(lines[7], sizeof(lines[7]), "%s/swapfile none swap noauto 0 0", dir);
        snprintf(lines[8], sizeof(lines[8]), "LABEL=picoswap swap swap pri=99999 0 0");
        snprintf(lines[9], sizeof(lines[9]), "tmpfs %s/mnt tmpfs no_such_tmpfs_option 0 0", dir);

        t.entries = calloc(10, sizeof(FstabEntry));
        ASSERT_TRUE(t.entries != NULL);
        for (i = 0; i < 10; i++)
                ASSERT_EQ_INT(fstab_parse_line(lines[i], &t.entries[t.n++]), 1);
        ASSERT_TRUE(fstab_has_swap(&t));

        cfg.record = record;
        cfg.api_floor = recording_api;
        cfg.sys_root = sys;
        cfg.dev_root = dev;
        cfg.device_timeout = 100 * USEC_PER_MSEC;
        cfg.swapon = fake_swapon;
        calls[0] = '\0';

        /* badswap, missing, noswap, the bad priority, and the mount line
         * (no namespace here, so the mount itself is refused). */
        ASSERT_EQ_INT(fstab_pass(&t, &cfg), 5);

        snprintf(want,
                 sizeof(want),
                 "m;%s/swapfile %d;%s/mmcblk0 %d;%s/busyswap 0;%s/badswap 0;",
                 dir,
                 SWAP_FLAG_PREFER | 7,
                 dev,
                 SWAP_FLAG_DISCARD,
                 dir,
                 dir);
        ASSERT_STREQ(calls, want);

        ASSERT_EQ_INT(t.entries[0].outcome, FSTAB_ACTIVE);
        ASSERT_EQ_INT(t.entries[1].outcome, FSTAB_ACTIVE);
        ASSERT_EQ_INT(t.entries[2].outcome, FSTAB_PRESENT);
        ASSERT_EQ_INT(t.entries[3].outcome, FSTAB_FAILED);
        ASSERT_EQ_INT(t.entries[4].outcome, FSTAB_FAILED);
        ASSERT_EQ_INT(t.entries[5].outcome, FSTAB_SKIPPED);
        ASSERT_EQ_INT(t.entries[6].outcome, FSTAB_ABSENT);
        ASSERT_EQ_INT(t.entries[7].outcome, FSTAB_NOAUTO);
        ASSERT_EQ_INT(t.entries[8].outcome, FSTAB_FAILED);
        ASSERT_EQ_INT(t.entries[9].outcome, FSTAB_FAILED);

        /* The record names swap by its source. */
        read_file(record, content, sizeof(content));
        snprintf(want, sizeof(want), "LABEL=picoswap active %s/mmcblk0\n", dev);
        ASSERT_TRUE(strstr(content, want) != NULL);
        ASSERT_TRUE(strstr(content, "LABEL=picoswap failed bad pri= in pri=99999\n") != NULL);
        snprintf(want, sizeof(want), "%s/badswap failed swapon: Invalid argument\n", dir);
        ASSERT_TRUE(strstr(content, want) != NULL);

        fstab_table_done(&t);
        test_rm_rf(dir);
        free(dir);
}

/* --- inside a private user + mount namespace --- */

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

        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "rw"));
        ASSERT_TRUE(test_has_opt(vfs, "nosuid") && test_has_opt(vfs, "nodev") && test_has_opt(vfs, "noexec"));
        ASSERT_TRUE(test_has_opt(vfs, "noatime"));
        ASSERT_TRUE(test_has_opt(sb, "size=1024k"));
        ASSERT_TRUE(test_has_opt(sb, "mode=700"));
        ASSERT_TRUE(stat(where, &st) == 0 && (st.st_mode & 07777) == 0700);
        fstab_entry_done(&e);

        /* ro reaches both halves: the mount and the superblock. */
        make_entry(&e, "tmpfs", "fresh/ro", "tmpfs", "ro,size=1m");
        path_in(where, sizeof(where), "fresh/ro");
        ASSERT_EQ_INT(fstab_mkdir_p(where, 0755), 0);
        ASSERT_EQ_INT(fstab_mount(&e, where, 0, NULL, err, sizeof(err)), 0);
        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "ro"));
        ASSERT_TRUE(test_has_opt(sb, "ro"));
        fstab_entry_done(&e);

        /* A floor on a fresh mount is applied even though the line never
         * asked for it. */
        make_entry(&e, "tmpfs", "fresh/floor", "tmpfs", "defaults");
        path_in(where, sizeof(where), "fresh/floor");
        ASSERT_EQ_INT(fstab_mkdir_p(where, 0755), 0);
        ASSERT_EQ_INT(fstab_mount(&e, where, MOUNT_ATTR_NOEXEC, NULL, err, sizeof(err)), 0);
        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "noexec"));
        ASSERT_TRUE(!test_has_opt(vfs, "nosuid"));
        fstab_entry_done(&e);

        /* The filesystem's own complaint reaches the caller, not just an
         * errno: the step that failed and the option it failed on. */
        make_entry(&e, "tmpfs", "fresh/bad", "tmpfs", "size=1m,no_such_tmpfs_option=1");
        path_in(where, sizeof(where), "fresh/bad");
        ASSERT_EQ_INT(fstab_mkdir_p(where, 0755), 0);
        ASSERT_TRUE(fstab_mount(&e, where, 0, NULL, err, sizeof(err)) < 0);
        ASSERT_TRUE(strstr(err, "fsconfig(no_such_tmpfs_option=1)") != NULL);
        ASSERT_TRUE(!test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
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
        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(sb, "size=1024k"));
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
        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "ro") && test_has_opt(vfs, "nosuid"));
        /* The source keeps its own attributes; only the clone is read-only. */
        ASSERT_TRUE(test_mount_options(src, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "rw") && !test_has_opt(vfs, "nosuid"));
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
        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "ro") && test_has_opt(sb, "ro"));

        /*
         * The root check's case: a bare rw remount of a read-only mount must
         * make BOTH the superblock and the mount writable -- reconfigure for
         * one, mount_setattr() for the other -- and, like mount(8), reset
         * nosuid it was not told to keep.
         */
        ASSERT_EQ_INT(fstab_remount(where, NULL, 0, err, sizeof(err)), 0);
        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "rw"));
        ASSERT_TRUE(test_has_opt(sb, "rw"));
        ASSERT_TRUE(!test_has_opt(vfs, "nosuid"));
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
        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "ro") && test_has_opt(sb, "ro"));
        ASSERT_TRUE(test_has_opt(sb, "size=2048k"));
        ASSERT_TRUE(test_has_opt(vfs, "noexec") && test_has_opt(vfs, "noatime"));

        /* The atime mode survives a remount that does not name one. */
        ASSERT_EQ_INT(fstab_options_parse("rw", &o), 0);
        ASSERT_EQ_INT(fstab_remount(where, &o, 0, err, sizeof(err)), 0);
        fstab_options_done(&o);
        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "rw") && test_has_opt(sb, "rw"));
        ASSERT_TRUE(test_has_opt(vfs, "noatime"));
        ASSERT_TRUE(!test_has_opt(vfs, "noexec"));

        /* A bad filesystem option fails the reconfigure and changes nothing,
         * the per-mount attributes included. */
        ASSERT_EQ_INT(fstab_options_parse("ro,no_such_tmpfs_option", &o), 0);
        ASSERT_TRUE(fstab_remount(where, &o, 0, err, sizeof(err)) < 0);
        ASSERT_TRUE(strstr(err, "fsconfig(no_such_tmpfs_option)") != NULL);
        fstab_options_done(&o);
        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "rw") && test_has_opt(sb, "rw"));

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
        ASSERT_TRUE(test_mount_options(api, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(sb, "size=2048k"));
        ASSERT_TRUE(test_has_opt(vfs, "nosuid") && test_has_opt(vfs, "nodev") && test_has_opt(vfs, "noexec"));

        /* Already mounted and not PID 1's own: left exactly as it was. */
        ASSERT_TRUE(test_mount_options(plain, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(sb, "size=1024k"));
        ASSERT_TRUE(!test_has_opt(vfs, "noexec"));

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

/* --- device-backed lines: resolution, the wait, the filesystem check --- */

static char fx_sys[PATH_MAX], fx_dev[PATH_MAX], fx_fsck[PATH_MAX], fx_log[PATH_MAX];

static const uint8_t uuid_stick[16] = { 0x5e, 0x5e, 0x5e, 0x5e, 0x11, 0x11, 0x22, 0x22,
                                        0x33, 0x33, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 };
#define UUID_STICK "5e5e5e5e-1111-2222-3333-444444444444"

/* An ext image on a whole unpartitioned disk `name`, with s_state `state`. */
static void fx_disk(const char *name, const char *label, uint8_t state) {
        char path[PATH_MAX * 2];

        ASSERT_EQ_INT(test_block_device(fx_sys, name, NULL, 0, 2048), 0);
        snprintf(path, sizeof(path), "%s/%s", fx_dev, name);
        ASSERT_EQ_INT(test_ext_image(path, uuid_stick, label), 0);
        ASSERT_EQ_INT(test_image_write(path, 1 << 20, &state, 1, 1024 + 58), 0);
}

/* fsck.ext4 as a script: logs its arguments, exits with `code`. */
static void fx_checker(int code) {
        char script[PATH_MAX * 3];

        snprintf(script, sizeof(script), "#!/bin/sh\necho \"$*\" >> %s\nexit %d\n", fx_log, code);
        ASSERT_EQ_INT(test_write_file(fx_fsck, "fsck.ext4", script), 0);
        {
                char path[PATH_MAX * 2];

                snprintf(path, sizeof(path), "%s/fsck.ext4", fx_fsck);
                ASSERT_EQ_INT(chmod(path, 0755), 0);
        }
        (void) unlink(fx_log);
}

static bool fx_checked(char *args, size_t size) {
        FILE *f = fopen(fx_log, "re");
        bool ran;

        if (!f)
                return false;
        ran = fgets(args, (int) size, f) != NULL;
        fclose(f);
        return ran;
}

static void fx_late_card(void *userdata, unsigned attempt) {
        unsigned *seen = userdata;

        *seen = attempt;
        if (attempt == 1)
                fx_disk("sdl", "late", 0x01);
}

/* Run the pass over one line (with `%s` standing for the scratch dir) and
 * hand back its outcome, keeping its reason in `reason`. */
static FstabOutcome run_line(const char *fmt, FstabPassConfig *cfg, char *reason, size_t size) {
        char line[PATH_MAX * 3], record[PATH_MAX];
        FstabTable t = { 0 };
        FstabOutcome o;

        snprintf(line, sizeof(line), fmt, scratch, scratch);
        path_in(record, sizeof(record), "fx/record");
        cfg->record = record;

        ASSERT_TRUE((t.entries = calloc(1, sizeof(FstabEntry))) != NULL);
        ASSERT_EQ_INT(fstab_parse_line(line, &t.entries[0]), 1);
        t.n = 1;

        (void) fstab_pass(&t, cfg);
        o = t.entries[0].outcome;
        snprintf(reason, size, "%s", t.entries[0].reason ? t.entries[0].reason : "");
        fstab_table_done(&t);
        return o;
}

static void test_pass_devices(void) {
        char fs[PATH_MAX], where[PATH_MAX], node[PATH_MAX * 2], reason[1024], args[PATH_MAX];
        char vfs[1024], sb[1024], mi_line[PATH_MAX * 3];
        FstabPassConfig cfg = { 0 };
        unsigned seen = 0;

        path_in(fx_sys, sizeof(fx_sys), "fx/sys");
        path_in(fx_dev, sizeof(fx_dev), "fx/dev");
        path_in(fx_fsck, sizeof(fx_fsck), "fx/sbin");
        path_in(fx_log, sizeof(fx_log), "fx/fsck.log");
        ASSERT_EQ_INT(fstab_mkdir_p(fx_dev, 0755), 0);
        ASSERT_EQ_INT(fstab_mkdir_p(fx_fsck, 0755), 0);

        /* "auto" mounts through a type list holding only tmpfs, which takes
         * any string as its source: what is under test is which source. */
        path_in(fs, sizeof(fs), "fx/filesystems");
        {
                FILE *f = fopen(fs, "we");

                ASSERT_TRUE(f != NULL);
                fputs("\ttmpfs\n", f);
                fclose(f);
        }

        fx_disk("sdb", "stick", 0x01);
        fx_disk("sdc", "dirty", 0x02); /* ERROR_FS: the gate sends it to fsck */
        fx_disk("sdd", "clean", 0x01);

        cfg.api_floor = never_api;
        cfg.filesystems = fs;
        cfg.sys_root = fx_sys;
        cfg.dev_root = fx_dev;
        cfg.fsck_dir = fx_fsck;
        cfg.device_timeout = 150 * USEC_PER_MSEC;
        fx_checker(0);

        /* UUID= resolved to the whole-disk ext on sdb, mounted from it. */
        snprintf(node, sizeof(node), "%s/sdb", fx_dev);
        ASSERT_EQ_INT(run_line("UUID=" UUID_STICK " %s/m/uuid auto size=1m 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_MOUNTED);
        path_in(where, sizeof(where), "m/uuid");
        ASSERT_EQ_INT(fstab_device_mounted("/proc/self/mountinfo", node, NULL, 0), 1);
        snprintf(mi_line, sizeof(mi_line), "auto size=1m from %s", node);
        ASSERT_STREQ(reason, mi_line);

        /* A device mounted already is never checked: the errored sdc, once
         * without a pass number and then again with one, under a checker
         * that would refuse the mount. */
        fx_checker(2);
        ASSERT_EQ_INT(run_line("LABEL=dirty %s/m/first auto size=1m 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_MOUNTED);
        ASSERT_EQ_INT(run_line("LABEL=dirty %s/m/again auto size=1m 0 2", &cfg, reason, sizeof(reason)),
                      FSTAB_MOUNTED);
        ASSERT_TRUE(!fx_checked(args, sizeof(args)));
        path_in(where, sizeof(where), "m/first");
        ASSERT_TRUE(umount2(where, MNT_DETACH) == 0);
        path_in(where, sizeof(where), "m/again");
        ASSERT_TRUE(umount2(where, MNT_DETACH) == 0);

        /* A clean ext filesystem passes the gate without a checker. */
        ASSERT_EQ_INT(run_line("LABEL=clean %s/m/clean auto size=1m 0 2", &cfg, reason, sizeof(reason)),
                      FSTAB_MOUNTED);
        ASSERT_TRUE(!fx_checked(args, sizeof(args)));

        /* An errored one gets fsck.ext4 -a on its node, and each verdict
         * its own ending. Unmounted between runs, or the next would find it
         * mounted and skip the check. */
        snprintf(node, sizeof(node), "%s/sdc", fx_dev);
        snprintf(mi_line, sizeof(mi_line), "-a %s\n", node);
        path_in(where, sizeof(where), "m/dirty");

        fx_checker(1);
        ASSERT_EQ_INT(run_line("LABEL=dirty %s/m/dirty auto size=1m 0 2", &cfg, reason, sizeof(reason)),
                      FSTAB_MOUNTED);
        ASSERT_TRUE(fx_checked(args, sizeof(args)));
        ASSERT_STREQ(args, mi_line);
        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)) && test_has_opt(vfs, "rw"));
        ASSERT_TRUE(umount2(where, MNT_DETACH) == 0);

        fx_checker(4);
        ASSERT_EQ_INT(run_line("LABEL=dirty %s/m/dirty auto size=1m 0 2", &cfg, reason, sizeof(reason)),
                      FSTAB_FAILED);
        ASSERT_STREQ(reason, "fsck left errors uncorrected, mounted read-only");
        ASSERT_TRUE(test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "ro") && test_has_opt(sb, "ro"));
        ASSERT_TRUE(umount2(where, MNT_DETACH) == 0);

        fx_checker(2);
        ASSERT_EQ_INT(run_line("LABEL=dirty %s/m/dirty auto size=1m 0 2", &cfg, reason, sizeof(reason)),
                      FSTAB_FAILED);
        ASSERT_STREQ(reason, "fsck.ext4 asks for a reboot (exit 2)");
        ASSERT_TRUE(!test_mount_options(where, vfs, sizeof(vfs), sb, sizeof(sb)));

        fx_checker(8);
        ASSERT_EQ_INT(run_line("LABEL=dirty %s/m/dirty auto size=1m 0 2", &cfg, reason, sizeof(reason)),
                      FSTAB_MOUNTED);
        ASSERT_TRUE(fx_checked(args, sizeof(args)));
        ASSERT_TRUE(umount2(where, MNT_DETACH) == 0);

        /* No checker installed: mounted unchecked. */
        {
                char path[PATH_MAX * 2];

                snprintf(path, sizeof(path), "%s/fsck.ext4", fx_fsck);
                ASSERT_EQ_INT(unlink(path), 0);
        }
        ASSERT_EQ_INT(run_line("LABEL=dirty %s/m/dirty auto size=1m 0 2", &cfg, reason, sizeof(reason)),
                      FSTAB_MOUNTED);
        ASSERT_TRUE(umount2(where, MNT_DETACH) == 0);

        /* A plain /dev path that exists is mounted from as written. */
        snprintf(node, sizeof(node), "%s/sdd", fx_dev);
        snprintf(mi_line, sizeof(mi_line), "%s %%s/m/plain auto size=1m 0 0", node);
        ASSERT_EQ_INT(run_line(mi_line, &cfg, reason, sizeof(reason)), FSTAB_MOUNTED);
        ASSERT_STREQ(reason, "auto size=1m");

        /* Never appears: skipped (degrading), or absent for nofail (not). */
        ASSERT_EQ_INT(run_line("LABEL=nowhere %s/m/gone auto defaults 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_SKIPPED);
        ASSERT_STREQ(reason, "no device after 150ms");
        ASSERT_EQ_INT(run_line("LABEL=nowhere %s/m/gone auto nofail 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_ABSENT);
        ASSERT_EQ_INT(run_line("/dev/pico-init-test-no-such-node %s/m/gone2 auto nofail 0 0",
                               &cfg,
                               reason,
                               sizeof(reason)),
                      FSTAB_ABSENT);

        /* A type with no UUID reader fails at once rather than waiting. */
        ASSERT_EQ_INT(run_line("UUID=" UUID_STICK " %s/m/f2 f2fs defaults 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_FAILED);
        ASSERT_STREQ(reason, "no UUID/LABEL reader for f2fs");

        /* A card that turns up while PID 1 waits. */
        cfg.device_timeout = 5 * USEC_PER_SEC;
        cfg.poll_hook = fx_late_card;
        cfg.poll_userdata = &seen;
        ASSERT_EQ_INT(run_line("LABEL=late %s/m/late auto size=1m 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_MOUNTED);
        ASSERT_EQ_INT(seen, 1);
        path_in(where, sizeof(where), "m/late");
        ASSERT_EQ_INT(fstab_is_mounted("/proc/self/mountinfo", where), 1);
}

/* --- ubifs lines: the UBI attach ahead of the pass, and the volume wait --- */

static char ubi_sys[PATH_MAX], ubi_dev[PATH_MAX];

static void ubi_attr(const char *fmt, int a, int b, const char *name, const char *content) {
        char rel[64], dir[PATH_MAX + 64];

        snprintf(rel, sizeof(rel), fmt, a, b);
        snprintf(dir, sizeof(dir), "%s/%s", ubi_sys, rel);
        ASSERT_EQ_INT(fstab_mkdir_p(dir, 0755), 0);
        ASSERT_EQ_INT(test_write_file(dir, name, content), 0);
}

/* UBI device `ubi` on MTD device `mtd`, with a volume 0 named "rootfs". */
static void ubi_attached(int ubi, int mtd) {
        char n[16];

        snprintf(n, sizeof(n), "%d\n", mtd);
        ubi_attr("class/ubi/ubi%d", ubi, 0, "mtd_num", n);
        ubi_attr("class/ubi/ubi%d_%d", ubi, 0, "name", "rootfs\n");
}

typedef struct UbiKernel {
        unsigned calls;
        int fail;
} UbiKernel;

/* UBI_IOCATT as the kernel answers it, minus the flash. */
static int ubi_fake_attach(const char *ctrl, struct ubi_attach_req *req, void *userdata) {
        UbiKernel *k = userdata;
        char path[PATH_MAX + 32];
        struct stat st;
        int num = req->ubi_num;

        (void) ctrl;
        k->calls++;
        if (k->fail)
                return -k->fail;

        if (num == UBI_DEV_NUM_AUTO)
                for (num = 0;; num++) {
                        snprintf(path, sizeof(path), "%s/class/ubi/ubi%d", ubi_sys, num);
                        if (stat(path, &st) < 0)
                                break;
                }
        ubi_attached(num, req->mtd_num);
        req->ubi_num = num;
        return 0;
}

static void ubi_late(void *userdata, unsigned attempt) {
        unsigned *seen = userdata;

        *seen = attempt;
        if (attempt == 2)
                ubi_attached(6, 7);
}

/*
 * A fresh fixture: MTD device 3 named "flash", /dev/ubi_ctrl, and `cmdline`
 * as the kernel command line.
 */
static void ubi_fixture(FstabPassConfig *cfg, UbiKernel *k, const char *cmdline) {
        char dir[PATH_MAX + 16];

        test_rm_rf(ubi_sys);
        test_rm_rf(ubi_dev);
        ubi_attr("class/mtd/mtd%d", 3, 0, "name", "flash\n");
        ASSERT_EQ_INT(fstab_mkdir_p(ubi_dev, 0755), 0);
        ASSERT_EQ_INT(test_write_file(ubi_dev, "ubi_ctrl", ""), 0);
        path_in(dir, sizeof(dir), "ubi");
        ASSERT_EQ_INT(test_write_file(dir, "cmdline", cmdline), 0);

        *k = (UbiKernel){ 0 };
        *cfg = (FstabPassConfig){
                .api_floor = never_api,
                .sys_root = ubi_sys,
                .dev_root = ubi_dev,
                .device_timeout = 150 * USEC_PER_MSEC,
                .ubi_attach = ubi_fake_attach,
                .ubi_attach_userdata = k,
        };
}

/* The mount itself cannot succeed here -- there is no flash behind any of
 * this -- so a line that got past every UBI step fails at the mount API,
 * whose step names all start "fs". */
static bool reached_mount(const char *reason) {
        return strncmp(reason, "fs", 2) == 0;
}

static void test_pass_ubi(void) {
        char cmdline[PATH_MAX + 16], reason[1024], line[PATH_MAX * 2], record[PATH_MAX], want[PATH_MAX + 32];
        FstabPassConfig cfg;
        FstabTable t = { 0 };
        UbiKernel k;
        unsigned seen = 0;

        path_in(ubi_sys, sizeof(ubi_sys), "ubi/sys");
        path_in(ubi_dev, sizeof(ubi_dev), "ubi/dev");
        path_in(cmdline, sizeof(cmdline), "ubi/cmdline");

        /* ubi.mtd= is carried out whatever fstab says, as the kernel would. */
        ubi_fixture(&cfg, &k, "root=/dev/mmcblk0p2 ubi.mtd=flash\n");
        cfg.cmdline = cmdline;
        path_in(record, sizeof(record), "ubi/record");
        cfg.record = record;
        ASSERT_EQ_INT(fstab_pass(&t, &cfg), 0);
        ASSERT_EQ_INT(k.calls, 1);

        /* Attached by PID 1, then mounted from the source as written. */
        ubi_fixture(&cfg, &k, "ubi.mtd=flash\n");
        cfg.cmdline = cmdline;
        ASSERT_EQ_INT(run_line("ubi0:rootfs %s/m/ubi ubifs defaults 0 1", &cfg, reason, sizeof(reason)),
                      FSTAB_FAILED);
        ASSERT_EQ_INT(k.calls, 1);
        ASSERT_TRUE(reached_mount(reason));
        ASSERT_TRUE(strstr(reason, "ubifs") != NULL);

        /* Attached already, by the kernel: no ioctl; and a volume it does
         * not have fails at once rather than after a wait. */
        ubi_fixture(&cfg, &k, "ubi.mtd=flash\n");
        cfg.cmdline = cmdline;
        cfg.device_timeout = 5 * USEC_PER_SEC;
        ubi_attached(0, 3);
        {
                usec_t t0 = now_monotonic();

                ASSERT_EQ_INT(run_line("ubi0:nosuch %s/m/ubi ubifs defaults 0 0", &cfg, reason, sizeof(reason)),
                              FSTAB_FAILED);
                ASSERT_TRUE(now_monotonic() - t0 < 1 * USEC_PER_SEC);
        }
        ASSERT_STREQ(reason, "ubi0 is attached without that volume");
        ASSERT_EQ_INT(k.calls, 0);
        ASSERT_EQ_INT(run_line("ubi0_0 %s/m/ubi ubifs defaults 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_FAILED);
        ASSERT_TRUE(reached_mount(reason));
        ASSERT_EQ_INT(run_line("ubi0_1 %s/m/ubi ubifs defaults 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_FAILED);
        ASSERT_STREQ(reason, "ubi0 is attached without that volume");

        /* The attach for the line's device number failed: the line says why. */
        ubi_fixture(&cfg, &k, "ubi.mtd=flash,0,0,2\n");
        cfg.cmdline = cmdline;
        k.fail = EINVAL;
        ASSERT_EQ_INT(run_line("ubi2_0 %s/m/ubi ubifs defaults 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_FAILED);
        ASSERT_STREQ(reason, "ubi2 not attached: UBI_IOCATT on mtd3: Invalid argument");
        ASSERT_EQ_INT(k.calls, 1);

        /* Its flash never appeared: skipped, or absent for nofail. */
        ubi_fixture(&cfg, &k, "ubi.mtd=nowhere,0,0,1\n");
        cfg.cmdline = cmdline;
        ASSERT_EQ_INT(run_line("ubi1:rootfs %s/m/ubi ubifs defaults 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_SKIPPED);
        ASSERT_STREQ(reason, "ubi1 not attached: MTD device nowhere never appeared");
        ASSERT_EQ_INT(run_line("ubi1:rootfs %s/m/ubi ubifs nofail 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_ABSENT);
        ASSERT_EQ_INT(k.calls, 0);

        /* Nothing names the device: waited for, then skipped or absent. */
        ubi_fixture(&cfg, &k, "quiet\n");
        cfg.cmdline = cmdline;
        ASSERT_EQ_INT(run_line("ubi5_0 %s/m/ubi ubifs defaults 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_SKIPPED);
        ASSERT_STREQ(reason, "ubi5 not attached after 150ms");
        ASSERT_EQ_INT(run_line("ubi5_0 %s/m/ubi ubifs nofail 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_ABSENT);

        /* ... and found when it turns up during the wait. */
        cfg.device_timeout = 5 * USEC_PER_SEC;
        cfg.poll_hook = ubi_late;
        cfg.poll_userdata = &seen;
        ASSERT_EQ_INT(run_line("ubi6!rootfs %s/m/ubi ubifs defaults 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_FAILED);
        ASSERT_EQ_INT(seen, 2);
        ASSERT_TRUE(reached_mount(reason));
        cfg.poll_hook = NULL;

        /* A node path needs the node as well as the volume. */
        cfg.device_timeout = 150 * USEC_PER_MSEC;
        ubi_attached(0, 3);
        snprintf(line, sizeof(line), "%s/ubi0_0 %%s/m/ubi ubifs defaults 0 0", ubi_dev);
        ASSERT_EQ_INT(run_line(line, &cfg, reason, sizeof(reason)), FSTAB_SKIPPED);
        snprintf(want, sizeof(want), "no %s/ubi0_0 after 150ms", ubi_dev);
        ASSERT_STREQ(reason, want);
        ASSERT_EQ_INT(test_write_file(ubi_dev, "ubi0_0", ""), 0);
        ASSERT_EQ_INT(run_line(line, &cfg, reason, sizeof(reason)), FSTAB_FAILED);
        ASSERT_TRUE(reached_mount(reason));

        /* Not ubifs: none of this applies. */
        ASSERT_EQ_INT(run_line("ubi9_9 %s/m/ubi tmpfs size=1m 0 0", &cfg, reason, sizeof(reason)),
                      FSTAB_MOUNTED);
}

/* Two stand-ins for the table's /dev/pts and /run entries, by their scratch
 * paths, with the table's own floors. */
static char stock_pts[PATH_MAX], stock_run[PATH_MAX];

static bool stock_api(const char *where, uint64_t *ret_floor) {
        if (strcmp(where, stock_pts) == 0) {
                *ret_floor = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC;
                return true;
        }
        if (strcmp(where, stock_run) == 0) {
                *ret_floor = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;
                return true;
        }
        return false;
}

/*
 * oe-core's stock fstab lines for /dev/pts and /run, against mounts made the
 * way mount-setup.c makes them. The devpts line differs from the table
 * (ptmxmode=), so it is really reapplied through a devpts reconfigure; gid=0
 * rather than the stock gid=5 only because gid 5 has no mapping in this
 * namespace.
 */
static void test_stock_api_lines(void) {
        char vfs[1024], sb[1024], record[PATH_MAX], line[PATH_MAX * 2];
        FstabPassConfig cfg = { 0 };
        FstabTable t = { 0 };

        path_in(stock_pts, sizeof(stock_pts), "stock/pts");
        path_in(stock_run, sizeof(stock_run), "stock/run");
        path_in(record, sizeof(record), "stock/fstab");
        ASSERT_EQ_INT(fstab_mkdir_p(stock_pts, 0755), 0);
        ASSERT_EQ_INT(fstab_mkdir_p(stock_run, 0755), 0);

        ASSERT_TRUE(mount("devpts", stock_pts, "devpts", MS_NOSUID | MS_NOEXEC, "newinstance,gid=0,mode=620") ==
                    0);
        ASSERT_TRUE(mount("tmpfs", stock_run, "tmpfs", MS_NOSUID | MS_NODEV | MS_STRICTATIME, "mode=0755") ==
                    0);

        t.entries = calloc(2, sizeof(FstabEntry));
        ASSERT_TRUE(t.entries != NULL);
        snprintf(line, sizeof(line), "devpts %s devpts mode=0620,ptmxmode=0666,gid=0 0 0", stock_pts);
        ASSERT_EQ_INT(fstab_parse_line(line, &t.entries[t.n++]), 1);
        snprintf(line, sizeof(line), "tmpfs %s tmpfs mode=0755,nodev,nosuid,strictatime 0 0", stock_run);
        ASSERT_EQ_INT(fstab_parse_line(line, &t.entries[t.n++]), 1);

        cfg.api_floor = stock_api;
        cfg.record = record;
        ASSERT_EQ_INT(fstab_pass(&t, &cfg), 0);
        ASSERT_EQ_INT(t.entries[0].outcome, FSTAB_REMOUNTED);
        ASSERT_EQ_INT(t.entries[1].outcome, FSTAB_REMOUNTED);

        ASSERT_TRUE(test_mount_options(stock_pts, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(sb, "ptmxmode=666"));
        ASSERT_TRUE(test_has_opt(vfs, "nosuid") && test_has_opt(vfs, "noexec"));

        /* strictatime shows in mountinfo as the absence of the other two. */
        ASSERT_TRUE(test_mount_options(stock_run, vfs, sizeof(vfs), sb, sizeof(sb)));
        ASSERT_TRUE(test_has_opt(vfs, "nosuid") && test_has_opt(vfs, "nodev"));
        ASSERT_TRUE(!test_has_opt(vfs, "relatime") && !test_has_opt(vfs, "noatime"));
        ASSERT_TRUE(test_has_opt(vfs, "rw"));

        fstab_table_done(&t);
}

int main(void) {
        char *dir;

        test_attr_masks();
        test_api_floor();
        test_is_mounted_and_mkdir();
        test_device_mounted();
        test_pass_skips();
        test_swap_flags();
        test_pass_swap();

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(scratch, sizeof(scratch), "%s", dir);

        if (!test_enter_mount_namespace()) {
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
        test_pass_devices();
        test_pass_ubi();
        test_stock_api_lines();

        ASSERT_TRUE(umount2(scratch, MNT_DETACH) == 0);
        test_rm_rf(dir);
        free(dir);

        printf("test-fstab-mount: all checks passed\n");
        return 0;
}
