/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The pure half of fstab processing: the line grammar, the option table, the
 * mount order and the outcome record. Nothing here mounts anything;
 * test-fstab-mount.c covers the half that does.
 *
 * The option table is the part most worth pinning. An option routed the wrong
 * way is not a cosmetic bug under the new mount API: the kernel rejects a VFS
 * attribute offered as an fsconfig() parameter, and rejects the whole mount
 * over one userspace option passed through to the filesystem.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#include "fstab.h"
#include "test-util.h"

/* oe-core's base-files fstab, the five active lines as shipped. */
static const char stock_fstab[] =
                "# stock fstab - you probably want to override this with a machine specific one\n"
                "\n"
                "/dev/root            /                    auto       defaults              1  1\n"
                "proc                 /proc                proc       defaults              0  0\n"
                "devpts               /dev/pts             devpts     mode=0620,ptmxmode=0666,gid=5      0  0\n"
                "tmpfs                /run                 tmpfs      mode=0755,nodev,nosuid,strictatime 0  0\n"
                "tmpfs                /var/volatile        tmpfs      defaults              0  0\n"
                "\n"
                "# uncomment this if your device has a SD/MMC/Transflash slot\n"
                "#/dev/mmcblk0p1       /media/card          auto       defaults,sync,noauto  0  0\n";

static void test_unescape(void) {
        char a[] = "/mnt/my\\040disk", b[] = "tab\\011here", c[] = "\\01x", d[] = "\\999", e[] = "end\\";
        char f[] = "\\134";

        fstab_unescape(a);
        ASSERT_STREQ(a, "/mnt/my disk");
        fstab_unescape(b);
        ASSERT_STREQ(b, "tab\there");

        /* Not three octal digits: kept exactly as written. */
        fstab_unescape(c);
        ASSERT_STREQ(c, "\\01x");
        fstab_unescape(d);
        ASSERT_STREQ(d, "\\999");
        fstab_unescape(e);
        ASSERT_STREQ(e, "end\\");

        /* An escaped backslash is one backslash, and is not unescaped twice. */
        fstab_unescape(f);
        ASSERT_STREQ(f, "\\");
}

static void test_escape(void) {
        char buf[64], small[6];
        char round[64];

        ASSERT_EQ_INT(fstab_escape("/mnt/my disk\\x", buf, sizeof(buf)), 0);
        ASSERT_STREQ(buf, "/mnt/my\\040disk\\134x");

        snprintf(round, sizeof(round), "%s", buf);
        fstab_unescape(round);
        ASSERT_STREQ(round, "/mnt/my disk\\x");

        ASSERT_EQ_INT(fstab_escape("/a b", small, sizeof(small)), -ENAMETOOLONG);
        ASSERT_EQ_INT(fstab_escape("/abcde", small, sizeof(small)), -ENAMETOOLONG);
        ASSERT_EQ_INT(fstab_escape("/abcd", small, sizeof(small)), 0);
        ASSERT_STREQ(small, "/abcd");
}

static void test_options_attrs(void) {
        FstabOptions o;

        /* defaults turns nothing on and nothing off -- in particular it does
         * NOT clear nosuid/nodev/noexec, which is what lets PID 1's floor for
         * its own API mounts survive a "defaults" fstab line. */
        ASSERT_EQ_INT(fstab_options_parse("defaults", &o), 0);
        ASSERT_EQ_INT(o.attr_set, 0);
        ASSERT_EQ_INT(o.attr_clr, 0);
        ASSERT_TRUE(o.data == NULL && o.sb_flags == NULL);
        ASSERT_TRUE(fstab_options_trivial(&o));
        fstab_options_done(&o);

        ASSERT_EQ_INT(fstab_options_parse("ro", &o), 0);
        ASSERT_EQ_INT(o.attr_set, MOUNT_ATTR_RDONLY);
        ASSERT_TRUE(!fstab_options_trivial(&o));
        fstab_options_done(&o);

        ASSERT_EQ_INT(fstab_options_parse("rw", &o), 0);
        ASSERT_EQ_INT(o.attr_set, 0);
        ASSERT_EQ_INT(o.attr_clr, MOUNT_ATTR_RDONLY);
        ASSERT_TRUE(fstab_options_trivial(&o));
        fstab_options_done(&o);

        /* The stock /run line: two hardening bits, an atime mode, and one
         * option that only tmpfs understands. */
        ASSERT_EQ_INT(fstab_options_parse("mode=0755,nodev,nosuid,strictatime", &o), 0);
        ASSERT_EQ_INT(o.attr_set, MOUNT_ATTR_NODEV | MOUNT_ATTR_NOSUID | MOUNT_ATTR_STRICTATIME);
        ASSERT_EQ_INT(o.attr_clr, MOUNT_ATTR__ATIME);
        ASSERT_TRUE(o.data && o.data[0] && !o.data[1]);
        ASSERT_STREQ(o.data[0], "mode=0755");
        ASSERT_TRUE(!fstab_options_trivial(&o));
        fstab_options_done(&o);

        /* Last one wins, per bit and for the atime field as a whole. */
        ASSERT_EQ_INT(fstab_options_parse("nosuid,suid,ro,rw,noexec", &o), 0);
        ASSERT_EQ_INT(o.attr_set, MOUNT_ATTR_NOEXEC);
        ASSERT_EQ_INT(o.attr_clr, MOUNT_ATTR_NOSUID | MOUNT_ATTR_RDONLY);
        fstab_options_done(&o);

        ASSERT_EQ_INT(fstab_options_parse("noatime,relatime", &o), 0);
        ASSERT_EQ_INT(o.attr_set & MOUNT_ATTR__ATIME, MOUNT_ATTR_RELATIME);
        ASSERT_EQ_INT(o.attr_clr, MOUNT_ATTR__ATIME);
        fstab_options_done(&o);

        ASSERT_EQ_INT(fstab_options_parse("strictatime,noatime,nodiratime,nosymfollow", &o), 0);
        ASSERT_EQ_INT(o.attr_set, MOUNT_ATTR_NOATIME | MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_NOSYMFOLLOW);
        ASSERT_EQ_INT(o.attr_clr, MOUNT_ATTR__ATIME);
        fstab_options_done(&o);

        /* A negated atime option claims the field and resets it to the
         * kernel's default, rather than being a no-op. */
        ASSERT_EQ_INT(fstab_options_parse("noatime,atime", &o), 0);
        ASSERT_EQ_INT(o.attr_set, 0);
        ASSERT_EQ_INT(o.attr_clr, MOUNT_ATTR__ATIME);
        ASSERT_TRUE(!fstab_options_trivial(&o));
        fstab_options_done(&o);

        /* A VFS attribute name with a value is not that attribute: it goes to
         * the filesystem as written, and the filesystem gets to say no. */
        ASSERT_EQ_INT(fstab_options_parse("ro=1", &o), 0);
        ASSERT_EQ_INT(o.attr_set, 0);
        ASSERT_TRUE(o.data && strcmp(o.data[0], "ro=1") == 0);
        fstab_options_done(&o);
}

static void test_options_routing(void) {
        FstabOptions o;

        /* Superblock flags are their own list, never data and never attrs. */
        ASSERT_EQ_INT(fstab_options_parse("sync,dirsync,lazytime,async", &o), 0);
        ASSERT_EQ_INT(o.attr_set, 0);
        ASSERT_TRUE(o.data == NULL);
        ASSERT_EQ_INT(pico_strv_length(o.sb_flags), 4);
        ASSERT_STREQ(o.sb_flags[0], "sync");
        ASSERT_STREQ(o.sb_flags[3], "async");
        ASSERT_TRUE(!fstab_options_trivial(&o));
        fstab_options_done(&o);

        /* Every userspace-only option consumed; the ones that mean something
         * to pico-init recorded as flags. */
        ASSERT_EQ_INT(fstab_options_parse(
                                      "defaults,auto,nofail,_netdev,noauto,user,users,nouser,owner,group,"
                                      "comment=x-gvfs-show,x-systemd.device-timeout=5s,X-mount.mkdir,"
                                      "x-systemd.requires=foo.service,uhelper=udisks2,sw",
                                      &o),
                      0);
        ASSERT_TRUE(o.data == NULL && o.sb_flags == NULL);
        ASSERT_EQ_INT(o.attr_set, 0);
        ASSERT_EQ_INT(o.attr_clr, 0);
        ASSERT_TRUE(o.nofail && o.netdev && o.noauto);
        ASSERT_TRUE(!o.automount && !o.bind && !o.propagation);
        ASSERT_EQ_INT(o.device_timeout, 5 * USEC_PER_SEC);
        fstab_options_done(&o);

        ASSERT_EQ_INT(fstab_options_parse("x-systemd.automount,bind", &o), 0);
        ASSERT_TRUE(o.automount && o.bind && !o.rbind);
        fstab_options_done(&o);

        ASSERT_EQ_INT(fstab_options_parse("rbind,rshared,loop=/dev/loop0,offset=512", &o), 0);
        ASSERT_TRUE(o.rbind && o.propagation && o.loop);
        ASSERT_TRUE(o.data == NULL);
        fstab_options_done(&o);

        /* Filesystem options pass through verbatim and in order, values with
         * '=' in them and empty values included. */
        ASSERT_EQ_INT(fstab_options_parse("errors=remount-ro,commit=60,,user_xattr,opt=a=b,empty=", &o), 0);
        ASSERT_EQ_INT(pico_strv_length(o.data), 5);
        ASSERT_STREQ(o.data[0], "errors=remount-ro");
        ASSERT_STREQ(o.data[1], "commit=60");
        ASSERT_STREQ(o.data[2], "user_xattr");
        ASSERT_STREQ(o.data[3], "opt=a=b");
        ASSERT_STREQ(o.data[4], "empty=");
        fstab_options_done(&o);

        /* An option with no name is malformed, not silently dropped. */
        ASSERT_EQ_INT(fstab_options_parse("mode=0755,=x", &o), -EINVAL);
        ASSERT_TRUE(o.data == NULL);

        /* An empty field is the same as defaults. */
        ASSERT_EQ_INT(fstab_options_parse("", &o), 0);
        ASSERT_TRUE(fstab_options_trivial(&o));
        fstab_options_done(&o);
        ASSERT_EQ_INT(fstab_options_parse(NULL, &o), 0);
        ASSERT_TRUE(fstab_options_trivial(&o));
        fstab_options_done(&o);
}

static void test_device_timeout(void) {
        static const struct {
                const char *opt;
                usec_t want;
                bool set;
        } cases[] = {
                {       "x-systemd.device-timeout=90",   90 * USEC_PER_SEC,  true },
                {    "x-systemd.device-timeout=500ms", 500 * USEC_PER_MSEC,  true },
                {     "x-systemd.device-timeout=2min",  120 * USEC_PER_SEC,  true },
                {        "x-systemd.device-timeout=0",                   0,  true },
                { "x-systemd.device-timeout=infinity",       USEC_INFINITY,  true },
                {    "x-systemd.device-timeout=bogus",       USEC_INFINITY, false },
                {      "x-systemd.device-timeout=5xs",       USEC_INFINITY, false },
                {                            "nofail",       USEC_INFINITY, false },
        };
        size_t i;

        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                FstabOptions o;

                ASSERT_EQ_INT(fstab_options_parse(cases[i].opt, &o), 0);
                if (o.device_timeout != cases[i].want) {
                        fprintf(stderr, "%s: got %llu\n", cases[i].opt, (unsigned long long) o.device_timeout);
                        ASSERT_TRUE(o.device_timeout == cases[i].want);
                }
                ASSERT_EQ_INT(o.device_timeout_set, cases[i].set);
                ASSERT_TRUE(o.data == NULL);
                fstab_options_done(&o);
        }
}

static void test_parse_line(void) {
        FstabEntry e;

        ASSERT_EQ_INT(fstab_parse_line("", &e), 0);
        ASSERT_EQ_INT(fstab_parse_line("   \t\n", &e), 0);
        ASSERT_EQ_INT(fstab_parse_line("# tmpfs /x tmpfs defaults 0 0\n", &e), 0);
        ASSERT_EQ_INT(fstab_parse_line("   # indented\n", &e), 0);
        ASSERT_EQ_INT(fstab_parse_line(NULL, &e), 0);

        ASSERT_EQ_INT(fstab_parse_line("tmpfs /var/volatile tmpfs defaults 0 0\n", &e), 1);
        ASSERT_STREQ(e.what, "tmpfs");
        ASSERT_STREQ(e.where, "/var/volatile");
        ASSERT_STREQ(e.type, "tmpfs");
        ASSERT_STREQ(e.options, "defaults");
        ASSERT_EQ_INT(e.freq, 0);
        ASSERT_EQ_INT(e.passno, 0);
        ASSERT_EQ_INT(e.outcome, FSTAB_PENDING);
        fstab_entry_done(&e);

        /* Trailing fields default, the way libmount has them. */
        ASSERT_EQ_INT(fstab_parse_line("tmpfs /tmp tmpfs", &e), 1);
        ASSERT_STREQ(e.options, "defaults");
        ASSERT_EQ_INT(e.passno, 0);
        ASSERT_TRUE(fstab_options_trivial(&e.opts));
        fstab_entry_done(&e);

        ASSERT_EQ_INT(fstab_parse_line("/dev/root / auto defaults 1", &e), 1);
        ASSERT_EQ_INT(e.freq, 1);
        ASSERT_EQ_INT(e.passno, 0);
        fstab_entry_done(&e);

        ASSERT_EQ_INT(fstab_parse_line("/dev/root\t/\tauto\tdefaults\t1\t1\n", &e), 1);
        ASSERT_STREQ(e.where, "/");
        ASSERT_EQ_INT(e.passno, 1);
        fstab_entry_done(&e);

        /* Escapes in every field, and a mount point normalized to what
         * mountinfo will call it. */
        ASSERT_EQ_INT(fstab_parse_line("LABEL=my\\040data /mnt//my\\040data/ ext4 comment=a\\040b 0 2", &e),
                      1);
        ASSERT_STREQ(e.what, "LABEL=my data");
        ASSERT_STREQ(e.where, "/mnt/my data");
        ASSERT_STREQ(e.options, "comment=a b");
        ASSERT_EQ_INT(e.passno, 2);
        fstab_entry_done(&e);

        /* Only absolute paths are normalized; swap's "none" is a word. */
        ASSERT_EQ_INT(fstab_parse_line("/dev/sda2 none swap sw 0 0", &e), 1);
        ASSERT_STREQ(e.where, "none");
        ASSERT_STREQ(e.type, "swap");
        fstab_entry_done(&e);

        ASSERT_EQ_INT(fstab_parse_line("//server/share /mnt/share cifs _netdev 0 0", &e), 1);
        ASSERT_STREQ(e.what, "//server/share");
        ASSERT_TRUE(e.opts.netdev);
        fstab_entry_done(&e);

        /* Malformed: too few fields, non-numeric freq or passno, a nameless
         * option. Every one of these leaves *e empty rather than half-set. */
        ASSERT_EQ_INT(fstab_parse_line("tmpfs /tmp", &e), -EINVAL);
        ASSERT_TRUE(e.what == NULL);
        ASSERT_EQ_INT(fstab_parse_line("tmpfs /tmp tmpfs defaults zero 0", &e), -EINVAL);
        ASSERT_EQ_INT(fstab_parse_line("tmpfs /tmp tmpfs defaults 0 1x", &e), -EINVAL);
        ASSERT_EQ_INT(fstab_parse_line("tmpfs /tmp tmpfs =oops 0 0", &e), -EINVAL);
        ASSERT_TRUE(e.what == NULL && e.opts.data == NULL);
}

static void test_load_stock(void) {
        FstabTable t;
        char *dir, path[4096];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "fstab", stock_fstab), 0);
        snprintf(path, sizeof(path), "%s/fstab", dir);

        ASSERT_EQ_INT(fstab_load(path, &t), 0);
        ASSERT_EQ_INT(t.n, 5);

        ASSERT_STREQ(t.entries[0].where, "/");
        ASSERT_EQ_INT(t.entries[0].line, 3);
        ASSERT_EQ_INT(t.entries[0].passno, 1);
        ASSERT_STREQ(t.entries[1].where, "/proc");
        ASSERT_STREQ(t.entries[2].where, "/dev/pts");
        ASSERT_EQ_INT(pico_strv_length(t.entries[2].opts.data), 3);
        ASSERT_STREQ(t.entries[2].opts.data[1], "ptmxmode=0666");
        ASSERT_STREQ(t.entries[3].where, "/run");
        ASSERT_STREQ(t.entries[4].where, "/var/volatile");
        ASSERT_EQ_INT(t.entries[4].line, 7);

        ASSERT_TRUE(fstab_find(&t, "/") == &t.entries[0]);
        ASSERT_TRUE(fstab_find(&t, "/var/volatile") == &t.entries[4]);
        ASSERT_TRUE(fstab_find(&t, "/media/card") == NULL);
        ASSERT_TRUE(fstab_find(&t, NULL) == NULL);

        fstab_table_done(&t);
        ASSERT_TRUE(t.entries == NULL && t.n == 0);

        /* A malformed line in the middle costs that line only; later lines
         * still count, with their real line numbers. The last of two lines
         * for one mount point is the one fstab_find() answers with. */
        ASSERT_EQ_INT(test_write_file(dir,
                                      "fstab",
                                      "tmpfs /a tmpfs defaults 0 0\n"
                                      "garbage\n"
                                      "tmpfs /b tmpfs size=1m 0 0\n"
                                      "tmpfs /a tmpfs size=2m 0 0\n"),
                      0);
        ASSERT_EQ_INT(fstab_load(path, &t), 0);
        ASSERT_EQ_INT(t.n, 3);
        ASSERT_EQ_INT(t.entries[1].line, 3);
        ASSERT_TRUE(fstab_find(&t, "/a") == &t.entries[2]);
        fstab_table_done(&t);

        /* No fstab at all is an answer, with a valid empty table. */
        snprintf(path, sizeof(path), "%s/missing", dir);
        ASSERT_EQ_INT(fstab_load(path, &t), -ENOENT);
        ASSERT_TRUE(t.entries == NULL && t.n == 0);
        fstab_table_done(&t);

        test_rm_rf(dir);
        free(dir);
}

static void test_mount_order(void) {
        static const char * const lines[] = {
                "tmpfs /var/volatile/log tmpfs defaults 0 0",
                "/dev/root / auto defaults 1 1",
                "tmpfs /var/volatile tmpfs defaults 0 0",
                "/dev/sda1 /data ext4 defaults 0 2",
                "tmpfs /var tmpfs defaults 0 0",
                "/dev/sdb1 /data/b ext4 defaults 0 2",
        };
        static const char * const want[] = {
                "/", "/data", "/var", "/var/volatile", "/data/b", "/var/volatile/log",
        };
        FstabTable t = { 0 };
        FstabEntry **order;
        size_t i;

        ASSERT_EQ_INT(fstab_path_depth("/"), 0);
        ASSERT_EQ_INT(fstab_path_depth("/var"), 1);
        ASSERT_EQ_INT(fstab_path_depth("/var/volatile"), 2);
        ASSERT_EQ_INT(fstab_path_depth("/var/volatile/"), 2);
        ASSERT_EQ_INT(fstab_path_depth("none"), 1);
        ASSERT_EQ_INT(fstab_path_depth(NULL), 0);

        t.entries = calloc(sizeof(lines) / sizeof(lines[0]), sizeof(FstabEntry));
        ASSERT_TRUE(t.entries != NULL);
        for (i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
                ASSERT_EQ_INT(fstab_parse_line(lines[i], &t.entries[i]), 1);
                t.n++;
        }

        ASSERT_EQ_INT(fstab_mount_order(&t, &order), 0);
        ASSERT_TRUE(order != NULL);
        for (i = 0; i < t.n; i++)
                ASSERT_STREQ(order[i]->where, want[i]);

        /* The sort orders pointers; the table itself keeps file order, which
         * is what the record is written in. */
        ASSERT_STREQ(t.entries[0].where, "/var/volatile/log");

        free(order);
        fstab_table_done(&t);

        ASSERT_EQ_INT(fstab_mount_order(&t, &order), 0);
        ASSERT_TRUE(order == NULL);
}

static void test_outcome_strings(void) {
        unsigned i;

        for (i = 0; i < _FSTAB_OUTCOME_MAX; i++)
                ASSERT_EQ_INT(fstab_outcome_from_string(fstab_outcome_to_string((FstabOutcome) i)), i);

        ASSERT_EQ_INT(fstab_outcome_from_string("bogus"), _FSTAB_OUTCOME_MAX);
        ASSERT_EQ_INT(fstab_outcome_from_string(NULL), _FSTAB_OUTCOME_MAX);
        ASSERT_STREQ(fstab_outcome_to_string(_FSTAB_OUTCOME_MAX), "unknown");

        /* Exactly two outcomes degrade the system. noauto is a line doing
         * what it says, and "present" is a mount that is already right. */
        ASSERT_TRUE(fstab_outcome_is_degraded(FSTAB_FAILED));
        ASSERT_TRUE(fstab_outcome_is_degraded(FSTAB_SKIPPED));
        ASSERT_TRUE(!fstab_outcome_is_degraded(FSTAB_MOUNTED));
        ASSERT_TRUE(!fstab_outcome_is_degraded(FSTAB_REMOUNTED));
        ASSERT_TRUE(!fstab_outcome_is_degraded(FSTAB_PRESENT));
        ASSERT_TRUE(!fstab_outcome_is_degraded(FSTAB_NOAUTO));
        ASSERT_TRUE(!fstab_outcome_is_degraded(FSTAB_PENDING));
        ASSERT_TRUE(!fstab_outcome_is_degraded(FSTAB_ABSENT));
        ASSERT_TRUE(!fstab_outcome_is_degraded(FSTAB_ACTIVE));
        ASSERT_STREQ(fstab_outcome_to_string(FSTAB_ABSENT), "absent");
        ASSERT_STREQ(fstab_outcome_to_string(FSTAB_ACTIVE), "active");
}

static void test_record(void) {
        FstabTable t = { 0 };
        char *dir, path[4096], *content = NULL;
        size_t len = 0;
        FILE *f;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(path, sizeof(path), "%s/fstab", dir);

        t.entries = calloc(6, sizeof(FstabEntry));
        ASSERT_TRUE(t.entries != NULL);
        ASSERT_EQ_INT(fstab_parse_line("tmpfs /var/volatile tmpfs defaults 0 0", &t.entries[0]), 1);
        ASSERT_EQ_INT(fstab_parse_line("/dev/sda1 /mnt/my\\040disk ext4 defaults 0 2", &t.entries[1]), 1);
        ASSERT_EQ_INT(fstab_parse_line("srv:/x /mnt/nfs nfs defaults 0 0", &t.entries[2]), 1);
        ASSERT_EQ_INT(fstab_parse_line("/dev/sdc1 /mnt/card auto noauto 0 0", &t.entries[3]), 1);
        ASSERT_EQ_INT(fstab_parse_line("LABEL=swap\\040a none swap sw 0 0", &t.entries[4]), 1);
        ASSERT_EQ_INT(fstab_parse_line("UUID=1234-ABCD /mnt/stick vfat nofail 0 0", &t.entries[5]), 1);
        t.n = 6;
        ASSERT_TRUE(fstab_has_swap(&t));

        fstab_entry_set_outcome(&t.entries[0], FSTAB_MOUNTED, "tmpfs");
        fstab_entry_set_outcome(&t.entries[1], FSTAB_FAILED, "fsconfig: %s\ne second line", "No such device");
        fstab_entry_set_outcome(&t.entries[2], FSTAB_SKIPPED, "network filesystem");
        fstab_entry_set_outcome(&t.entries[3], FSTAB_NOAUTO, NULL);
        fstab_entry_set_outcome(&t.entries[4], FSTAB_ACTIVE, "/dev/sda3");
        fstab_entry_set_outcome(&t.entries[5], FSTAB_ABSENT, "no device appeared");

        ASSERT_EQ_INT(fstab_record_write(&t, path), 0);

        f = fopen(path, "re");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(getdelim(&content, &len, '\0', f) > 0);
        fclose(f);

        /* One line per entry in file order, the mount point escaped so the
         * record stays whitespace-separable, a kernel message's newline
         * flattened, and "-" standing in for no reason at all. */
        ASSERT_STREQ(content,
                     "/var/volatile mounted tmpfs\n"
                     "/mnt/my\\040disk failed fsconfig: No such device e second line\n"
                     "/mnt/nfs skipped network filesystem\n"
                     "/mnt/card noauto -\n"
                     "LABEL=swap\\040a active /dev/sda3\n"
                     "/mnt/stick absent no device appeared\n");
        free(content);

        ASSERT_EQ_INT(fstab_record_count_degraded(path), 2);

        /* Rewritten in place: no temporary file left beside it. */
        fstab_entry_set_outcome(&t.entries[1], FSTAB_MOUNTED, "ext4");
        fstab_entry_set_outcome(&t.entries[2], FSTAB_NOAUTO, NULL);
        ASSERT_EQ_INT(fstab_record_write(&t, path), 0);
        ASSERT_EQ_INT(fstab_record_count_degraded(path), 0);
        {
                char tmp[4200];

                snprintf(tmp, sizeof(tmp), "%s.tmp", path);
                ASSERT_TRUE(access(tmp, F_OK) < 0 && errno == ENOENT);
        }

        /* An empty table is an empty record, which is not an absent one. */
        fstab_table_done(&t);
        ASSERT_TRUE(!fstab_has_swap(&t));
        ASSERT_TRUE(!fstab_has_swap(NULL));
        ASSERT_EQ_INT(fstab_record_write(&t, path), 0);
        ASSERT_EQ_INT(fstab_record_count_degraded(path), 0);

        /* Lines the reader does not understand are not counted. */
        ASSERT_EQ_INT(test_write_file(dir, "fstab", "garbage\n/x failed why\n/y bogus-outcome z\n\n"), 0);
        ASSERT_EQ_INT(fstab_record_count_degraded(path), 1);

        snprintf(path, sizeof(path), "%s/missing", dir);
        ASSERT_EQ_INT(fstab_record_count_degraded(path), -ENOENT);

        snprintf(path, sizeof(path), "%s/no/such/dir/fstab", dir);
        ASSERT_EQ_INT(fstab_record_write(&t, path), -ENOENT);

        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_unescape();
        test_escape();
        test_options_attrs();
        test_options_routing();
        test_device_timeout();
        test_parse_line();
        test_load_stock();
        test_mount_order();
        test_outcome_strings();
        test_record();

        printf("test-fstab: all checks passed\n");
        return 0;
}
