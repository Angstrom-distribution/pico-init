/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * udevadm against a fixture sysfs, /dev, /run/devd and udev database built in
 * a temporary directory. udevadm.c is included so its file-local functions can
 * be called and its roots repointed; main() is renamed out of the way, as
 * test-devd-opts.c does for devd.c.
 *
 * Not covered here: anything that needs a real device node (resolving a /dev
 * name through its major:minor needs mknod) or a running devd (settle and
 * control --exit against a live process are a boot test).
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define main udevadm_main
#pragma GCC diagnostic ignored "-Wunused-function"
#include "udevadm.c"
#undef main

#include "../test-util.h"

static char root[PATH_MAX];
static char sys_root[PATH_MAX], dev_root[PATH_MAX], run_root[PATH_MAX], udev_run_root[PATH_MAX],
                db_root[PATH_MAX];

static void fixture_path(char ret[static PATH_MAX], const char *rel) {
        ASSERT_TRUE((size_t) snprintf(ret, PATH_MAX, "%s/%s", root, rel) < PATH_MAX);
}

static void read_file(const char *path, char *buf, size_t size) {
        FILE *f = fopen(path, "re");
        size_t n;

        ASSERT_TRUE(f != NULL);
        n = fread(buf, 1, size - 1, f);
        buf[n] = '\0';
        ASSERT_EQ_INT(fclose(f), 0);
}

/*
 * The kernel's layout, reduced: a platform device on a bus with a driver, a
 * virtio disk and its partition in the block class, a module, and a file in a
 * class directory that is not a device at all (net's bonding_masters).
 */
static void build_fixture(void) {
        static const char * const dirs[] = {
                "sys",
                "sys/devices",
                "sys/devices/platform",
                "sys/devices/platform/foo",
                "sys/devices/virtio",
                "sys/devices/virtio/vda",
                "sys/devices/virtio/vda/vda1",
                "sys/bus",
                "sys/bus/platform",
                "sys/bus/platform/devices",
                "sys/bus/platform/drivers",
                "sys/bus/platform/drivers/drv",
                "sys/class",
                "sys/class/block",
                "sys/class/net",
                "sys/module",
                "sys/module/m1",
                "sys/kernel",
                "dev",
                "dev/disk",
                "dev/disk/by-uuid",
                "run",
                "run/devd",
                "run/udev",
                "run/udev/data",
        };
        static const char * const empty_uevents[] = {
                "sys/devices/platform/foo/uevent",
                "sys/devices/virtio/vda/vda1/uevent",
                "sys/bus/platform/uevent",
                "sys/bus/platform/drivers/drv/uevent",
                "sys/module/m1/uevent",
        };
        static const uint8_t uuid[16] = {
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        };
        char path[PATH_MAX];

        for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
                ASSERT_EQ_INT(test_mkdir(root, dirs[i]), 0);
        for (size_t i = 0; i < sizeof(empty_uevents) / sizeof(empty_uevents[0]); i++)
                ASSERT_EQ_INT(test_write_file(root, empty_uevents[i], ""), 0);

        ASSERT_EQ_INT(test_write_file(root,
                                      "sys/devices/virtio/vda/uevent",
                                      "MAJOR=254\nMINOR=0\nDEVNAME=vda\nDEVTYPE=disk\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(root, "sys/devices/virtio/vda/size", "8\n"), 0);
        ASSERT_EQ_INT(test_symlink(root, "sys/devices/virtio/vda/subsystem", "../../../class/block"), 0);

        ASSERT_EQ_INT(test_symlink(root, "sys/bus/platform/devices/foo", "../../../devices/platform/foo"), 0);
        ASSERT_EQ_INT(test_symlink(root, "sys/class/block/vda", "../../devices/virtio/vda"), 0);
        ASSERT_EQ_INT(test_symlink(root, "sys/class/block/vda1", "../../devices/virtio/vda/vda1"), 0);
        ASSERT_EQ_INT(test_write_file(root, "sys/class/net/bonding_masters", ""), 0);
        ASSERT_EQ_INT(test_write_file(root, "sys/kernel/uevent_seqnum", "10\n"), 0);

        /* An ext4 filesystem on the "node", which is a regular file here. */
        fixture_path(path, "dev/vda");
        ASSERT_EQ_INT(test_ext_image(path, uuid, "my root"), 0);
        ASSERT_EQ_INT(test_symlink(root, "dev/disk/by-uuid/12345678-9abc-def0-0123-456789abcdef", "../../vda"),
                      0);

        ASSERT_EQ_INT(test_write_file(root, "run/udev/data/b254:0", "I:123\nE:FOO=bar\nV:1\n"), 0);

        fixture_path(sys_root, "sys");
        fixture_path(dev_root, "dev");
        fixture_path(run_root, "run/devd");
        fixture_path(udev_run_root, "run/udev");
        fixture_path(db_root, "run/udev/data");

        ctx.sys_root = sys_root;
        ctx.dev_root = dev_root;
        ctx.run_root = run_root;
        ctx.udev_run_root = udev_run_root;
        ctx.db_root = db_root;
}

static void test_parse_sec(void) {
        usec_t t = 0;

        ASSERT_EQ_INT(parse_sec("0", &t), 0);
        ASSERT_TRUE(t == 0);
        ASSERT_EQ_INT(parse_sec("5", &t), 0);
        ASSERT_TRUE(t == 5 * USEC_PER_SEC);
        ASSERT_EQ_INT(parse_sec("1.5", &t), 0);
        ASSERT_TRUE(t == 1500 * USEC_PER_MSEC);
        ASSERT_EQ_INT(parse_sec("250ms", &t), 0);
        ASSERT_TRUE(t == 250 * USEC_PER_MSEC);
        ASSERT_EQ_INT(parse_sec("2 min", &t), 0);
        ASSERT_TRUE(t == 120 * USEC_PER_SEC);
        ASSERT_EQ_INT(parse_sec("infinity", &t), 0);
        ASSERT_TRUE(t == USEC_INFINITY);

        ASSERT_EQ_INT(parse_sec("", &t), -EINVAL);
        ASSERT_EQ_INT(parse_sec("x", &t), -EINVAL);
        ASSERT_EQ_INT(parse_sec("-1", &t), -EINVAL);
        ASSERT_EQ_INT(parse_sec(" 5", &t), -EINVAL);
        ASSERT_EQ_INT(parse_sec("5 parsecs", &t), -EINVAL);
}

static size_t list_len(char **l) {
        return pico_strv_length(l);
}

static void assert_entry(char **l, size_t i, const char *rel) {
        char expect[PATH_MAX];

        fixture_path(expect, rel);
        ASSERT_TRUE(i < list_len(l));
        ASSERT_STREQ(l[i], expect);
}

static void test_trigger_collect(void) {
        TriggerFilter f = { 0 };
        char **l = NULL;
        char vda[PATH_MAX];

        ASSERT_EQ_INT(trigger_collect(TRIGGER_DEVICES, &f, &l), 0);
        ASSERT_EQ_INT(list_len(l), 3);
        assert_entry(l, 0, "sys/devices/platform/foo");
        assert_entry(l, 1, "sys/devices/virtio/vda");
        assert_entry(l, 2, "sys/devices/virtio/vda/vda1");
        l = pico_strv_free(l);

        ASSERT_EQ_INT(trigger_collect(TRIGGER_SUBSYSTEMS, &f, &l), 0);
        ASSERT_EQ_INT(list_len(l), 3);
        assert_entry(l, 0, "sys/bus/platform");
        assert_entry(l, 1, "sys/bus/platform/drivers/drv");
        assert_entry(l, 2, "sys/module/m1");
        l = pico_strv_free(l);

        ASSERT_EQ_INT(trigger_collect(TRIGGER_ALL, &f, &l), 0);
        ASSERT_EQ_INT(list_len(l), 6);
        l = pico_strv_free(l);

        ASSERT_EQ_INT(pico_strv_extend(&f.subsystem_match, "bl*"), 0);
        ASSERT_EQ_INT(trigger_collect(TRIGGER_DEVICES, &f, &l), 0);
        ASSERT_EQ_INT(list_len(l), 2);
        assert_entry(l, 0, "sys/devices/virtio/vda");
        l = pico_strv_free(l);
        trigger_filter_done(&f);

        ASSERT_EQ_INT(pico_strv_extend(&f.subsystem_nomatch, "block"), 0);
        ASSERT_EQ_INT(trigger_collect(TRIGGER_DEVICES, &f, &l), 0);
        ASSERT_EQ_INT(list_len(l), 1);
        assert_entry(l, 0, "sys/devices/platform/foo");
        l = pico_strv_free(l);
        trigger_filter_done(&f);

        /* A subsystem filter names "drivers", never the bus a driver is on. */
        ASSERT_EQ_INT(pico_strv_extend(&f.subsystem_match, "drivers"), 0);
        ASSERT_EQ_INT(trigger_collect(TRIGGER_SUBSYSTEMS, &f, &l), 0);
        ASSERT_EQ_INT(list_len(l), 1);
        assert_entry(l, 0, "sys/bus/platform/drivers/drv");
        l = pico_strv_free(l);
        trigger_filter_done(&f);

        ASSERT_EQ_INT(pico_strv_extend(&f.sysname_match, "vda1"), 0);
        ASSERT_EQ_INT(trigger_collect(TRIGGER_DEVICES, &f, &l), 0);
        ASSERT_EQ_INT(list_len(l), 1);
        assert_entry(l, 0, "sys/devices/virtio/vda/vda1");
        l = pico_strv_free(l);
        trigger_filter_done(&f);

        /* The parent and everything under it, not its siblings. */
        ASSERT_EQ_INT(resolve_device("/devices/virtio/vda", true, vda), 0);
        ASSERT_EQ_INT(pico_strv_extend(&f.parents, vda), 0);
        ASSERT_EQ_INT(trigger_collect(TRIGGER_DEVICES, &f, &l), 0);
        ASSERT_EQ_INT(list_len(l), 2);
        l = pico_strv_free(l);
        trigger_filter_done(&f);

        ASSERT_EQ_INT(pico_strv_extend(&f.attr_match, "size=8"), 0);
        ASSERT_EQ_INT(trigger_collect(TRIGGER_DEVICES, &f, &l), 0);
        ASSERT_EQ_INT(list_len(l), 1);
        assert_entry(l, 0, "sys/devices/virtio/vda");
        l = pico_strv_free(l);
        trigger_filter_done(&f);

        ASSERT_EQ_INT(pico_strv_extend(&f.attr_nomatch, "size"), 0);
        ASSERT_EQ_INT(trigger_collect(TRIGGER_DEVICES, &f, &l), 0);
        ASSERT_EQ_INT(list_len(l), 2);
        l = pico_strv_free(l);
        trigger_filter_done(&f);

        ASSERT_EQ_INT(pico_strv_extend(&f.property_match, "DEVTYPE=di*"), 0);
        ASSERT_EQ_INT(trigger_collect(TRIGGER_DEVICES, &f, &l), 0);
        ASSERT_EQ_INT(list_len(l), 1);
        assert_entry(l, 0, "sys/devices/virtio/vda");
        l = pico_strv_free(l);
        trigger_filter_done(&f);
}

static void test_trigger_write(void) {
        char path[PATH_MAX], buf[64];
        char *dry[] = { (char *) "trigger", (char *) "--dry-run", (char *) "--action=add", NULL };
        char *real[] = {
                (char *) "trigger",
                (char *) "--subsystem-match=block",
                (char *) "--sysname-match=vda1",
                (char *) "--action=add",
                NULL,
        };

        fixture_path(path, "sys/devices/platform/foo/uevent");

        ASSERT_EQ_INT(verb_trigger(3, dry), 0);
        read_file(path, buf, sizeof(buf));
        ASSERT_STREQ(buf, "");

        ASSERT_EQ_INT(verb_trigger(4, real), 0);
        read_file(path, buf, sizeof(buf));
        ASSERT_STREQ(buf, "");
        fixture_path(path, "sys/devices/virtio/vda/vda1/uevent");
        read_file(path, buf, sizeof(buf));
        ASSERT_STREQ(buf, "add");

        /* Left alone by the sysname filter; test_info() reads it. */
        fixture_path(path, "sys/devices/virtio/vda/uevent");
        read_file(path, buf, sizeof(buf));
        ASSERT_TRUE(strncmp(buf, "MAJOR=254\n", 10) == 0);
}

static void test_info(void) {
        InfoDevice *d = malloc(sizeof(*d));
        char syspath[PATH_MAX], expect[PATH_MAX];

        ASSERT_TRUE(d != NULL);
        ASSERT_EQ_INT(resolve_device("/devices/virtio/vda", true, syspath), 0);
        ASSERT_EQ_INT(info_load(syspath, d), 0);

        ASSERT_STREQ(d->props[0].key, "DEVPATH");
        ASSERT_STREQ(d->props[0].value, "/devices/virtio/vda");
        ASSERT_STREQ(d->devpath, "/devices/virtio/vda");
        ASSERT_STREQ(d->sysname, "vda");
        ASSERT_STREQ(d->subsystem, "block");
        ASSERT_TRUE(d->have_devno && d->major_n == 254 && d->minor_n == 0);

        fixture_path(expect, "dev/vda");
        ASSERT_STREQ(info_get(d, "DEVNAME"), expect);
        ASSERT_STREQ(info_node_name(d), "vda");
        ASSERT_STREQ(info_get(d, "DEVTYPE"), "disk");
        ASSERT_STREQ(info_get(d, "SUBSYSTEM"), "block");
        ASSERT_STREQ(info_get(d, "USEC_INITIALIZED"), "123");
        ASSERT_STREQ(info_get(d, "FOO"), "bar");

        /* What fs-lib.sh's det_fs() and label_uuid_to_dev() rely on. */
        ASSERT_STREQ(info_get(d, "ID_FS_TYPE"), "ext4");
        ASSERT_STREQ(info_get(d, "ID_FS_USAGE"), "filesystem");
        ASSERT_STREQ(info_get(d, "ID_FS_UUID"), "12345678-9abc-def0-0123-456789abcdef");
        ASSERT_STREQ(info_get(d, "ID_FS_UUID_ENC"), "12345678-9abc-def0-0123-456789abcdef");
        ASSERT_STREQ(info_get(d, "ID_FS_LABEL"), "my_root");
        ASSERT_STREQ(info_get(d, "ID_FS_LABEL_ENC"), "my\\x20root");

        ASSERT_STREQ(d->links, "disk/by-uuid/12345678-9abc-def0-0123-456789abcdef");
        fixture_path(expect, "dev/disk/by-uuid/12345678-9abc-def0-0123-456789abcdef");
        ASSERT_STREQ(info_get(d, "DEVLINKS"), expect);

        /* A partition with an empty uevent file: just what sysfs gives. */
        ASSERT_EQ_INT(resolve_device("/devices/virtio/vda/vda1", true, syspath), 0);
        ASSERT_EQ_INT(info_load(syspath, d), 0);
        ASSERT_EQ_INT(d->n_props, 1);
        ASSERT_STREQ(d->devname, "");
        ASSERT_TRUE(info_get(d, "ID_FS_TYPE") == NULL);

        ASSERT_EQ_INT(resolve_device("/devices/virtio/nope", true, syspath), -ENODEV);

        free(d);
}

static void test_settle_state(void) {
        char path[PATH_MAX];

        fixture_path(path, "run/devd/seqnum");
        ASSERT_EQ_INT(settle_check(10), 0);

        ASSERT_EQ_INT(test_write_file(root, "run/devd/seqnum", "10\n"), 0);
        ASSERT_EQ_INT(settle_check(10), 1);
        ASSERT_EQ_INT(settle_check(9), 1);
        ASSERT_EQ_INT(settle_check(11), 0);

        /* The flag alone is enough to say busy, whatever the counter says. */
        ASSERT_EQ_INT(test_write_file(root, "run/udev/queue", ""), 0);
        ASSERT_EQ_INT(settle_check(10), 0);
        fixture_path(path, "run/udev/queue");
        ASSERT_EQ_INT(unlink(path), 0);

        /* No devd: nothing to wait for, as udevadm does without udevd. */
        ASSERT_TRUE(!devd_pid(NULL));
        ASSERT_EQ_INT(settle_wait(0, NULL), 0);
        ASSERT_EQ_INT(settle_wait(USEC_INFINITY, NULL), 0);

        /* A live pid that is not devd's must not count: control --exit
         * would signal it. */
        (void) snprintf(path, sizeof(path), "%d\n", (int) getpid());
        ASSERT_EQ_INT(test_write_file(root, "run/devd/pid", path), 0);
        ASSERT_TRUE(!devd_pid(NULL));
        fixture_path(path, "run/devd/pid");
        ASSERT_EQ_INT(unlink(path), 0);
}

static void test_encoding(void) {
        char buf[64];

        fs_string_safe("a b\tc", buf, sizeof(buf));
        ASSERT_STREQ(buf, "a_b_c");
        fs_string_enc("a b/c", buf, sizeof(buf));
        ASSERT_STREQ(buf, "a\\x20b\\x2fc");
        fs_string_enc("Ok-1.2_x:y=z@#+", buf, sizeof(buf));
        ASSERT_STREQ(buf, "Ok-1.2_x:y=z@#+");

        /* Truncated at a whole escape, never inside one. */
        fs_string_enc("ab ", buf, 6);
        ASSERT_STREQ(buf, "ab");
}

static int run(int (*verb)(int, char **), char **argv) {
        int n = 0;

        while (argv[n])
                n++;
        return verb(n, argv);
}

static void test_command_lines(void) {
        char *control_none[] = { (char *) "control", NULL };
        char *control_reload[] = { (char *) "control", (char *) "--reload", NULL };
        char *control_property[] = { (char *) "control", (char *) "--property=hookdir=/lib/dracut/hooks", NULL };
        char *control_bad_property[] = { (char *) "control", (char *) "-p", (char *) "noequal", NULL };
        char *control_log[] = { (char *) "control", (char *) "--log-level=info", NULL };
        char *control_bad_log[] = { (char *) "control", (char *) "--log-level=chatty", NULL };
        char *control_exit[] = { (char *) "control", (char *) "--exit", NULL };
        char *control_ping[] = { (char *) "control", (char *) "--ping", NULL };
        char *control_extra[] = { (char *) "control", (char *) "--reload", (char *) "extra", NULL };
        char *settle_ok[] = { (char *) "settle", (char *) "--timeout=0", (char *) "--exit-if-exists=/x", NULL };
        char *settle_bad_timeout[] = { (char *) "settle", (char *) "--timeout=soon", NULL };
        char *settle_seq[] = { (char *) "settle", (char *) "-s", (char *) "1", NULL };
        char *settle_extra[] = { (char *) "settle", (char *) "extra", NULL };
        char *trigger_type[] = { (char *) "trigger", (char *) "--type=bogus", NULL };
        char *trigger_action[] = { (char *) "trigger", (char *) "--action=explode", NULL };
        char *trigger_tag[] = { (char *) "trigger", (char *) "--tag-match=systemd", NULL };
        char *trigger_property[] = { (char *) "trigger", (char *) "--property-match=NOEQUALS", NULL };
        char *trigger_unknown[] = { (char *) "trigger", (char *) "/sys/devices/nowhere", NULL };
        char *info_cleanup[] = { (char *) "info", (char *) "--cleanup-db", NULL };
        char *info_none[] = { (char *) "info", NULL };
        char *info_tree[] = { (char *) "info", (char *) "--tree", NULL };
        char *info_missing[] = {
                (char *) "info", (char *) "--query=property", (char *) "--name=nosuchdev", NULL
        };
        char *info_bad_query[] = { (char *) "info", (char *) "--query=everything", (char *) "--name=vda", NULL };
        char *main_unknown[] = { (char *) "udevadm", (char *) "frobnicate", NULL };
        char *main_unsupported[] = { (char *) "udevadm", (char *) "monitor", NULL };
        char *main_bad_option[] = { (char *) "udevadm", (char *) "--bogus", (char *) "info", NULL };
        char *main_none[] = { (char *) "udevadm", NULL };
        char *main_version[] = { (char *) "udevadm", (char *) "--debug", (char *) "version", NULL };

        ASSERT_EQ_INT(run(verb_control, control_none), 1);
        ASSERT_EQ_INT(run(verb_control, control_reload), 0);
        ASSERT_EQ_INT(run(verb_control, control_property), 0);
        ASSERT_EQ_INT(run(verb_control, control_bad_property), 1);
        ASSERT_EQ_INT(run(verb_control, control_log), 0);
        ASSERT_EQ_INT(run(verb_control, control_bad_log), 1);
        ASSERT_EQ_INT(run(verb_control, control_exit), 0);
        ASSERT_EQ_INT(run(verb_control, control_ping), 1);
        ASSERT_EQ_INT(run(verb_control, control_extra), 1);

        ASSERT_EQ_INT(run(verb_settle, settle_ok), 0);
        ASSERT_EQ_INT(run(verb_settle, settle_bad_timeout), 1);
        ASSERT_EQ_INT(run(verb_settle, settle_seq), 1);
        ASSERT_EQ_INT(run(verb_settle, settle_extra), 1);

        ASSERT_EQ_INT(run(verb_trigger, trigger_type), 1);
        ASSERT_EQ_INT(run(verb_trigger, trigger_action), 1);
        ASSERT_EQ_INT(run(verb_trigger, trigger_tag), 1);
        ASSERT_EQ_INT(run(verb_trigger, trigger_property), 1);
        ASSERT_EQ_INT(run(verb_trigger, trigger_unknown), 1);

        ASSERT_EQ_INT(run(verb_info, info_cleanup), 0);
        ASSERT_EQ_INT(run(verb_info, info_none), 1);
        ASSERT_EQ_INT(run(verb_info, info_tree), 1);
        ASSERT_EQ_INT(run(verb_info, info_missing), 1);
        ASSERT_EQ_INT(run(verb_info, info_bad_query), 1);

        ASSERT_EQ_INT(run(udevadm_main, main_unknown), 1);
        ASSERT_EQ_INT(run(udevadm_main, main_unsupported), 1);
        ASSERT_EQ_INT(run(udevadm_main, main_bad_option), 1);
        ASSERT_EQ_INT(run(udevadm_main, main_none), 1);
        ASSERT_EQ_INT(run(udevadm_main, main_version), 0);
}

int main(void) {
        char *tmp = test_tmpdir_new();

        ASSERT_TRUE(tmp != NULL);
        ASSERT_TRUE((size_t) snprintf(root, sizeof(root), "%s", tmp) < sizeof(root));

        build_fixture();

        test_parse_sec();
        test_trigger_collect();
        test_trigger_write();
        test_info();
        test_settle_state();
        test_encoding();
        test_command_lines();

        test_rm_rf(tmp);
        free(tmp);
        return 0;
}
