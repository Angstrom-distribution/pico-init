/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * UBI attach against a fixture sysfs tree and a fake kernel.
 *
 * No kernel this runs on has MTD flash, and UBI_IOCATT on a real one would
 * need it plus CAP_SYS_RESOURCE, so the ioctl is the seam: fake_attach()
 * behaves as the kernel's ctrl_cdev_ioctl() does -- ENODEV for an MTD device
 * that is not there, EEXIST for one already attached or a number already
 * taken, otherwise the lowest free number (or the one asked for), with the
 * new device and its volumes appearing in sysfs as the ioctl returns. What is
 * under test is everything around the ioctl: the ubi.mtd= grammar, the lookups
 * the kernel would do by number, name and node, the already-attached and
 * number-taken checks, what the request asks for, the order automatic numbers
 * are given in, and the waits.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "fstab-mount.h"
#include "test-util.h"
#include "ubi-attach.h"

static char scratch[PATH_MAX], sys[PATH_MAX], dev[PATH_MAX];

static void fx_reset(void) {
        char path[PATH_MAX + 32];

        test_rm_rf(sys);
        test_rm_rf(dev);
        snprintf(path, sizeof(path), "%s/class/mtd", sys);
        ASSERT_EQ_INT(fstab_mkdir_p(path, 0755), 0);
        ASSERT_EQ_INT(fstab_mkdir_p(dev, 0755), 0);
}

static void fx_attr(const char *dir, const char *name, const char *content) {
        ASSERT_EQ_INT(fstab_mkdir_p(dir, 0755), 0);
        ASSERT_EQ_INT(test_write_file(dir, name, content), 0);
}

/* mtdN named `name`, and its read-only twin mtdNro, as the kernel lists them. */
static void fx_mtd(int n, const char *name) {
        char dir[PATH_MAX + 32], content[128];

        snprintf(content, sizeof(content), "%s\n", name);
        snprintf(dir, sizeof(dir), "%s/class/mtd/mtd%d", sys, n);
        fx_attr(dir, "name", content);
        snprintf(dir, sizeof(dir), "%s/class/mtd/mtd%dro", sys, n);
        fx_attr(dir, "name", content);
}

static void fx_ubi(int ubi, int mtd) {
        char dir[PATH_MAX + 32], content[32];

        snprintf(content, sizeof(content), "%d\n", mtd);
        snprintf(dir, sizeof(dir), "%s/class/ubi/ubi%d", sys, ubi);
        fx_attr(dir, "mtd_num", content);
}

static void fx_vol(int ubi, int vol, const char *name) {
        char dir[PATH_MAX + 32], content[160];

        snprintf(content, sizeof(content), "%s\n", name);
        snprintf(dir, sizeof(dir), "%s/class/ubi/ubi%d_%d", sys, ubi, vol);
        fx_attr(dir, "name", content);
}

static void fx_ctrl(void) {
        ASSERT_EQ_INT(test_write_file(dev, "ubi_ctrl", ""), 0);
}

typedef struct FakeKernel {
        unsigned calls;
        struct ubi_attach_req last; /* as it was handed in */
        int fail;                   /* errno to answer with, before anything else */
        bool race;                  /* attach, then answer EEXIST anyway */
        bool bare_eexist;           /* answer EEXIST, attaching nothing */
} FakeKernel;

static bool fx_exists(const char *fmt, int n) {
        char path[PATH_MAX + 64], rel[64];
        struct stat st;

        snprintf(rel, sizeof(rel), fmt, n);
        snprintf(path, sizeof(path), "%s/%s", sys, rel);
        return stat(path, &st) == 0;
}

static int fake_attach(const char *ctrl, struct ubi_attach_req *req, void *userdata) {
        FakeKernel *k = userdata;
        char want[PATH_MAX + 16];
        int num;

        snprintf(want, sizeof(want), "%s/ubi_ctrl", dev);
        ASSERT_STREQ(ctrl, want);

        k->calls++;
        k->last = *req;

        if (k->fail)
                return -k->fail;
        if (k->bare_eexist)
                return -EEXIST;
        if (!fx_exists("class/mtd/mtd%d", req->mtd_num))
                return -ENODEV;
        if (ubi_attached_as(sys, req->mtd_num) >= 0)
                return -EEXIST;

        num = req->ubi_num;
        if (num == UBI_DEV_NUM_AUTO) {
                for (num = 0; fx_exists("class/ubi/ubi%d", num); num++)
                        ;
        } else if (fx_exists("class/ubi/ubi%d", num))
                return -EEXIST;

        fx_ubi(num, req->mtd_num);
        fx_vol(num, 0, "rootfs");

        if (k->race)
                return -EEXIST;

        req->ubi_num = num;
        return 0;
}

static void param(const char *val, UbiMtdParam *p) {
        ASSERT_EQ_INT(ubi_mtd_param_parse(val, p), 1);
}

static void test_param_parse(void) {
        char longest[UBI_MTD_PARAM_LEN_MAX + 1];
        UbiMtdParam p;

        /* The kernel's own examples. */
        param("/dev/mtd0", &p);
        ASSERT_STREQ(p.mtd, "/dev/mtd0");
        ASSERT_EQ_INT(p.vid_hdr_offs, 0);
        ASSERT_EQ_INT(p.max_beb_per1024, 0);
        ASSERT_EQ_INT(p.ubi_num, UBI_DEV_NUM_AUTO);
        ASSERT_TRUE(!p.enable_fm && !p.need_resv_pool);

        param("content,1984", &p);
        ASSERT_STREQ(p.mtd, "content");
        ASSERT_EQ_INT(p.vid_hdr_offs, 1984);

        param("/dev/mtd1,0,25", &p);
        ASSERT_EQ_INT(p.max_beb_per1024, 25);
        ASSERT_EQ_INT(p.ubi_num, UBI_DEV_NUM_AUTO);

        param("/dev/mtd1,0,0,5", &p);
        ASSERT_EQ_INT(p.ubi_num, 5);
        ASSERT_TRUE(!p.enable_fm);

        param("2,0,0,6,1", &p);
        ASSERT_STREQ(p.mtd, "2");
        ASSERT_EQ_INT(p.ubi_num, 6);
        ASSERT_TRUE(p.enable_fm && !p.need_resv_pool);

        param("1,0,0,5,0,1", &p);
        ASSERT_TRUE(!p.enable_fm && p.need_resv_pool);

        /* vid_hdr_offs is a byte count: any base, K/M/G. */
        param("nand,0x800", &p);
        ASSERT_EQ_INT(p.vid_hdr_offs, 2048);
        param("nand,2K", &p);
        ASSERT_EQ_INT(p.vid_hdr_offs, 2048);
        param("nand,4KiB", &p);
        ASSERT_EQ_INT(p.vid_hdr_offs, 4096);
        param("nand,1M", &p);
        ASSERT_EQ_INT(p.vid_hdr_offs, 1 << 20);
        param("nand,2048\n", &p);
        ASSERT_EQ_INT(p.vid_hdr_offs, 2048);
        param("nand,0,0,-1", &p);
        ASSERT_EQ_INT(p.ubi_num, UBI_DEV_NUM_AUTO);
        param("nand,0,768,31", &p);
        ASSERT_EQ_INT(p.max_beb_per1024, 768);
        ASSERT_EQ_INT(p.ubi_num, 31);

        /* Empty: ignored, as the kernel ignores it. */
        ASSERT_EQ_INT(ubi_mtd_param_parse("", &p), 0);

        /* Malformed. */
        ASSERT_EQ_INT(ubi_mtd_param_parse(NULL, &p), -EINVAL);
        ASSERT_EQ_INT(ubi_mtd_param_parse(",2048", &p), -EINVAL);
        ASSERT_EQ_INT(ubi_mtd_param_parse("nand,x", &p), -EINVAL);
        ASSERT_EQ_INT(ubi_mtd_param_parse("nand,", &p), -EINVAL);
        ASSERT_EQ_INT(ubi_mtd_param_parse("nand,2Q", &p), -EINVAL);
        ASSERT_EQ_INT(ubi_mtd_param_parse("nand,4G", &p), -EINVAL);
        ASSERT_EQ_INT(ubi_mtd_param_parse("nand,0,769", &p), -EINVAL);
        ASSERT_EQ_INT(ubi_mtd_param_parse("nand,0,-1", &p), -EINVAL);
        ASSERT_EQ_INT(ubi_mtd_param_parse("nand,0,0,32", &p), -EINVAL);
        ASSERT_EQ_INT(ubi_mtd_param_parse("nand,0,0,x", &p), -EINVAL);
        ASSERT_EQ_INT(ubi_mtd_param_parse("nand,0,0, 3", &p), -EINVAL);
        ASSERT_EQ_INT(ubi_mtd_param_parse("nand,0,0,0,y", &p), -EINVAL);
        ASSERT_EQ_INT(ubi_mtd_param_parse("a,1,2,3,4,5,6", &p), -EINVAL);

        /* 63 characters fit, 64 do not. */
        memset(longest, 'n', sizeof(longest));
        longest[UBI_MTD_PARAM_LEN_MAX - 1] = '\0';
        param(longest, &p);
        ASSERT_EQ_INT(strlen(p.mtd), UBI_MTD_PARAM_LEN_MAX - 1);
        longest[UBI_MTD_PARAM_LEN_MAX - 1] = 'n';
        longest[UBI_MTD_PARAM_LEN_MAX] = '\0';
        ASSERT_EQ_INT(ubi_mtd_param_parse(longest, &p), -EINVAL);
}

static void test_cmdline(void) {
        UbiMtdParam p[UBI_ATTACH_MAX];
        char big[64 * 16] = "", path[PATH_MAX + 16];
        size_t n;
        int i;

        n = ubi_cmdline_params(
                        "console=ttyS0,115200 ubi.mtd=nand,2048 root=/dev/mmcblk0p2 "
                        "\"ubi.mtd=data fs\" ubi.mtd= ubi.mtd=bad,x ubi.mtd=\"quoted val,0,0,3\" "
                        "ubi.mtd ubi.mtdx=1 xubi.mtd=2 -- ubi.mtd=7\n",
                        p,
                        UBI_ATTACH_MAX);
        ASSERT_EQ_INT(n, 3);
        ASSERT_STREQ(p[0].mtd, "nand");
        ASSERT_EQ_INT(p[0].vid_hdr_offs, 2048);
        ASSERT_STREQ(p[1].mtd, "data fs");
        ASSERT_STREQ(p[2].mtd, "quoted val");
        ASSERT_EQ_INT(p[2].ubi_num, 3);

        /* Nothing, and a line that is only the separator. */
        ASSERT_EQ_INT(ubi_cmdline_params("", p, UBI_ATTACH_MAX), 0);
        ASSERT_EQ_INT(ubi_cmdline_params("  --  ubi.mtd=1", p, UBI_ATTACH_MAX), 0);
        ASSERT_EQ_INT(ubi_cmdline_params(NULL, p, UBI_ATTACH_MAX), 0);

        /* No more than `max`: the kernel stops at UBI_MAX_DEVICES too. */
        for (i = 0; i < 40; i++)
                snprintf(big + strlen(big), sizeof(big) - strlen(big), "ubi.mtd=%d ", i);
        ASSERT_EQ_INT(ubi_cmdline_params(big, p, UBI_ATTACH_MAX), UBI_ATTACH_MAX);
        ASSERT_STREQ(p[UBI_ATTACH_MAX - 1].mtd, "31");
        ASSERT_EQ_INT(ubi_cmdline_params(big, p, 2), 2);

        ASSERT_EQ_INT(test_write_file(scratch, "cmdline", "root=/dev/vda2 ubi.mtd=flash,0,0,1\n"), 0);
        snprintf(path, sizeof(path), "%s/cmdline", scratch);
        ASSERT_EQ_INT(ubi_cmdline_load(path, p, UBI_ATTACH_MAX), 1);
        ASSERT_STREQ(p[0].mtd, "flash");
        ASSERT_EQ_INT(p[0].ubi_num, 1);
        snprintf(path, sizeof(path), "%s/no-cmdline", scratch);
        ASSERT_EQ_INT(ubi_cmdline_load(path, p, UBI_ATTACH_MAX), -ENOENT);
}

static void source(const char *what, int ubi, int vol, const char *name, bool path) {
        UbiSource s;

        ASSERT_TRUE(ubi_source_parse(what, &s));
        ASSERT_EQ_INT(s.ubi_num, ubi);
        ASSERT_EQ_INT(s.vol_id, vol);
        ASSERT_STREQ(s.name, name);
        ASSERT_EQ_INT(s.path, path);
}

static void test_source_parse(void) {
        char too_long[UBI_MAX_VOLUME_NAME + 16];
        UbiSource s;

        source("ubi0_1", 0, 1, "", false);
        source("ubi3_0", 3, 0, "", false);
        source("ubi3", 0, 3, "", false);
        source("ubi1:rootfs", 1, -1, "rootfs", false);
        source("ubi1!rootfs", 1, -1, "rootfs", false);
        source("ubi:data", 0, -1, "data", false);
        source("ubi!data", 0, -1, "data", false);
        source("ubi2:my vol", 2, -1, "my vol", false);
        source("/dev/ubi2_0", 2, 0, "", true);
        source("/dev/ubi/ubi1_3", 1, 3, "", true);

        ASSERT_TRUE(!ubi_source_parse("ubi", &s));
        ASSERT_TRUE(!ubi_source_parse("ubi:", &s));
        ASSERT_TRUE(!ubi_source_parse("ubi0:", &s));
        ASSERT_TRUE(!ubi_source_parse("ubix", &s));
        ASSERT_TRUE(!ubi_source_parse("ubi0_", &s));
        ASSERT_TRUE(!ubi_source_parse("ubi0_1x", &s));
        ASSERT_TRUE(!ubi_source_parse("ubi32_0", &s));
        ASSERT_TRUE(!ubi_source_parse("/dev/sda1", &s));
        ASSERT_TRUE(!ubi_source_parse("/dev/ubi0", &s));
        ASSERT_TRUE(!ubi_source_parse("/dev/ubi_ctrl", &s));
        ASSERT_TRUE(!ubi_source_parse("mtd:rootfs", &s));
        ASSERT_TRUE(!ubi_source_parse("UBI0_0", &s));
        ASSERT_TRUE(!ubi_source_parse(NULL, &s));

        memset(too_long, 'v', sizeof(too_long));
        memcpy(too_long, "ubi0:", 5);
        too_long[5 + UBI_MAX_VOLUME_NAME] = '\0';
        ASSERT_TRUE(ubi_source_parse(too_long, &s));
        too_long[5 + UBI_MAX_VOLUME_NAME] = 'v';
        too_long[6 + UBI_MAX_VOLUME_NAME] = '\0';
        ASSERT_TRUE(!ubi_source_parse(too_long, &s));
}

static void test_lookups(void) {
        char path[PATH_MAX + 64], desc[160];
        UbiSource s;

        fx_reset();
        fx_mtd(0, "bootloader");
        fx_mtd(1, "kernel");
        fx_mtd(2, "data");
        fx_mtd(10, "data");

        ASSERT_EQ_INT(ubi_mtd_find(sys, "2"), 2);
        ASSERT_EQ_INT(ubi_mtd_find(sys, "0x2"), 2);
        ASSERT_EQ_INT(ubi_mtd_find(sys, "10"), 10);
        ASSERT_EQ_INT(ubi_mtd_find(sys, "kernel"), 1);
        /* The lowest number carrying a name, whatever readdir's order. */
        ASSERT_EQ_INT(ubi_mtd_find(sys, "data"), 2);
        ASSERT_EQ_INT(ubi_mtd_find(sys, "7"), -ENOENT);
        ASSERT_EQ_INT(ubi_mtd_find(sys, "nosuch"), -ENOENT);
        ASSERT_EQ_INT(ubi_mtd_find(sys, "/nonexistent/mtd9"), -ENOENT);
        ASSERT_EQ_INT(ubi_mtd_find(sys, ""), -EINVAL);
        /* A node that exists but is no MTD character device. */
        snprintf(path, sizeof(path), "%s/class/mtd/mtd0/name", sys);
        ASSERT_EQ_INT(ubi_mtd_find(sys, path), -EINVAL);

        ASSERT_EQ_INT(ubi_mtd_num_from_devnum(makedev(90, 4)), 2);
        ASSERT_EQ_INT(ubi_mtd_num_from_devnum(makedev(90, 5)), 2);
        ASSERT_EQ_INT(ubi_mtd_num_from_devnum(makedev(8, 1)), -EINVAL);

        /* No UBI at all. */
        ASSERT_EQ_INT(ubi_attached_as(sys, 1), -ENOENT);
        ASSERT_EQ_INT(ubi_device_mtd(sys, 0), -ENOENT);
        ubi_source_parse("ubi0_0", &s);
        ASSERT_EQ_INT(ubi_volume_present(sys, &s), -ENODEV);

        fx_ubi(0, 1);
        fx_vol(0, 0, "rootfs");
        fx_vol(0, 1, "data");
        fx_ubi(1, 2);
        fx_vol(1, 0, "rootfs");
        /* A volume directory is never a device, whatever it holds. */
        snprintf(path, sizeof(path), "%s/class/ubi/ubi1_0", sys);
        fx_attr(path, "mtd_num", "10\n");

        ASSERT_EQ_INT(ubi_attached_as(sys, 1), 0);
        ASSERT_EQ_INT(ubi_attached_as(sys, 2), 1);
        ASSERT_EQ_INT(ubi_attached_as(sys, 10), -ENOENT);
        ASSERT_EQ_INT(ubi_device_mtd(sys, 1), 2);
        ASSERT_EQ_INT(ubi_device_mtd(sys, 3), -ENOENT);

        ubi_source_parse("ubi0_1", &s);
        ASSERT_EQ_INT(ubi_volume_present(sys, &s), 1);
        ubi_source_parse("ubi0_5", &s);
        ASSERT_EQ_INT(ubi_volume_present(sys, &s), 0);
        ubi_source_parse("ubi1:rootfs", &s);
        ASSERT_EQ_INT(ubi_volume_present(sys, &s), 1);
        ubi_source_parse("ubi1:data", &s);
        ASSERT_EQ_INT(ubi_volume_present(sys, &s), 0);
        ubi_source_parse("ubi:data", &s);
        ASSERT_EQ_INT(ubi_volume_present(sys, &s), 1);
        ubi_source_parse("ubi2_0", &s);
        ASSERT_EQ_INT(ubi_volume_present(sys, &s), -ENODEV);

        ubi_source_parse("ubi1:rootfs", &s);
        ubi_source_describe(&s, desc, sizeof(desc));
        ASSERT_STREQ(desc, "ubi1 volume \"rootfs\"");
        ubi_source_parse("ubi0_5", &s);
        ubi_source_describe(&s, desc, sizeof(desc));
        ASSERT_STREQ(desc, "ubi0 volume 5");

        ASSERT_STREQ(ubi_attach_state_to_string(UBI_ATTACH_WAIT_CTRL), "wait-ctrl");
        ASSERT_TRUE(ubi_attach_state_to_string(_UBI_ATTACH_STATE_MAX) == NULL);
}

static void request(UbiAttach *a, const char *val) {
        UbiMtdParam p;

        param(val, &p);
        ubi_attach_init(a, &p);
}

/* One step at a time: each state, and each way out of it. */
static void test_step(void) {
        FakeKernel k = { 0 };
        UbiEnv env = { .sys_root = sys, .dev_root = dev, .attach = fake_attach, .attach_userdata = &k };
        char path[PATH_MAX + 16];
        UbiAttach a;

        fx_reset();
        fx_mtd(0, "boot");
        fx_mtd(1, "kernel");
        fx_mtd(2, "data");
        fx_ctrl();

        /* Attached, with exactly what ubi.mtd= said -- fastmap off unless
         * enable_fm, as the kernel parameter has it. */
        request(&a, "data,2048,20,-1,0,1");
        ASSERT_TRUE(ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_DONE);
        ASSERT_EQ_INT(a.ubi_num, 0);
        ASSERT_EQ_INT(a.mtd_num, 2);
        ASSERT_TRUE(!a.already);
        ASSERT_STREQ(a.reason, "mtd2 attached as ubi0");
        ASSERT_EQ_INT(k.calls, 1);
        ASSERT_EQ_INT(k.last.ubi_num, UBI_DEV_NUM_AUTO);
        ASSERT_EQ_INT(k.last.mtd_num, 2);
        ASSERT_EQ_INT(k.last.vid_hdr_offset, 2048);
        ASSERT_EQ_INT(k.last.max_beb_per1024, 20);
        ASSERT_EQ_INT(k.last.disable_fm, 1);
        ASSERT_EQ_INT(k.last.need_resv_pool, 1);
        ASSERT_EQ_INT(ubi_attached_as(sys, 2), 0);

        request(&a, "kernel,0,0,4,1");
        ASSERT_TRUE(ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_DONE);
        ASSERT_EQ_INT(a.ubi_num, 4);
        ASSERT_EQ_INT(k.last.ubi_num, 4);
        ASSERT_EQ_INT(k.last.disable_fm, 0);
        ASSERT_EQ_INT(k.last.need_resv_pool, 0);
        ASSERT_EQ_INT(k.calls, 2);

        /* Attached already -- by the kernel, say, with UBI built in: done,
         * and no ioctl. By number this time. */
        request(&a, "2");
        ASSERT_TRUE(ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_DONE);
        ASSERT_EQ_INT(a.ubi_num, 0);
        ASSERT_TRUE(a.already);
        ASSERT_STREQ(a.reason, "mtd2 was attached as ubi0 already");
        request(&a, "data,0,0,0");
        ASSERT_TRUE(ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_DONE);
        ASSERT_EQ_INT(k.calls, 2);

        /* ... but under another number than the one asked for. */
        request(&a, "data,0,0,3");
        ASSERT_TRUE(ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_FAILED);
        ASSERT_STREQ(a.reason, "mtd2 is attached as ubi0 already, not ubi3");
        ASSERT_EQ_INT(a.ubi_num, -1);

        /* A number another MTD device holds. */
        request(&a, "boot,0,0,4");
        ASSERT_TRUE(ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_FAILED);
        ASSERT_STREQ(a.reason, "ubi4 is taken by mtd1 already");
        ASSERT_EQ_INT(k.calls, 2);

        /* The kernel says no. */
        k.fail = EINVAL;
        request(&a, "boot");
        ASSERT_TRUE(ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_FAILED);
        ASSERT_STREQ(a.reason, "UBI_IOCATT on mtd0: Invalid argument");
        ASSERT_EQ_INT(k.calls, 3);
        k.fail = 0;

        /* EEXIST with nothing in sysfs to show for it is a failure ... */
        k.bare_eexist = true;
        request(&a, "boot");
        ASSERT_TRUE(ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_FAILED);
        ASSERT_STREQ(a.reason, "UBI_IOCATT on mtd0: File exists");
        k.bare_eexist = false;

        /* ... but where something else attached it first, it is done. */
        k.race = true;
        request(&a, "boot");
        ASSERT_TRUE(ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_DONE);
        ASSERT_TRUE(a.already);
        ASSERT_EQ_INT(a.ubi_num, 1);
        k.race = false;

        /* Not an MTD node at all. */
        snprintf(path, sizeof(path), "%s/ubi_ctrl", dev);
        request(&a, path);
        ASSERT_TRUE(ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_FAILED);
        ASSERT_TRUE(strstr(a.reason, "is not an MTD device: Invalid argument") != NULL);

        /* Waiting: for the flash, then for UBI, and a step at each that
         * changes nothing until the thing waited for is there. */
        fx_reset();
        request(&a, "late");
        ASSERT_TRUE(!ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_WAIT_MTD);
        ASSERT_TRUE(!ubi_attach_step(&a, &env));
        fx_mtd(5, "late");
        ASSERT_TRUE(!ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_WAIT_CTRL);
        ASSERT_EQ_INT(a.mtd_num, 5);
        ASSERT_TRUE(!ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(k.calls, 5);
        fx_ctrl();
        ASSERT_TRUE(ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_DONE);
        ASSERT_EQ_INT(a.ubi_num, 0);
        ASSERT_EQ_INT(k.calls, 6);

        /* A terminal state stays put. */
        ASSERT_TRUE(ubi_attach_step(&a, &env));
        ASSERT_EQ_INT(a.state, UBI_ATTACH_DONE);
        ASSERT_EQ_INT(k.calls, 6);
}

typedef struct Late {
        unsigned at;   /* the attempt to act on */
        unsigned seen; /* the last attempt the hook saw */
        int what;      /* 0: an MTD device named "late", 1: /dev/ubi_ctrl */
} Late;

static void late_hook(void *userdata, unsigned attempt) {
        Late *l = userdata;

        l->seen = attempt;
        if (attempt != l->at)
                return;
        if (l->what == 0)
                fx_mtd(6, "late");
        else
                fx_ctrl();
}

static void test_run(void) {
        FakeKernel k = { 0 };
        UbiEnv env = { .sys_root = sys, .dev_root = dev, .attach = fake_attach, .attach_userdata = &k };
        UbiAttach v[3];
        Late late = { 0 };
        usec_t t0;

        /* Automatic numbers in command line order, not MTD order. */
        fx_reset();
        fx_mtd(1, "a");
        fx_mtd(3, "b");
        fx_mtd(4, "c");
        fx_ctrl();
        request(&v[0], "b");
        request(&v[1], "a");
        request(&v[2], "c,0,0,5");
        ASSERT_EQ_INT(ubi_attach_run(v, 3, &env, 150 * USEC_PER_MSEC), 3);
        ASSERT_EQ_INT(v[0].ubi_num, 0);
        ASSERT_EQ_INT(v[1].ubi_num, 1);
        ASSERT_EQ_INT(v[2].ubi_num, 5);
        ASSERT_EQ_INT(ubi_attached_as(sys, 3), 0);
        ASSERT_EQ_INT(ubi_attached_as(sys, 1), 1);

        /* The flash turning up while PID 1 waits. */
        fx_reset();
        fx_ctrl();
        env.poll_hook = late_hook;
        env.poll_userdata = &late;
        late = (Late){ .at = 2, .what = 0 };
        request(&v[0], "late");
        t0 = now_monotonic();
        ASSERT_EQ_INT(ubi_attach_run(v, 1, &env, 5 * USEC_PER_SEC), 1);
        ASSERT_TRUE(now_monotonic() - t0 < 2 * USEC_PER_SEC);
        ASSERT_EQ_INT(late.seen, 2);
        ASSERT_EQ_INT(v[0].mtd_num, 6);
        ASSERT_EQ_INT(v[0].state, UBI_ATTACH_DONE);

        /* UBI turning up while PID 1 waits. */
        fx_reset();
        fx_mtd(6, "late");
        late = (Late){ .at = 3, .what = 1 };
        request(&v[0], "late");
        ASSERT_EQ_INT(ubi_attach_run(v, 1, &env, 5 * USEC_PER_SEC), 1);
        ASSERT_EQ_INT(late.seen, 3);
        ASSERT_EQ_INT(v[0].state, UBI_ATTACH_DONE);

        /* Neither ever does. The deadline is shared, and a request after one
         * that used it all up still gets its one look. */
        fx_reset();
        fx_mtd(1, "here");
        late = (Late){ 0 };
        request(&v[0], "nowhere");
        request(&v[1], "here");
        t0 = now_monotonic();
        ASSERT_EQ_INT(ubi_attach_run(v, 2, &env, 150 * USEC_PER_MSEC), 0);
        ASSERT_TRUE(now_monotonic() - t0 < 1 * USEC_PER_SEC);
        ASSERT_EQ_INT(v[0].state, UBI_ATTACH_TIMEOUT);
        ASSERT_STREQ(v[0].reason, "MTD device nowhere never appeared");
        ASSERT_EQ_INT(v[1].state, UBI_ATTACH_TIMEOUT);
        ASSERT_EQ_INT(v[1].mtd_num, 1);
        ASSERT_TRUE(strncmp(v[1].reason, "UBI never appeared: no ", 23) == 0);

        fx_ctrl();
        request(&v[0], "nowhere");
        request(&v[1], "here");
        ASSERT_EQ_INT(ubi_attach_run(v, 2, &env, 150 * USEC_PER_MSEC), 1);
        ASSERT_EQ_INT(v[0].state, UBI_ATTACH_TIMEOUT);
        ASSERT_EQ_INT(v[1].state, UBI_ATTACH_DONE);
}

int main(void) {
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(scratch, sizeof(scratch), "%s", dir);
        snprintf(sys, sizeof(sys), "%s/sys", dir);
        snprintf(dev, sizeof(dev), "%s/dev", dir);

        test_param_parse();
        test_cmdline();
        test_source_parse();
        test_lookups();
        test_step();
        test_run();

        test_rm_rf(dir);
        free(dir);

        printf("test-ubi-attach: all checks passed\n");
        return 0;
}
