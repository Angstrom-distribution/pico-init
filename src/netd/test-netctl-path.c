/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Fixture tests for path_id_from_devpath() (netctl-path.c): the ID_PATH
 * walk netctl's own `status <iface>` uses, driven against a hand-built
 * directory tree under a scratch dir rather than the real /sys -- pure
 * string/readlink() work, so it does not need a container or root to test.
 *
 * Each fixture is a chain of plain directories, one per ancestor the real
 * walk would see, with only a "subsystem" symlink at each level (its target
 * need not exist -- path_id_classify() only reads the link text's
 * basename, never resolves it). Deeper than the chain itself, this test's
 * own scratch directory and everything above it have no "subsystem" of
 * their own, so the walk harmlessly runs out of matches once it climbs past
 * the fixture -- exactly like real /sys running out past /sys/devices.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../test-util.h"
#include "netctl-path.h"

/* mkdir(), one path component at a time -- test_mkdir() (test-util.h) only
 * ever makes one level under an already-existing parent, and these
 * fixtures are several levels deep. */
static void mkdir_p(const char *path) {
        char buf[PATH_MAX];
        size_t len = strlen(path);

        ASSERT_TRUE(len < sizeof buf);
        snprintf(buf, sizeof buf, "%s", path);

        for (size_t i = 1; i < len; i++) {
                if (buf[i] != '/')
                        continue;
                buf[i] = '\0';
                if (mkdir(buf, 0755) < 0)
                        ASSERT_TRUE(errno == EEXIST);
                buf[i] = '/';
        }

        if (mkdir(buf, 0755) < 0)
                ASSERT_TRUE(errno == EEXIST);
}

/* A "subsystem" symlink at `devdir`, pointing at `target` (never resolved --
 * only its basename is read, see path_id_classify()). */
static void put_subsystem(const char *devdir, const char *target) {
        char path[PATH_MAX];

        snprintf(path, sizeof path, "%s/subsystem", devdir);
        (void) unlink(path);
        ASSERT_TRUE(symlink(target, path) == 0);
}

static void test_pci_only(char *root) {
        char dev[PATH_MAX], result[256];

        snprintf(dev, sizeof dev, "%s/0000:0c:00.0", root);
        mkdir_p(dev);
        put_subsystem(dev, "../../../bus/pci");

        ASSERT_TRUE(path_id_from_devpath(dev, result, sizeof result));
        ASSERT_STREQ(result, "pci-0000:0c:00.0");
}

static void test_usb_only(char *root) {
        char dev[PATH_MAX], result[256];

        snprintf(dev, sizeof dev, "%s/1-2:1.0", root);
        mkdir_p(dev);
        put_subsystem(dev, "../../../bus/usb");

        ASSERT_TRUE(path_id_from_devpath(dev, result, sizeof result));
        ASSERT_STREQ(result, "usb-0:2:1.0");
}

/* The task's own worked example: a USB-Ethernet dongle on a PCI-attached
 * USB controller. */
static void test_usb_over_pci(char *root) {
        char pci_dev[PATH_MAX], usb_dev[PATH_MAX], result[256];

        snprintf(pci_dev, sizeof pci_dev, "%s/0000:0c:00.0", root);
        /* GCC's format-truncation checker cannot see that these are short,
         * controlled test fixture path segments -- it only sees an
         * unbounded %s into a PATH_MAX buffer. Real risk is zero here. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        snprintf(usb_dev, sizeof usb_dev, "%s/1-2:1.0", pci_dev);
#pragma GCC diagnostic pop
        mkdir_p(usb_dev);
        put_subsystem(pci_dev, "../../../bus/pci");
        put_subsystem(usb_dev, "../../../bus/usb");

        ASSERT_TRUE(path_id_from_devpath(usb_dev, result, sizeof result));
        ASSERT_STREQ(result, "pci-0000:0c:00.0-usb-0:2:1.0");
}

static void test_platform_integrated(char *root) {
        char dev[PATH_MAX], result[256];

        snprintf(dev, sizeof dev, "%s/20980000.ethernet", root);
        mkdir_p(dev);
        put_subsystem(dev, "../../../bus/platform");

        ASSERT_TRUE(path_id_from_devpath(dev, result, sizeof result));
        ASSERT_STREQ(result, "platform-20980000.ethernet");
}

/* usb1 (root hub) -> 1-1 (device) -> 1-1.2 (device) -> 1-1.2:1.0 (interface,
 * the network device's own node) -- four USB ancestors in a row must
 * collapse to the one segment the leaf-most of them produces, not four. */
static void test_nested_usb_collapses(char *root) {
        char usb1[PATH_MAX], d1[PATH_MAX], d2[PATH_MAX], iface[PATH_MAX], result[256];
        size_t n;

        snprintf(usb1, sizeof usb1, "%s/usb1", root);
        /* Same GCC format-truncation false positive as test_usb_over_pci():
         * short, controlled test fixture segments into a PATH_MAX buffer. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        snprintf(d1, sizeof d1, "%s/1-1", usb1);
        snprintf(d2, sizeof d2, "%s/1-1.2", d1);
        snprintf(iface, sizeof iface, "%s/1-1.2:1.0", d2);
#pragma GCC diagnostic pop
        mkdir_p(iface);

        put_subsystem(usb1, "../../bus/usb");
        put_subsystem(d1, "../../../bus/usb");
        put_subsystem(d2, "../../../bus/usb");
        put_subsystem(iface, "../../../bus/usb");

        ASSERT_TRUE(path_id_from_devpath(iface, result, sizeof result));
        ASSERT_STREQ(result, "usb-0:1.2:1.0");

        /* Exactly one segment: a single "usb-" occurrence, not one per
         * collapsed ancestor. */
        n = 0;
        for (const char *p = result; (p = strstr(p, "usb-")); p++)
                n++;
        ASSERT_EQ_INT(n, 1);
}

/* virtio-net under qemu: upstream's own full implementation refuses this
 * topology too (virtio only ever sets a transport, never a parent), so no
 * Path row -- never a guess. */
static void test_unsupported_topology_returns_false(char *root) {
        char dev[PATH_MAX], result[256];

        snprintf(dev, sizeof dev, "%s/virtio0", root);
        mkdir_p(dev);
        put_subsystem(dev, "../../../bus/virtio");

        ASSERT_TRUE(!path_id_from_devpath(dev, result, sizeof result));
}

int main(void) {
        char *root = test_tmpdir_new();

        ASSERT_TRUE(root != NULL);

        {
                char sub[PATH_MAX];

                /* Each case gets its own subdirectory so the fixtures never
                 * interfere with each other's ancestor walk. */
                snprintf(sub, sizeof sub, "%s/pci-only", root);
                test_pci_only(sub);

                snprintf(sub, sizeof sub, "%s/usb-only", root);
                test_usb_only(sub);

                snprintf(sub, sizeof sub, "%s/usb-over-pci", root);
                test_usb_over_pci(sub);

                snprintf(sub, sizeof sub, "%s/platform", root);
                test_platform_integrated(sub);

                snprintf(sub, sizeof sub, "%s/nested-usb", root);
                test_nested_usb_collapses(sub);

                snprintf(sub, sizeof sub, "%s/unsupported", root);
                test_unsupported_topology_returns_false(sub);
        }

        test_rm_rf(root);
        free(root);
        return 0;
}
