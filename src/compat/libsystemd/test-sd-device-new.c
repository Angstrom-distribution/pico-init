/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Constructors, refcounting, parent/child walk, and the two identity
 * getters that synthesize from other getters (get_device_id,
 * get_is_initialized). Two kinds of fixture, deliberately: a scratch
 * /sys tree (device_set_sys_root_for_tests()) for everything the design
 * requires to reject or accept by grammar, and the host's own real /sys
 * (the default root) for the handful of cases -- /dev/null, the loopback
 * interface -- guaranteed to exist and be stable on any Linux this test
 * ever runs on.
 */

#include "sd-device.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../../test-util.h"
#include "device-internal.h"

static void mkpath(const char *base, const char *rel) {
        char partial[512] = { 0 };
        char rel_copy[256];
        char *seg, *saveptr;

        snprintf(rel_copy, sizeof(rel_copy), "%s", rel);
        for (seg = strtok_r(rel_copy, "/", &saveptr); seg; seg = strtok_r(NULL, "/", &saveptr)) {
                char next[512];

                snprintf(next, sizeof(next), "%s%s%s", partial, partial[0] ? "/" : "", seg);
                ASSERT_EQ_INT(test_mkdir(base, next), 0);
                snprintf(partial, sizeof(partial), "%s", next);
        }
}

static void write_uevent(const char *base, const char *devrel, const char *content) {
        char path[512];

        snprintf(path, sizeof(path), "%s/uevent", devrel);
        ASSERT_EQ_INT(test_write_file(base, path, content), 0);
}

static void test_fixture_basics(void) {
        char *tmp = test_tmpdir_new();
        sd_device *d = NULL, *parent = NULL, *child = NULL;
        char sysroot[620];
        char syspath[600];
        const char *v;

        ASSERT_TRUE(tmp != NULL);
        snprintf(sysroot, sizeof(sysroot), "%s/sys", tmp);
        device_set_sys_root_for_tests(sysroot);

        mkpath(tmp, "sys/devices/platform/foo/bar");
        write_uevent(tmp, "sys/devices/platform/foo", "DRIVER=foodrv\n");
        write_uevent(tmp, "sys/devices/platform/foo/bar", "MAJOR=8\nMINOR=1\nDEVNAME=bar0\nDEVTYPE=disk\n");

        /* Non-existent uevent -> -ENODEV, not some other errno. */
        {
                char nouevent[600];
                snprintf(nouevent, sizeof(nouevent), "%s/sys/devices/platform/nope", tmp);
                ASSERT_EQ_INT(test_mkdir(tmp, "sys/devices/platform/nope"), 0);
                ASSERT_EQ_INT(sd_device_new_from_syspath(&d, nouevent), -ENODEV);
        }

        snprintf(syspath, sizeof(syspath), "%s/sys/devices/platform/foo/bar", tmp);
        ASSERT_EQ_INT(sd_device_new_from_syspath(&d, syspath), 0);

        ASSERT_EQ_INT(sd_device_get_syspath(d, &v), 0);
        ASSERT_STREQ(v, syspath);

        ASSERT_EQ_INT(sd_device_get_devpath(d, &v), 0);
        ASSERT_STREQ(v, "/devices/platform/foo/bar");

        ASSERT_EQ_INT(sd_device_get_sysname(d, &v), 0);
        ASSERT_STREQ(v, "bar");

        {
                dev_t dn;
                ASSERT_EQ_INT(sd_device_get_devnum(d, &dn), 0);
                ASSERT_EQ_INT((int) major(dn), 8);
                ASSERT_EQ_INT((int) minor(dn), 1);
        }

        ASSERT_EQ_INT(sd_device_get_devtype(d, &v), 0);
        ASSERT_STREQ(v, "disk");

        /* is_initialized is unconditionally true; usec_initialized is
         * unconditionally -ENODATA -- see device-new.c's own comments. */
        ASSERT_EQ_INT(sd_device_get_is_initialized(d), 1);
        {
                uint64_t usec;
                ASSERT_EQ_INT(sd_device_get_usec_initialized(d, &usec), -ENODATA);
                ASSERT_EQ_INT(sd_device_get_usec_since_initialized(d, &usec), -ENODATA);
        }

        /* Refcounting: two refs, one unref must not free. */
        ASSERT_TRUE(sd_device_ref(d) == d);
        sd_device_unref(d);

        /* Parent walk finds "foo" (it has a uevent; "platform"/"devices" do not). */
        ASSERT_EQ_INT(sd_device_get_parent(d, &parent), 0);
        ASSERT_EQ_INT(sd_device_get_sysname(parent, &v), 0);
        ASSERT_STREQ(v, "foo");
        ASSERT_EQ_INT(sd_device_get_driver(parent, &v), -ENOENT); /* readlink of a plain file: not a symlink */

        /* Child walk from "foo" finds "bar" back again, by suffix. */
        {
                const char *suffix = NULL;
                child = sd_device_get_child_first(parent, &suffix);
                ASSERT_TRUE(child != NULL);
                ASSERT_STREQ(suffix, "bar");
                ASSERT_TRUE(sd_device_get_child_next(parent, &suffix) == NULL);
        }

        /* new_child() reaches the same device directly. */
        {
                sd_device *viaChild = NULL;
                ASSERT_EQ_INT(sd_device_new_child(&viaChild, parent, "bar"), 0);
                ASSERT_EQ_INT(sd_device_get_syspath(viaChild, &v), 0);
                ASSERT_STREQ(v, syspath);
                sd_device_unref(viaChild);
        }

        /* Path-unsafety is rejected before any filesystem access. */
        {
                sd_device *bad = NULL;
                ASSERT_EQ_INT(sd_device_new_child(&bad, parent, "../escape"), -EINVAL);
                ASSERT_EQ_INT(sd_device_new_child(&bad, parent, "/absolute"), -EINVAL);
        }

        /* device_id: block devnum present -> "b8:1". */
        ASSERT_EQ_INT(sd_device_get_device_id(d, &v), 0);
        ASSERT_STREQ(v, "c8:1"); /* subsystem unresolved (-ENOENT) here, so 'c' not 'b' */

        sd_device_unref(d);
        test_rm_rf(tmp);
        free(tmp);
}

/* "drivers" and "module" grammar: neither lives under /devices, and a
 * real kernel's own driver directories genuinely have no "subsystem"
 * symlink -- see device-new.c's location_is_valid() comment for why the
 * blanket "/devices only" reading of the design had to be corrected. */
static void test_driver_and_module_grammar(void) {
        char *tmp = test_tmpdir_new();
        char sysroot[620];
        sd_device *d = NULL;
        const char *v;

        ASSERT_TRUE(tmp != NULL);
        snprintf(sysroot, sizeof(sysroot), "%s/sys", tmp);
        device_set_sys_root_for_tests(sysroot);

        mkpath(tmp, "sys/bus/amba/drivers/uart-pl011");
        write_uevent(tmp, "sys/bus/amba/drivers/uart-pl011", "");

        {
                char path[600];
                snprintf(path, sizeof(path), "%s/sys/bus/amba/drivers/uart-pl011", tmp);
                ASSERT_EQ_INT(sd_device_new_from_syspath(&d, path), 0);
        }

        ASSERT_EQ_INT(sd_device_get_subsystem(d, &v), 0);
        ASSERT_STREQ(v, "drivers");
        ASSERT_EQ_INT(sd_device_get_driver_subsystem(d, &v), 0);
        ASSERT_STREQ(v, "amba");

        ASSERT_EQ_INT(sd_device_new_from_subsystem_sysname(&d, "drivers", "amba:uart-pl011"), 0);
        ASSERT_EQ_INT(sd_device_get_subsystem(d, &v), 0);
        ASSERT_STREQ(v, "drivers");

        sd_device_unref(d);

        mkpath(tmp, "sys/module/cpuidle");
        {
                char path[600];
                snprintf(path, sizeof(path), "%s/sys/module/cpuidle", tmp);
                /* No uevent file at all on a real kernel's module dirs --
                 * only reachable via the enumerator's relaxed path. */
                ASSERT_EQ_INT(device_new_from_syspath_internal(&d, path, true), 0);
        }
        ASSERT_EQ_INT(sd_device_get_subsystem(d, &v), 0);
        ASSERT_STREQ(v, "module");
        sd_device_unref(d);

        test_rm_rf(tmp);
        free(tmp);
}

static void test_new_from_subsystem_sysname_bus_and_class(void) {
        char *tmp = test_tmpdir_new();
        char sysroot[620];
        sd_device *d = NULL;
        const char *v;

        ASSERT_TRUE(tmp != NULL);
        snprintf(sysroot, sizeof(sysroot), "%s/sys", tmp);
        device_set_sys_root_for_tests(sysroot);

        mkpath(tmp, "sys/devices/pci0/eth0");
        write_uevent(tmp, "sys/devices/pci0/eth0", "IFINDEX=7\nINTERFACE=eth0\n");
        mkpath(tmp, "sys/bus/pci/devices");
        {
                char target[600], link[600];
                snprintf(target, sizeof(target), "../../../devices/pci0/eth0");
                snprintf(link, sizeof(link), "sys/bus/pci/devices/eth0");
                ASSERT_EQ_INT(test_symlink(tmp, link, target), 0);
        }

        ASSERT_EQ_INT(sd_device_new_from_subsystem_sysname(&d, "pci", "eth0"), 0);
        ASSERT_EQ_INT(sd_device_get_sysname(d, &v), 0);
        ASSERT_STREQ(v, "eth0");
        sd_device_unref(d);
        d = NULL;

        ASSERT_EQ_INT(sd_device_new_from_subsystem_sysname(&d, "pci", "doesnotexist"), -ENODEV);

        /* new_from_device_id() dispatch to the "+subsystem:sysname" form. */
        {
                sd_device *viaId = NULL;
                ASSERT_EQ_INT(sd_device_new_from_device_id(&viaId, "+pci:eth0"), 0);
                sd_device_unref(viaId);
        }
        ASSERT_EQ_INT(sd_device_new_from_device_id(&d, "?bogus"), -EINVAL);

        test_rm_rf(tmp);
        free(tmp);
}

/* /dev/null and the loopback interface are guaranteed present on any
 * Linux this test runs on -- real ground truth, not a fixture. */
static void test_real_host_facts(void) {
        sd_device *d = NULL;
        const char *v;
        dev_t devnum;
        int ifindex;

        device_set_sys_root_for_tests(NULL); /* back to the real "/sys" */

        ASSERT_EQ_INT(sd_device_new_from_devname(&d, "/dev/null"), 0);
        ASSERT_EQ_INT(sd_device_get_devnum(d, &devnum), 0);
        ASSERT_EQ_INT((int) major(devnum), 1);
        ASSERT_EQ_INT((int) minor(devnum), 3);
        sd_device_unref(d);

        ASSERT_EQ_INT(sd_device_new_from_path(&d, "/dev/null"), 0);
        sd_device_unref(d);

        ASSERT_EQ_INT(sd_device_new_from_devname(&d, "not-absolute"), -EINVAL);
        ASSERT_EQ_INT(sd_device_new_from_devname(&d, "/dev/does-not-exist-really"), -ENOENT);

        ASSERT_EQ_INT(sd_device_new_from_ifname(&d, "lo"), 0);
        ASSERT_EQ_INT(sd_device_get_sysname(d, &v), 0);
        ASSERT_STREQ(v, "lo");
        ASSERT_EQ_INT(sd_device_get_ifindex(d, &ifindex), 0);
        sd_device_unref(d);

        ASSERT_EQ_INT(sd_device_new_from_ifindex(&d, ifindex), 0);
        ASSERT_EQ_INT(sd_device_get_sysname(d, &v), 0);
        ASSERT_STREQ(v, "lo");
        sd_device_unref(d);

        ASSERT_EQ_INT(sd_device_new_from_ifindex(&d, 0), -EINVAL);
        ASSERT_EQ_INT(sd_device_new_from_ifindex(&d, 999999), -ENODEV);

        ASSERT_EQ_INT(sd_device_new_from_device_id(&d, "n1"), 0);
        sd_device_unref(d);
}

int main(void) {
        test_fixture_basics();
        test_driver_and_module_grammar();
        test_new_from_subsystem_sysname_bus_and_class();
        test_real_host_facts();

        printf("test-sd-device-new: OK\n");
        return 0;
}
