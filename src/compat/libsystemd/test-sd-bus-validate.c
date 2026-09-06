/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The D-Bus naming grammar validators, against the real spec rules
 * (message-protocol-names): interface/member/bus-name element structure,
 * digit-leading-element rejection, object-path element rules.
 */

#include "sd-bus.h"

#include <errno.h>

#include "../../test-util.h"

static void test_interface_name(void) {
        ASSERT_EQ_INT(sd_bus_interface_name_is_valid(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_interface_name_is_valid("org.freedesktop.DBus"), 1);
        ASSERT_EQ_INT(sd_bus_interface_name_is_valid("org"), 0); /* needs >=2 elements */
        ASSERT_EQ_INT(sd_bus_interface_name_is_valid(""), 0);
        ASSERT_EQ_INT(sd_bus_interface_name_is_valid("org.1foo"), 0);    /* element starts with digit */
        ASSERT_EQ_INT(sd_bus_interface_name_is_valid("org..foo"), 0);    /* empty element */
        ASSERT_EQ_INT(sd_bus_interface_name_is_valid("org.foo-bar"), 0); /* no hyphen in interfaces */
        ASSERT_EQ_INT(sd_bus_interface_name_is_valid(".org.foo"), 0);    /* leading dot */
        ASSERT_EQ_INT(sd_bus_interface_name_is_valid("org.foo."), 0);    /* trailing dot */
}

static void test_member_name(void) {
        ASSERT_EQ_INT(sd_bus_member_name_is_valid(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_member_name_is_valid("Get"), 1);
        ASSERT_EQ_INT(sd_bus_member_name_is_valid("Get_Property2"), 1);
        ASSERT_EQ_INT(sd_bus_member_name_is_valid(""), 0);
        ASSERT_EQ_INT(sd_bus_member_name_is_valid("2Get"), 0);
        ASSERT_EQ_INT(sd_bus_member_name_is_valid("Get.Property"), 0); /* no '.' allowed */
        ASSERT_EQ_INT(sd_bus_member_name_is_valid("Get-Property"), 0); /* no '-' allowed */
}

static void test_object_path(void) {
        ASSERT_EQ_INT(sd_bus_object_path_is_valid(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_object_path_is_valid("/"), 1);
        ASSERT_EQ_INT(sd_bus_object_path_is_valid("/org/freedesktop/DBus"), 1);
        ASSERT_EQ_INT(sd_bus_object_path_is_valid(""), 0);
        ASSERT_EQ_INT(sd_bus_object_path_is_valid("org/freedesktop"), 0);   /* no leading '/' */
        ASSERT_EQ_INT(sd_bus_object_path_is_valid("/org/"), 0);             /* trailing '/' */
        ASSERT_EQ_INT(sd_bus_object_path_is_valid("/org//freedesktop"), 0); /* empty element */
        ASSERT_EQ_INT(sd_bus_object_path_is_valid("/org.freedesktop"), 0); /* '.' is not a valid path char */
        ASSERT_EQ_INT(sd_bus_object_path_is_valid("/org_freedesktop"), 1); /* '_' is */
}

static void test_service_name(void) {
        ASSERT_EQ_INT(sd_bus_service_name_is_valid(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_service_name_is_valid("org.freedesktop.DBus"), 1);
        ASSERT_EQ_INT(sd_bus_service_name_is_valid("org.freedesktop.hostname1"), 1);
        ASSERT_EQ_INT(sd_bus_service_name_is_valid(":1.42"), 1);       /* unique name, digit-leading ok */
        ASSERT_EQ_INT(sd_bus_service_name_is_valid(":"), 0);           /* unique with no elements */
        ASSERT_EQ_INT(sd_bus_service_name_is_valid("org.foo-bar"), 1); /* hyphen allowed here */
        ASSERT_EQ_INT(sd_bus_service_name_is_valid("org.1foo"), 0); /* well-known: no digit-leading element */
        ASSERT_EQ_INT(sd_bus_service_name_is_valid("org"), 0);      /* needs >=2 elements */
}

int main(void) {
        test_interface_name();
        test_member_name();
        test_object_path();
        test_service_name();

        printf("test-sd-bus-validate: all checks passed\n");
        return 0;
}
