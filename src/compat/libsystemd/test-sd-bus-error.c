/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_bus_error: the name<->errno table, set/setf/set_const/set_errno,
 * copy/move ownership semantics, is_set/has_name(s), and add_map().
 */

#include "sd-bus.h"

#include <errno.h>
#include <string.h>

#include "../../test-util.h"

static void test_set_and_get_errno(void) {
        sd_bus_error e = SD_BUS_ERROR_NULL;

        ASSERT_EQ_INT(sd_bus_error_set(&e, SD_BUS_ERROR_FILE_NOT_FOUND, "no such file"), -ENOENT);
        ASSERT_STREQ(e.name, SD_BUS_ERROR_FILE_NOT_FOUND);
        ASSERT_STREQ(e.message, "no such file");
        ASSERT_EQ_INT(e._need_free, 1);
        ASSERT_EQ_INT(sd_bus_error_get_errno(&e), ENOENT);
        ASSERT_EQ_INT(sd_bus_error_is_set(&e), 1);
        sd_bus_error_free(&e);
        ASSERT_EQ_INT(sd_bus_error_is_set(&e), 0);
        ASSERT_TRUE(e.name == NULL && e.message == NULL && e._need_free == 0);
}

static void test_set_null_name_clears(void) {
        sd_bus_error e = SD_BUS_ERROR_NULL;

        ASSERT_EQ_INT(sd_bus_error_set(&e, SD_BUS_ERROR_FAILED, NULL), -EACCES);
        ASSERT_EQ_INT(sd_bus_error_set(&e, NULL, NULL), 0);
        ASSERT_TRUE(!sd_bus_error_is_set(&e));
}

static void test_unknown_name_maps_to_eio(void) {
        sd_bus_error e = SD_BUS_ERROR_NULL;

        ASSERT_EQ_INT(sd_bus_error_set(&e, "com.example.TotallyMadeUp", NULL), -EIO);
        ASSERT_EQ_INT(sd_bus_error_get_errno(&e), EIO);
        sd_bus_error_free(&e);
}

static void test_setf(void) {
        sd_bus_error e = SD_BUS_ERROR_NULL;

        ASSERT_EQ_INT(sd_bus_error_setf(&e, SD_BUS_ERROR_INVALID_ARGS, "bad arg: %d", 42), -EINVAL);
        ASSERT_STREQ(e.message, "bad arg: 42");
        sd_bus_error_free(&e);
}

static void test_set_const(void) {
        sd_bus_error e = SD_BUS_ERROR_NULL;
        static const char name[] = SD_BUS_ERROR_TIMEOUT;

        ASSERT_EQ_INT(sd_bus_error_set_const(&e, name, "timed out"), -ETIMEDOUT);
        ASSERT_EQ_INT(e._need_free, 0);
        ASSERT_TRUE(e.name == name); /* verbatim pointer, not a copy */
        sd_bus_error_free(&e);       /* must not attempt to free a static string */
}

static void test_set_errno(void) {
        sd_bus_error e = SD_BUS_ERROR_NULL;

        ASSERT_EQ_INT(sd_bus_error_set_errno(&e, ENOENT), -ENOENT);
        ASSERT_STREQ(e.name, SD_BUS_ERROR_FILE_NOT_FOUND); /* first table entry for ENOENT */
        ASSERT_TRUE(e.message != NULL && strlen(e.message) > 0);
        sd_bus_error_free(&e);

        /* An errno with no entry in the standard table at all still gets a
         * real, round-trippable name via the System.Error.<NAME> fallback. */
        ASSERT_EQ_INT(sd_bus_error_set_errno(&e, EDOM), -EDOM);
        ASSERT_STREQ(e.name, "System.Error.EDOM");
        ASSERT_EQ_INT(sd_bus_error_get_errno(&e), EDOM);
        sd_bus_error_free(&e);

        ASSERT_EQ_INT(sd_bus_error_set_errno(&e, 0), 0);
        ASSERT_TRUE(!sd_bus_error_is_set(&e));
}

static void test_copy_and_move(void) {
        sd_bus_error src = SD_BUS_ERROR_NULL, dst = SD_BUS_ERROR_NULL;

        sd_bus_error_set(&src, SD_BUS_ERROR_ACCESS_DENIED, "no");
        ASSERT_EQ_INT(sd_bus_error_copy(&dst, &src), -EACCES);
        ASSERT_STREQ(dst.name, SD_BUS_ERROR_ACCESS_DENIED);
        ASSERT_STREQ(dst.message, "no");
        ASSERT_TRUE(dst.name != src.name); /* deep copy, independent allocation */
        sd_bus_error_free(&dst);

        ASSERT_EQ_INT(sd_bus_error_move(&dst, &src), -EACCES);
        ASSERT_STREQ(dst.name, SD_BUS_ERROR_ACCESS_DENIED);
        ASSERT_TRUE(!sd_bus_error_is_set(&src)); /* src is zeroed by the move */
        sd_bus_error_free(&dst);
}

static void test_has_name(void) {
        sd_bus_error e = SD_BUS_ERROR_NULL;

        sd_bus_error_set(&e, SD_BUS_ERROR_UNKNOWN_METHOD, NULL);
        ASSERT_EQ_INT(sd_bus_error_has_name(&e, SD_BUS_ERROR_UNKNOWN_METHOD), 1);
        ASSERT_EQ_INT(sd_bus_error_has_name(&e, SD_BUS_ERROR_UNKNOWN_OBJECT), 0);
        ASSERT_EQ_INT(sd_bus_error_has_names(&e, SD_BUS_ERROR_UNKNOWN_OBJECT, SD_BUS_ERROR_UNKNOWN_METHOD), 1);
        ASSERT_EQ_INT(sd_bus_error_has_names(&e, SD_BUS_ERROR_UNKNOWN_OBJECT, SD_BUS_ERROR_UNKNOWN_INTERFACE),
                      0);
        sd_bus_error_free(&e);
}

static void test_add_map(void) {
        static const sd_bus_error_map extra[] = {
                SD_BUS_ERROR_MAP("com.example.NotFound", ENOENT),
                SD_BUS_ERROR_MAP_END,
        };
        sd_bus_error e = SD_BUS_ERROR_NULL;

        ASSERT_EQ_INT(sd_bus_error_add_map(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_error_add_map(extra), 1); /* newly registered */
        ASSERT_EQ_INT(sd_bus_error_add_map(extra), 0); /* already registered */

        ASSERT_EQ_INT(sd_bus_error_set(&e, "com.example.NotFound", NULL), -ENOENT);
        sd_bus_error_free(&e);
}

int main(void) {
        test_set_and_get_errno();
        test_set_null_name_clears();
        test_unknown_name_maps_to_eio();
        test_setf();
        test_set_const();
        test_set_errno();
        test_copy_and_move();
        test_has_name();
        test_add_map();

        printf("test-sd-bus-error: all checks passed\n");
        return 0;
}
