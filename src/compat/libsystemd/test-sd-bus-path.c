/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Object-path label escaping and the template-driven multi-label variants:
 * round-trips, the empty-label "_" fallback, malformed-escape rejection,
 * and template mismatch/match cases.
 */

#include "sd-bus.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../../test-util.h"

static void test_encode_decode_roundtrip(void) {
        char *encoded = NULL, *decoded = NULL;

        ASSERT_EQ_INT(sd_bus_path_encode("/org/freedesktop/systemd1/unit", "foo.service", &encoded), 0);
        ASSERT_STREQ(encoded, "/org/freedesktop/systemd1/unit/foo_2eservice");

        ASSERT_EQ_INT(sd_bus_path_decode(encoded, "/org/freedesktop/systemd1/unit", &decoded), 1);
        ASSERT_STREQ(decoded, "foo.service");

        free(encoded);
        free(decoded);
}

static void test_encode_root_prefix(void) {
        char *encoded = NULL;

        ASSERT_EQ_INT(sd_bus_path_encode("/", "hello", &encoded), 0);
        ASSERT_STREQ(encoded, "/hello");
        free(encoded);
}

static void test_encode_empty_label(void) {
        char *encoded = NULL, *decoded = NULL;

        ASSERT_EQ_INT(sd_bus_path_encode("/p", "", &encoded), 0);
        ASSERT_STREQ(encoded, "/p/_");

        ASSERT_EQ_INT(sd_bus_path_decode(encoded, "/p", &decoded), 1);
        ASSERT_STREQ(decoded, "");

        free(encoded);
        free(decoded);
}

static void test_decode_not_a_descendant(void) {
        char *decoded = (char *) 0x1; /* sentinel, must become NULL */

        ASSERT_EQ_INT(sd_bus_path_decode("/foobar", "/foo", &decoded), 0);
        ASSERT_TRUE(decoded == NULL);
}

static void test_decode_bad_escape(void) {
        char *decoded = NULL;

        /* "_" with no two following hex digits */
        ASSERT_EQ_INT(sd_bus_path_decode("/p/foo_", "/p", &decoded), -EINVAL);
        /* "_zz" -- not hex digits */
        ASSERT_EQ_INT(sd_bus_path_decode("/p/foo_zz", "/p", &decoded), -EINVAL);
}

static void test_invalid_args(void) {
        char *ret = NULL;

        ASSERT_EQ_INT(sd_bus_path_encode(NULL, "x", &ret), -EINVAL);
        ASSERT_EQ_INT(sd_bus_path_encode("/p", NULL, &ret), -EINVAL);
        ASSERT_EQ_INT(sd_bus_path_encode("/p", "x", NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_path_encode("not-a-path", "x", &ret), -EINVAL);

        ASSERT_EQ_INT(sd_bus_path_decode(NULL, "/p", &ret), -EINVAL);
        ASSERT_EQ_INT(sd_bus_path_decode("/p", NULL, &ret), -EINVAL);
        ASSERT_EQ_INT(sd_bus_path_decode("/p", "/p", NULL), -EINVAL);
}

static void test_encode_many(void) {
        char *ret = NULL;

        ASSERT_EQ_INT(sd_bus_path_encode_many(&ret, "/org/freedesktop/systemd1/unit/%", "foo.service"), 0);
        ASSERT_STREQ(ret, "/org/freedesktop/systemd1/unit/foo_2eservice");
        free(ret);
        ret = NULL;

        ASSERT_EQ_INT(sd_bus_path_encode_many(&ret, "/unit/%/sub/%", "a.b", "c/d"), 0);
        ASSERT_STREQ(ret, "/unit/a_2eb/sub/c_2fd");
        free(ret);
        ret = NULL;

        /* No '%' at all: plain path, nothing substituted. */
        ASSERT_EQ_INT(sd_bus_path_encode_many(&ret, "/unit/literal"), 0);
        ASSERT_STREQ(ret, "/unit/literal");
        free(ret);
}

static void test_decode_many(void) {
        char *a = NULL, *b = NULL;

        ASSERT_EQ_INT(sd_bus_path_decode_many("/unit/a_2eb/sub/c_2fd", "/unit/%/sub/%", &a, &b), 1);
        ASSERT_STREQ(a, "a.b");
        ASSERT_STREQ(b, "c/d");
        free(a);
        free(b);

        /* Structural mismatch: different element count. */
        a = NULL;
        ASSERT_EQ_INT(sd_bus_path_decode_many("/unit/x/extra", "/unit/%", &a), 0);
        ASSERT_TRUE(a == NULL);

        /* Literal element mismatch. */
        a = NULL;
        ASSERT_EQ_INT(sd_bus_path_decode_many("/other/x", "/unit/%", &a), 0);
        ASSERT_TRUE(a == NULL);

        /* A NULL capture slot is skipped, not an error. */
        ASSERT_EQ_INT(sd_bus_path_decode_many("/unit/a_2eb/sub/c_2fd", "/unit/%/sub/%", NULL, &b), 1);
        ASSERT_STREQ(b, "c/d");
        free(b);
}

int main(void) {
        test_encode_decode_roundtrip();
        test_encode_root_prefix();
        test_encode_empty_label();
        test_decode_not_a_descendant();
        test_decode_bad_escape();
        test_invalid_args();
        test_encode_many();
        test_decode_many();

        printf("test-sd-bus-path: all checks passed\n");
        return 0;
}
