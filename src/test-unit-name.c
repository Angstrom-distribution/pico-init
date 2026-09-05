/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Name parsing in isolation: no Manager, no filesystem -- every case here is
 * a string in, a string (or bool, or int) out. unit_name_is_valid() itself
 * lives in unit.c, not unit-name.c (it needs UNIT_NAME_MAX and the type
 * table), but its structural template/instance rules are exactly what
 * unit-name.c's own functions have to agree with, so the validity cases stay
 * in this file rather than splitting across two.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-util.h"
#include "unit-name.h"
#include "unit.h"

static void test_valid_names(void) {
        char long_name[UNIT_NAME_MAX + 1];
        size_t prefix_len = sizeof(long_name) - 1 - strlen(".service");

        ASSERT_TRUE(unit_name_is_valid("foo.service"));
        ASSERT_TRUE(unit_name_is_valid("foo@bar.service"));
        ASSERT_TRUE(unit_name_is_valid("foo@.service")); /* a template is a valid name */
        ASSERT_TRUE(unit_name_is_valid("a-b_c:d.socket"));
        ASSERT_TRUE(unit_name_is_valid("getty@tty1.target"));

        memset(long_name, 'a', prefix_len);
        memcpy(long_name + prefix_len, ".service", strlen(".service") + 1);
        ASSERT_EQ_INT(strlen(long_name), UNIT_NAME_MAX);
        ASSERT_TRUE(unit_name_is_valid(long_name));
}

static void test_invalid_names(void) {
        char too_long[UNIT_NAME_MAX + 2];
        size_t prefix_len = sizeof(too_long) - 1 - strlen(".service");

        ASSERT_TRUE(!unit_name_is_valid(NULL));
        ASSERT_TRUE(!unit_name_is_valid(""));
        /* "@.service"/"@bar.service" (empty prefix) are added once unit.c's
         * structural name rule lands -- see that commit's edit to this file. */
        ASSERT_TRUE(!unit_name_is_valid(".service"));
        ASSERT_TRUE(!unit_name_is_valid(".hidden.service"));
        ASSERT_TRUE(!unit_name_is_valid("foo")); /* no suffix */
        ASSERT_TRUE(!unit_name_is_valid("foo.bogus"));
        ASSERT_TRUE(!unit_name_is_valid("../evil.service"));
        ASSERT_TRUE(!unit_name_is_valid("foo bar.service"));

        memset(too_long, 'a', prefix_len);
        memcpy(too_long + prefix_len, ".service", strlen(".service") + 1);
        ASSERT_EQ_INT(strlen(too_long), UNIT_NAME_MAX + 1);
        ASSERT_TRUE(!unit_name_is_valid(too_long));
}

static void test_is_template(void) {
        ASSERT_TRUE(unit_name_is_template("foo@.service"));
        ASSERT_TRUE(!unit_name_is_template("foo@bar.service"));
        ASSERT_TRUE(!unit_name_is_template("foo.service"));
}

static void test_is_instance(void) {
        ASSERT_TRUE(unit_name_is_instance("foo@bar.service"));
        ASSERT_TRUE(!unit_name_is_instance("foo@.service"));
        ASSERT_TRUE(!unit_name_is_instance("foo.service"));
}

static void test_to_instance(void) {
        char *i = NULL;

        ASSERT_EQ_INT(unit_name_to_instance("foo@bar.service", &i), 0);
        ASSERT_STREQ(i, "bar");
        free(i);

        /* the documented deviation from v30, which returns "" here */
        i = NULL;
        ASSERT_EQ_INT(unit_name_to_instance("foo@.service", &i), 0);
        ASSERT_TRUE(i == NULL);

        i = NULL;
        ASSERT_EQ_INT(unit_name_to_instance("foo.service", &i), 0);
        ASSERT_TRUE(i == NULL);

        /* an extra '@' belongs to the instance, not a second separator */
        i = NULL;
        ASSERT_EQ_INT(unit_name_to_instance("foo@a@b.service", &i), 0);
        ASSERT_STREQ(i, "a@b");
        free(i);
}

static void test_to_prefix(void) {
        char *p;

        p = unit_name_to_prefix("foo@bar.service");
        ASSERT_STREQ(p, "foo");
        free(p);

        p = unit_name_to_prefix("foo.service");
        ASSERT_STREQ(p, "foo");
        free(p);
}

static void test_prefix_and_instance(void) {
        char *p;

        p = unit_name_to_prefix_and_instance("foo@bar.service");
        ASSERT_STREQ(p, "foo@bar");
        free(p);

        p = unit_name_to_prefix_and_instance("foo.service");
        ASSERT_STREQ(p, "foo");
        free(p);
}

static void test_template(void) {
        char *t;

        t = unit_name_template("foo@bar.service");
        ASSERT_STREQ(t, "foo@.service");
        free(t);

        t = unit_name_template("foo@.service");
        ASSERT_STREQ(t, "foo@.service");
        free(t);

        t = unit_name_template("foo.service");
        ASSERT_STREQ(t, "foo.service");
        free(t);
}

static void test_replace_instance(void) {
        char *r;

        r = unit_name_replace_instance("foo@.service", "tty1");
        ASSERT_STREQ(r, "foo@tty1.service");
        free(r);

        r = unit_name_replace_instance("foo@old.service", "new");
        ASSERT_STREQ(r, "foo@new.service");
        free(r);

        /* the regression test for v30's `p - f`-before-NULL-check UB
         * (unit-name.c:314): a name with no '@' at all must come back
         * unchanged, not crash or corrupt memory. */
        r = unit_name_replace_instance("foo.service", "x");
        ASSERT_STREQ(r, "foo.service");
        free(r);
}

static void test_unescape(void) {
        char *u;

        u = unit_name_unescape("ttyGS0");
        ASSERT_STREQ(u, "ttyGS0");
        free(u);

        u = unit_name_unescape("dev-ttyS0");
        ASSERT_STREQ(u, "dev/ttyS0");
        free(u);

        u = unit_name_unescape("a\\x20b");
        ASSERT_STREQ(u, "a b");
        free(u);

        u = unit_name_unescape("\\x2f");
        ASSERT_STREQ(u, "/");
        free(u);

        /* invalid escape (not a hex digit): kept literal */
        u = unit_name_unescape("a\\xzz");
        ASSERT_STREQ(u, "a\\xzz");
        free(u);

        /* truncated escape at the very end of the string: no read past
         * the NUL, and the lone backslash is kept literal */
        u = unit_name_unescape("a\\");
        ASSERT_STREQ(u, "a\\");
        free(u);
}

int main(void) {
        test_valid_names();
        test_invalid_names();
        test_is_template();
        test_is_instance();
        test_to_instance();
        test_to_prefix();
        test_prefix_and_instance();
        test_template();
        test_replace_instance();
        test_unescape();

        printf("test-unit-name: all checks passed\n");
        return 0;
}
