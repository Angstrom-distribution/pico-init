/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The substitution engine in isolation, against a synthetic table -- no
 * Unit, no Manager. That is the point of specifier.c being its own file
 * rather than folded into unit-name.c or unit.c: the engine has no idea
 * what a unit is, and this is what proves it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "specifier.h"
#include "test-util.h"

#define LONG_VAL_LEN 200
static char long_val[LONG_VAL_LEN + 1];

static const PicoSpecifier test_table[] = {
        { 'a', pico_specifier_string, "A-VALUE" },
        { 'e', pico_specifier_string,        "" },
        { 'g', pico_specifier_string,  long_val },
        {   0,                  NULL,      NULL },
};

static char *expand(const char *text) {
        char *r = NULL;

        ASSERT_EQ_INT(pico_specifier_printf(text, test_table, NULL, &r), 0);
        ASSERT_TRUE(r != NULL);
        return r;
}

static void test_no_specifier_copied_verbatim(void) {
        char *r = expand("hello world");

        ASSERT_STREQ(r, "hello world");
        free(r);
}

static void test_percent_percent(void) {
        char *r = expand("100%% done");

        ASSERT_STREQ(r, "100% done");
        free(r);
}

static void test_known_specifier_at_start_and_end(void) {
        char *r;

        r = expand("%a-tail");
        ASSERT_STREQ(r, "A-VALUE-tail");
        free(r);

        r = expand("head-%a");
        ASSERT_STREQ(r, "head-A-VALUE");
        free(r);
}

/* The drop-in-tolerance property: a specifier this engine has no table
 * entry for must survive untouched, not vanish or error -- an upstream
 * unit carrying %t or %c must still parse. */
static void test_unknown_specifier_passthrough(void) {
        char *r = expand("before %z after");

        ASSERT_STREQ(r, "before %z after");
        free(r);
}

/* v30 silently drops a lone trailing '%'; pico keeps it literal. */
static void test_trailing_percent_preserved(void) {
        char *r = expand("abc%");

        ASSERT_STREQ(r, "abc%");
        free(r);
}

static void test_empty_expansion_removes_specifier(void) {
        char *r = expand("x%ey");

        ASSERT_STREQ(r, "xy");
        free(r);
}

/*
 * Proves the growable buffer, which is the whole reason for departing from
 * v30's j/k/l realloc arithmetic: five 200-byte expansions in a row force
 * several doublings of the output buffer, and the result still has to come
 * out exactly right.
 */
static void test_growth_across_several_large_expansions(void) {
        char want[5 * LONG_VAL_LEN + 1];
        char *r;
        int i;

        memset(long_val, 'Q', LONG_VAL_LEN);
        long_val[LONG_VAL_LEN] = '\0';

        for (i = 0; i < 5; i++)
                memcpy(want + i * LONG_VAL_LEN, long_val, LONG_VAL_LEN);
        want[5 * LONG_VAL_LEN] = '\0';

        r = expand("%g%g%g%g%g");
        ASSERT_STREQ(r, want);
        free(r);
}

/* v30's specifier_string() does assert(data) -- an abort waiting to happen
 * the moment a caller passes it a NULL. Reached directly here, and again
 * through the real handler chain in test-unit-parse.c. */
static void test_specifier_string_null_data(void) {
        char *r = NULL;

        ASSERT_EQ_INT(pico_specifier_string('x', NULL, NULL, &r), 0);
        ASSERT_STREQ(r, "");
        free(r);
}

int main(void) {
        test_no_specifier_copied_verbatim();
        test_percent_percent();
        test_known_specifier_at_start_and_end();
        test_unknown_specifier_passthrough();
        test_trailing_percent_preserved();
        test_empty_expansion_removes_specifier();
        test_growth_across_several_large_expansions();
        test_specifier_string_null_data();

        printf("test-specifier: all checks passed\n");
        return 0;
}
