/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Condition*= evaluation: the kernel command line matching, the directory
 * check and the list semantics (negation, the triggering group). The command
 * line comes from a fixture file through pico_condition_cmdline_path, never
 * from /proc/cmdline.
 */

#include "condition.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-util.h"
#include "util.h"

static char *root;
static char cmdline_file[PATH_MAX];

static void set_cmdline(const char *text) {
        ASSERT_EQ_INT(test_write_file(root, "cmdline", text), 0);
}

static bool check(ConditionType type, const char *param, bool trigger, bool negate) {
        Condition c = { .type = type, .parameter = (char *) param, .negate = negate, .trigger = trigger };

        return condition_test(&c);
}

static bool cmdline_cond(const char *param) {
        return check(CONDITION_KERNEL_COMMAND_LINE, param, false, false);
}

static void test_cmdline_match(void) {
        /* a bare word is a key, with or without a value; never a prefix of one */
        ASSERT_TRUE(condition_cmdline_has("quiet root=/dev/sda1 ro", "quiet"));
        ASSERT_TRUE(condition_cmdline_has("quiet root=/dev/sda1 ro", "root"));
        ASSERT_TRUE(condition_cmdline_has("quiet root=/dev/sda1 ro", "ro"));
        ASSERT_TRUE(!condition_cmdline_has("quiet root=/dev/sda1 ro", "roo"));
        ASSERT_TRUE(!condition_cmdline_has("quieter", "quiet"));
        ASSERT_TRUE(!condition_cmdline_has("quiet", "quieter"));
        ASSERT_TRUE(!condition_cmdline_has("xquiet", "quiet"));

        /* key=value is an exact match of the whole word */
        ASSERT_TRUE(condition_cmdline_has("quiet root=/dev/sda1 ro", "root=/dev/sda1"));
        ASSERT_TRUE(!condition_cmdline_has("quiet root=/dev/sda1 ro", "root=/dev/sda"));
        ASSERT_TRUE(!condition_cmdline_has("quiet root=/dev/sda1 ro", "root=/dev/sda12"));
        ASSERT_TRUE(!condition_cmdline_has("quiet root=/dev/sda1 ro", "root="));
        ASSERT_TRUE(!condition_cmdline_has("quiet", "quiet=1"));
        ASSERT_TRUE(condition_cmdline_has("modules_load=a,b", "modules_load"));
        ASSERT_TRUE(condition_cmdline_has("rd.modules_load=a,b", "rd.modules_load"));
        ASSERT_TRUE(!condition_cmdline_has("rd.modules_load=a,b", "modules_load"));

        /* '-' and '_' are different here */
        ASSERT_TRUE(!condition_cmdline_has("modules_load=a", "modules-load"));
        ASSERT_TRUE(condition_cmdline_has("modules-load=a", "modules-load"));

        /* quotes group a word and are removed */
        ASSERT_TRUE(condition_cmdline_has("x=\"a b\" y", "x=a b"));
        ASSERT_TRUE(condition_cmdline_has("x=\"a b\" y", "x"));
        ASSERT_TRUE(!condition_cmdline_has("x=\"a b\" y", "x=a"));
        ASSERT_TRUE(!condition_cmdline_has("x=\"a b\" y", "b"));
        ASSERT_TRUE(condition_cmdline_has("'x y'=z", "x y=z"));
        ASSERT_TRUE(condition_cmdline_has("x=\"a b\" y", "y"));

        /* an unterminated quote costs the rest of the line, not what came before */
        ASSERT_TRUE(condition_cmdline_has("first x=\"a b", "first"));
        ASSERT_TRUE(!condition_cmdline_has("first x=\"a b", "x"));

        /* tabs and repeated spaces separate words */
        ASSERT_TRUE(condition_cmdline_has("  a \t b  ", "b"));

        /* nothing to find */
        ASSERT_TRUE(!condition_cmdline_has("", "quiet"));
        ASSERT_TRUE(!condition_cmdline_has("   ", "quiet"));
        ASSERT_TRUE(!condition_cmdline_has("quiet", ""));
        ASSERT_TRUE(!condition_cmdline_has(NULL, "quiet"));
        ASSERT_TRUE(!condition_cmdline_has("quiet", NULL));
}

/* Through the injected file: the line ends in a newline, as /proc/cmdline does. */
static void test_cmdline_source(void) {
        pico_condition_cmdline_path = cmdline_file;

        set_cmdline("console=ttyS0 modules_load=ipv6 quiet\n");
        ASSERT_TRUE(cmdline_cond("quiet"));
        ASSERT_TRUE(cmdline_cond("modules_load"));
        ASSERT_TRUE(cmdline_cond("modules_load=ipv6"));
        ASSERT_TRUE(!cmdline_cond("modules_load=ipv4"));
        ASSERT_TRUE(!cmdline_cond("rd.modules_load"));

        /* the last word is found even with the newline right behind it */
        set_cmdline("a\nb\n");
        ASSERT_TRUE(cmdline_cond("a"));
        ASSERT_TRUE(cmdline_cond("b"));

        /* an empty file is an empty command line */
        set_cmdline("");
        ASSERT_TRUE(!cmdline_cond("quiet"));
        ASSERT_TRUE(check(CONDITION_KERNEL_COMMAND_LINE, "quiet", false, true));

        /* so is a file that does not exist, and negation then holds */
        pico_condition_cmdline_path = "/nonexistent/pico-init-test/cmdline";
        ASSERT_TRUE(!cmdline_cond("quiet"));
        ASSERT_TRUE(check(CONDITION_KERNEL_COMMAND_LINE, "quiet", false, true));

        /* the source is read at each evaluation, not cached */
        pico_condition_cmdline_path = cmdline_file;
        set_cmdline("one\n");
        ASSERT_TRUE(cmdline_cond("one"));
        set_cmdline("two\n");
        ASSERT_TRUE(!cmdline_cond("one"));
        ASSERT_TRUE(cmdline_cond("two"));
}

static void test_directory_not_empty(void) {
        char path[PATH_MAX], cmd[PATH_MAX * 2];
        const char *hidden[] = { ".hidden",   "foo~",       "lost+found", "aquota.user", "aquota.group",
                                 "a.rpmsave", "a.dpkg-old", "a.swp",      "a.bak",       "a.old",
                                 "a.new",     "a.ignore",   NULL };

        snprintf(path, sizeof(path), "%s/dir", root);
        ASSERT_EQ_INT(test_mkdir(root, "dir"), 0);
        ASSERT_TRUE(!condition_directory_not_empty(path));

        /* hidden and backup names do not count */
        for (const char **h = hidden; *h; h++) {
                ASSERT_EQ_INT(test_write_file(path, *h, "x"), 0);
                ASSERT_TRUE(!condition_directory_not_empty(path));
        }

        /* a name that merely contains a suffix is a real entry */
        ASSERT_EQ_INT(test_mkdir(root, "dir2"), 0);
        snprintf(cmd, sizeof(cmd), "%s/dir2", root);
        ASSERT_EQ_INT(test_write_file(cmd, "bakery", "x"), 0);
        ASSERT_TRUE(condition_directory_not_empty(cmd));

        ASSERT_EQ_INT(test_write_file(path, "50-foo.conf", ""), 0);
        ASSERT_TRUE(condition_directory_not_empty(path));

        /* a subdirectory is an entry */
        ASSERT_EQ_INT(test_mkdir(root, "dir3"), 0);
        snprintf(cmd, sizeof(cmd), "%s/dir3", root);
        ASSERT_EQ_INT(test_mkdir(cmd, "sub"), 0);
        ASSERT_TRUE(condition_directory_not_empty(cmd));

        /* a link to a directory is followed */
        ASSERT_EQ_INT(test_symlink(root, "link", "dir"), 0);
        snprintf(cmd, sizeof(cmd), "%s/link", root);
        ASSERT_TRUE(condition_directory_not_empty(cmd));

        /* missing, and not a directory: false */
        snprintf(cmd, sizeof(cmd), "%s/missing", root);
        ASSERT_TRUE(!condition_directory_not_empty(cmd));
        snprintf(cmd, sizeof(cmd), "%s/dir/50-foo.conf", root);
        ASSERT_TRUE(!condition_directory_not_empty(cmd));
        ASSERT_TRUE(!condition_directory_not_empty(NULL));

        /* negated through the condition */
        ASSERT_TRUE(check(CONDITION_DIRECTORY_NOT_EMPTY, path, false, false));
        ASSERT_TRUE(!check(CONDITION_DIRECTORY_NOT_EMPTY, path, false, true));
}

static void test_path_conditions(void) {
        char file[PATH_MAX], missing[PATH_MAX];

        snprintf(file, sizeof(file), "%s/cmdline", root);
        snprintf(missing, sizeof(missing), "%s/missing", root);

        ASSERT_TRUE(check(CONDITION_PATH_EXISTS, file, false, false));
        ASSERT_TRUE(!check(CONDITION_PATH_EXISTS, missing, false, false));
        ASSERT_TRUE(check(CONDITION_PATH_EXISTS, missing, false, true));
        ASSERT_TRUE(check(CONDITION_PATH_IS_DIRECTORY, root, false, false));
        ASSERT_TRUE(!check(CONDITION_PATH_IS_DIRECTORY, file, false, false));
        ASSERT_TRUE(check(CONDITION_PATH_IS_DIRECTORY, file, false, true));
}

static bool list_result(const Condition *l, size_t n) {
        return condition_test_list(l, n, NULL);
}

/*
 * systemd's condition_test_list(): every non-triggering condition holds, and
 * at least one triggering one when there is any. T is true under the fixture
 * (the file "cmdline" exists), F is false.
 */
static void test_list_semantics(void) {
        char t[PATH_MAX], f[PATH_MAX];
        const Condition *failed;
        Condition *l = NULL;
        size_t n = 0;

        snprintf(t, sizeof(t), "%s/cmdline", root);
        snprintf(f, sizeof(f), "%s/missing", root);

        /* an empty list is true */
        ASSERT_TRUE(list_result(NULL, 0));

        /* all non-triggering must hold */
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_PATH_EXISTS, t, false, false), 0);
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_PATH_EXISTS, t, false, false), 0);
        ASSERT_TRUE(list_result(l, n));
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_PATH_EXISTS, f, false, false), 0);
        ASSERT_TRUE(!condition_test_list(l, n, &failed));
        ASSERT_TRUE(failed == &l[2]);
        l = condition_free_list(l, n);
        n = 0;

        /* triggering only: one is enough, none is not */
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_PATH_EXISTS, f, true, false), 0);
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_PATH_EXISTS, f, true, false), 0);
        ASSERT_TRUE(!condition_test_list(l, n, &failed));
        ASSERT_TRUE(failed == &l[0]);
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_PATH_EXISTS, t, true, false), 0);
        ASSERT_TRUE(condition_test_list(l, n, &failed));
        ASSERT_TRUE(failed == NULL);

        /* a failing non-triggering one still decides, whatever the group says */
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_PATH_EXISTS, f, false, false), 0);
        ASSERT_TRUE(!condition_test_list(l, n, &failed));
        ASSERT_TRUE(failed == &l[3]);
        l = condition_free_list(l, n);
        n = 0;

        /* a triggering group does not rescue a failing non-triggering one,
         * and a passing non-triggering one does not stand in for the group */
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_PATH_EXISTS, t, false, false), 0);
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_PATH_EXISTS, f, true, false), 0);
        ASSERT_TRUE(!list_result(l, n));
        l = condition_free_list(l, n);
        n = 0;

        /* '!' applies per condition, with or without '|' */
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_PATH_EXISTS, f, true, true), 0);
        ASSERT_TRUE(list_result(l, n));
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_PATH_EXISTS, t, false, true), 0);
        ASSERT_TRUE(!list_result(l, n));
        l = condition_free_list(l, n);
        n = 0;

        /* the mix systemd-modules-load.service uses: directories and command line words */
        pico_condition_cmdline_path = cmdline_file;
        set_cmdline("quiet\n");
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_DIRECTORY_NOT_EMPTY, f, true, false), 0);
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_KERNEL_COMMAND_LINE, "modules_load", true, false), 0);
        ASSERT_EQ_INT(condition_add(&l, &n, CONDITION_KERNEL_COMMAND_LINE, "rd.modules_load", true, false), 0);
        ASSERT_TRUE(!list_result(l, n));
        set_cmdline("quiet modules_load=dummy\n");
        ASSERT_TRUE(list_result(l, n));
        set_cmdline("rd.modules_load=dummy\n");
        ASSERT_TRUE(list_result(l, n));
        l = condition_free_list(l, n);
        n = 0;

        ASSERT_EQ_INT(condition_add(&l, &n, _CONDITION_TYPE_MAX, "x", false, false), -EINVAL);
        ASSERT_TRUE(l == NULL);
}

static void test_type_names(void) {
        ASSERT_EQ_INT(condition_type_from_string("ConditionKernelCommandLine"), CONDITION_KERNEL_COMMAND_LINE);
        ASSERT_EQ_INT(condition_type_from_string("ConditionDirectoryNotEmpty"), CONDITION_DIRECTORY_NOT_EMPTY);
        ASSERT_EQ_INT(condition_type_from_string("ConditionPathExists"), CONDITION_PATH_EXISTS);
        ASSERT_EQ_INT(condition_type_from_string("ConditionPathIsReadWrite"), _CONDITION_TYPE_INVALID);
        ASSERT_STREQ(condition_type_to_string(CONDITION_PATH_IS_DIRECTORY), "ConditionPathIsDirectory");
        ASSERT_TRUE(condition_type_to_string(_CONDITION_TYPE_MAX) == NULL);
        ASSERT_TRUE(condition_type_is_path(CONDITION_DIRECTORY_NOT_EMPTY));
        ASSERT_TRUE(!condition_type_is_path(CONDITION_KERNEL_COMMAND_LINE));
}

int main(void) {
        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);
        snprintf(cmdline_file, sizeof(cmdline_file), "%s/cmdline", root);
        set_cmdline("quiet\n");

        test_cmdline_match();
        test_cmdline_source();
        test_directory_not_empty();
        test_path_conditions();
        test_list_semantics();
        test_type_names();

        test_rm_rf(root);
        free(root);
        printf("test-condition: all checks passed\n");
        return 0;
}
