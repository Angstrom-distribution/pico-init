/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The tmpfiles.d(5) grammar and the file-precedence rule, without touching
 * the real filesystem: every path goes through a --root under a temporary
 * directory, and nothing here calls pico_tmpfiles_create().
 *
 * The precedence cases are the ones the design singles out as easy to get
 * wrong: a same-named file in /etc must replace the /usr/lib one outright,
 * a /dev/null symlink must mask, and the survivors must sort by basename
 * across directories. Each is asserted on the list itself, so a regression
 * shows up as "wrong file" rather than as a missing directory later.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../test-util.h"
#include "../util.h"
#include "tmpfiles.h"

static char *root;

static PicoTmpfiles *fresh(void) {
        PicoTmpfiles *t = NULL;

        ASSERT_EQ_INT(pico_tmpfiles_new(&t), 0);
        ASSERT_EQ_INT(pico_tmpfiles_set_root(t, root), 0);
        t->boot = true;
        return t;
}

static PicoTmpfilesItem *only_item(PicoTmpfiles *t, const char *path) {
        char full[PATH_MAX];
        PicoTmpfilesArray *a;

        ASSERT_TRUE(snprintf(full, sizeof(full), "%s%s", root, path) < (int) sizeof(full));
        a = pico_tmpfiles_find(t, full);
        ASSERT_TRUE(a != NULL);
        ASSERT_EQ_INT(a->n_items, 1);
        return &a->items[0];
}

static void absent(PicoTmpfiles *t, const char *path) {
        char full[PATH_MAX];

        ASSERT_TRUE(snprintf(full, sizeof(full), "%s%s", root, path) < (int) sizeof(full));
        ASSERT_TRUE(pico_tmpfiles_find(t, full) == NULL);
}

static void test_path_helpers(void) {
        char buf[64];

        strcpy(buf, "///foo//./bar/.");
        ASSERT_STREQ(pico_tmpfiles_path_simplify(buf), "/foo/bar");
        strcpy(buf, "/run/foo/");
        ASSERT_STREQ(pico_tmpfiles_path_simplify(buf), "/run/foo");
        strcpy(buf, "/");
        ASSERT_STREQ(pico_tmpfiles_path_simplify(buf), "/");
        strcpy(buf, "foo/./bar");
        ASSERT_STREQ(pico_tmpfiles_path_simplify(buf), "foo/bar");
        strcpy(buf, "/../foo/bar/..");
        ASSERT_STREQ(pico_tmpfiles_path_simplify(buf), "/../foo/bar/..");

        ASSERT_STREQ(pico_tmpfiles_path_startswith("/var/run/foo", "/var/run"), "foo");
        ASSERT_STREQ(pico_tmpfiles_path_startswith("/var/run", "/var/run"), "");
        ASSERT_TRUE(pico_tmpfiles_path_startswith("/var/runner", "/var/run") == NULL);
        ASSERT_TRUE(pico_tmpfiles_path_startswith("/var", "/var/run") == NULL);
        ASSERT_STREQ(pico_tmpfiles_path_startswith("/dev//shm", "/dev/"), "shm");
}

static void test_basic_fields(void) {
        PicoTmpfiles *t = fresh();
        PicoTmpfilesItem *i;

        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "a.conf", 1, "d /run/named 0755 65534 65534 - -"), 0);
        i = only_item(t, "/run/named");
        ASSERT_EQ_INT(i->type, 'd');
        ASSERT_TRUE(i->mode_set);
        ASSERT_EQ_INT(i->mode, 0755);
        ASSERT_TRUE(i->uid_set);
        ASSERT_EQ_INT(i->uid, 65534);
        ASSERT_TRUE(i->gid_set);
        ASSERT_EQ_INT(i->gid, 65534);
        ASSERT_TRUE(i->argument == NULL);
        ASSERT_TRUE(i->age == NULL);

        /* defaults: 0755 for directories, 0644 for everything else, no owner */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "a.conf", 2, "d /run/plain"), 0);
        i = only_item(t, "/run/plain");
        ASSERT_TRUE(!i->mode_set);
        ASSERT_EQ_INT(i->mode, 0755);
        ASSERT_TRUE(!i->uid_set && !i->gid_set);

        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "a.conf", 3, "f /run/plainfile - - - -"), 0);
        i = only_item(t, "/run/plainfile");
        ASSERT_EQ_INT(i->mode, 0644);

        /* the argument is the rest of the line, leading blanks skipped */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "a.conf", 4, "f /run/motd 0644 root root -    hello   world"),
                      0);
        i = only_item(t, "/run/motd");
        ASSERT_STREQ(i->argument, "hello   world");

        /* a dash argument is no argument */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "a.conf", 5, "f /run/dash 0644 root root - -"), 0);
        i = only_item(t, "/run/dash");
        ASSERT_TRUE(i->argument == NULL);

        /* age is kept verbatim for a later --clean and nothing else */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "a.conf", 6, "d /run/aged 1777 root root 10d"), 0);
        i = only_item(t, "/run/aged");
        ASSERT_STREQ(i->age, "10d");
        ASSERT_EQ_INT(i->mode, 01777);

        ASSERT_TRUE(!t->invalid_config);
        pico_tmpfiles_free(t);
}

static void test_quoting_and_escapes(void) {
        PicoTmpfiles *t = fresh();
        PicoTmpfilesItem *i;

        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "q.conf", 1, "d \"/run/with space\" 0755 root root -"), 0);
        i = only_item(t, "/run/with space");
        ASSERT_EQ_INT(i->type, 'd');

        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "q.conf", 2, "d '/run/single'"), 0);
        i = only_item(t, "/run/single");
        ASSERT_EQ_INT(i->type, 'd');

        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "q.conf", 3, "d /run/esc\\x20aped"), 0);
        i = only_item(t, "/run/esc aped");
        ASSERT_EQ_INT(i->type, 'd');

        /* argument: C escapes decoded, the newline is real */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "q.conf", 4, "f /run/nl - - - - line1\\nline2\\x20"), 0);
        i = only_item(t, "/run/nl");
        ASSERT_STREQ(i->argument, "line1\nline2 ");

        /* leading whitespace in an argument needs an escape */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "q.conf", 5, "f /run/lead - - - - \\sx"), 0);
        i = only_item(t, "/run/lead");
        ASSERT_STREQ(i->argument, " x");

        ASSERT_TRUE(!t->invalid_config);

        /* unbalanced quote is invalid configuration */
        ASSERT_TRUE(pico_tmpfiles_parse_line(t, "q.conf", 6, "d \"/run/open 0755") < 0);
        ASSERT_TRUE(t->invalid_config);

        pico_tmpfiles_free(t);
}

static void test_modifiers(void) {
        PicoTmpfiles *t = fresh();
        PicoTmpfilesItem *i;

        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "m.conf", 1, "L+ /run/link - - - - /dev/null"), 0);
        i = only_item(t, "/run/link");
        ASSERT_TRUE(i->append_or_force);
        ASSERT_STREQ(i->argument, "/dev/null");

        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "m.conf", 2, "d- /run/tolerant"), 0);
        i = only_item(t, "/run/tolerant");
        ASSERT_TRUE(i->allow_failure);

        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "m.conf", 3, "L? /run/maybe - - - - /nowhere"), 0);
        i = only_item(t, "/run/maybe");
        ASSERT_TRUE(i->ignore_if_target_missing);

        /* $ marks a line for --purge, which does not exist here: accepted, inert */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "m.conf", 4, "d$ /run/purgeable"), 0);
        only_item(t, "/run/purgeable");

        /* ! applies with --boot ... */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "m.conf", 5, "D! /run/bootonly 1777 root root 10d"), 0);
        only_item(t, "/run/bootonly");
        ASSERT_TRUE(!t->invalid_config);

        /* ... and is dropped without it, silently */
        t->boot = false;
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "m.conf", 6, "d! /run/notnow"), 0);
        absent(t, "/run/notnow");
        ASSERT_TRUE(!t->invalid_config);
        t->boot = true;

        /* ? is L-only; a repeated or unknown modifier is a syntax error */
        ASSERT_TRUE(pico_tmpfiles_parse_line(t, "m.conf", 7, "d? /run/bad") < 0);
        ASSERT_TRUE(t->invalid_config);
        t->invalid_config = false;
        ASSERT_TRUE(pico_tmpfiles_parse_line(t, "m.conf", 8, "d++ /run/bad") < 0);
        ASSERT_TRUE(t->invalid_config);
        t->invalid_config = false;
        ASSERT_TRUE(pico_tmpfiles_parse_line(t, "m.conf", 9, "d# /run/bad") < 0);
        ASSERT_TRUE(t->invalid_config);
        t->invalid_config = false;

        /* the three modifiers with no machinery here skip the line, loudly but validly */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "m.conf", 10, "f~ /run/b64 - - - - aGVsbG8="), 0);
        absent(t, "/run/b64");
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "m.conf", 11, "f^ /run/cred - - - - tmpfiles.x"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "m.conf", 12, "d= /run/typed"), 0);
        ASSERT_TRUE(!t->invalid_config);

        pico_tmpfiles_free(t);
}

static void test_types(void) {
        PicoTmpfiles *t = fresh();
        PicoTmpfilesItem *i;
        char expected[PATH_MAX];

        /* every letter tmpfiles.d(5) defines parses; the unimplemented ones
         * are skipped without becoming invalid configuration */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 1, "w /run/w - - - - x"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 2, "e /run/e - - - 1d"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 3, "p /run/p"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 4, "c /run/c - - - - 1:3"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 5, "b /run/b - - - - 8:0"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 6, "t /run/t - - - - user.x=1"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 7, "h /run/h - - - - +i"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 8, "a /run/a - - - - u:root:rwx"), 0);
        ASSERT_EQ_INT(t->n_items + t->n_globs, 0);
        ASSERT_TRUE(!t->invalid_config);

        /* the no-op-on-create ones are kept, in the glob set */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 9, "x /run/keep/*"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 10, "r /run/gone"), 0);
        ASSERT_EQ_INT(t->n_globs, 2);
        ASSERT_EQ_INT(t->n_items, 0);

        /* z/Z are globs; d/f/L/C are not */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 11, "z /run/z* 0600 - -"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 12, "d /run/d"), 0);
        ASSERT_EQ_INT(t->n_globs, 3);
        ASSERT_EQ_INT(t->n_items, 1);

        /* z with no mode leaves the mode alone (mode_set false), unlike d */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 13, "z /run/zz - 65534 -"), 0);
        i = only_item(t, "/run/zz");
        ASSERT_TRUE(!i->mode_set);
        ASSERT_TRUE(i->uid_set && !i->gid_set);

        /* L without an argument points at the factory copy */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 14, "L /etc/factory-link"), 0);
        i = only_item(t, "/etc/factory-link");
        ASSERT_STREQ(i->argument, "/usr/share/factory/etc/factory-link");

        /* C: a missing source skips the line, an existing one is root-prefixed */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 15, "C /etc/nowhere - - - - /usr/share/missing"),
                      0);
        absent(t, "/etc/nowhere");
        ASSERT_EQ_INT(test_mkdir(root, "usr"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr/share"), 0);
        ASSERT_EQ_INT(test_write_file(root, "usr/share/src.txt", "x"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "t.conf", 16, "C /etc/copied - - - - /usr/share/src.txt"),
                      0);
        i = only_item(t, "/etc/copied");
        ASSERT_TRUE(snprintf(expected, sizeof(expected), "%s/usr/share/src.txt", root) <
                    (int) sizeof(expected));
        ASSERT_STREQ(i->argument, expected);
        ASSERT_TRUE(pico_tmpfiles_parse_line(t, "t.conf", 17, "C /etc/rel - - - - relative/src") < 0);
        ASSERT_TRUE(t->invalid_config);
        t->invalid_config = false;

        /* an unknown letter is invalid */
        ASSERT_TRUE(pico_tmpfiles_parse_line(t, "t.conf", 18, "k /run/k") < 0);
        ASSERT_TRUE(t->invalid_config);
        t->invalid_config = false;

        /* too few fields, a relative path */
        ASSERT_TRUE(pico_tmpfiles_parse_line(t, "t.conf", 19, "d") < 0);
        ASSERT_TRUE(t->invalid_config);
        t->invalid_config = false;
        ASSERT_TRUE(pico_tmpfiles_parse_line(t, "t.conf", 20, "d run/rel") < 0);
        ASSERT_TRUE(t->invalid_config);

        pico_tmpfiles_free(t);
}

static void test_mode_and_owner(void) {
        PicoTmpfiles *t = fresh();
        PicoTmpfilesItem *i;

        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "o.conf", 1, "d /run/masked ~0777"), 0);
        i = only_item(t, "/run/masked");
        ASSERT_TRUE(i->mask_perms && i->mode_set);
        ASSERT_EQ_INT(i->mode, 0777);

        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "o.conf", 2, "d /run/oncreate :0700 :0 :0"), 0);
        i = only_item(t, "/run/oncreate");
        ASSERT_TRUE(i->mode_only_create && i->uid_only_create && i->gid_only_create);
        ASSERT_EQ_INT(i->mode, 0700);
        ASSERT_EQ_INT(i->uid, 0);

        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "o.conf", 3, "d /run/named - root root"), 0);
        i = only_item(t, "/run/named");
        ASSERT_TRUE(i->uid_set && i->gid_set);
        ASSERT_EQ_INT(i->uid, 0);
        ASSERT_EQ_INT(i->gid, 0);
        ASSERT_TRUE(!t->invalid_config);

        /* a bad mode, an unknown user */
        ASSERT_TRUE(pico_tmpfiles_parse_line(t, "o.conf", 4, "d /run/badmode 0999") < 0);
        ASSERT_TRUE(t->invalid_config);
        t->invalid_config = false;
        ASSERT_TRUE(pico_tmpfiles_parse_line(t, "o.conf", 5, "d /run/badmode +755") < 0);
        t->invalid_config = false;
        ASSERT_TRUE(pico_tmpfiles_parse_line(t, "o.conf", 6, "d /run/nouser 0755 pico-no-such-user-xyz root") <
                    0);
        ASSERT_TRUE(t->invalid_config);
        t->invalid_config = false;

        /* --graceful turns that into "leave ownership alone" */
        t->graceful = true;
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "o.conf", 7, "d /run/nouser 2755 pico-no-such-user-xyz root"),
                      0);
        i = only_item(t, "/run/nouser");
        ASSERT_TRUE(!i->uid_set);
        ASSERT_TRUE(i->gid_set);
        ASSERT_EQ_INT(i->mode, 0755); /* special bits dropped, as upstream */
        ASSERT_TRUE(!t->invalid_config);

        pico_tmpfiles_free(t);
}

static void test_specifiers_and_var_run(void) {
        PicoTmpfiles *t = fresh();
        PicoTmpfilesItem *i;

        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "s.conf", 1, "d %t/spec"), 0);
        only_item(t, "/run/spec");
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "s.conf", 2, "d %S/state - - - - "), 0);
        only_item(t, "/var/lib/state");
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "s.conf", 3, "f %L/100%%.log - - - - 50%%"), 0);
        i = only_item(t, "/var/log/100%.log");
        ASSERT_STREQ(i->argument, "50%");

        /* /var/run is folded into /run so the two spellings dedup */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "s.conf", 4, "d /var/run/legacy"), 0);
        only_item(t, "/run/legacy");
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "s.conf", 5, "d /var/run"), 0);
        only_item(t, "/var/run");
        ASSERT_TRUE(!t->invalid_config);

        /* an unknown specifier is invalid, as upstream, never passed through */
        ASSERT_TRUE(pico_tmpfiles_parse_line(t, "s.conf", 6, "d /run/%Y") < 0);
        ASSERT_TRUE(t->invalid_config);
        absent(t, "/run/%Y");

        pico_tmpfiles_free(t);
}

static void test_prefixes(void) {
        PicoTmpfiles *t = fresh();

        ASSERT_EQ_INT(pico_tmpfiles_add_exclude_prefix(t, "/dev"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "p.conf", 1, "d /dev/excluded"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "p.conf", 2, "d /devices/kept"), 0);
        ASSERT_EQ_INT(t->n_items, 1);
        only_item(t, "/devices/kept");

        ASSERT_EQ_INT(pico_tmpfiles_add_prefix(t, "/run"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "p.conf", 3, "d /var/lib/dropped"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "p.conf", 4, "d /run/included"), 0);
        ASSERT_EQ_INT(t->n_items, 2);
        only_item(t, "/run/included");

        pico_tmpfiles_free(t);
}

static void test_duplicates_and_order(void) {
        PicoTmpfiles *t = fresh();
        PicoTmpfilesArray *a;
        char full[PATH_MAX];

        /* first line wins; a conflicting later one is dropped */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "01.conf", 1, "d /run/dup 0700 root root"), 0);
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "02.conf", 1, "d /run/dup 0755 root root"), 0);
        ASSERT_EQ_INT(only_item(t, "/run/dup")->mode, 0700);

        /* an identical repeat is compatible and is kept, as upstream keeps it */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "03.conf", 1, "d /run/dup 0700 root root"), 0);
        ASSERT_TRUE(snprintf(full, sizeof(full), "%s/run/dup", root) < (int) sizeof(full));
        a = pico_tmpfiles_find(t, full);
        ASSERT_TRUE(a != NULL);
        ASSERT_EQ_INT(a->n_items, 2);
        ASSERT_EQ_INT(a->items[0].mode, 0700);
        ASSERT_EQ_INT(a->items[1].mode, 0700);

        /* a non-owning line on the same path is compatible, and a glob, so
         * it lives in the other set */
        ASSERT_EQ_INT(pico_tmpfiles_parse_line(t, "04.conf", 1, "z /run/dup 0750 - -"), 0);
        a = pico_tmpfiles_find(t, full);
        ASSERT_EQ_INT(a->n_items, 2);
        a = NULL;
        {
                size_t k;

                for (k = 0; k < t->n_globs; k++)
                        if (strcmp(t->globs[k]->path, full) == 0)
                                a = t->globs[k];
        }
        ASSERT_TRUE(a != NULL);
        ASSERT_EQ_INT(a->items[0].type, 'z');

        ASSERT_TRUE(!t->invalid_config);
        pico_tmpfiles_free(t);
}

static void test_file_precedence(void) {
        PicoTmpfiles *t = fresh();
        char **files = NULL;
        char expect[4][PATH_MAX];
        size_t k;

        ASSERT_EQ_INT(test_mkdir(root, "etc"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "etc/tmpfiles.d"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "run"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "run/tmpfiles.d"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr/lib"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr/lib/tmpfiles.d"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr/local"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr/local/lib"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "usr/local/lib/tmpfiles.d"), 0);

        /* vendor files */
        ASSERT_EQ_INT(test_write_file(root, "usr/lib/tmpfiles.d/aaa.conf", "d /run/aaa\n"), 0);
        ASSERT_EQ_INT(test_write_file(root, "usr/lib/tmpfiles.d/foo.conf", "d /run/from-lib\n"), 0);
        ASSERT_EQ_INT(test_write_file(root, "usr/lib/tmpfiles.d/masked.conf", "d /run/masked\n"), 0);
        ASSERT_EQ_INT(test_write_file(root, "usr/lib/tmpfiles.d/zzz.conf", "d /run/zzz\n"), 0);
        ASSERT_EQ_INT(test_write_file(root, "usr/lib/tmpfiles.d/notaconf.txt", "d /run/no\n"), 0);
        ASSERT_EQ_INT(test_write_file(root, "usr/lib/tmpfiles.d/local.conf", "d /run/from-lib-local\n"), 0);
        /* the admin's override, and a mask */
        ASSERT_EQ_INT(test_write_file(root, "etc/tmpfiles.d/foo.conf", "d /run/from-etc\n"), 0);
        ASSERT_EQ_INT(test_symlink(root, "etc/tmpfiles.d/masked.conf", "/dev/null"), 0);
        /* /run beats /usr/lib, /usr/local/lib beats /usr/lib */
        ASSERT_EQ_INT(test_write_file(root, "run/tmpfiles.d/mmm.conf", "d /run/mmm\n"), 0);
        ASSERT_EQ_INT(test_write_file(root, "usr/lib/tmpfiles.d/mmm.conf", "d /run/mmm-lib\n"), 0);
        ASSERT_EQ_INT(test_write_file(root, "usr/local/lib/tmpfiles.d/local.conf", "d /run/from-local\n"), 0);

        ASSERT_EQ_INT(pico_tmpfiles_list_config_files(t, &files), 0);
        ASSERT_EQ_INT(pico_strv_length(files), 5);

        /* sorted by basename across directories, each name exactly once */
        ASSERT_TRUE(snprintf(expect[0], PATH_MAX, "%s/usr/lib/tmpfiles.d/aaa.conf", root) < PATH_MAX);
        ASSERT_TRUE(snprintf(expect[1], PATH_MAX, "%s/etc/tmpfiles.d/foo.conf", root) < PATH_MAX);
        ASSERT_TRUE(snprintf(expect[2], PATH_MAX, "%s/usr/local/lib/tmpfiles.d/local.conf", root) < PATH_MAX);
        ASSERT_TRUE(snprintf(expect[3], PATH_MAX, "%s/run/tmpfiles.d/mmm.conf", root) < PATH_MAX);
        ASSERT_STREQ(files[0], expect[0]);
        ASSERT_STREQ(files[1], expect[1]);
        ASSERT_STREQ(files[2], expect[2]);
        ASSERT_STREQ(files[3], expect[3]);
        ASSERT_TRUE(strstr(files[4], "/usr/lib/tmpfiles.d/zzz.conf") != NULL);
        for (k = 0; files[k]; k++) {
                ASSERT_TRUE(strstr(files[k], "masked.conf") == NULL);
                ASSERT_TRUE(strstr(files[k], "/usr/lib/tmpfiles.d/foo.conf") == NULL);
                ASSERT_TRUE(strstr(files[k], "notaconf") == NULL);
        }
        pico_strv_free(files);

        /* and read through: only the /etc lines of foo.conf exist */
        ASSERT_EQ_INT(pico_tmpfiles_read_config(t), 0);
        only_item(t, "/run/from-etc");
        absent(t, "/run/from-lib");
        absent(t, "/run/masked");
        absent(t, "/run/mmm-lib");
        absent(t, "/run/from-lib-local");
        only_item(t, "/run/mmm");
        only_item(t, "/run/from-local");
        ASSERT_TRUE(!t->invalid_config);

        pico_tmpfiles_free(t);
}

static void test_read_file_lines(void) {
        PicoTmpfiles *t = fresh();

        ASSERT_EQ_INT(test_write_file(root,
                                      "lines.conf",
                                      "# comment\n"
                                      "\n"
                                      "   \n"
                                      "  d /run/indented 0755 root root -   \n"
                                      "bogus line here\n"
                                      "d /run/after-bogus\n"),
                      0);
        {
                char full[PATH_MAX];

                ASSERT_TRUE(snprintf(full, sizeof(full), "%s/lines.conf", root) < (int) sizeof(full));
                ASSERT_EQ_INT(pico_tmpfiles_read_file(t, full), 0);
                ASSERT_EQ_INT(pico_tmpfiles_read_file(t, "/nonexistent/x.conf"), -ENOENT);
        }
        only_item(t, "/run/indented");
        only_item(t, "/run/after-bogus");
        ASSERT_TRUE(t->invalid_config); /* the bogus line, and nothing else lost */

        pico_tmpfiles_free(t);
}

int main(void) {
        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);

        test_path_helpers();
        test_basic_fields();
        test_quoting_and_escapes();
        test_modifiers();
        test_types();
        test_mode_and_owner();
        test_specifiers_and_var_run();
        test_prefixes();
        test_duplicates_and_order();
        test_file_precedence();
        test_read_file_lines();

        test_rm_rf(root);
        free(root);
        printf("test-tmpfiles-conf: all passed\n");
        return 0;
}
