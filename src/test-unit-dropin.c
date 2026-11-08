/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Drop-in files (unit-dropin.c) through a real Manager and real files: the
 * precedence between the three search directories, the order the files are
 * applied in, list resets, the dash-truncated and type-level directories,
 * a drop-in for a unit without a file, the file and line of a bad line, and
 * a reload that sees a drop-in added or removed.
 *
 * The tree is <tmp>/etc, <tmp>/run and <tmp>/lib, searched in that order.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "manager.h"
#include "service.h"
#include "test-util.h"
#include "unit.h"

static const char SERVICE_FILE[] = "[Unit]\nDescription=base\n\n[Service]\nExecStart=/bin/base\n";

struct tree {
        char *root;
        char dirs[3][PATH_MAX]; /* etc, run, lib */
        Manager *m;
};

static void tree_new(struct tree *t) {
        static const char * const names[] = { "etc", "run", "lib" };
        const char *path[4];
        int i;

        memset(t, 0, sizeof(*t));
        t->root = test_tmpdir_new();
        ASSERT_TRUE(t->root != NULL);

        for (i = 0; i < 3; i++) {
                ASSERT_EQ_INT(test_mkdir(t->root, names[i]), 0);
                snprintf(t->dirs[i], sizeof(t->dirs[i]), "%s/%s", t->root, names[i]);
                path[i] = t->dirs[i];
        }
        path[3] = NULL;

        ASSERT_EQ_INT(manager_new(&t->m), 0);
        ASSERT_EQ_INT(manager_set_unit_path(t->m, path), 0);
}

static void tree_free(struct tree *t) {
        manager_free(t->m);
        test_rm_rf(t->root);
        free(t->root);
}

/* "etc"/"run"/"lib" -> directory index */
static int which(const char *dir) {
        return strcmp(dir, "etc") == 0 ? 0 : strcmp(dir, "run") == 0 ? 1 : 2;
}

static void put(struct tree *t, const char *dir, const char *rel, const char *content) {
        ASSERT_EQ_INT(test_write_file(t->dirs[which(dir)], rel, content), 0);
}

static void mkd(struct tree *t, const char *dir, const char *rel) {
        ASSERT_EQ_INT(test_mkdir(t->dirs[which(dir)], rel), 0);
}

static Unit *load(struct tree *t, const char *id) {
        Unit *u = NULL;

        ASSERT_EQ_INT(manager_load_unit(t->m, id, &u), 0);
        ASSERT_TRUE(u != NULL);
        return u;
}

/* The applied drop-ins as "dir/file" pairs relative to the tree root, joined by ' '. */
static const char *applied(struct tree *t, Unit *u) {
        static char buf[1024];
        size_t root_len = strlen(t->root), off = 0;
        char **p;

        buf[0] = '\0';
        for (p = u->dropin_paths; p && *p; p++) {
                ASSERT_TRUE(strncmp(*p, t->root, root_len) == 0);
                off += (size_t) snprintf(
                                buf + off, sizeof(buf) - off, "%s%s", off ? " " : "", *p + root_len + 1);
        }
        return buf;
}

static char cap_buf[4096];
static int cap_saved = -1;
static FILE *cap_file;

static void cap_begin(void) {
        fflush(stderr);
        cap_file = tmpfile();
        ASSERT_TRUE(cap_file != NULL);
        cap_saved = dup(STDERR_FILENO);
        ASSERT_TRUE(cap_saved >= 0);
        ASSERT_TRUE(dup2(fileno(cap_file), STDERR_FILENO) >= 0);
}

static const char *cap_end(void) {
        size_t n;

        fflush(stderr);
        ASSERT_TRUE(dup2(cap_saved, STDERR_FILENO) >= 0);
        close(cap_saved);
        rewind(cap_file);
        n = fread(cap_buf, 1, sizeof(cap_buf) - 1, cap_file);
        cap_buf[n] = '\0';
        fclose(cap_file);
        return cap_buf;
}

/* The same file name in all three directories: the highest-priority one is
 * applied and the others are not read at all. */
static void test_precedence_between_directories(void) {
        struct tree t;
        Unit *u;

        tree_new(&t);
        put(&t, "lib", "a.service", SERVICE_FILE);
        mkd(&t, "etc", "a.service.d");
        mkd(&t, "run", "a.service.d");
        mkd(&t, "lib", "a.service.d");
        put(&t, "lib", "a.service.d/10-x.conf", "[Unit]\nDescription=lib\n");
        put(&t, "run", "a.service.d/10-x.conf", "[Unit]\nDescription=run\n");
        put(&t, "etc", "a.service.d/10-x.conf", "[Unit]\nDescription=etc\n");

        u = load(&t, "a.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(applied(&t, u), "etc/a.service.d/10-x.conf");
        ASSERT_STREQ(u->description, "etc");
        tree_free(&t);

        /* without the /etc copy the /run one wins over /usr/lib */
        tree_new(&t);
        put(&t, "lib", "a.service", SERVICE_FILE);
        mkd(&t, "run", "a.service.d");
        mkd(&t, "lib", "a.service.d");
        put(&t, "lib", "a.service.d/10-x.conf", "[Unit]\nDescription=lib\n");
        put(&t, "run", "a.service.d/10-x.conf", "[Unit]\nDescription=run\n");

        u = load(&t, "a.service");
        ASSERT_STREQ(applied(&t, u), "run/a.service.d/10-x.conf");
        ASSERT_STREQ(u->description, "run");
        tree_free(&t);
}

/* An empty drop-in, or a link to /dev/null, in a higher directory cancels the
 * same name below it. */
static void test_same_name_masks_lower_directory(void) {
        struct tree t;
        Unit *u;

        tree_new(&t);
        put(&t, "lib", "a.service", SERVICE_FILE);
        put(&t, "lib", "b.service", SERVICE_FILE);
        mkd(&t, "etc", "a.service.d");
        mkd(&t, "lib", "a.service.d");
        mkd(&t, "etc", "b.service.d");
        mkd(&t, "lib", "b.service.d");
        put(&t, "lib", "a.service.d/10-x.conf", "[Unit]\nDescription=lib\n");
        put(&t, "etc", "a.service.d/10-x.conf", "");
        put(&t, "lib", "b.service.d/10-x.conf", "[Unit]\nDescription=lib\n");
        ASSERT_EQ_INT(test_symlink(t.dirs[0], "b.service.d/10-x.conf", "/dev/null"), 0);

        u = load(&t, "a.service");
        ASSERT_STREQ(u->description, "base");
        u = load(&t, "b.service");
        ASSERT_STREQ(u->description, "base");
        tree_free(&t);
}

/* Files are applied by name whichever directory they came from. */
static void test_name_order_across_directories(void) {
        struct tree t;
        Unit *u;

        tree_new(&t);
        put(&t, "lib", "a.service", SERVICE_FILE);
        mkd(&t, "etc", "a.service.d");
        mkd(&t, "run", "a.service.d");
        mkd(&t, "lib", "a.service.d");
        put(&t, "etc", "a.service.d/20-b.conf", "[Unit]\nDescription=etc20\n");
        put(&t, "run", "a.service.d/15-c.conf", "[Unit]\nDescription=run15\n");
        put(&t, "lib", "a.service.d/10-a.conf", "[Unit]\nDescription=lib10\n");
        put(&t, "lib", "a.service.d/90-notes.txt", "[Unit]\nDescription=txt\n");
        put(&t, "lib", "a.service.d/.30-hidden.conf", "[Unit]\nDescription=hidden\n");

        u = load(&t, "a.service");
        ASSERT_STREQ(applied(&t, u),
                     "lib/a.service.d/10-a.conf run/a.service.d/15-c.conf etc/a.service.d/20-b.conf");
        ASSERT_STREQ(u->description, "etc20");
        tree_free(&t);
}

/* ExecStart= followed by an empty assignment starts the list over. */
static void test_list_reset(void) {
        struct tree t;
        Unit *u;
        Service *s;

        tree_new(&t);
        put(&t, "lib", "a.service", SERVICE_FILE);
        put(&t, "lib", "b.service", SERVICE_FILE);
        mkd(&t, "etc", "a.service.d");
        mkd(&t, "etc", "b.service.d");
        put(&t, "etc", "a.service.d/10-exec.conf", "[Service]\nExecStart=\nExecStart=/bin/new arg\n");
        put(&t, "etc", "b.service.d/10-exec.conf", "[Service]\nEnvironment=A=1\n");
        put(&t, "lib", "b.service", "[Service]\nExecStart=/bin/base\nEnvironment=B=2\n");

        u = load(&t, "a.service");
        s = SERVICE(u);
        ASSERT_TRUE(s->exec_start != NULL);
        ASSERT_STREQ(s->exec_start[0], "/bin/new");
        ASSERT_STREQ(s->exec_start[1], "arg");
        ASSERT_TRUE(s->exec_start[2] == NULL);
        ASSERT_EQ_INT(u->n_degraded_directives, 0);

        /* without the reset a list directive adds to the unit file's */
        u = load(&t, "b.service");
        s = SERVICE(u);
        ASSERT_TRUE(s->environment != NULL);
        ASSERT_STREQ(s->environment[0], "B=2");
        ASSERT_STREQ(s->environment[1], "A=1");
        tree_free(&t);

        /* a reset in a drop-in drops what the unit file collected */
        tree_new(&t);
        put(&t, "lib", "b.service", "[Service]\nExecStart=/bin/base\nEnvironment=B=2\n");
        mkd(&t, "etc", "b.service.d");
        put(&t, "etc", "b.service.d/10-env.conf", "[Service]\nEnvironment=\nEnvironment=A=1\n");
        u = load(&t, "b.service");
        s = SERVICE(u);
        ASSERT_STREQ(s->environment[0], "A=1");
        ASSERT_TRUE(s->environment[1] == NULL);
        tree_free(&t);
}

/* foo-bar.service reads foo-bar.service.d, foo-.service.d and service.d, and
 * where a name occurs in several the more specific directory wins. */
static void test_dash_truncated_and_type_level_directories(void) {
        struct tree t;
        Unit *u;

        tree_new(&t);
        put(&t, "lib", "foo-bar.service", SERVICE_FILE);
        mkd(&t, "lib", "foo-bar.service.d");
        mkd(&t, "lib", "foo-.service.d");
        mkd(&t, "lib", "service.d");
        mkd(&t, "etc", "foo-baz.service.d"); /* a sibling, not a prefix */
        put(&t, "lib", "foo-bar.service.d/20-own.conf", "[Unit]\nDescription=own\n");
        put(&t, "lib", "foo-.service.d/10-prefix.conf", "[Unit]\nDescription=prefix\n");
        put(&t, "lib", "service.d/05-type.conf", "[Unit]\nDescription=type\n");
        put(&t, "lib", "foo-.service.d/30-dup.conf", "[Unit]\nDescription=prefix-dup\n");
        put(&t, "lib", "service.d/30-dup.conf", "[Unit]\nDescription=type-dup\n");
        put(&t, "etc", "foo-baz.service.d/99-other.conf", "[Unit]\nDescription=sibling\n");

        u = load(&t, "foo-bar.service");
        ASSERT_STREQ(applied(&t, u),
                     "lib/service.d/05-type.conf lib/foo-.service.d/10-prefix.conf "
                     "lib/foo-bar.service.d/20-own.conf lib/foo-.service.d/30-dup.conf");
        ASSERT_STREQ(u->description, "prefix-dup");
        tree_free(&t);

        /* every prefix of a longer name, nearest first */
        tree_new(&t);
        put(&t, "lib", "a-b-c.service", SERVICE_FILE);
        mkd(&t, "lib", "a-b-.service.d");
        mkd(&t, "lib", "a-.service.d");
        put(&t, "lib", "a-b-.service.d/10-x.conf", "[Unit]\nDescription=a-b-\n");
        put(&t, "lib", "a-.service.d/10-x.conf", "[Unit]\nDescription=a-\n");
        put(&t, "lib", "a-.service.d/20-y.conf", "[Unit]\nAfter=network.target\n");

        u = load(&t, "a-b-c.service");
        ASSERT_STREQ(applied(&t, u), "lib/a-b-.service.d/10-x.conf lib/a-.service.d/20-y.conf");
        ASSERT_STREQ(u->description, "a-b-");
        tree_free(&t);

        /* the type-level directory is also read for a unit with no dash */
        tree_new(&t);
        put(&t, "lib", "plain.service", SERVICE_FILE);
        put(&t, "lib", "plain.target", "[Unit]\nDescription=t\n");
        mkd(&t, "etc", "service.d");
        mkd(&t, "etc", "target.d");
        put(&t, "etc", "service.d/10-x.conf", "[Unit]\nDescription=svc\n");
        put(&t, "etc", "target.d/10-x.conf", "[Unit]\nDescription=tgt\n");
        ASSERT_STREQ(load(&t, "plain.service")->description, "svc");
        ASSERT_STREQ(load(&t, "plain.target")->description, "tgt");
        tree_free(&t);
}

/* An instance reads its own directory, the template's, and the truncated
 * prefixes of both. */
static void test_instance_and_template_directories(void) {
        struct tree t;
        Unit *u;

        tree_new(&t);
        put(&t, "lib", "foo-bar@.service", SERVICE_FILE);
        mkd(&t, "lib", "foo-bar@x.service.d");
        mkd(&t, "lib", "foo-bar@.service.d");
        mkd(&t, "lib", "foo-.service.d");
        mkd(&t, "lib", "foo-@x.service.d");
        mkd(&t, "lib", "foo-@.service.d");
        mkd(&t, "lib", "service.d");
        put(&t, "lib", "foo-bar@x.service.d/10-a.conf", "[Unit]\nDescription=instance\n");
        put(&t, "lib", "foo-bar@.service.d/20-b.conf", "[Unit]\nDescription=template\n");
        put(&t, "lib", "foo-.service.d/30-c.conf", "[Unit]\nDescription=template-prefix\n");
        put(&t, "lib", "foo-@x.service.d/40-d.conf", "[Unit]\nDescription=instance-prefix\n");
        put(&t, "lib", "foo-@.service.d/50-e.conf", "[Unit]\nDescription=template-prefix-2\n");
        put(&t, "lib", "service.d/60-f.conf", "[Unit]\nDescription=type\n");

        u = load(&t, "foo-bar@x.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(applied(&t, u),
                     "lib/foo-bar@x.service.d/10-a.conf lib/foo-bar@.service.d/20-b.conf "
                     "lib/foo-.service.d/30-c.conf lib/foo-@x.service.d/40-d.conf "
                     "lib/foo-@.service.d/50-e.conf lib/service.d/60-f.conf");
        ASSERT_STREQ(u->description, "type");
        tree_free(&t);
}

/* A directory does not make a unit: with no file the unit does not load, as
 * for a service in systemd, and the drop-in is not applied. */
static void test_dropin_for_a_unit_without_a_file(void) {
        struct tree t;
        Unit *u = NULL;

        tree_new(&t);
        mkd(&t, "etc", "ghost.service.d");
        put(&t, "etc", "ghost.service.d/10-x.conf", "[Service]\nExecStart=/bin/ghost\n");
        mkd(&t, "etc", "service.d");
        put(&t, "etc", "service.d/10-y.conf", "[Service]\nExecStart=/bin/ghost\n");

        ASSERT_EQ_INT(manager_load_unit(t.m, "ghost.service", &u), 0);
        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_ERROR);
        ASSERT_TRUE(u->fragment_path == NULL);
        ASSERT_TRUE(u->dropin_paths == NULL);

        /* the boot scan does not turn a lone directory into a unit either */
        ASSERT_EQ_INT(manager_load_units(t.m, NULL), 0);
        ASSERT_TRUE(manager_get_unit(t.m, "ghost.service") == u);
        ASSERT_EQ_INT(u->load_state, UNIT_ERROR);
        tree_free(&t);

        /* a masked unit stays masked */
        tree_new(&t);
        ASSERT_EQ_INT(test_symlink(t.dirs[0], "m.service", "/dev/null"), 0);
        put(&t, "lib", "m.service", SERVICE_FILE);
        mkd(&t, "etc", "m.service.d");
        put(&t, "etc", "m.service.d/10-x.conf", "[Unit]\nDescription=x\n");
        u = load(&t, "m.service");
        ASSERT_EQ_INT(u->load_state, UNIT_MASKED);
        ASSERT_TRUE(u->dropin_paths == NULL);
        tree_free(&t);
}

/* A bad line costs that line and names the drop-in's file and line. */
static void test_bad_line_names_file_and_line(void) {
        struct tree t;
        const char *log;
        char want[PATH_MAX + 64];
        Unit *u;

        tree_new(&t);
        put(&t, "lib", "a.service", SERVICE_FILE);
        mkd(&t, "etc", "a.service.d");
        put(&t,
            "etc",
            "a.service.d/10-bad.conf",
            "[Unit]\n"
            "Description=from dropin\n"
            "this is not an assignment\n"
            "[Service]\n"
            "KillMode=bogus\n"
            "Environment=KEPT=1\n");
        put(&t, "etc", "a.service.d/20-ok.conf", "[Service]\nEnvironment=LATER=1\n");

        cap_begin();
        u = load(&t, "a.service");
        log = cap_end();

        snprintf(want, sizeof(want), "%s/etc/a.service.d/10-bad.conf:3: ", t.root);
        ASSERT_TRUE(strstr(log, want) != NULL);
        snprintf(want, sizeof(want), "%s/etc/a.service.d/10-bad.conf:5: invalid KillMode= value 'bogus'", t.root);
        ASSERT_TRUE(strstr(log, want) != NULL);

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->description, "from dropin");
        ASSERT_STREQ(SERVICE(u)->environment[0], "KEPT=1");
        ASSERT_STREQ(SERVICE(u)->environment[1], "LATER=1");
        tree_free(&t);

        /* a drop-in that cannot be opened is skipped, the unit still loads */
        tree_new(&t);
        put(&t, "lib", "a.service", SERVICE_FILE);
        mkd(&t, "etc", "a.service.d");
        ASSERT_EQ_INT(test_symlink(t.dirs[0], "a.service.d/10-dangling.conf", "/nonexistent/target"), 0);
        put(&t, "etc", "a.service.d/20-ok.conf", "[Unit]\nDescription=ok\n");

        cap_begin();
        u = load(&t, "a.service");
        log = cap_end();

        ASSERT_TRUE(strstr(log, "10-dangling.conf") != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->description, "ok");
        tree_free(&t);
}

/* The checks that need the whole unit run after the drop-ins: a unit file
 * with no ExecStart= is complete once a drop-in supplies it. */
static void test_verification_sees_the_dropins(void) {
        struct tree t;
        Unit *u;

        tree_new(&t);
        put(&t, "lib", "a.service", "[Unit]\nDescription=no exec\n\n[Service]\nType=simple\n");
        mkd(&t, "etc", "a.service.d");
        put(&t, "etc", "a.service.d/10-exec.conf", "[Service]\nExecStart=/bin/late\n");
        u = load(&t, "a.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(SERVICE(u)->exec_start[0], "/bin/late");
        tree_free(&t);
}

static void test_reload_sees_added_and_removed_dropins(void) {
        struct tree t;
        Unit *u;
        char path[PATH_MAX];

        tree_new(&t);
        put(&t, "lib", "a.service", SERVICE_FILE);
        put(&t, "lib", "b.service", SERVICE_FILE);
        mkd(&t, "etc", "b.service.d");
        put(&t, "etc", "b.service.d/10-x.conf", "[Unit]\nDescription=gone soon\n");
        ASSERT_EQ_INT(manager_load_units(t.m, NULL), 0);

        u = manager_get_unit(t.m, "a.service");
        ASSERT_TRUE(u != NULL);
        ASSERT_STREQ(u->description, "base");
        ASSERT_TRUE(u->dropin_paths == NULL);
        ASSERT_STREQ(manager_get_unit(t.m, "b.service")->description, "gone soon");

        mkd(&t, "etc", "a.service.d");
        put(&t, "etc", "a.service.d/10-x.conf", "[Unit]\nDescription=added\n");
        snprintf(path, sizeof(path), "%s/etc/b.service.d/10-x.conf", t.root);
        ASSERT_EQ_INT(unlink(path), 0);

        ASSERT_TRUE(manager_reload(t.m) >= 2);
        ASSERT_STREQ(u->description, "added");
        ASSERT_STREQ(applied(&t, u), "etc/a.service.d/10-x.conf");
        u = manager_get_unit(t.m, "b.service");
        ASSERT_STREQ(u->description, "base");
        ASSERT_TRUE(u->dropin_paths == NULL);

        /* an edit of a drop-in alone is enough */
        put(&t, "etc", "a.service.d/10-x.conf", "[Unit]\nDescription=edited\n");
        ASSERT_TRUE(manager_reload(t.m) >= 1);
        ASSERT_STREQ(manager_get_unit(t.m, "a.service")->description, "edited");

        /* and a new directory with the unit file untouched */
        mkd(&t, "run", "a.service.d");
        put(&t, "run", "a.service.d/05-early.conf", "[Unit]\nDescription=early\n");
        ASSERT_TRUE(manager_reload(t.m) >= 1);
        ASSERT_STREQ(manager_get_unit(t.m, "a.service")->description, "edited");
        ASSERT_STREQ(applied(&t, manager_get_unit(t.m, "a.service")),
                     "run/a.service.d/05-early.conf etc/a.service.d/10-x.conf");
        tree_free(&t);
}

int main(void) {
        test_precedence_between_directories();
        test_same_name_masks_lower_directory();
        test_name_order_across_directories();
        test_list_reset();
        test_dash_truncated_and_type_level_directories();
        test_instance_and_template_directories();
        test_dropin_for_a_unit_without_a_file();
        test_bad_line_names_file_and_line();
        test_verification_sees_the_dropins();
        test_reload_sees_added_and_removed_dropins();

        printf("test-unit-dropin: all checks passed\n");
        return 0;
}
