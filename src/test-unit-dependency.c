/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * M1's acceptance test: a three-unit "A wants B, A after C" graph loaded from
 * real fragments on disk, with the edges asserted to be exactly what the files
 * said -- plus the regressions for the two bugs this milestone's review found
 * (a unit name that escapes the search directory, and an edge inserted twice).
 *
 * The units are written to a temporary directory and the manager is pointed at
 * it, so this exercises the real loader end to end: directory scan, fragment
 * parse, dependency resolution through the load queue, and cycle detection.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "manager.h"
#include "test-util.h"
#include "unit.h"

static const char *unit_a =
                "[Unit]\n"
                "Description=Unit A\n"
                "Wants=b.service\n"
                "After=c.service\n"
                "\n"
                "[Service]\n"
                "ExecStart=/bin/true\n";

static const char *unit_b =
                "[Unit]\n"
                "Description=Unit B\n"
                "\n"
                "[Service]\n"
                "ExecStart=/bin/true\n";

static const char *unit_c =
                "[Unit]\n"
                "Description=Unit C\n"
                "\n"
                "[Service]\n"
                "ExecStart=/bin/true\n";

static Manager *manager_for(const char *dir) {
        const char * const path[] = { dir, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT(manager_set_unit_path(m, path), 0);

        return m;
}

/* M1's "Done when": A wants B and runs after C, exactly as written. */
static void test_three_unit_ordering(void) {
        Unit *a, *b, *c;
        Manager *m;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.service", unit_a), 0);
        ASSERT_EQ_INT(test_write_file(dir, "b.service", unit_b), 0);
        ASSERT_EQ_INT(test_write_file(dir, "c.service", unit_c), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.service");
        b = manager_get_unit(m, "b.service");
        c = manager_get_unit(m, "c.service");

        ASSERT_TRUE(a != NULL);
        ASSERT_TRUE(b != NULL);
        ASSERT_TRUE(c != NULL);

        ASSERT_EQ_INT(a->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(b->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(c->load_state, UNIT_LOADED);

        ASSERT_STREQ(a->description, "Unit A");

        /* the declared edges */
        ASSERT_TRUE(unit_has_dependency(a, UNIT_WANTS, b));
        ASSERT_TRUE(unit_has_dependency(a, UNIT_AFTER, c));

        /*
         * The inverse of an ordering edge must be recorded too: without it the
         * cycle detector and the job engine only ever see half the graph, and
         * "C before A" would be invisible from C.
         */
        ASSERT_TRUE(unit_has_dependency(c, UNIT_BEFORE, a));

        /* Wants has no inverse slot in this model -- B must not have gained one */
        ASSERT_EQ_INT(b->n_dependencies[UNIT_REQUIRES], 0);
        ASSERT_EQ_INT(b->n_dependencies[UNIT_WANTS], 0);

        /* and nothing here forms an ordering cycle */
        ASSERT_EQ_INT(unit_dependency_detect_cycles(m), 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* Adding the same edge twice must not grow the array. */
static void test_dependency_dedup_and_self(void) {
        Unit *a, *b;
        Manager *m;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a.service", unit_a), 0);
        ASSERT_EQ_INT(test_write_file(dir, "b.service", unit_b), 0);
        ASSERT_EQ_INT(test_write_file(dir, "c.service", unit_c), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.service");
        b = manager_get_unit(m, "b.service");
        ASSERT_TRUE(a && b);

        ASSERT_EQ_INT(a->n_dependencies[UNIT_WANTS], 1);

        /* re-adding is a successful no-op, not a second entry */
        ASSERT_EQ_INT(unit_add_dependency(a, UNIT_WANTS, b), 0);
        ASSERT_EQ_INT(a->n_dependencies[UNIT_WANTS], 1);

        /* and the same for an ordering edge, including its inverse */
        ASSERT_EQ_INT(unit_add_dependency(a, UNIT_BEFORE, b), 0);
        ASSERT_EQ_INT(a->n_dependencies[UNIT_BEFORE], 1);
        ASSERT_EQ_INT(b->n_dependencies[UNIT_AFTER], 1);
        ASSERT_EQ_INT(unit_add_dependency(a, UNIT_BEFORE, b), 0);
        ASSERT_EQ_INT(a->n_dependencies[UNIT_BEFORE], 1);
        ASSERT_EQ_INT(b->n_dependencies[UNIT_AFTER], 1);

        /* a unit ordered against itself is a one-node cycle; reject it up front */
        ASSERT_EQ_INT(unit_add_dependency(a, UNIT_AFTER, a), -EINVAL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A real ordering cycle must be reported, not silently accepted. */
static void test_cycle_detection(void) {
        Manager *m;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "x.service",
                                      "[Unit]\nAfter=y.service\n[Service]\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "y.service",
                                      "[Unit]\nAfter=z.service\n[Service]\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "z.service",
                                      "[Unit]\nAfter=x.service\n[Service]\nExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        ASSERT_TRUE(manager_get_unit(m, "x.service") != NULL);
        ASSERT_TRUE(manager_get_unit(m, "y.service") != NULL);
        ASSERT_TRUE(manager_get_unit(m, "z.service") != NULL);

        ASSERT_EQ_INT(unit_dependency_detect_cycles(m), -ELOOP);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Regression for the review finding that no unit-name validation existed
 * before a dependency token became a path. The fragment below asks for a unit
 * outside the search directory; it must be dropped, not loaded, and must not
 * appear in the unit table under any name.
 */
static void test_dependency_name_cannot_escape(void) {
        size_t n_before;
        Manager *m;
        char *dir;
        Unit *a;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "a.service",
                                      "[Unit]\n"
                                      "Requires=../../tmp/evil.service\n"
                                      "Requires=/etc/passwd\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        a = manager_get_unit(m, "a.service");
        ASSERT_TRUE(a != NULL);
        ASSERT_EQ_INT(a->load_state, UNIT_LOADED);

        /* the bad names were dropped: no Requires edge was recorded at all */
        ASSERT_EQ_INT(a->n_dependencies[UNIT_REQUIRES], 0);

        /* and only a.service itself is in the table */
        n_before = m->n_units;
        ASSERT_EQ_INT(n_before, 1);
        ASSERT_TRUE(manager_get_unit(m, "../../tmp/evil.service") == NULL);
        ASSERT_TRUE(manager_get_unit(m, "/etc/passwd") == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_unit_name_validation(void) {
        char toolong[UNIT_NAME_MAX + 32];

        /* accepted */
        ASSERT_TRUE(unit_name_is_valid("foo.service"));
        ASSERT_TRUE(unit_name_is_valid("multi-user.target"));
        ASSERT_TRUE(unit_name_is_valid("serial-getty@ttyGS0.service"));
        ASSERT_TRUE(unit_name_is_valid("a_b:c.service"));

        /* rejected */
        ASSERT_TRUE(!unit_name_is_valid(NULL));
        ASSERT_TRUE(!unit_name_is_valid(""));
        ASSERT_TRUE(!unit_name_is_valid("../../tmp/evil.service"));
        ASSERT_TRUE(!unit_name_is_valid("/etc/passwd"));
        ASSERT_TRUE(!unit_name_is_valid("foo/bar.service"));
        ASSERT_TRUE(!unit_name_is_valid("."));
        ASSERT_TRUE(!unit_name_is_valid(".."));
        ASSERT_TRUE(!unit_name_is_valid(".hidden.service"));
        ASSERT_TRUE(!unit_name_is_valid("foo bar.service"));  /* whitespace */
        ASSERT_TRUE(!unit_name_is_valid("foo\nbar.service")); /* control char */
        ASSERT_TRUE(!unit_name_is_valid("foo.socket"));       /* no such unit type here */
        ASSERT_TRUE(!unit_name_is_valid("noSuffix"));

        memset(toolong, 'a', sizeof(toolong) - 1);
        toolong[sizeof(toolong) - 1] = '\0';
        memcpy(toolong + sizeof(toolong) - 9, ".service", 9);
        ASSERT_TRUE(!unit_name_is_valid(toolong));
}

/* Targets are a real unit type now, and load from the same search path. */
static void test_target_loads(void) {
        Manager *m;
        char *dir;
        Unit *t;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "default.target", "[Unit]\nDescription=Default\nWants=a.service\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "a.service", unit_b), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        t = manager_get_unit(m, "default.target");
        ASSERT_TRUE(t != NULL);
        ASSERT_EQ_INT(t->type, UNIT_TARGET);
        ASSERT_EQ_INT(t->load_state, UNIT_LOADED);
        ASSERT_TRUE(unit_has_dependency(t, UNIT_WANTS, manager_get_unit(m, "a.service")));

        /* a target starts with no process involved */
        ASSERT_EQ_INT(unit_active_state(t), UNIT_INACTIVE);
        ASSERT_EQ_INT(unit_start(t), 0);
        ASSERT_EQ_INT(unit_active_state(t), UNIT_ACTIVE);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_unit_name_validation();
        test_three_unit_ordering();
        test_dependency_dedup_and_self();
        test_cycle_detection();
        test_dependency_name_cannot_escape();
        test_target_loads();

        printf("test-unit-dependency: all checks passed\n");
        return 0;
}
