/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * M2's boot-rooting acceptance test: .wants/.requires directories, [Install]
 * WantedBy=/RequiredBy=, and preset application (systemd.preset(5) rules,
 * including its counter-intuitive "no rule matched" == enable default), all
 * exercised against real fragments and real symlinks on disk.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "manager.h"
#include "test-util.h"
#include "unit-enable.h"
#include "unit.h"

static const char *default_target_unit = "[Unit]\nDescription=Default\n";

static const char *simple_service = "[Unit]\nDescription=svc\n[Service]\nExecStart=/bin/true\n";

static Manager *manager_for(const char *unit_dir) {
        const char * const unit_path[] = { unit_dir, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT(manager_set_unit_path(m, unit_path), 0);

        return m;
}

static void set_one_preset_dir(Manager *m, const char *dir) {
        const char * const preset_path[] = { dir, NULL };

        ASSERT_EQ_INT(manager_set_preset_path(m, preset_path), 0);
}

static void set_two_preset_dirs(Manager *m, const char *dir1, const char *dir2) {
        const char * const preset_path[] = { dir1, dir2, NULL };

        ASSERT_EQ_INT(manager_set_preset_path(m, preset_path), 0);
}

/*
 * The boot-startup enablement phase (manager-startup.c steps 3-4), factored
 * out here so tests can drive it without also dragging in cycle detection and
 * job creation. Follows the same iteration hazard rule manager-startup.c
 * documents: index freshly and re-read m->n_units, never cache the array.
 */
static void apply_enablement(Manager *m) {
        size_t i;

        for (i = 0; i < m->n_units; i++) {
                Unit *u = m->units[i];

                if (u->load_state != UNIT_LOADED)
                        continue;

                ASSERT_TRUE(unit_add_wants_requires_dirs(u) == 0);
        }

        ASSERT_TRUE(manager_apply_presets(m) >= 0);
}

/* A default.target with no static Wants=, pulling in exactly what a real
 * default.target.wants/ directory names -- nothing more, nothing less. */
static void test_wants_dir_produces_wants_edges(void) {
        Unit *target, *a, *b;
        Manager *m;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "default.target", default_target_unit), 0);
        ASSERT_EQ_INT(test_write_file(dir, "a.service", simple_service), 0);
        ASSERT_EQ_INT(test_write_file(dir, "b.service", simple_service), 0);
        ASSERT_EQ_INT(test_mkdir(dir, "default.target.wants"), 0);
        ASSERT_EQ_INT(test_symlink(dir, "default.target.wants/a.service", "../a.service"), 0);
        ASSERT_EQ_INT(test_symlink(dir, "default.target.wants/b.service", "../b.service"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        target = manager_get_unit(m, "default.target");
        a = manager_get_unit(m, "a.service");
        b = manager_get_unit(m, "b.service");
        ASSERT_TRUE(target && a && b);

        ASSERT_EQ_INT(unit_add_wants_requires_dirs(target), 0);

        ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, a));
        ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, b));
        ASSERT_EQ_INT(target->n_dependencies[UNIT_WANTS], 2); /* exactly those two, nothing else */
        ASSERT_EQ_INT(target->n_dependencies[UNIT_REQUIRES], 0);

        ASSERT_TRUE(a->enabled);
        ASSERT_TRUE(b->enabled);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* Same mechanism, .requires/ this time, producing Requires edges instead. */
static void test_requires_dir_produces_requires_edges(void) {
        Unit *target, *a;
        Manager *m;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "default.target", default_target_unit), 0);
        ASSERT_EQ_INT(test_write_file(dir, "a.service", simple_service), 0);
        ASSERT_EQ_INT(test_mkdir(dir, "default.target.requires"), 0);
        ASSERT_EQ_INT(test_symlink(dir, "default.target.requires/a.service", "../a.service"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        target = manager_get_unit(m, "default.target");
        a = manager_get_unit(m, "a.service");
        ASSERT_TRUE(target && a);

        ASSERT_EQ_INT(unit_add_wants_requires_dirs(target), 0);

        ASSERT_TRUE(unit_has_dependency(target, UNIT_REQUIRES, a));
        ASSERT_EQ_INT(target->n_dependencies[UNIT_REQUIRES], 1);
        ASSERT_EQ_INT(target->n_dependencies[UNIT_WANTS], 0);
        ASSERT_TRUE(a->enabled);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A missing .wants/.requires directory is normal, not an error -- an image
 * may ship no admin overrides for a given unit at all.
 */
static void test_missing_wants_dir_is_not_an_error(void) {
        Unit *target;
        Manager *m;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "default.target", default_target_unit), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        target = manager_get_unit(m, "default.target");
        ASSERT_TRUE(target != NULL);

        ASSERT_EQ_INT(unit_add_wants_requires_dirs(target), 0);
        ASSERT_EQ_INT(target->n_dependencies[UNIT_WANTS], 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* [Install] WantedBy=default.target plus a preset "enable" line: the edge
 * runs from default.target to the service, and the service ends up enabled. */
static void test_install_wantedby_with_preset_enable(void) {
        Unit *target, *foo;
        Manager *m;
        char *udir, *pdir;

        udir = test_tmpdir_new();
        pdir = test_tmpdir_new();
        ASSERT_TRUE(udir && pdir);

        ASSERT_EQ_INT(test_write_file(udir, "default.target", default_target_unit), 0);
        ASSERT_EQ_INT(test_write_file(udir,
                                      "foo.service",
                                      "[Unit]\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=default.target\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(pdir, "10-test.preset", "enable foo.service\n"), 0);

        m = manager_for(udir);
        set_one_preset_dir(m, pdir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        target = manager_get_unit(m, "default.target");
        foo = manager_get_unit(m, "foo.service");
        ASSERT_TRUE(target && foo);
        ASSERT_TRUE(!foo->enabled);

        ASSERT_EQ_INT(manager_apply_presets(m), 1);

        ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, foo));
        ASSERT_TRUE(foo->enabled);

        manager_free(m);
        test_rm_rf(udir);
        test_rm_rf(pdir);
        free(udir);
        free(pdir);
}

/* Same shape, but the preset says "disable": no edge, despite [Install] data
 * asking for one. */
static void test_install_wantedby_with_preset_disable(void) {
        Unit *target, *foo;
        Manager *m;
        char *udir, *pdir;

        udir = test_tmpdir_new();
        pdir = test_tmpdir_new();
        ASSERT_TRUE(udir && pdir);

        ASSERT_EQ_INT(test_write_file(udir, "default.target", default_target_unit), 0);
        ASSERT_EQ_INT(test_write_file(udir,
                                      "foo.service",
                                      "[Unit]\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=default.target\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(pdir, "10-test.preset", "disable foo.service\n"), 0);

        m = manager_for(udir);
        set_one_preset_dir(m, pdir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        target = manager_get_unit(m, "default.target");
        foo = manager_get_unit(m, "foo.service");
        ASSERT_TRUE(target && foo);

        ASSERT_EQ_INT(manager_apply_presets(m), 0); /* nothing got enabled */

        ASSERT_TRUE(!unit_has_dependency(target, UNIT_WANTS, foo));
        ASSERT_TRUE(!foo->enabled);

        manager_free(m);
        test_rm_rf(udir);
        test_rm_rf(pdir);
        free(udir);
        free(pdir);
}

/*
 * The rule most likely to be implemented backwards: when no preset rule
 * matches a unit at all, `systemctl preset`'s own default is ENABLE, not
 * disable. Assert it explicitly rather than trusting the other tests to
 * catch a flipped default.
 */
static void test_no_matching_rule_defaults_to_enable(void) {
        Unit *target, *foo;
        Manager *m;
        char *udir, *pdir;

        udir = test_tmpdir_new();
        pdir = test_tmpdir_new();
        ASSERT_TRUE(udir && pdir);

        ASSERT_EQ_INT(test_write_file(udir, "default.target", default_target_unit), 0);
        ASSERT_EQ_INT(test_write_file(udir,
                                      "foo.service",
                                      "[Unit]\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=default.target\n"),
                      0);
        /* a preset file that exists but says nothing at all about foo.service */
        ASSERT_EQ_INT(test_write_file(pdir, "10-test.preset", "enable completely-unrelated.service\n"), 0);

        m = manager_for(udir);
        set_one_preset_dir(m, pdir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        target = manager_get_unit(m, "default.target");
        foo = manager_get_unit(m, "foo.service");
        ASSERT_TRUE(target && foo);

        ASSERT_EQ_INT(manager_preset_query(m, "foo.service"), -ENOENT);

        ASSERT_EQ_INT(manager_apply_presets(m), 1);

        ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, foo));
        ASSERT_TRUE(foo->enabled);

        manager_free(m);
        test_rm_rf(udir);
        test_rm_rf(pdir);
        free(udir);
        free(pdir);
}

/* Preset precedence: within one directory, the lexicographically earliest
 * filename wins, regardless of enable/disable ordering by name. */
static void test_preset_filename_precedence(void) {
        Manager *m;
        char *pdir;

        pdir = test_tmpdir_new();
        ASSERT_TRUE(pdir != NULL);

        ASSERT_EQ_INT(test_write_file(pdir, "10-a.preset", "enable svc.service\n"), 0);
        ASSERT_EQ_INT(test_write_file(pdir, "20-b.preset", "disable svc.service\n"), 0);

        /* and the reverse spelling, to prove it is filename order deciding
         * this and not "enable beats disable" or vice versa */
        ASSERT_EQ_INT(test_write_file(pdir, "05-disable.preset", "disable svc2.service\n"), 0);
        ASSERT_EQ_INT(test_write_file(pdir, "50-enable.preset", "enable svc2.service\n"), 0);

        m = manager_for(pdir); /* unit_path is unused by manager_preset_query */
        set_one_preset_dir(m, pdir);

        ASSERT_EQ_INT(manager_preset_query(m, "svc.service"), 1);  /* "10-a" < "20-b" */
        ASSERT_EQ_INT(manager_preset_query(m, "svc2.service"), 0); /* "05-disable" < "50-enable" */

        manager_free(m);
        test_rm_rf(pdir);
        free(pdir);
}

/* A same-named preset file in an earlier search-path directory shadows the
 * one in a later directory entirely -- the later file's rules are never
 * consulted, even for a unit the earlier file says nothing about. */
static void test_preset_dir_shadowing(void) {
        Manager *m;
        char *dir1, *dir2;

        dir1 = test_tmpdir_new();
        dir2 = test_tmpdir_new();
        ASSERT_TRUE(dir1 && dir2);

        ASSERT_EQ_INT(test_write_file(dir1, "10-common.preset", "enable svc.service\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir2, "10-common.preset", "disable svc.service\n"), 0);

        m = manager_for(dir1);
        set_two_preset_dirs(m, dir1, dir2);

        ASSERT_EQ_INT(manager_preset_query(m, "svc.service"), 1); /* dir1's file, not dir2's */

        manager_free(m);
        test_rm_rf(dir1);
        test_rm_rf(dir2);
        free(dir1);
        free(dir2);
}

/* Shell-style wildcards, e.g. for a templated unit family. */
static void test_preset_glob_matching(void) {
        Manager *m;
        char *pdir;

        pdir = test_tmpdir_new();
        ASSERT_TRUE(pdir != NULL);

        ASSERT_EQ_INT(test_write_file(pdir, "10-test.preset", "enable foo-*.service\n"), 0);

        m = manager_for(pdir);
        set_one_preset_dir(m, pdir);

        ASSERT_EQ_INT(manager_preset_query(m, "foo-bar.service"), 1);
        ASSERT_EQ_INT(manager_preset_query(m, "foo-baz.service"), 1);
        ASSERT_EQ_INT(manager_preset_query(m, "other.service"), -ENOENT);

        manager_free(m);
        test_rm_rf(pdir);
        free(pdir);
}

/*
 * A unit already enabled by a real .wants/ symlink must stay enabled even
 * when a preset rule would otherwise say "disable" -- the symlink is an
 * explicit decision already made, and a preset only fills in what nothing
 * else spoke for.
 */
static void test_symlink_enabled_survives_disable_preset(void) {
        Unit *target, *foo;
        Manager *m;
        char *udir, *pdir;

        udir = test_tmpdir_new();
        pdir = test_tmpdir_new();
        ASSERT_TRUE(udir && pdir);

        ASSERT_EQ_INT(test_write_file(udir, "default.target", default_target_unit), 0);
        ASSERT_EQ_INT(test_write_file(udir,
                                      "foo.service",
                                      "[Unit]\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=default.target\n"),
                      0);
        ASSERT_EQ_INT(test_mkdir(udir, "default.target.wants"), 0);
        ASSERT_EQ_INT(test_symlink(udir, "default.target.wants/foo.service", "../foo.service"), 0);
        ASSERT_EQ_INT(test_write_file(pdir, "10-test.preset", "disable foo.service\n"), 0);

        m = manager_for(udir);
        set_one_preset_dir(m, pdir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        target = manager_get_unit(m, "default.target");
        foo = manager_get_unit(m, "foo.service");
        ASSERT_TRUE(target && foo);

        ASSERT_EQ_INT(unit_add_wants_requires_dirs(target), 0);
        ASSERT_TRUE(foo->enabled); /* the symlink already decided this */

        ASSERT_EQ_INT(manager_apply_presets(m), 0); /* nothing left for presets to enable */

        ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, foo)); /* edge from the symlink survives */
        ASSERT_TRUE(foo->enabled);                                 /* the disable rule never got a say */

        manager_free(m);
        test_rm_rf(udir);
        test_rm_rf(pdir);
        free(udir);
        free(pdir);
}

/* The real preset file shipping in the angstrom-pico image today, including
 * .timer/.path unit names pico-init has no vtable for -- those must parse
 * without error and simply never match a loaded .service/.target unit. */
static void test_real_angstrom_pico_preset_parses(void) {
        static const char *preset =
                        "disable systemd-firstboot.service\n"
                        "disable fstrim.timer\n"
                        "disable firstboot-grow-rootfs.service\n"
                        "enable pico-resolv.path\n"
                        "enable serial-getty@ttyGS0.service\n";
        Manager *m;
        char *pdir;

        pdir = test_tmpdir_new();
        ASSERT_TRUE(pdir != NULL);

        ASSERT_EQ_INT(test_write_file(pdir, "20-angstrom-pico.preset", preset), 0);

        m = manager_for(pdir);
        set_one_preset_dir(m, pdir);

        ASSERT_EQ_INT(manager_preset_query(m, "systemd-firstboot.service"), 0);
        ASSERT_EQ_INT(manager_preset_query(m, "firstboot-grow-rootfs.service"), 0);
        ASSERT_EQ_INT(manager_preset_query(m, "serial-getty@ttyGS0.service"), 1);

        /* pico-resolv.path and fstrim.timer name unit types pico-init cannot
         * instantiate; querying a name pico-init actually could load must
         * simply not match them, not crash or misbehave. */
        ASSERT_EQ_INT(manager_preset_query(m, "pico-resolv.service"), -ENOENT);
        ASSERT_EQ_INT(manager_preset_query(m, "unrelated.service"), -ENOENT);

        manager_free(m);
        test_rm_rf(pdir);
        free(pdir);
}

/*
 * M2's acceptance criterion, made literal: a default.target pulling in units
 * via real WantedBy=/preset resolution ends up wanting exactly the set a
 * hand-built explicit list would -- alpha via a .wants/ symlink, beta via a
 * preset "enable", delta via the no-rule-matched default, and NOT gamma,
 * which a preset explicitly disables despite its own [Install] WantedBy=.
 */
static void test_default_target_boots_hand_built_set(void) {
        Unit *target, *alpha, *beta, *gamma, *delta;
        Manager *m;
        char *udir, *pdir;

        udir = test_tmpdir_new();
        pdir = test_tmpdir_new();
        ASSERT_TRUE(udir && pdir);

        ASSERT_EQ_INT(test_write_file(udir, "default.target", default_target_unit), 0);
        ASSERT_EQ_INT(test_write_file(udir, "alpha.service", simple_service), 0);
        ASSERT_EQ_INT(test_mkdir(udir, "default.target.wants"), 0);
        ASSERT_EQ_INT(test_symlink(udir, "default.target.wants/alpha.service", "../alpha.service"), 0);

        ASSERT_EQ_INT(test_write_file(udir,
                                      "beta.service",
                                      "[Unit]\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=default.target\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(udir,
                                      "gamma.service",
                                      "[Unit]\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=default.target\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(udir,
                                      "delta.service",
                                      "[Unit]\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=default.target\n"),
                      0);

        /* beta: explicit enable. gamma: explicit disable. delta: no rule at
         * all, so it falls to the default-enable behaviour under test. */
        ASSERT_EQ_INT(test_write_file(pdir, "10-test.preset", "enable beta.service\ndisable gamma.service\n"),
                      0);

        m = manager_for(udir);
        set_one_preset_dir(m, pdir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        apply_enablement(m);

        target = manager_get_unit(m, "default.target");
        alpha = manager_get_unit(m, "alpha.service");
        beta = manager_get_unit(m, "beta.service");
        gamma = manager_get_unit(m, "gamma.service");
        delta = manager_get_unit(m, "delta.service");
        ASSERT_TRUE(target && alpha && beta && gamma && delta);

        /* the hand-built explicit list: {alpha, beta, delta}, not gamma */
        ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, alpha));
        ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, beta));
        ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, delta));
        ASSERT_TRUE(!unit_has_dependency(target, UNIT_WANTS, gamma));
        ASSERT_EQ_INT(target->n_dependencies[UNIT_WANTS], 3);

        ASSERT_TRUE(alpha->enabled);
        ASSERT_TRUE(beta->enabled);
        ASSERT_TRUE(delta->enabled);
        ASSERT_TRUE(!gamma->enabled);

        manager_free(m);
        test_rm_rf(udir);
        test_rm_rf(pdir);
        free(udir);
        free(pdir);
}

int main(void) {
        test_wants_dir_produces_wants_edges();
        test_requires_dir_produces_requires_edges();
        test_missing_wants_dir_is_not_an_error();
        test_install_wantedby_with_preset_enable();
        test_install_wantedby_with_preset_disable();
        test_no_matching_rule_defaults_to_enable();
        test_preset_filename_precedence();
        test_preset_dir_shadowing();
        test_preset_glob_matching();
        test_symlink_enabled_survives_disable_preset();
        test_real_angstrom_pico_preset_parses();
        test_default_target_boots_hand_built_set();

        printf("test-boot-root: all checks passed\n");
        return 0;
}
