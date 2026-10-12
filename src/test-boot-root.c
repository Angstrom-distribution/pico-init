/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Boot rooting: .wants/.requires directories, [Install]
 * WantedBy=/RequiredBy=, and preset application (systemd.preset(5) rules,
 * including its counter-intuitive "no rule matched" == enable default), all
 * exercised against real fragments and real symlinks on disk.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
 *
 * Gated on m->first_boot exactly like manager-startup.c's own step 4: a
 * caller that wants presets applied has to say so explicitly with
 * manager_set_first_boot(m, true) first, matching what a real boot does
 * exactly once per machine.
 */
static void apply_enablement(Manager *m) {
        size_t i;

        for (i = 0; i < m->n_units; i++) {
                Unit *u = m->units[i];

                if (u->load_state != UNIT_LOADED)
                        continue;

                ASSERT_TRUE(unit_add_wants_requires_dirs(u) == 0);
        }

        if (m->first_boot)
                ASSERT_TRUE(manager_apply_presets(m) >= 0);
}

/* Whether <dir>/<target><suffix>/<unit_id> exists as a symlink -- the
 * on-disk fact manager_apply_presets() produces whenever it enables a unit,
 * not just the in-memory edge and u->enabled. */
static bool enable_symlink_on_disk(const char *dir, const char *target, const char *suffix, const char *unit_id) {
        char path[PATH_MAX];
        struct stat st;
        int n;

        n = snprintf(path, sizeof(path), "%s/%s%s/%s", dir, target, suffix, unit_id);
        ASSERT_TRUE(n > 0 && (size_t) n < sizeof(path));

        return lstat(path, &st) == 0;
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
        /* a preset-driven enable is persisted as a real symlink too, not just
         * an in-memory edge */
        ASSERT_TRUE(enable_symlink_on_disk(udir, "default.target", ".wants", "foo.service"));

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
        /* "disable" writes nothing: no symlink appears for a unit presets
         * left disabled */
        ASSERT_TRUE(!enable_symlink_on_disk(udir, "default.target", ".wants", "foo.service"));

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
        ASSERT_TRUE(enable_symlink_on_disk(udir, "default.target", ".wants", "foo.service"));

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
 * A default.target pulling in units
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

        /* presets only ever act on first boot */
        manager_set_first_boot(m, true);
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

        /* alpha's symlink was already on disk (hand-built fixture); beta
         * and delta are new, persisted by the preset step just now; gamma
         * gets none */
        ASSERT_TRUE(enable_symlink_on_disk(udir, "default.target", ".wants", "alpha.service"));
        ASSERT_TRUE(enable_symlink_on_disk(udir, "default.target", ".wants", "beta.service"));
        ASSERT_TRUE(enable_symlink_on_disk(udir, "default.target", ".wants", "delta.service"));
        ASSERT_TRUE(!enable_symlink_on_disk(udir, "default.target", ".wants", "gamma.service"));

        manager_free(m);
        test_rm_rf(udir);
        test_rm_rf(pdir);
        free(udir);
        free(pdir);
}

/*
 * The full manager_startup() path, not just apply_enablement(): on a real
 * first boot (m->first_boot set before startup runs, exactly as main.c's
 * machine_id_setup() result does it), a preset "enable" gets persisted as a
 * real symlink on disk, not just an in-memory edge -- the thing that lets a
 * later, non-first boot see the same decision without presets ever running
 * again.
 */
static void test_first_boot_persists_preset_symlinks(void) {
        Unit *foo;
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
        manager_set_first_boot(m, true);

        ASSERT_EQ_INT(manager_startup(m, "default.target"), 0);

        foo = manager_get_unit(m, "foo.service");
        ASSERT_TRUE(foo != NULL);
        ASSERT_TRUE(foo->enabled);
        ASSERT_TRUE(enable_symlink_on_disk(udir, "default.target", ".wants", "foo.service"));

        manager_free(m);
        test_rm_rf(udir);
        test_rm_rf(pdir);
        free(udir);
        free(pdir);
}

/*
 * `systemctl disable foo` (here, removing the symlink by hand, as that verb
 * does) must stay disabled across a later boot, even though the preset still
 * says "enable", because a non-first boot never consults presets.
 */
static void test_second_boot_does_not_resurrect_a_disabled_unit(void) {
        Unit *foo;
        Manager *m;
        char *udir, *pdir;
        char linkpath[PATH_MAX];
        int n;

        udir = test_tmpdir_new();
        pdir = test_tmpdir_new();
        ASSERT_TRUE(udir && pdir);

        ASSERT_EQ_INT(test_write_file(udir, "default.target", default_target_unit), 0);
        ASSERT_EQ_INT(test_write_file(udir,
                                      "foo.service",
                                      "[Unit]\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=default.target\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(pdir, "10-test.preset", "enable foo.service\n"), 0);

        /* boot 1: first boot, preset enables foo and persists its symlink */
        m = manager_for(udir);
        set_one_preset_dir(m, pdir);
        manager_set_first_boot(m, true);
        ASSERT_EQ_INT(manager_startup(m, "default.target"), 0);

        foo = manager_get_unit(m, "foo.service");
        ASSERT_TRUE(foo && foo->enabled);
        ASSERT_TRUE(enable_symlink_on_disk(udir, "default.target", ".wants", "foo.service"));

        manager_free(m);

        /* "systemctl disable foo.service": remove exactly the symlink that
         * verb removes, leaving the preset's own "enable" rule untouched. */
        n = snprintf(linkpath, sizeof(linkpath), "%s/default.target.wants/foo.service", udir);
        ASSERT_TRUE(n > 0 && (size_t) n < sizeof(linkpath));
        ASSERT_EQ_INT(unlink(linkpath), 0);
        ASSERT_TRUE(!enable_symlink_on_disk(udir, "default.target", ".wants", "foo.service"));

        /* boot 2: a fresh Manager over the same fixture root, NOT first
         * boot -- presets must not be consulted at all. */
        m = manager_for(udir);
        set_one_preset_dir(m, pdir);
        manager_set_first_boot(m, false);
        ASSERT_EQ_INT(manager_startup(m, "default.target"), 0);

        foo = manager_get_unit(m, "foo.service");
        ASSERT_TRUE(foo != NULL);
        ASSERT_TRUE(!foo->enabled);
        ASSERT_TRUE(!enable_symlink_on_disk(udir, "default.target", ".wants", "foo.service"));

        manager_free(m);
        test_rm_rf(udir);
        test_rm_rf(pdir);
        free(udir);
        free(pdir);
}

/*
 * Every ordinary service is ordered After=sockets.target, so none can race a
 * socket it may be activated by -- pico's compressed slice of upstream's
 * After=basic.target -> After=sockets.target chain.
 *
 * The three negative cases are the point: a Socket must NOT be ordered after
 * the target it installs into, a Target must not either (that closes a
 * cycle), and an explicit ordering in the unit file outranks the default. The
 * whole rule is worthless if applying it makes the graph unorderable, so the
 * real cycle checker is run at the end rather than trusted.
 */
static void test_services_ordered_after_sockets_target(void) {
        Unit *sockets, *svc, *sock, *other, *explicit_before;
        Manager *m;
        char *udir;

        udir = test_tmpdir_new();
        ASSERT_TRUE(udir != NULL);

        ASSERT_EQ_INT(test_write_file(udir, "default.target", default_target_unit), 0);
        ASSERT_EQ_INT(test_write_file(udir, "sockets.target", "[Unit]\nDescription=Socket units\n"), 0);
        ASSERT_EQ_INT(test_write_file(udir, "svc.service", simple_service), 0);
        ASSERT_EQ_INT(test_write_file(udir, "other.target", "[Unit]\nDescription=Other\n"), 0);
        ASSERT_EQ_INT(test_write_file(udir,
                                      "svc.socket",
                                      "[Socket]\nListenStream=/run/pico-test-order.sock\n"
                                      "[Install]\nWantedBy=sockets.target\n"),
                      0);
        /* An explicit Before= must survive: this one legitimately runs before
         * sockets.target and must not be flipped. */
        ASSERT_EQ_INT(test_write_file(udir,
                                      "early.service",
                                      "[Unit]\nBefore=sockets.target\n[Service]\nExecStart=/bin/true\n"),
                      0);

        m = manager_for(udir);
        ASSERT_EQ_INT(manager_startup(m, "default.target"), 0);

        sockets = manager_get_unit(m, "sockets.target");
        svc = manager_get_unit(m, "svc.service");
        sock = manager_get_unit(m, "svc.socket");
        other = manager_get_unit(m, "other.target");
        explicit_before = manager_get_unit(m, "early.service");
        ASSERT_TRUE(sockets && svc && sock && other && explicit_before);

        /* the rule itself */
        ASSERT_TRUE(unit_has_dependency(svc, UNIT_AFTER, sockets));

        /* a socket is not ordered after the target it installs into */
        ASSERT_TRUE(!unit_has_dependency(sock, UNIT_AFTER, sockets));

        /* nor is another target, which would close a cycle */
        ASSERT_TRUE(!unit_has_dependency(other, UNIT_AFTER, sockets));

        /* an explicit ordering outranks the default, in the stated direction */
        ASSERT_TRUE(unit_has_dependency(explicit_before, UNIT_BEFORE, sockets));
        ASSERT_TRUE(!unit_has_dependency(explicit_before, UNIT_AFTER, sockets));

        /* and the graph is still orderable with all of that applied */
        ASSERT_EQ_INT(unit_dependency_detect_cycles(m), 0);

        manager_free(m);
        test_rm_rf(udir);
        free(udir);
}

/*
 * units-global-cycle-check-fatal: a cycle among units the default target's
 * boot transaction never reaches (nothing Wants=/Requires= either one) must
 * not stop the whole boot -- the real, transaction-scoped cycle breaker
 * (job.c transaction_verify_order()) is what has to answer for units that
 * are actually part of the transaction.
 */
static void test_startup_survives_a_cycle_outside_the_transaction(void) {
        Manager *m;
        Unit *target;
        char *udir;

        udir = test_tmpdir_new();
        ASSERT_TRUE(udir != NULL);

        ASSERT_EQ_INT(test_write_file(udir, "default.target", default_target_unit), 0);

        /* Neither unit is WantedBy=/RequiredBy= anything, and neither is
         * listed in any .wants/.requires dir -- nothing in the boot
         * transaction ever reaches them. */
        ASSERT_EQ_INT(test_write_file(udir,
                                      "a.service",
                                      "[Unit]\nAfter=b.service\n[Service]\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(udir,
                                      "b.service",
                                      "[Unit]\nAfter=a.service\n[Service]\nExecStart=/bin/true\n"),
                      0);

        m = manager_for(udir);

        ASSERT_EQ_INT(manager_startup(m, "default.target"), 0);

        target = manager_get_unit(m, "default.target");
        ASSERT_TRUE(target != NULL);
        ASSERT_EQ_INT(target->load_state, UNIT_LOADED);
        ASSERT_TRUE(target->job != NULL);
        ASSERT_EQ_INT(target->job->type, JOB_START);

        manager_free(m);
        test_rm_rf(udir);
        free(udir);
}

/* An "ignore" rule is a verdict of its own: the first matching rule wins, so
 * the unit is left alone instead of falling through to the default enable. */
static void test_preset_ignore_leaves_the_unit_alone(void) {
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
        ASSERT_EQ_INT(test_write_file(pdir, "10-test.preset", "ignore foo.service\nenable *\n"), 0);
        ASSERT_EQ_INT(test_write_file(pdir, "20-test.preset", "enable foo.service\n"), 0);

        m = manager_for(udir);
        set_one_preset_dir(m, pdir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        target = manager_get_unit(m, "default.target");
        foo = manager_get_unit(m, "foo.service");
        ASSERT_TRUE(target && foo);

        ASSERT_EQ_INT(manager_apply_presets(m), 0);
        ASSERT_TRUE(!foo->enabled);
        ASSERT_TRUE(!unit_has_dependency(target, UNIT_WANTS, foo));
        ASSERT_TRUE(!enable_symlink_on_disk(udir, "default.target", ".wants", "foo.service"));

        manager_free(m);
        test_rm_rf(udir);
        test_rm_rf(pdir);
        free(udir);
        free(pdir);
}

/* Patterns are matched without backslash escapes, so the backslash in an
 * escaped unit name (a\x2db) is literal. */
static void test_preset_pattern_backslash_is_literal(void) {
        Manager *m;
        char *pdir;

        pdir = test_tmpdir_new();
        ASSERT_TRUE(pdir != NULL);

        ASSERT_EQ_INT(test_write_file(pdir, "10-test.preset", "disable a\\x2db.service\n"), 0);

        m = manager_for(pdir);
        set_one_preset_dir(m, pdir);

        ASSERT_EQ_INT(manager_preset_query(m, "a\\x2db.service"), 0);
        ASSERT_EQ_INT(manager_preset_query(m, "ax2db.service"), -ENOENT);

        manager_free(m);
        test_rm_rf(pdir);
        free(pdir);
}

int main(void) {
        test_services_ordered_after_sockets_target();
        test_wants_dir_produces_wants_edges();
        test_requires_dir_produces_requires_edges();
        test_missing_wants_dir_is_not_an_error();
        test_install_wantedby_with_preset_enable();
        test_install_wantedby_with_preset_disable();
        test_no_matching_rule_defaults_to_enable();
        test_preset_filename_precedence();
        test_preset_dir_shadowing();
        test_preset_glob_matching();
        test_preset_ignore_leaves_the_unit_alone();
        test_preset_pattern_backslash_is_literal();
        test_symlink_enabled_survives_disable_preset();
        test_real_angstrom_pico_preset_parses();
        test_default_target_boots_hand_built_set();
        test_first_boot_persists_preset_symlinks();
        test_second_boot_does_not_resurrect_a_disabled_unit();
        test_startup_survives_a_cycle_outside_the_transaction();

        printf("test-boot-root: all checks passed\n");
        return 0;
}
