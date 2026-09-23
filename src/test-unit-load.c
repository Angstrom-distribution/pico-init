/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The template/instance fallback in unit-load.c, the precedence it has to
 * get right, and the two manager.c gates around it (the boot scan's skip,
 * manager_load_unit()'s rejection) -- all against a real Manager and real
 * files on disk, never a mock of the search loop.
 *
 * test_wants_symlink_instantiates_template() is also (g)'s own regression:
 * the plan's own confirmation that a .wants symlink resolves purely by
 * name, with nothing in unit-enable.c needing to change, gets no commit of
 * its own -- this is where that claim is actually exercised end to end.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "manager.h"
#include "service.h"
#include "test-util.h"
#include "unit-enable.h"
#include "unit.h"

static Manager *manager_for(const char *dir) {
        const char * const path[] = { dir, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT(manager_set_unit_path(m, path), 0);

        return m;
}

/* dirA searched before dirB -- matches PICO_UNIT_DIR/PICO_PACKAGED_UNIT_DIR's
 * own override-then-packaged order, which is the ordering the
 * cross-directory precedence case has to prove is not accidentally reversed. */
static Manager *manager_for2(const char *dirA, const char *dirB) {
        const char * const path[] = { dirA, dirB, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT(manager_set_unit_path(m, path), 0);

        return m;
}

static const char *basename_of(const char *path) {
        const char *slash = strrchr(path, '/');

        return slash ? slash + 1 : path;
}

static void test_literal_instance_loads(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "foo@bar.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        u = manager_get_unit(m, "foo@bar.service");
        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->instance, "bar");
        ASSERT_TRUE(u->fragment_path != NULL);
        ASSERT_STREQ(basename_of(u->fragment_path), "foo@bar.service");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_template_fallback(void) {
        Manager *m;
        char *dir;
        Unit *u = NULL;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "foo@.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_unit(m, "foo@bar.service", &u), 0);

        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->id, "foo@bar.service");
        ASSERT_STREQ(u->instance, "bar");
        ASSERT_TRUE(u->fragment_path != NULL);
        ASSERT_STREQ(basename_of(u->fragment_path), "foo@.service");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_literal_beats_template_same_dir(void) {
        Manager *m;
        char *dir;
        Unit *u = NULL;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "foo@.service",
                                      "[Unit]\nDescription=Template\n\n[Service]\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "foo@bar.service",
                                      "[Unit]\nDescription=Literal\n\n[Service]\nExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_unit(m, "foo@bar.service", &u), 0);

        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->description, "Literal");
        ASSERT_STREQ(basename_of(u->fragment_path), "foo@bar.service");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The precedence case that actually matters: a template that ships in the
 * higher-priority directory must not shadow a literal instance file that
 * ships in a lower-priority one. This is what unit-load.c's own header
 * comment calls out as the ordering a per-directory "optimization" would
 * silently invert -- and it is the exact shape G3(b)'s
 * serial-getty@ttyGS0.service override depends on.
 */
static void test_literal_beats_template_across_dirs(void) {
        Manager *m;
        char *dirA, *dirB;
        Unit *u = NULL;

        dirA = test_tmpdir_new();
        dirB = test_tmpdir_new();
        ASSERT_TRUE(dirA != NULL && dirB != NULL);

        ASSERT_EQ_INT(test_write_file(dirA,
                                      "foo@.service",
                                      "[Unit]\nDescription=Template\n\n[Service]\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dirB,
                                      "foo@bar.service",
                                      "[Unit]\nDescription=Literal\n\n[Service]\nExecStart=/bin/true\n"),
                      0);

        m = manager_for2(dirA, dirB);
        ASSERT_EQ_INT(manager_load_unit(m, "foo@bar.service", &u), 0);

        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->description, "Literal");
        ASSERT_STREQ(basename_of(u->fragment_path), "foo@bar.service");

        manager_free(m);
        test_rm_rf(dirA);
        test_rm_rf(dirB);
        free(dirA);
        free(dirB);
}

static void test_non_instance_miss_does_not_try_template(void) {
        Manager *m;
        char *dir;
        Unit *u = NULL;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "foo@.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_unit(m, "nope.service", &u), 0);

        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_ERROR);
        ASSERT_TRUE(u->fragment_path == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_template_id_rejected(void) {
        Manager *m;
        char *dir;
        Unit *u = NULL;
        size_t n_before;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "foo@.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);
        n_before = m->n_units;

        ASSERT_EQ_INT(manager_load_unit(m, "foo@.service", &u), -EINVAL);
        ASSERT_TRUE(u == NULL);
        ASSERT_EQ_INT((long long) m->n_units, (long long) n_before); /* no junk node left behind */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_boot_scan_skips_templates(void) {
        Manager *m;
        char *dir;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "foo@.service", "[Service]\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "plain.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        ASSERT_TRUE(manager_get_unit(m, "foo@.service") == NULL);
        ASSERT_TRUE(manager_get_unit(m, "plain.service") != NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The end-to-end (g) confirmation: a .wants symlink named after an instance
 * nobody ever shipped a fragment for still resolves, purely by name, through
 * unit_load()'s template fallback -- nothing in unit-enable.c had to change
 * for this to work. %I in the template's ExecStart= is expanded to the real
 * instance by the time the unit is loaded, proving the fallback and
 * unit-parse.c's specifier expansion compose correctly end to end.
 */
static void test_wants_symlink_instantiates_template(void) {
        Manager *m;
        char *dir;
        Unit *target, *inst;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "default.target", "[Unit]\nDescription=Default\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "serial-getty@.service",
                                      "[Unit]\n"
                                      "Description=Getty\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/echo %I\n"
                                      "\n"
                                      "[Install]\n"
                                      "WantedBy=default.target\n"),
                      0);
        ASSERT_EQ_INT(test_mkdir(dir, "default.target.wants"), 0);
        {
                char wantsdir[PATH_MAX];

                snprintf(wantsdir, sizeof(wantsdir), "%s/default.target.wants", dir);
                ASSERT_EQ_INT(test_symlink(wantsdir, "serial-getty@ttyGS0.service", "../serial-getty@.service"),
                              0);
        }

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        target = manager_get_unit(m, "default.target");
        ASSERT_TRUE(target != NULL);
        ASSERT_EQ_INT(unit_add_wants_requires_dirs(target), 0);

        inst = manager_get_unit(m, "serial-getty@ttyGS0.service");
        ASSERT_TRUE(inst != NULL);
        ASSERT_EQ_INT(inst->load_state, UNIT_LOADED);
        ASSERT_STREQ(inst->instance, "ttyGS0");
        ASSERT_TRUE(inst->enabled);
        ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, inst));

        s = (Service *) inst;
        ASSERT_STREQ(s->exec_start[0], "/bin/echo");
        ASSERT_STREQ(s->exec_start[1], "ttyGS0");
        ASSERT_TRUE(s->exec_start[2] == NULL);

        /* the template itself never enters the table -- only its instance does */
        ASSERT_TRUE(manager_get_unit(m, "serial-getty@.service") == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_presets_never_see_a_template(void) {
        Manager *m;
        char *dir, *presetdir;
        int n;

        dir = test_tmpdir_new();
        presetdir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL && presetdir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "foo@.service", "[Service]\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "plain.service",
                                      "[Unit]\nDescription=Plain\n\n[Service]\nExecStart=/bin/true\n\n"
                                      "[Install]\nWantedBy=default.target\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(presetdir, "10-x.preset", "disable *\n"), 0);

        m = manager_for(dir);
        {
                const char * const preset_path[] = { presetdir, NULL };

                ASSERT_EQ_INT(manager_set_preset_path(m, preset_path), 0);
        }
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        n = manager_apply_presets(m);
        ASSERT_TRUE(n >= 0); /* no error walking the table */

        ASSERT_TRUE(manager_get_unit(m, "foo@.service") == NULL);

        manager_free(m);
        test_rm_rf(dir);
        test_rm_rf(presetdir);
        free(dir);
        free(presetdir);
}

/*
 * oe-core's set_systemd_default_target leaves exactly this on every image:
 * /etc/systemd/system/default.target -> /usr/lib/systemd/system/multi-user.target,
 * shadowing the packaged default.target. Before alias support pico parsed
 * multi-user.target's body under the id "default.target", never loaded
 * multi-user.target itself, and so never scanned multi-user.target.wants/ --
 * every WantedBy=multi-user.target unit silently never started.
 */
static void test_symlink_alias_is_one_unit(void) {
        Manager *m;
        char *etc, *lib;
        Unit *def, *multi, *wanted_a, *wanted_b;
        char path[PATH_MAX];

        etc = test_tmpdir_new();
        lib = test_tmpdir_new();
        ASSERT_TRUE(etc != NULL && lib != NULL);

        ASSERT_EQ_INT(test_write_file(lib, "default.target", "[Unit]\nDescription=Packaged default\n"), 0);
        ASSERT_EQ_INT(test_write_file(lib, "multi-user.target", "[Unit]\nDescription=Multi-User System\n"), 0);
        ASSERT_EQ_INT(test_write_file(lib, "a.service", "[Service]\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_write_file(lib, "b.service", "[Service]\nExecStart=/bin/true\n"), 0);

        snprintf(path, sizeof(path), "%s/multi-user.target", lib);
        ASSERT_EQ_INT(test_symlink(etc, "default.target", path), 0);

        /* one enablement under each name */
        ASSERT_EQ_INT(test_mkdir(etc, "multi-user.target.wants"), 0);
        snprintf(path, sizeof(path), "%s/multi-user.target.wants", etc);
        ASSERT_EQ_INT(test_symlink(path, "a.service", "../a.service"), 0);
        ASSERT_EQ_INT(test_mkdir(lib, "default.target.wants"), 0);
        snprintf(path, sizeof(path), "%s/default.target.wants", lib);
        ASSERT_EQ_INT(test_symlink(path, "b.service", "../b.service"), 0);

        m = manager_for2(etc, lib);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        def = manager_get_unit(m, "default.target");
        multi = manager_get_unit(m, "multi-user.target");
        ASSERT_TRUE(def != NULL);
        ASSERT_TRUE(def == multi);
        ASSERT_STREQ(def->id, "multi-user.target");
        ASSERT_TRUE(unit_has_name(def, "default.target"));
        ASSERT_EQ_INT(def->load_state, UNIT_LOADED);
        ASSERT_STREQ(def->description, "Multi-User System");

        ASSERT_EQ_INT(unit_add_wants_requires_dirs(def), 0);
        wanted_a = manager_get_unit(m, "a.service");
        wanted_b = manager_get_unit(m, "b.service");
        ASSERT_TRUE(wanted_a != NULL && wanted_b != NULL);
        ASSERT_TRUE(unit_has_dependency(def, UNIT_WANTS, wanted_a));
        ASSERT_TRUE(unit_has_dependency(def, UNIT_WANTS, wanted_b));

        manager_free(m);
        test_rm_rf(etc);
        test_rm_rf(lib);
        free(etc);
        free(lib);
}

/* A mask (-> /dev/null), a same-name link and a cross-type link are not aliases. */
static void test_non_alias_symlinks(void) {
        char *etc, *lib;
        Manager *m;
        char *canon = NULL;
        char path[PATH_MAX];

        etc = test_tmpdir_new();
        lib = test_tmpdir_new();
        ASSERT_TRUE(etc != NULL && lib != NULL);

        ASSERT_EQ_INT(test_write_file(lib, "same.service", "[Service]\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_write_file(lib, "other.target", "[Unit]\n"), 0);
        snprintf(path, sizeof(path), "%s/same.service", lib);
        ASSERT_EQ_INT(test_symlink(etc, "same.service", path), 0);
        ASSERT_EQ_INT(test_symlink(etc, "masked.service", "/dev/null"), 0);
        snprintf(path, sizeof(path), "%s/other.target", lib);
        ASSERT_EQ_INT(test_symlink(etc, "cross.service", path), 0);

        m = manager_for2(etc, lib);
        ASSERT_EQ_INT(unit_resolve_alias(m, "same.service", &canon), 0);
        ASSERT_TRUE(canon == NULL);
        ASSERT_EQ_INT(unit_resolve_alias(m, "masked.service", &canon), 0);
        ASSERT_EQ_INT(unit_resolve_alias(m, "cross.service", &canon), 0);
        ASSERT_EQ_INT(unit_resolve_alias(m, "absent.service", &canon), 0);

        manager_free(m);
        test_rm_rf(etc);
        test_rm_rf(lib);
        free(etc);
        free(lib);
}

/*
 * units-mask-inverted: /etc/foo.service -> /dev/null must shadow
 * /usr/lib/foo.service, not skip past it to load the lower-priority copy
 * (v30 load-fragment.c:2217-2218, null_or_empty()).
 */
static void test_mask_shadows_lower_priority_fragment(void) {
        char *etc, *lib;
        Manager *m;
        Unit *u = NULL;

        etc = test_tmpdir_new();
        lib = test_tmpdir_new();
        ASSERT_TRUE(etc != NULL && lib != NULL);

        ASSERT_EQ_INT(test_write_file(lib, "foo.service", "[Service]\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_symlink(etc, "foo.service", "/dev/null"), 0);

        m = manager_for2(etc, lib);
        ASSERT_EQ_INT(manager_load_unit(m, "foo.service", &u), 0);

        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_MASKED);
        ASSERT_TRUE(u->fragment_path == NULL);

        manager_free(m);
        test_rm_rf(etc);
        test_rm_rf(lib);
        free(etc);
        free(lib);
}

/* The same rule for an instance: a masked literal must not fall back to the
 * template, the same way a real literal beats the template (G3(b)). */
static void test_masked_instance_does_not_fall_back_to_template(void) {
        char *dir;
        Manager *m;
        Unit *u = NULL;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "serial-getty@.service", "[Service]\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_symlink(dir, "serial-getty@ttyS0.service", "/dev/null"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_unit(m, "serial-getty@ttyS0.service", &u), 0);

        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_MASKED);
        ASSERT_TRUE(u->fragment_path == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A zero-length regular file masks exactly like a symlink to /dev/null. */
static void test_empty_file_masks(void) {
        char *dir;
        Manager *m;
        Unit *u = NULL;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "empty.service", ""), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_unit(m, "empty.service", &u), 0);

        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_MASKED);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Multi-hop alias chains and the two ways they can loop, none of it covered
 * before this: test_non_alias_symlinks() and test_symlink_alias_is_one_unit()
 * only ever exercise one hop.
 */

/* a -> b -> c (a real fragment): resolves straight through to c. */
static void test_alias_chain_resolves_to_final_canonical(void) {
        char *dir;
        Manager *m;
        char *canon = NULL;
        char path[PATH_MAX];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "c.service", "[Service]\nExecStart=/bin/true\n"), 0);
        snprintf(path, sizeof(path), "%s/c.service", dir);
        ASSERT_EQ_INT(test_symlink(dir, "b.service", path), 0);
        snprintf(path, sizeof(path), "%s/b.service", dir);
        ASSERT_EQ_INT(test_symlink(dir, "a.service", path), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(unit_resolve_alias(m, "a.service", &canon), 1);
        ASSERT_STREQ(canon, "c.service");
        free(canon);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* p -> q -> p: the cycle closes back on the name unit_resolve_alias() itself
 * started from, caught by its own "cycle back to the start" check well
 * before the hop bound. */
static void test_alias_cycle_back_to_start_is_not_an_alias(void) {
        char *dir;
        Manager *m;
        char *canon = NULL;
        char path[PATH_MAX];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        snprintf(path, sizeof(path), "%s/q.service", dir);
        ASSERT_EQ_INT(test_symlink(dir, "p.service", path), 0);
        snprintf(path, sizeof(path), "%s/p.service", dir);
        ASSERT_EQ_INT(test_symlink(dir, "q.service", path), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(unit_resolve_alias(m, "p.service", &canon), 0);
        ASSERT_TRUE(canon == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A chain of nine hops (a0 -> a1 -> ... -> a8, a8 a real fragment) exceeds
 * ALIAS_MAX_HOPS (8, unit-load.c) without ever revisiting a0 -- the bounded-
 * hop safety net, not the cycle-back-to-start shortcut, is what has to catch
 * this or unit_resolve_alias() would walk it forever on a sufficiently long
 * (or maliciously crafted) symlink chain.
 */
static void test_alias_chain_longer_than_max_hops_is_not_an_alias(void) {
        char *dir;
        Manager *m;
        char *canon = NULL;
        char name[32], target[32], path[PATH_MAX];
        int i;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "a8.service", "[Service]\nExecStart=/bin/true\n"), 0);
        for (i = 7; i >= 0; i--) {
                snprintf(name, sizeof(name), "a%d.service", i);
                snprintf(target, sizeof(target), "a%d.service", i + 1);
                snprintf(path, sizeof(path), "%s/%s", dir, target);
                ASSERT_EQ_INT(test_symlink(dir, name, path), 0);
        }

        m = manager_for(dir);
        ASSERT_EQ_INT(unit_resolve_alias(m, "a0.service", &canon), 0);
        ASSERT_TRUE(canon == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A dangling alias -- ghost.service names nothing real anywhere in the
 * search path -- still resolves by name (aliasing is purely syntactic;
 * whether the canonical has a fragment is unit_load()'s separate concern).
 * manager_load_unit() must hand back a real, correctly-named UNIT_ERROR
 * unit rather than failing the call outright.
 */
static void test_alias_to_nonexistent_canonical_loads_as_error(void) {
        char *dir;
        Manager *m;
        Unit *u = NULL;
        char path[PATH_MAX];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        snprintf(path, sizeof(path), "%s/ghost.service", dir);
        ASSERT_EQ_INT(test_symlink(dir, "alias.service", path), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_unit(m, "alias.service", &u), 0);

        ASSERT_TRUE(u != NULL);
        ASSERT_STREQ(u->id, "ghost.service");
        ASSERT_TRUE(unit_has_name(u, "alias.service"));
        ASSERT_EQ_INT(u->load_state, UNIT_ERROR);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_symlink_alias_is_one_unit();
        test_non_alias_symlinks();
        test_literal_instance_loads();
        test_template_fallback();
        test_literal_beats_template_same_dir();
        test_literal_beats_template_across_dirs();
        test_non_instance_miss_does_not_try_template();
        test_template_id_rejected();
        test_boot_scan_skips_templates();
        test_wants_symlink_instantiates_template();
        test_presets_never_see_a_template();
        test_mask_shadows_lower_priority_fragment();
        test_masked_instance_does_not_fall_back_to_template();
        test_empty_file_masks();
        test_alias_chain_resolves_to_final_canonical();
        test_alias_cycle_back_to_start_is_not_an_alias();
        test_alias_chain_longer_than_max_hops_is_not_an_alias();
        test_alias_to_nonexistent_canonical_loads_as_error();

        printf("test-unit-load: all checks passed\n");
        return 0;
}
