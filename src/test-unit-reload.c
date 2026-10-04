/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * SIGHUP reload (unit-reload.c) against a real Manager and real files on
 * disk. The reload is driven through manager_dispatch_signal(m, SIGHUP) --
 * the function the signalfd callback calls -- rather than a real signal to
 * the test process, the same way test-manager-shutdown.c drives the other
 * signals.
 *
 * The "running" service is a child this test forks itself and hands to the
 * unit as its main pid. That keeps the test free of cgroups and root while
 * still proving the property that matters: reload rewrites configuration and
 * never touches the process that was started from the old one.
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "manager.h"
#include "service.h"
#include "test-util.h"
#include "unit.h"

static Manager *manager_for(const char *dir) {
        const char * const path[] = { dir, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT(manager_set_unit_path(m, path), 0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        return m;
}

static Unit *loaded_unit(Manager *m, const char *id) {
        Unit *u = manager_get_unit(m, id);

        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        return u;
}

static void remove_file(const char *dir, const char *name) {
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, name);

        ASSERT_TRUE(n > 0 && (size_t) n < sizeof(path));
        ASSERT_EQ_INT(unlink(path), 0);
}

static const char OLD_SERVICE[] =
                "[Unit]\n"
                "Description=Old description\n"
                "\n"
                "[Service]\n"
                "Type=simple\n"
                "ExecStart=/bin/true old\n"
                "Environment=OLD=1\n"
                "Restart=no\n"
                "RestartSec=1\n"
                "PrivateTmp=yes\n";

/* The unit as loaded from OLD_SERVICE, checked field by field so every
 * "left exactly as it was" case below means the same thing. */
static void assert_old_service(Unit *u) {
        Service *s = SERVICE(u);

        ASSERT_STREQ(u->description, "Old description");
        ASSERT_EQ_INT(s->type, SERVICE_TYPE_SIMPLE);
        ASSERT_TRUE(s->exec_start != NULL);
        ASSERT_STREQ(s->exec_start[0], "/bin/true");
        ASSERT_STREQ(s->exec_start[1], "old");
        ASSERT_TRUE(s->environment != NULL);
        ASSERT_STREQ(s->environment[0], "OLD=1");
        ASSERT_TRUE(s->environment[1] == NULL);
        ASSERT_EQ_INT(s->restart, SERVICE_RESTART_NO);
        ASSERT_EQ_INT(s->restart_usec, 1 * USEC_PER_SEC);
        ASSERT_EQ_INT(u->n_degraded_directives, 1);
        ASSERT_STREQ(u->degraded_directives[0], "PrivateTmp");
        ASSERT_TRUE(u->wanted_by == NULL);
}

/* A child that sits in pause() until killed: the stand-in for a daemon
 * started from the old configuration. */
static pid_t fork_sleeper(void) {
        pid_t pid = fork();

        ASSERT_TRUE(pid >= 0);
        if (pid == 0) {
                for (;;)
                        pause();
        }

        return pid;
}

static void reap_sleeper(pid_t pid) {
        int status;

        ASSERT_EQ_INT(kill(pid, SIGKILL), 0);
        ASSERT_EQ_INT(waitpid(pid, &status, 0), pid);
}

/*
 * The target case: a running service's file changes on disk, SIGHUP
 * arrives, and every directive now reads the new value -- on the same Unit
 * object, still RUNNING, with the same main pid, and that pid still alive
 * and never signalled.
 */
static void test_reload_updates_running_service(void) {
        Manager *m;
        Service *s;
        char *dir;
        Unit *u;
        pid_t pid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "a.service", OLD_SERVICE), 0);

        m = manager_for(dir);
        u = loaded_unit(m, "a.service");
        s = SERVICE(u);
        assert_old_service(u);

        pid = fork_sleeper();
        s->state = SERVICE_RUNNING;
        s->main_pid = pid;

        ASSERT_EQ_INT(test_write_file(dir,
                                      "a.service",
                                      "[Unit]\n"
                                      "Description=New description\n"
                                      "\n"
                                      "[Service]\n"
                                      "Type=oneshot\n"
                                      "ExecStart=/bin/false new\n"
                                      "Environment=NEW=2 OTHER=3\n"
                                      "Restart=on-failure\n"
                                      "RestartSec=7\n"
                                      "RemainAfterExit=yes\n"
                                      "\n"
                                      "[Install]\n"
                                      "WantedBy=multi-user.target\n"),
                      0);

        ASSERT_EQ_INT(manager_dispatch_signal(m, SIGHUP), 0);

        ASSERT_TRUE(manager_get_unit(m, "a.service") == u);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->description, "New description");
        ASSERT_EQ_INT(s->type, SERVICE_TYPE_ONESHOT);
        ASSERT_STREQ(s->exec_start[0], "/bin/false");
        ASSERT_STREQ(s->exec_start[1], "new");
        ASSERT_STREQ(s->environment[0], "NEW=2");
        ASSERT_STREQ(s->environment[1], "OTHER=3");
        ASSERT_TRUE(s->environment[2] == NULL);
        ASSERT_EQ_INT(s->restart, SERVICE_RESTART_ON_FAILURE);
        ASSERT_EQ_INT(s->restart_usec, 7 * USEC_PER_SEC);
        ASSERT_TRUE(s->remain_after_exit);
        ASSERT_TRUE(u->wanted_by != NULL);
        ASSERT_STREQ(u->wanted_by[0], "multi-user.target");

        /* PrivateTmp= is gone from the file, so from the record too */
        ASSERT_EQ_INT(u->n_degraded_directives, 0);

        /* runtime state untouched, and the process never signalled */
        ASSERT_EQ_INT(s->state, SERVICE_RUNNING);
        ASSERT_EQ_INT(s->main_pid, pid);
        ASSERT_TRUE(u->job == NULL);
        ASSERT_EQ_INT(kill(pid, 0), 0);
        ASSERT_EQ_INT(waitpid(pid, NULL, WNOHANG), 0);

        reap_sleeper(pid);
        s->main_pid = 0;
        s->state = SERVICE_DEAD;

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A file that no longer validates -- here, ExecStart= removed, which
 * service_verify() refuses -- changes nothing: not even the directives that
 * parsed fine before the failure was found.
 */
static void test_reload_invalid_file_keeps_old(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "a.service", OLD_SERVICE), 0);

        m = manager_for(dir);
        u = loaded_unit(m, "a.service");

        ASSERT_EQ_INT(test_write_file(dir,
                                      "a.service",
                                      "[Unit]\n"
                                      "Description=Half-written\n"
                                      "\n"
                                      "[Service]\n"
                                      "Environment=HALF=1\n"
                                      "Restart=on-failure\n"),
                      0);

        ASSERT_TRUE(unit_reload(u) < 0);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        assert_old_service(u);

        /* the SIGHUP path takes the same failure without erroring itself */
        ASSERT_EQ_INT(manager_dispatch_signal(m, SIGHUP), 0);
        assert_old_service(u);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A deleted or masked fragment is a load-state change, which reload does
 * not make: the unit keeps what it loaded. */
static void test_reload_missing_or_masked_file_keeps_old(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "a.service", OLD_SERVICE), 0);

        m = manager_for(dir);
        u = loaded_unit(m, "a.service");

        remove_file(dir, "a.service");
        ASSERT_EQ_INT(unit_reload(u), -ENOENT);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        assert_old_service(u);

        ASSERT_EQ_INT(test_write_file(dir, "a.service", ""), 0);
        ASSERT_TRUE(unit_reload(u) < 0);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        assert_old_service(u);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A control process still walking the old command list, or a job still in
 * flight, defers the reload rather than swapping values under it. */
static void test_reload_busy_service_is_skipped(void) {
        Manager *m;
        Service *s;
        char *dir;
        Unit *u;
        pid_t pid;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "a.service", OLD_SERVICE), 0);

        m = manager_for(dir);
        u = loaded_unit(m, "a.service");
        s = SERVICE(u);

        ASSERT_EQ_INT(test_write_file(dir, "a.service", "[Service]\nExecStart=/bin/false\n"), 0);

        pid = fork_sleeper();
        s->state = SERVICE_START_PRE;
        s->control_pid = pid;

        ASSERT_EQ_INT(unit_reload(u), -EBUSY);
        assert_old_service(u);
        ASSERT_EQ_INT(s->control_pid, pid);
        ASSERT_EQ_INT(waitpid(pid, NULL, WNOHANG), 0);

        reap_sleeper(pid);
        s->control_pid = 0;
        s->state = SERVICE_DEAD;

        /* once idle, the next reload picks the change up */
        ASSERT_EQ_INT(unit_reload(u), 1);
        ASSERT_STREQ(s->exec_start[0], "/bin/false");
        ASSERT_TRUE(u->description == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Dependency edges stay exactly as loaded, in both directions: the per-unit
 * reload parse has no manager to resolve a.service's new After=c.service
 * through, so that edge is never added, even though manager_reload()'s own
 * full-rescan steps (unit-reload.c) separately load c.service itself as a
 * new, otherwise-unrelated unit -- exactly as a real `systemctl daemon-
 * reload` makes a new unit file known without acting on it. Other
 * directives in the same file still update.
 */
static void test_reload_leaves_dependency_edges(void) {
        Manager *m;
        char *dir;
        Unit *a;
        Unit *b;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "a.service",
                                      "[Unit]\n"
                                      "Description=A\n"
                                      "After=b.service\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "b.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);
        a = loaded_unit(m, "a.service");
        b = loaded_unit(m, "b.service");
        ASSERT_TRUE(unit_has_dependency(a, UNIT_AFTER, b));
        ASSERT_TRUE(unit_has_dependency(b, UNIT_BEFORE, a));

        ASSERT_EQ_INT(test_write_file(dir,
                                      "a.service",
                                      "[Unit]\n"
                                      "Description=A2\n"
                                      "After=c.service\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "c.service", "[Service]\nExecStart=/bin/true\n"), 0);

        ASSERT_EQ_INT(manager_reload(m), 2);

        ASSERT_STREQ(a->description, "A2");
        ASSERT_EQ_INT(a->n_dependencies[UNIT_AFTER], 1);
        ASSERT_TRUE(unit_has_dependency(a, UNIT_AFTER, b));
        ASSERT_EQ_INT(b->n_dependencies[UNIT_BEFORE], 1);
        ASSERT_TRUE(unit_has_dependency(b, UNIT_BEFORE, a));

        /* c.service is now a known unit (the full-reload fragment rescan),
         * but a's own After=c.service edge was never added -- unrelated to
         * whether c.service itself got loaded. */
        {
                Unit *c = manager_get_unit(m, "c.service");

                ASSERT_TRUE(c != NULL);
                ASSERT_EQ_INT(c->load_state, UNIT_LOADED);
                ASSERT_TRUE(!unit_has_dependency(a, UNIT_AFTER, c));
        }

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* Not only services: a target's [Unit] values reload the same way, and its
 * active state is left where it was. */
static void test_reload_target(void) {
        Manager *m;
        char *dir;
        Unit *t;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "x.target", "[Unit]\nDescription=Old target\n"), 0);

        m = manager_for(dir);
        t = loaded_unit(m, "x.target");
        ASSERT_EQ_INT(unit_start(t), 0);
        ASSERT_EQ_INT(unit_active_state(t), UNIT_ACTIVE);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "x.target",
                                      "[Unit]\nDescription=New target\nConditionPathExists=/nonexistent\n"),
                      0);
        ASSERT_EQ_INT(unit_reload(t), 1);

        ASSERT_STREQ(t->description, "New target");
        ASSERT_TRUE(t->condition_path_exists != NULL);
        ASSERT_STREQ(t->condition_path_exists[0], "/nonexistent");
        ASSERT_EQ_INT(unit_active_state(t), UNIT_ACTIVE);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The daemon-reload requirement manager_reload() grew for the picoctl ctrl
 * verb (manager-ctrl.c): a unit file dropped into the search path after
 * "boot" becomes a known, loaded unit, and a .wants/ symlink added after
 * boot is picked up -- both without starting anything, matching real
 * `systemctl daemon-reload` exactly.
 */
static void test_reload_discovers_new_unit_and_wants_symlink(void) {
        Manager *m;
        char *dir;
        Unit *t;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "x.target", "[Unit]\nDescription=X\n"), 0);

        m = manager_for(dir);
        t = loaded_unit(m, "x.target");
        ASSERT_TRUE(manager_get_unit(m, "d.service") == NULL);

        /* A unit file that did not exist at "boot", plus a .wants/ symlink
         * naming it -- both added after the fact, the same as an operator
         * dropping a new unit into /etc/systemd/system before reloading. */
        ASSERT_EQ_INT(test_write_file(dir, "d.service", "[Service]\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_mkdir(dir, "x.target.wants"), 0);
        ASSERT_EQ_INT(test_symlink(dir, "x.target.wants/d.service", "../d.service"), 0);

        /* unit_reload() reports 1 for any successful re-parse, whether or
         * not the file's content actually changed (test_reload_target()'s
         * own assertion makes the same point) -- so this counts x.target's
         * own reload, not d.service, which is freshly LOADED afterwards,
         * never "reloaded". */
        ASSERT_EQ_INT(manager_reload(m), 1);

        {
                Unit *d = manager_get_unit(m, "d.service");

                ASSERT_TRUE(d != NULL);
                ASSERT_EQ_INT(d->load_state, UNIT_LOADED);
                ASSERT_TRUE(unit_has_dependency(t, UNIT_WANTS, d));
                ASSERT_TRUE(d->enabled);
        }

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_reload_updates_running_service();
        test_reload_invalid_file_keeps_old();
        test_reload_missing_or_masked_file_keeps_old();
        test_reload_busy_service_is_skipped();
        test_reload_leaves_dependency_edges();
        test_reload_target();
        test_reload_discovers_new_unit_and_wants_symlink();

        printf("test-unit-reload: all checks passed\n");
        return 0;
}
