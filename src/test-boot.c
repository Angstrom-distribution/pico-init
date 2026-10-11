/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * A real boot, end to end, against a minimal unit set.
 *
 * Fragment parsing, the load queue, .wants/ symlinks, preset application,
 * transaction ordering, fork/exec, SIGCHLD reaping through the signalfd and
 * cgroup supervision all have to work together, so the test drives the real
 * manager_loop() rather than calling the dispatch functions itself: that is
 * what proves the loop wires them together in the right order.
 *
 * The loop is stopped by a timer event that sets the objective, which also
 * exercises the timer queue, the epoll registration and objective handling.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "manager.h"
#include "service.h"
#include "target.h"
#include "test-util.h"
#include "timer.h"
#include "unit.h"

/* A boot-plumbing unit: runs once, stays "active" afterwards. */
static const char *sysinit_service =
                "[Unit]\n"
                "Description=Early setup\n"
                "\n"
                "[Service]\n"
                "Type=oneshot\n"
                "RemainAfterExit=yes\n"
                "ExecStart=/bin/true\n";

/* A long-running unit, ordered after the plumbing. PrivateTmp= is dropped
 * by the parser, so this is also the one degraded unit the boot summary counts. */
static const char *console_service =
                "[Unit]\n"
                "Description=Console\n"
                "After=sysinit.service\n"
                "\n"
                "[Service]\n"
                "Type=simple\n"
                "PrivateTmp=yes\n"
                "ExecStart=/bin/sleep 300\n"
                "\n"
                "[Install]\n"
                "WantedBy=default.target\n";

/* Has [Install] data, but the preset says no. Must never start. */
static const char *disabled_service =
                "[Unit]\n"
                "Description=Should not run\n"
                "\n"
                "[Service]\n"
                "Type=simple\n"
                "ExecStart=/bin/sleep 300\n"
                "\n"
                "[Install]\n"
                "WantedBy=default.target\n";

static const char *preset_file =
                "# the real angstrom-pico preset uses exactly this syntax\n"
                "disable disabled.service\n"
                "enable console.service\n";

static void stop_the_loop(void *userdata, usec_t now) {
        Manager *m = userdata;

        (void) now;
        m->objective = MANAGER_EXIT;
}

int main(void) {
        Unit *sysinit, *console, *disabled, *target;
        char cgroup_root[256];
        bool have_cgroup = false;
        char *unitdir, *presetdir;
        Manager *m = NULL;
        int objective;

        unitdir = test_tmpdir_new();
        ASSERT_TRUE(unitdir != NULL);
        presetdir = test_tmpdir_new();
        ASSERT_TRUE(presetdir != NULL);

        /* --- the minimal unit set --- */

        ASSERT_EQ_INT(test_write_file(unitdir, "default.target", "[Unit]\nDescription=Default\n"), 0);
        ASSERT_EQ_INT(test_write_file(unitdir, "sysinit.service", sysinit_service), 0);
        ASSERT_EQ_INT(test_write_file(unitdir, "console.service", console_service), 0);
        ASSERT_EQ_INT(test_write_file(unitdir, "disabled.service", disabled_service), 0);

        /*
         * sysinit is enabled the way `systemctl enable` does it -- a real
         * symlink in a .wants/ directory. console is enabled the other way,
         * by a preset rule acting on its [Install] section. Both paths have to
         * work, and they are genuinely different code.
         */
        ASSERT_EQ_INT(test_mkdir(unitdir, "default.target.wants"), 0);
        {
                char wants[512];

                snprintf(wants, sizeof(wants), "%s/default.target.wants", unitdir);
                ASSERT_EQ_INT(test_symlink(wants, "sysinit.service", "../sysinit.service"), 0);
        }

        ASSERT_EQ_INT(test_write_file(presetdir, "10-test.preset", preset_file), 0);

        /* --- boot --- */

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);

        {
                const char * const up[] = { unitdir, NULL };
                const char * const pd[] = { presetdir, NULL };

                ASSERT_EQ_INT(manager_set_unit_path(m, up), 0);
                ASSERT_EQ_INT(manager_set_preset_path(m, pd), 0);
        }

        /*
         * Use the real cgroup hierarchy where there is one, so this exercises
         * actual process supervision rather than a directory that merely looks
         * like cgroupfs. A scratch directory cannot stand in: cgroup_v2_new()
         * opens cgroup.procs, which only a real cgroupfs provides, and the
         * service would silently degrade to running unsupervised -- proving
         * the fallback works, but not supervision.
         *
         * Services live at <root>/system.slice/<unit> and cgroup_v2_new()
         * creates only the leaf, so the slice has to exist first.
         */
        snprintf(cgroup_root, sizeof(cgroup_root), "/sys/fs/cgroup/pico-boot-test-%lld", (long long) getpid());

        if (mkdir(cgroup_root, 0755) < 0) {
                fprintf(stderr, "no writable cgroup2 hierarchy (%s), skipping\n", strerror(errno));
                manager_free(m);
                test_rm_rf(unitdir);
                test_rm_rf(presetdir);
                free(unitdir);
                free(presetdir);
                return 77; /* meson: SKIP */
        }

        have_cgroup = true;
        ASSERT_EQ_INT(test_mkdir(cgroup_root, "system.slice"), 0);
        ASSERT_EQ_INT(manager_set_cgroup_root(m, cgroup_root), 0);

        /* a first boot: presets, not symlinks, enable these fixture units */
        manager_set_first_boot(m, true);
        ASSERT_EQ_INT(manager_startup(m, NULL), 0);

        /* --- enablement resolved before anything ran --- */

        target = manager_get_unit(m, "default.target");
        sysinit = manager_get_unit(m, "sysinit.service");
        console = manager_get_unit(m, "console.service");
        disabled = manager_get_unit(m, "disabled.service");

        ASSERT_TRUE(target != NULL);
        ASSERT_TRUE(sysinit != NULL);
        ASSERT_TRUE(console != NULL);
        ASSERT_TRUE(disabled != NULL);

        ASSERT_EQ_INT(target->type, UNIT_TARGET);

        /* enabled by the .wants/ symlink */
        ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, sysinit));

        /* enabled by the preset acting on [Install] WantedBy= */
        ASSERT_TRUE(unit_has_dependency(target, UNIT_WANTS, console));

        /* and the preset's "disable" really means it, despite [Install] data */
        ASSERT_TRUE(!unit_has_dependency(target, UNIT_WANTS, disabled));

        /* the ordering edge and its inverse both survived the round trip */
        ASSERT_TRUE(unit_has_dependency(console, UNIT_AFTER, sysinit));
        ASSERT_TRUE(unit_has_dependency(sysinit, UNIT_BEFORE, console));

        /* the graph is orderable */
        ASSERT_EQ_INT(unit_dependency_detect_cycles(m), 0);

        /* --- run the real loop until a timer stops it --- */

        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 3 * USEC_PER_SEC, stop_the_loop, m, NULL), 0);

        objective = manager_loop(m);
        ASSERT_EQ_INT(objective, MANAGER_EXIT);

        /* --- what booting was supposed to produce --- */

        /*
         * The oneshot ran and stayed active: RemainAfterExit=yes is what makes
         * "run once, then count as satisfied" expressible, and without it no
         * real boot-plumbing unit could hold a target up.
         */
        ASSERT_EQ_INT(SERVICE(sysinit)->state, SERVICE_EXITED);
        ASSERT_EQ_INT(SERVICE(sysinit)->result, SERVICE_SUCCESS);
        ASSERT_EQ_INT(unit_active_state(sysinit), UNIT_ACTIVE);

        /* the long-running one is up, and its process is real */
        ASSERT_EQ_INT(SERVICE(console)->state, SERVICE_RUNNING);
        ASSERT_EQ_INT(unit_active_state(console), UNIT_ACTIVE);
        ASSERT_TRUE(SERVICE(console)->main_pid > 0);

        /* the disabled one was never started */
        ASSERT_EQ_INT(SERVICE(disabled)->state, SERVICE_DEAD);
        ASSERT_EQ_INT(SERVICE(disabled)->main_pid, 0);

        /* and the boot target itself was reached */
        ASSERT_EQ_INT(unit_active_state(target), UNIT_ACTIVE);

        /* every job completed; nothing is still queued */
        ASSERT_TRUE(m->run_queue == NULL);
        ASSERT_TRUE(target->job == NULL);
        ASSERT_TRUE(sysinit->job == NULL);
        ASSERT_TRUE(console->job == NULL);

        /* the boot settled, so the one-line degradation summary went out,
         * counting console.service's dropped PrivateTmp= and nothing else */
        ASSERT_TRUE(m->degradation_summary_logged);
        ASSERT_EQ_INT(manager_count_degraded_units(m), 1);
        ASSERT_EQ_INT(console->n_degraded_directives, 1);
        ASSERT_STREQ(console->degraded_directives[0], "PrivateTmp");
        ASSERT_EQ_INT(sysinit->n_degraded_directives, 0);

        /* --- shut it down again --- */

        {
                pid_t console_pid = SERVICE(console)->main_pid;

                ASSERT_EQ_INT(manager_shutdown(m, MANAGER_POWEROFF), 0);
                ASSERT_EQ_INT(m->pending_objective, MANAGER_POWEROFF);

                /* the objective is NOT adopted until the stop jobs drain --
                 * that is the whole difference between an orderly shutdown and
                 * simply leaving the loop */
                ASSERT_EQ_INT(m->objective, MANAGER_EXIT);

                m->objective = MANAGER_RUNNING;
                objective = manager_loop(m);
                ASSERT_EQ_INT(objective, MANAGER_POWEROFF);

                ASSERT_EQ_INT(unit_active_state(console), UNIT_INACTIVE);
                ASSERT_EQ_INT(unit_active_state(target), UNIT_INACTIVE);

                /* the service's process is genuinely gone, not just forgotten */
                ASSERT_TRUE(kill(console_pid, 0) < 0);
        }

        manager_free(m);

        if (have_cgroup) {
                char slice[512];

                snprintf(slice, sizeof(slice), "%s/system.slice", cgroup_root);
                rmdir(slice);
                rmdir(cgroup_root);
        }

        test_rm_rf(unitdir);
        test_rm_rf(presetdir);
        free(unitdir);
        free(presetdir);

        printf("test-boot: booted a minimal unit set, supervised it, and shut it down again\n");
        return 0;
}
