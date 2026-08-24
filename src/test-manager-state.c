/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The state publisher (plan §1.7, C0): files matching every unit's reported state through a real fixture
 * boot, FAILED/Result=/NRestarts= fidelity, removal with the unit, no partial file ever observable
 * during transition churn, and an unwritable /run costing picoctl its verbs but never the boot.
 *
 * Real fork()/execve() throughout, driven through the actual manager_loop() and its real signalfd --
 * same discipline test-boot.c and test-service.c already established, because the property under test
 * (files matching reality) is only proven by reality actually happening.
 */

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "manager-state.h"
#include "manager.h"
#include "service.h"
#include "target.h"
#include "test-util.h"
#include "timer.h"
#include "unit.h"

/* --- shared helpers --- */

static void test_sleep_ms(int ms) {
        struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long) (ms % 1000) * 1000000L };

        nanosleep(&ts, NULL);
}

/* Read one Property from <runtime_dir>/units/<unit_id>, per manager-state.h's
 * documented layout -- tests re-derive the path the same way test-boot.c
 * re-derives cgroup paths, rather than this module exposing internals just
 * for tests to read back. 0 with *out set, -ENOENT if the file or the key is
 * missing, -EPROTO if a line has no trailing newline (a torn write). */
static int read_property(
                const char *runtime_dir, const char *unit_id, const char *key, char *out, size_t out_size) {
        char path[PATH_MAX];
        size_t klen = strlen(key);
        char line[1024];
        FILE *f;
        int n;

        n = snprintf(path, sizeof(path), "%s/units/%s", runtime_dir, unit_id);
        if (n < 0 || (size_t) n >= sizeof(path))
                return -ENAMETOOLONG;

        f = fopen(path, "re");
        if (!f)
                return -ENOENT;

        while (fgets(line, sizeof(line), f)) {
                char *nl = strchr(line, '\n');

                if (!nl) {
                        fclose(f);
                        return -EPROTO; /* every real line this writer produces ends in '\n' */
                }
                *nl = '\0';

                if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
                        snprintf(out, out_size, "%s", line + klen + 1);
                        fclose(f);
                        return 0;
                }
        }

        fclose(f);
        return -ENOENT;
}

static bool unit_file_exists(const char *runtime_dir, const char *unit_id) {
        char path[PATH_MAX];
        struct stat st;

        snprintf(path, sizeof(path), "%s/units/%s", runtime_dir, unit_id);
        return stat(path, &st) == 0;
}

static void stop_the_loop(void *userdata, usec_t now) {
        Manager *m = userdata;

        (void) now;
        m->objective = MANAGER_EXIT;
}

/* --- test 1: a real boot's files match every unit's reported state --- */

static const char *console_service =
                "[Unit]\n"
                "Description=Console\n"
                "\n"
                "[Service]\n"
                "Type=simple\n"
                "ExecStart=/bin/sleep 300\n"
                "\n"
                "[Install]\n"
                "WantedBy=default.target\n";

static const char *sysinit_service =
                "[Unit]\n"
                "Description=Early setup\n"
                "\n"
                "[Service]\n"
                "Type=oneshot\n"
                "RemainAfterExit=yes\n"
                "ExecStart=/bin/true\n"
                "\n"
                "[Install]\n"
                "WantedBy=default.target\n";

static void test_boot_files_match_reality(void) {
        char *unitdir, *rtdir;
        Manager *m = NULL;
        Unit *target, *sysinit, *console;
        char val[256];
        int objective;

        unitdir = test_tmpdir_new();
        rtdir = test_tmpdir_new();
        ASSERT_TRUE(unitdir != NULL && rtdir != NULL);

        ASSERT_EQ_INT(test_write_file(unitdir, "default.target", "[Unit]\nDescription=Default\n"), 0);
        ASSERT_EQ_INT(test_write_file(unitdir, "sysinit.service", sysinit_service), 0);
        ASSERT_EQ_INT(test_write_file(unitdir, "console.service", console_service), 0);

        ASSERT_EQ_INT(manager_new(&m), 0);
        {
                const char * const up[] = { unitdir, NULL };
                const char * const pd[] = { NULL };

                ASSERT_EQ_INT(manager_set_unit_path(m, up), 0);
                ASSERT_EQ_INT(manager_set_preset_path(m, pd), 0);
        }
        ASSERT_EQ_INT(manager_set_runtime_dir(m, rtdir), 0);

        ASSERT_EQ_INT(manager_startup(m, NULL), 0);

        /* manager_state_setup() ran inside manager_startup(): the manager
         * file must already exist, before a single unit has transitioned. */
        {
                char mgr[PATH_MAX];
                struct stat st;

                snprintf(mgr, sizeof(mgr), "%s/manager", rtdir);
                ASSERT_TRUE(stat(mgr, &st) == 0);
        }

        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 3 * USEC_PER_SEC, stop_the_loop, m, NULL), 0);
        objective = manager_loop(m);
        ASSERT_EQ_INT(objective, MANAGER_EXIT);

        target = manager_get_unit(m, "default.target");
        sysinit = manager_get_unit(m, "sysinit.service");
        console = manager_get_unit(m, "console.service");
        ASSERT_TRUE(target && sysinit && console);

        /* default.target: an active, no-process unit */
        ASSERT_EQ_INT(read_property(rtdir, "default.target", "ActiveState", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "active");
        ASSERT_EQ_INT(read_property(rtdir, "default.target", "SubState", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "active");
        ASSERT_EQ_INT(read_property(rtdir, "default.target", "LoadState", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "loaded");
        ASSERT_EQ_INT(read_property(rtdir, "default.target", "Description", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "Default");
        ASSERT_EQ_INT(read_property(rtdir, "default.target", "FragmentPath", val, sizeof(val)), 0);
        ASSERT_STREQ(val, target->fragment_path);

        /* sysinit.service: oneshot, RemainAfterExit=yes -> EXITED/active */
        ASSERT_EQ_INT(read_property(rtdir, "sysinit.service", "ActiveState", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "active");
        ASSERT_EQ_INT(read_property(rtdir, "sysinit.service", "SubState", val, sizeof(val)), 0);
        ASSERT_STREQ(val, service_state_to_string(SERVICE(sysinit)->state));
        ASSERT_STREQ(val, "exited");
        ASSERT_EQ_INT(read_property(rtdir, "sysinit.service", "Result", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "success");
        ASSERT_EQ_INT(read_property(rtdir, "sysinit.service", "ExecMainCode", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "exited"); /* CLD_EXITED, named, not "1" */
        ASSERT_EQ_INT(read_property(rtdir, "sysinit.service", "ExecMainStatus", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "0");
        ASSERT_EQ_INT(read_property(rtdir, "sysinit.service", "UnitFileState", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "enabled"); /* enabled by the .wants/ resolution manager_startup() did */

        /* console.service: still running, a real pid the file must name */
        ASSERT_EQ_INT(read_property(rtdir, "console.service", "ActiveState", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "active");
        ASSERT_EQ_INT(read_property(rtdir, "console.service", "SubState", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "running");
        ASSERT_EQ_INT(read_property(rtdir, "console.service", "MainPID", val, sizeof(val)), 0);
        {
                char expect[32];

                snprintf(expect, sizeof(expect), "%d", (int) SERVICE(console)->main_pid);
                ASSERT_STREQ(val, expect);
                ASSERT_TRUE(SERVICE(console)->main_pid > 0);
        }
        ASSERT_EQ_INT(read_property(rtdir, "console.service", "NRestarts", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "0");

        /* the manager file: unit count matches, updated by the boot */
        {
                char mgrval[64];
                int n;
                FILE *f;
                char mgrpath[PATH_MAX];

                n = snprintf(mgrpath, sizeof(mgrpath), "%s/manager", rtdir);
                ASSERT_TRUE(n > 0 && (size_t) n < sizeof(mgrpath));
                f = fopen(mgrpath, "re");
                ASSERT_TRUE(f != NULL);
                ASSERT_TRUE(fgets(mgrval, sizeof(mgrval), f) != NULL); /* Objective= */
                ASSERT_TRUE(fgets(mgrval, sizeof(mgrval), f) != NULL); /* DefaultTarget= */
                ASSERT_STREQ(mgrval, "DefaultTarget=default.target\n");
                ASSERT_TRUE(fgets(mgrval, sizeof(mgrval), f) != NULL); /* NUnits= */
                {
                        char expect[32];

                        snprintf(expect, sizeof(expect), "NUnits=%zu\n", m->n_units);
                        ASSERT_STREQ(mgrval, expect);
                }
                fclose(f);
        }

        manager_free(m);
        test_rm_rf(unitdir);
        test_rm_rf(rtdir);
        free(unitdir);
        free(rtdir);
}

/* --- test 2: a killed service publishes FAILED with matching Result=/ExecMainCode=/NRestarts= --- */

static void test_killed_service_shows_failure(void) {
        char *unitdir, *rtdir;
        Manager *m = NULL;
        Unit *victim;
        pid_t main_pid;
        char val[64];

        unitdir = test_tmpdir_new();
        rtdir = test_tmpdir_new();
        ASSERT_TRUE(unitdir != NULL && rtdir != NULL);

        /* Restart=no: one clean SIGKILL -> FAILED, no restart complexity to
         * race against the assertions below. */
        ASSERT_EQ_INT(test_write_file(unitdir,
                                      "victim.service",
                                      "[Unit]\nDescription=victim\n[Service]\nType=simple\nExecStart=/bin/sleep 100\n"),
                      0);

        ASSERT_EQ_INT(manager_new(&m), 0);
        {
                const char * const up[] = { unitdir, NULL };

                ASSERT_EQ_INT(manager_set_unit_path(m, up), 0);
        }
        ASSERT_EQ_INT(manager_set_runtime_dir(m, rtdir), 0);
        ASSERT_EQ_INT(manager_state_setup(m), 0);

        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);
        victim = manager_get_unit(m, "victim.service");
        ASSERT_TRUE(victim != NULL);

        ASSERT_EQ_INT(unit_start(victim), 0);
        ASSERT_EQ_INT(SERVICE(victim)->state, SERVICE_RUNNING);
        main_pid = SERVICE(victim)->main_pid;
        ASSERT_TRUE(main_pid > 0);

        ASSERT_EQ_INT(read_property(rtdir, "victim.service", "ActiveState", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "active");

        ASSERT_TRUE(kill(main_pid, SIGKILL) == 0);

        /* Drive the real signalfd/timerfd loop, exactly test-service.c's
         * reap_for(): SIGCHLD -> service_sigchld_event() -> unit_notify() ->
         * manager_state_notify_unit(). */
        {
                struct pollfd pfd = { .fd = pico_signal_fd(m->signal), .events = POLLIN };
                bool reaped = false;
                int tries;

                for (tries = 0; tries < 50 && !reaped; tries++) {
                        int r = poll(&pfd, 1, 100);

                        if (r <= 0)
                                continue;

                        for (;;) {
                                int signo;
                                int rr = pico_signal_read(m->signal, &signo);

                                if (rr == -EAGAIN)
                                        break;
                                ASSERT_TRUE(rr >= 0);
                                if (signo != SIGCHLD)
                                        continue;

                                for (;;) {
                                        siginfo_t info;

                                        memset(&info, 0, sizeof(info));
                                        if (waitid(P_ALL, 0, &info, WEXITED | WNOHANG) < 0 || info.si_pid == 0)
                                                break;
                                        if (info.si_pid != main_pid)
                                                continue;

                                        service_sigchld_event(
                                                        SERVICE(victim),
                                                        info.si_pid,
                                                        info.si_code,
                                                        info.si_status);
                                        reaped = true;
                                }
                        }
                }
                ASSERT_TRUE(reaped);
        }

        ASSERT_EQ_INT(SERVICE(victim)->state, SERVICE_FAILED);
        ASSERT_EQ_INT(SERVICE(victim)->result, SERVICE_FAILURE_SIGNAL);

        ASSERT_EQ_INT(read_property(rtdir, "victim.service", "ActiveState", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "failed");
        ASSERT_EQ_INT(read_property(rtdir, "victim.service", "SubState", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "failed");
        ASSERT_EQ_INT(read_property(rtdir, "victim.service", "Result", val, sizeof(val)), 0);
        ASSERT_STREQ(val, service_result_to_string(SERVICE(victim)->result));
        ASSERT_STREQ(val, "signal");
        ASSERT_EQ_INT(read_property(rtdir, "victim.service", "ExecMainCode", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "killed"); /* CLD_KILLED, named, not "2" */
        ASSERT_EQ_INT(read_property(rtdir, "victim.service", "ExecMainStatus", val, sizeof(val)), 0);
        ASSERT_STREQ(val, "9"); /* SIGKILL, not a packed wait status */
        ASSERT_EQ_INT(read_property(rtdir, "victim.service", "NRestarts", val, sizeof(val)), 0);
        {
                char expect[16];

                snprintf(expect, sizeof(expect), "%u", SERVICE(victim)->n_restarts);
                ASSERT_STREQ(val, expect);
                ASSERT_STREQ(val, "0"); /* Restart=no: never restarted */
        }

        manager_free(m);
        test_rm_rf(unitdir);
        test_rm_rf(rtdir);
        free(unitdir);
        free(rtdir);
}

/* --- test 3: a unit's file vanishes exactly when the unit is freed --- */

static void test_file_vanishes_with_unit(void) {
        Manager *m = NULL;
        char *rtdir;
        Unit *u;

        rtdir = test_tmpdir_new();
        ASSERT_TRUE(rtdir != NULL);

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_EQ_INT(manager_set_runtime_dir(m, rtdir), 0);
        ASSERT_EQ_INT(manager_state_setup(m), 0);

        /*
         * Deliberately NOT added to m->units[] via manager_add_unit(): this
         * isolates manager_state_forget_unit()'s own contract (a file must
         * not outlive its unit) from manager_free()'s bulk teardown order,
         * where manager_state_done() already removes every file before the
         * per-unit unit_free() loop even runs. Freeing this unit directly
         * is therefore both safe (manager_free() below never sees it) and
         * the only way to observe forget_unit() acting while m->state is
         * still alive.
         */
        ASSERT_EQ_INT(unit_new(m, UNIT_TARGET, "standalone.target", &u), 0);
        u->load_state = UNIT_LOADED;

        manager_state_notify_unit(u); /* force a publish without a real transition */
        ASSERT_TRUE(unit_file_exists(rtdir, "standalone.target"));

        unit_free(u);
        ASSERT_TRUE(!unit_file_exists(rtdir, "standalone.target"));

        manager_free(m);
        test_rm_rf(rtdir);
        free(rtdir);
}

/* --- test 4: an unwritable /run costs picoctl its verbs, never the boot --- */

static void test_unwritable_runtime_dir_never_fails_boot(void) {
        char *unitdir, *blockdir;
        char bogus_runtime[PATH_MAX];
        Manager *m = NULL;
        Unit *console;
        int objective;

        unitdir = test_tmpdir_new();
        blockdir = test_tmpdir_new();
        ASSERT_TRUE(unitdir != NULL && blockdir != NULL);

        /* A regular file standing where a directory is needed: mkdir() on it
         * fails EEXIST (ensure_dir() treats that as "already there", same as
         * a real already-mounted /run), but mkdir()ing the units/ subdir
         * underneath it then fails ENOTDIR -- the real, if unusual, way an
         * image could hand PID 1 an unwritable runtime dir. */
        ASSERT_EQ_INT(test_write_file(blockdir, "not-a-directory", ""), 0);
        snprintf(bogus_runtime, sizeof(bogus_runtime), "%s/not-a-directory", blockdir);

        ASSERT_EQ_INT(test_write_file(unitdir, "default.target", "[Unit]\nDescription=Default\n"), 0);
        ASSERT_EQ_INT(test_write_file(unitdir, "console.service", console_service), 0);

        ASSERT_EQ_INT(manager_new(&m), 0);
        {
                const char * const up[] = { unitdir, NULL };
                const char * const pd[] = { NULL };

                ASSERT_EQ_INT(manager_set_unit_path(m, up), 0);
                ASSERT_EQ_INT(manager_set_preset_path(m, pd), 0);
        }
        ASSERT_EQ_INT(manager_set_runtime_dir(m, bogus_runtime), 0);

        /* Direct check: setup itself must report the failure ... */
        ASSERT_TRUE(manager_state_setup(m) < 0);
        ASSERT_TRUE(m->state == NULL);

        /* ... and manager_startup(), which calls it internally and only
         * logs a warning, must still boot successfully despite that. */
        ASSERT_EQ_INT(manager_startup(m, NULL), 0);
        ASSERT_TRUE(m->state == NULL); /* still degraded, not silently recovered */

        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 2 * USEC_PER_SEC, stop_the_loop, m, NULL), 0);
        objective = manager_loop(m);
        ASSERT_EQ_INT(objective, MANAGER_EXIT);

        console = manager_get_unit(m, "console.service");
        ASSERT_TRUE(console != NULL);
        ASSERT_EQ_INT(unit_active_state(console), UNIT_ACTIVE); /* the boot proceeded regardless */
        ASSERT_TRUE(SERVICE(console)->main_pid > 0);

        /* No units/ directory was ever created under the bogus path. */
        {
                char units_path[PATH_MAX + 16];
                struct stat st;

                snprintf(units_path, sizeof(units_path), "%s/units", bogus_runtime);
                ASSERT_TRUE(stat(units_path, &st) < 0);
        }

        manager_free(m); /* must not crash despite every unit_free() calling
                             manager_state_forget_unit() against a NULL m->state */

        test_rm_rf(unitdir);
        test_rm_rf(blockdir);
        free(unitdir);
        free(blockdir);
}

/* --- test 5: a reader polling during transition churn never sees a partial file --- */

/*
 * Whole-file well-formedness: ends in '\n' (no torn trailing line -- the tmp
 * file is only ever rename()d in after fclose() succeeds, so a reader can
 * never observe a write in progress) and contains the one property every
 * publish writes first. Absence (ENOENT) is accepted too, per the contract,
 * though this test's fixture publishes before the churn starts and never
 * frees the unit, so it is never actually exercised here.
 */
static bool state_file_is_well_formed_or_absent(const char *path) {
        char buf[4096 + 1];
        size_t total = 0;
        FILE *f;

        f = fopen(path, "re");
        if (!f)
                return errno == ENOENT;

        while (total < sizeof(buf) - 1) {
                size_t got = fread(buf + total, 1, sizeof(buf) - 1 - total, f);

                if (got == 0)
                        break;
                total += got;
        }

        if (ferror(f)) {
                fclose(f);
                return false;
        }
        fclose(f);

        if (total == 0)
                return false;

        buf[total] = '\0';
        return buf[total - 1] == '\n' && strstr(buf, "ActiveState=") != NULL;
}

static void test_reader_never_sees_partial_file(void) {
        char *unitdir, *rtdir;
        char state_path[PATH_MAX];
        Manager *m = NULL;
        Unit *u;
        Service *s;
        pid_t reader;
        int status;
        unsigned iterations;

        unitdir = test_tmpdir_new();
        rtdir = test_tmpdir_new();
        ASSERT_TRUE(unitdir != NULL && rtdir != NULL);

        /* Fast, real crash/restart churn, bounded by B7's own start-limit
         * (5 attempts / 10s) -- real transitions, not a synthetic write
         * loop calling the publisher directly. */
        ASSERT_EQ_INT(test_write_file(unitdir,
                                      "churn.service",
                                      "[Unit]\n[Service]\nType=simple\n"
                                      "ExecStart=/bin/sh -c \"exit 1\"\n"
                                      "Restart=on-failure\nRestartSec=1ms\n"),
                      0);

        ASSERT_EQ_INT(manager_new(&m), 0);
        {
                const char * const up[] = { unitdir, NULL };

                ASSERT_EQ_INT(manager_set_unit_path(m, up), 0);
        }
        ASSERT_EQ_INT(manager_set_runtime_dir(m, rtdir), 0);
        ASSERT_EQ_INT(manager_state_setup(m), 0);

        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);
        u = manager_get_unit(m, "churn.service");
        ASSERT_TRUE(u != NULL);
        s = SERVICE(u);

        snprintf(state_path, sizeof(state_path), "%s/units/churn.service", rtdir);

        reader = fork();
        ASSERT_TRUE(reader >= 0);

        if (reader == 0) {
                /* Child: tight-loop reader, bounded by wall clock rather
                 * than by any signal from the parent -- this decouples the
                 * two processes completely, which is the point: the reader
                 * must survive being scheduled at any arbitrary instant
                 * relative to the writer, not a cooperative one. */
                struct timespec start, now;
                long elapsed_ms;

                clock_gettime(CLOCK_MONOTONIC, &start);
                for (;;) {
                        if (!state_file_is_well_formed_or_absent(state_path))
                                _exit(1);

                        clock_gettime(CLOCK_MONOTONIC, &now);
                        elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
                                        (now.tv_nsec - start.tv_nsec) / 1000000;
                        if (elapsed_ms > 1500)
                                _exit(0);
                }
        }

        /* Parent: pump the real state machine through as many crash/restart
         * cycles as B7's start limit allows, exactly test-service.c's
         * test_b7_start_limit_stops_the_loop() pattern. */
        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);

        for (iterations = 0; iterations < s->start_limit_burst * 4 && s->state != SERVICE_FAILED;
             iterations++) {
                if (s->main_pid > 0) {
                        struct pollfd pfd = { .fd = pico_signal_fd(m->signal), .events = POLLIN };

                        if (poll(&pfd, 1, 500) > 0) {
                                for (;;) {
                                        int signo;
                                        int rr = pico_signal_read(m->signal, &signo);

                                        if (rr == -EAGAIN)
                                                break;
                                        if (rr < 0 || signo != SIGCHLD)
                                                continue;

                                        for (;;) {
                                                siginfo_t info;

                                                memset(&info, 0, sizeof(info));
                                                if (waitid(P_ALL, 0, &info, WEXITED | WNOHANG) < 0 ||
                                                    info.si_pid == 0)
                                                        break;
                                                if (info.si_pid == s->main_pid)
                                                        service_sigchld_event(
                                                                        s,
                                                                        info.si_pid,
                                                                        info.si_code,
                                                                        info.si_status);
                                        }
                                }
                        }
                } else if (s->state == SERVICE_AUTO_RESTART) {
                        struct pollfd pfd = { .fd = pico_timer_fd(m->timer), .events = POLLIN };

                        if (poll(&pfd, 1, 500) > 0)
                                pico_timer_dispatch(m->timer);
                } else
                        break;
        }

        ASSERT_EQ_INT(s->state, SERVICE_FAILED);
        /* B7's start-limit rejection is itself the final failure, not the
         * last crash's exit code -- matches test-service.c's own
         * test_b7_start_limit_stops_the_loop(). */
        ASSERT_EQ_INT(s->result, SERVICE_FAILURE_START_LIMIT);

        /* Let the reader run out its own time budget before checking it, so
         * it samples well past the last write above too. */
        test_sleep_ms(200);

        ASSERT_TRUE(waitpid(reader, &status, 0) == reader);
        ASSERT_TRUE(WIFEXITED(status));
        ASSERT_EQ_INT(WEXITSTATUS(status), 0); /* never caught a torn or malformed read */

        manager_free(m);
        test_rm_rf(unitdir);
        test_rm_rf(rtdir);
        free(unitdir);
        free(rtdir);
}

int main(void) {
        test_boot_files_match_reality();
        test_killed_service_shows_failure();
        test_file_vanishes_with_unit();
        test_unwritable_runtime_dir_never_fails_boot();
        test_reader_never_sees_partial_file();

        printf("test-manager-state: all checks passed\n");
        return 0;
}
