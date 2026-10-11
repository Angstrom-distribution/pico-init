/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Tests the timer queue, cgroups v2 and SIGCHLD reaping.
 *
 * The cgroup half needs a writable cgroup2 hierarchy. Where there is one it
 * runs for real -- create, populate, observe the empty event, kill, remove --
 * because a mocked directory tree would test the parsing and none of the
 * behaviour that actually matters. Where there is not, it exits 77, meson's
 * SKIP code, rather than failing.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cgroups-v2.h"
#include "test-util.h"
#include "timer.h"
#include "util.h"

/* --- timer --- */

static int fire_order[8];
static size_t n_fired;

static void record_cb(void *userdata, usec_t now) {
        (void) now;
        ASSERT_TRUE(n_fired < sizeof(fire_order) / sizeof(fire_order[0]));
        fire_order[n_fired++] = (int) (intptr_t) userdata;
}

/* Three timers added out of order must fire in deadline order. */
static void test_timer_ordering(void) {
        PicoTimer *t = NULL;
        usec_t base;

        n_fired = 0;

        ASSERT_EQ_INT(pico_timer_new(&t), 0);
        base = now_monotonic();

        /* added 3, 1, 2 -- must fire 1, 2, 3 */
        ASSERT_EQ_INT(pico_timer_add(t, base + 30 * USEC_PER_MSEC, record_cb, (void *) (intptr_t) 3, NULL), 0);
        ASSERT_EQ_INT(pico_timer_add(t, base + 10 * USEC_PER_MSEC, record_cb, (void *) (intptr_t) 1, NULL), 0);
        ASSERT_EQ_INT(pico_timer_add(t, base + 20 * USEC_PER_MSEC, record_cb, (void *) (intptr_t) 2, NULL), 0);

        /* wait past the last deadline, then dispatch once */
        usleep(80 * 1000);
        ASSERT_EQ_INT(pico_timer_dispatch(t), 3);

        ASSERT_EQ_INT(n_fired, 3);
        ASSERT_EQ_INT(fire_order[0], 1);
        ASSERT_EQ_INT(fire_order[1], 2);
        ASSERT_EQ_INT(fire_order[2], 3);

        pico_timer_free(t);
}

/*
 * Regression: a deadline of 0 must fire, not disarm the queue. timer_arm()
 * encodes an empty queue as an all-zero itimerspec, so an unclamped 0 would
 * silently mean "never".
 */
static void test_timer_zero_deadline(void) {
        PicoTimer *t = NULL;

        n_fired = 0;

        ASSERT_EQ_INT(pico_timer_new(&t), 0);
        ASSERT_EQ_INT(pico_timer_add(t, 0, record_cb, (void *) (intptr_t) 7, NULL), 0);

        usleep(10 * 1000);
        ASSERT_EQ_INT(pico_timer_dispatch(t), 1);
        ASSERT_EQ_INT(n_fired, 1);
        ASSERT_EQ_INT(fire_order[0], 7);

        pico_timer_free(t);
}

/* USEC_INFINITY means "never" and must not be queueable. */
static void test_timer_infinity_refused(void) {
        PicoTimer *t = NULL;

        ASSERT_EQ_INT(pico_timer_new(&t), 0);
        ASSERT_EQ_INT(pico_timer_add(t, USEC_INFINITY, record_cb, NULL, NULL), -EINVAL);
        pico_timer_free(t);
}

static PicoTimerEvent *owned_handle;

static void clearing_cb(void *userdata, usec_t now) {
        (void) now;
        (void) userdata;

        /*
         * The whole point of the contract: by the time a callback runs, the
         * owner's handle has already been cleared by the queue itself.
         */
        ASSERT_TRUE(owned_handle == NULL);
        n_fired++;
}

/* The handle self-clears on fire, and on cancel. */
static void test_timer_handle_self_clears(void) {
        PicoTimer *t = NULL;

        n_fired = 0;
        owned_handle = NULL;

        ASSERT_EQ_INT(pico_timer_new(&t), 0);

        ASSERT_EQ_INT(pico_timer_add(t, now_monotonic() + USEC_PER_MSEC, clearing_cb, NULL, &owned_handle), 0);
        ASSERT_TRUE(owned_handle != NULL);

        usleep(20 * 1000);
        ASSERT_EQ_INT(pico_timer_dispatch(t), 1);
        ASSERT_EQ_INT(n_fired, 1);
        ASSERT_TRUE(owned_handle == NULL); /* cleared by the fire */

        /* and cancelling clears it too */
        ASSERT_EQ_INT(pico_timer_add(t, now_monotonic() + 60 * USEC_PER_SEC, record_cb, NULL, &owned_handle),
                      0);
        ASSERT_TRUE(owned_handle != NULL);
        ASSERT_EQ_INT(pico_timer_cancel(t, owned_handle), 0);
        ASSERT_TRUE(owned_handle == NULL);

        pico_timer_free(t);
}

static PicoTimer *rearm_timer;
static int rearm_count;

static void rearm_cb(void *userdata, usec_t now) {
        (void) userdata;

        /* a callback may safely arm a new event from inside the dispatch loop */
        if (++rearm_count < 3)
                ASSERT_EQ_INT(pico_timer_add(rearm_timer, now + USEC_PER_MSEC, rearm_cb, NULL, NULL), 0);
}

static void test_timer_callback_may_rearm(void) {
        rearm_timer = NULL;
        rearm_count = 0;

        ASSERT_EQ_INT(pico_timer_new(&rearm_timer), 0);
        ASSERT_EQ_INT(pico_timer_add(rearm_timer, now_monotonic() + USEC_PER_MSEC, rearm_cb, NULL, NULL), 0);

        while (rearm_count < 3) {
                usleep(5 * 1000);
                ASSERT_TRUE(pico_timer_dispatch(rearm_timer) >= 0);
        }

        ASSERT_EQ_INT(rearm_count, 3);
        pico_timer_free(rearm_timer);
}

/* --- SIGCHLD reaping under load --- */

/*
 * Fork a batch of children that exit immediately, then reap them all with the
 * same peek-attribute-reap loop manager-loop.c uses. Every child must be
 * accounted for exactly once and none lost -- a signal-driven loop that reaps
 * fewer than it forked is the failure this guards.
 */
static void test_sigchld_under_load(void) {
#define N_CHILDREN 32
        pid_t pids[N_CHILDREN];
        bool seen[N_CHILDREN] = { false };
        int reaped = 0;
        int guard = 0;
        int i;

        for (i = 0; i < N_CHILDREN; i++) {
                pid_t p = fork();

                ASSERT_TRUE(p >= 0);
                if (p == 0)
                        _exit(i % 2); /* mix of clean and non-clean exits */
                pids[i] = p;
        }

        while (reaped < N_CHILDREN) {
                siginfo_t si;

                si.si_pid = 0;

                if (waitid(P_ALL, 0, &si, WEXITED | WNOHANG | WNOWAIT) < 0) {
                        if (errno == EINTR)
                                continue;
                        ASSERT_TRUE(errno == ECHILD);
                        break;
                }

                if (si.si_pid <= 0) {
                        /* nothing ready yet; bounded so a lost child fails the
                         * suite instead of hanging it */
                        ASSERT_TRUE(++guard < 10000);
                        usleep(1000);
                        continue;
                }

                for (i = 0; i < N_CHILDREN; i++)
                        if (pids[i] == si.si_pid) {
                                ASSERT_TRUE(!seen[i]); /* exactly once */
                                seen[i] = true;
                                break;
                        }

                ASSERT_TRUE(i < N_CHILDREN); /* attributed, not a stray */
                ASSERT_EQ_INT(si.si_code, CLD_EXITED);

                ASSERT_TRUE(waitid(P_PID, si.si_pid, &si, WEXITED) == 0);
                reaped++;
        }

        ASSERT_EQ_INT(reaped, N_CHILDREN);
        for (i = 0; i < N_CHILDREN; i++)
                ASSERT_TRUE(seen[i]);
#undef N_CHILDREN
}

/* --- cgroups v2 --- */

#define CGROUP_ROOT "/sys/fs/cgroup"

static bool cgroup_v2_available(void) {
        struct stat st;

        return stat(CGROUP_ROOT "/cgroup.controllers", &st) == 0;
}

static void cgroup_test_path(char *buf, size_t size) {
        snprintf(buf, size, CGROUP_ROOT "/pico-init-test-%lld", (long long) getpid());
}

/* Create, populate, observe populated/empty, kill, remove. */
static void test_cgroup_lifecycle(void) {
        struct pico_cgroup *cg = NULL;
        char path[PATH_MAX];
        int status;
        pid_t child;
        int r;
        int i;

        cgroup_test_path(path, sizeof(path));
        rmdir(path); /* leftover from an aborted run */

        r = cgroup_v2_new(path, &cg);
        if (r < 0) {
                fprintf(stderr, "cgroup create failed (%s), skipping cgroup tests\n", strerror(-r));
                exit(77); /* meson: SKIP */
        }

        /* a fresh cgroup is empty */
        ASSERT_EQ_INT(cgroup_v2_is_empty(cg), 1);

        child = fork();
        ASSERT_TRUE(child >= 0);
        if (child == 0) {
                /* long enough to be observed alive, short enough not to wedge
                 * the suite if the kill path is broken */
                sleep(30);
                _exit(0);
        }

        r = cgroup_v2_add_process(cg, child);
        if (r < 0) {
                kill(child, SIGKILL);
                waitpid(child, &status, 0);
                cgroup_v2_free(cg);
                fprintf(stderr, "cgroup.procs write failed (%s), skipping\n", strerror(-r));
                exit(77);
        }

        ASSERT_EQ_INT(cgroup_v2_is_empty(cg), 0); /* now populated */

        /* kill everything in it, atomically where the kernel allows */
        ASSERT_EQ_INT(cgroup_v2_kill(cg), 0);

        waitpid(child, &status, 0);

        /* emptiness is observable after the kill */
        for (i = 0; i < 1000 && cgroup_v2_is_empty(cg) == 0; i++)
                usleep(1000);
        ASSERT_EQ_INT(cgroup_v2_is_empty(cg), 1);

        cgroup_v2_free(cg);
}

/*
 * The SIGKILL fallback is what pre-5.14 kernels get, and it is the path most
 * likely to rot precisely because no modern kernel exercises it. Force it by
 * closing cgroup.kill, so it runs here on every CI machine.
 */
static void test_cgroup_kill_fallback(void) {
        struct pico_cgroup *cg = NULL;
        char path[PATH_MAX];
        int status;
        pid_t child;
        int i;

        cgroup_test_path(path, sizeof(path));
        rmdir(path);

        if (cgroup_v2_new(path, &cg) < 0)
                exit(77);

        /* pretend the kernel has no cgroup.kill */
        if (cg->kill_fd >= 0) {
                close(cg->kill_fd);
                cg->kill_fd = -1;
        }
        ASSERT_TRUE(!cgroup_v2_kill_is_atomic(cg));

        child = fork();
        ASSERT_TRUE(child >= 0);
        if (child == 0) {
                sleep(30);
                _exit(0);
        }

        if (cgroup_v2_add_process(cg, child) < 0) {
                kill(child, SIGKILL);
                waitpid(child, &status, 0);
                cgroup_v2_free(cg);
                exit(77);
        }

        ASSERT_EQ_INT(cgroup_v2_is_empty(cg), 0);

        /* the fallback must actually kill, not merely return success */
        ASSERT_EQ_INT(cgroup_v2_kill(cg), 0);

        waitpid(child, &status, 0);
        ASSERT_TRUE(WIFSIGNALED(status));
        ASSERT_EQ_INT(WTERMSIG(status), SIGKILL);

        for (i = 0; i < 1000 && cgroup_v2_is_empty(cg) == 0; i++)
                usleep(1000);
        ASSERT_EQ_INT(cgroup_v2_is_empty(cg), 1);

        cgroup_v2_free(cg);
}

/* A removed cgroup reads as empty, not as an error. */
static void test_cgroup_gone_is_empty(void) {
        struct pico_cgroup *cg = NULL;
        char path[PATH_MAX];

        cgroup_test_path(path, sizeof(path));
        rmdir(path);

        if (cgroup_v2_new(path, &cg) < 0)
                exit(77);

        /* remove it behind the object's back, as a stop-timeout kill would */
        ASSERT_EQ_INT(rmdir(path), 0);

        ASSERT_EQ_INT(cgroup_v2_is_empty(cg), 1);

        cgroup_v2_free(cg);
}

int main(void) {
        test_timer_ordering();
        test_timer_zero_deadline();
        test_timer_infinity_refused();
        test_timer_handle_self_clears();
        test_timer_callback_may_rearm();
        test_sigchld_under_load();

        if (!cgroup_v2_available()) {
                fprintf(stderr, "no cgroup2 hierarchy at %s, skipping cgroup tests\n", CGROUP_ROOT);
                printf("test-timer-cgroup: timer and sigchld checks passed, cgroup skipped\n");
                return 77;
        }

        test_cgroup_lifecycle();
        test_cgroup_kill_fallback();
        test_cgroup_gone_is_empty();

        printf("test-timer-cgroup: all checks passed\n");
        return 0;
}
