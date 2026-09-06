/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Real epoll/timerfd/signalfd/pidfd/inotify throughout -- no mocked kernel
 * objects. The one thing this cannot exercise from an ordinary test process
 * is sd_event_new()'s getpid()==1 guard, since driving that honestly needs a
 * real PID-1 process (a pid namespace, which this build environment cannot
 * assume); that path is exercised implicitly every time pico-init itself
 * boots and never calls into this shim.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-event.h"

/* Same relative-path convention src/devd/test-devd-block.c uses for the
 * same shared scaffolding: quote-includes resolve against the including
 * file's own directory first, and this family's includes are the family's
 * own subdir, not the project root. */
#include "../../test-util.h"

static int defer_exit_cb(sd_event_source *s, void *userdata) {
        return sd_event_exit(sd_event_source_get_event(s), (int) (intptr_t) userdata);
}

static int noop_cb(sd_event_source *s, void *userdata) {
        (void) s;
        (void) userdata;
        return 0;
}

static void test_new_ref_unref(void) {
        sd_event *e = NULL;

        ASSERT_EQ_INT(sd_event_new(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_event_new(&e), 0);
        ASSERT_TRUE(e != NULL);
        ASSERT_EQ_INT(sd_event_get_state(e), SD_EVENT_INITIAL);

        sd_event_ref(e);
        ASSERT_TRUE(sd_event_unref(e) == NULL);
        ASSERT_TRUE(sd_event_unref(e) == NULL);
}

static void test_default_query_then_create(void) {
        /* ret == NULL is a pure query: never creates, and reports whether
         * one already exists (0 or 1), not a fixed value -- this is the
         * one place this test suite deliberately follows the verified real
         * behaviour over a looser paraphrase in the family's own design
         * brief; see sd-event.c's sd_event_default(). */
        ASSERT_EQ_INT(sd_event_default(NULL), 0);

        sd_event *e1 = NULL, *e2 = NULL;
        ASSERT_EQ_INT(sd_event_default(&e1), 1);  /* newly created */
        ASSERT_EQ_INT(sd_event_default(NULL), 1); /* now exists */
        ASSERT_EQ_INT(sd_event_default(&e2), 0);  /* reused, not new */
        ASSERT_TRUE(e1 == e2);

        sd_event_unref(e1);
        sd_event_unref(e2);
}

static void test_exit_on_idle(void) {
        sd_event *e = NULL;
        int r;

        ASSERT_EQ_INT(sd_event_new(&e), 0);
        ASSERT_EQ_INT(sd_event_set_exit_on_idle(e, 1), 0);
        ASSERT_EQ_INT(sd_event_get_exit_on_idle(e), 1);

        /* No sources at all: prepare() sees idle immediately and exits. */
        r = sd_event_loop(e);
        ASSERT_EQ_INT(r, 0);
        ASSERT_EQ_INT(sd_event_get_state(e), SD_EVENT_FINISHED);

        sd_event_unref(e);
}

static void test_defer_runs_and_exits(void) {
        sd_event *e = NULL;
        sd_event_source *s = NULL;
        int r;

        ASSERT_EQ_INT(sd_event_new(&e), 0);
        ASSERT_EQ_INT(sd_event_add_defer(e, &s, defer_exit_cb, (void *) (intptr_t) 42), 0);

        r = sd_event_loop(e);
        ASSERT_EQ_INT(r, 42);

        int code = -1;
        ASSERT_EQ_INT(sd_event_get_exit_code(e, &code), 0);
        ASSERT_EQ_INT(code, 42);

        sd_event_source_unref(s);
        sd_event_unref(e);
}

static int io_read_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        char c;

        ASSERT_TRUE(revents & EPOLLIN);
        ASSERT_EQ_INT(read(fd, &c, 1), 1);
        ASSERT_EQ_INT(c, 'x');

        return sd_event_exit(sd_event_source_get_event(s), (int) (intptr_t) userdata);
}

static void test_io_pipe(void) {
        sd_event *e = NULL;
        sd_event_source *s = NULL;
        int fds[2];
        uint32_t got;

        ASSERT_TRUE(pipe(fds) == 0);
        ASSERT_EQ_INT(sd_event_new(&e), 0);

        ASSERT_EQ_INT(sd_event_add_io(e, &s, fds[0], EPOLLIN, io_read_cb, (void *) (intptr_t) 7), 0);
        ASSERT_EQ_INT(sd_event_source_get_io_fd(s), fds[0]);
        ASSERT_EQ_INT(sd_event_source_set_io_fd_own(s, 1), 0);

        /* Not pending yet: nothing written, and no wait() has run. */
        ASSERT_EQ_INT(sd_event_source_get_io_revents(s, &got), -ENODATA);

        ASSERT_EQ_INT((int) write(fds[1], "x", 1), 1);

        /* get_io_revents() is only meaningful in the window between a
         * wait() that found the source ready and the dispatch() that
         * clears `pending` again -- verified against real upstream's own
         * source_dispatch(): it calls source_set_pending(s, false) BEFORE
         * invoking s->io.callback(), so even real sd-event returns
         * -ENODATA if a callback calls this on its own source. Exercise
         * the window where it actually returns something, via manual
         * prepare()/wait() steps instead of sd_event_loop().
         *
         * prepare() alone returns 0 here: nothing is pending yet (the byte
         * sitting in the pipe is not "pending" until an actual epoll_wait()
         * says so), which is exactly why sd_event_run() always follows a
         * 0 from prepare() with a real wait() call. */
        ASSERT_EQ_INT(sd_event_prepare(e), 0);
        ASSERT_EQ_INT(sd_event_wait(e, 0), 1);
        ASSERT_EQ_INT(sd_event_source_get_io_revents(s, &got), 0);
        ASSERT_TRUE(got & EPOLLIN);

        ASSERT_EQ_INT(sd_event_dispatch(e), 1); /* runs io_read_cb(), which calls sd_event_exit() */
        ASSERT_EQ_INT(sd_event_source_get_io_revents(s, &got), -ENODATA); /* cleared before the callback ran */

        int code = -1;
        ASSERT_EQ_INT(sd_event_get_exit_code(e, &code), 0);
        ASSERT_EQ_INT(code, 7);

        sd_event_source_unref(s); /* closes fds[0] via io_fd_own */
        close(fds[1]);
        sd_event_unref(e);
}

static int time_cb(sd_event_source *s, uint64_t usec, void *userdata) {
        (void) usec;
        return sd_event_exit(sd_event_source_get_event(s), (int) (intptr_t) userdata);
}

static void test_time_relative(void) {
        sd_event *e = NULL;
        sd_event_source *s = NULL;

        ASSERT_EQ_INT(sd_event_new(&e), 0);
        ASSERT_EQ_INT(sd_event_add_time_relative(
                                      e, &s, CLOCK_MONOTONIC, 5 * 1000 /* 5ms */, 0, time_cb, (void *) (intptr_t) 3),
                      0);

        clockid_t clk = -1;
        ASSERT_EQ_INT(sd_event_source_get_time_clock(s, &clk), 0);
        ASSERT_EQ_INT(clk, CLOCK_MONOTONIC);

        uint64_t acc = 0;
        ASSERT_EQ_INT(sd_event_source_get_time_accuracy(s, &acc), 0);
        ASSERT_EQ_INT(acc, 250000); /* default */

        ASSERT_EQ_INT(sd_event_loop(e), 3);

        sd_event_source_unref(s);
        sd_event_unref(e);
}

static int signal_cb(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        ASSERT_EQ_INT((int) si->ssi_signo, SIGUSR1);
        return sd_event_exit(sd_event_source_get_event(s), (int) (intptr_t) userdata);
}

static void test_signal(void) {
        sd_event *e = NULL;
        sd_event_source *s = NULL;
        sigset_t mask;

        sigemptyset(&mask);
        sigaddset(&mask, SIGUSR1);
        ASSERT_TRUE(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);

        ASSERT_EQ_INT(sd_event_new(&e), 0);

        /* Not already blocked -> -EBUSY, matching upstream. */
        sd_event_source *bad = NULL;
        ASSERT_EQ_INT(sd_event_add_signal(e, &bad, SIGUSR2, signal_cb, NULL), -EBUSY);

        ASSERT_EQ_INT(sd_event_add_signal(e, &s, SIGUSR1, signal_cb, (void *) (intptr_t) 9), 0);
        ASSERT_EQ_INT(sd_event_source_get_signal(s), SIGUSR1);

        /* Duplicate signal source on the same loop -> -EBUSY. */
        sd_event_source *dup = NULL;
        ASSERT_EQ_INT(sd_event_add_signal(e, &dup, SIGUSR1, signal_cb, NULL), -EBUSY);

        ASSERT_TRUE(raise(SIGUSR1) == 0);
        ASSERT_EQ_INT(sd_event_loop(e), 9);

        sd_event_source_unref(s);
        sd_event_unref(e);
        sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

static int post_count_cb(sd_event_source *s, void *userdata) {
        int *n = userdata;
        (void) s;
        (*n)++;
        return 0;
}

static int defer_once_cb(sd_event_source *s, void *userdata) {
        int *n = userdata;
        (*n)++;
        return sd_event_source_set_enabled(s, SD_EVENT_OFF);
}

static void test_post_fires_after_other_dispatch(void) {
        sd_event *e = NULL;
        sd_event_source *post = NULL, *defer = NULL;
        int post_n = 0, defer_n = 0;
        int pending;

        ASSERT_EQ_INT(sd_event_new(&e), 0);
        ASSERT_EQ_INT(sd_event_add_post(e, &post, post_count_cb, &post_n), 0);
        ASSERT_EQ_INT(sd_event_add_defer(e, &defer, defer_once_cb, &defer_n), 0);

        /* Before anything runs, POST is not pending. */
        ASSERT_EQ_INT(sd_event_source_get_pending(post), 0);

        /* One manual step: prepare() marks DEFER pending, wait(0) sees it,
         * dispatch() runs the DEFER source (which disables itself) and, as
         * a side effect of dispatching a non-POST source, marks POST
         * pending for the run after this one. */
        ASSERT_EQ_INT(sd_event_prepare(e), 1);
        ASSERT_EQ_INT(sd_event_dispatch(e), 1);
        ASSERT_EQ_INT(defer_n, 1);
        ASSERT_EQ_INT(sd_event_source_get_pending(post), 1);
        ASSERT_EQ_INT(post_n, 0); /* not dispatched yet */

        /* Next step dispatches the now-pending POST source. */
        ASSERT_EQ_INT(sd_event_prepare(e), 1);
        pending = sd_event_dispatch(e);
        ASSERT_EQ_INT(pending, 1);
        ASSERT_EQ_INT(post_n, 1);

        sd_event_source_unref(post);
        sd_event_source_unref(defer);
        sd_event_unref(e);
}

struct priority_log {
        int order[3];
        int n;
};

static int priority_log_cb(sd_event_source *s, void *userdata) {
        struct priority_log *log = userdata;
        int64_t prio = 0;

        sd_event_source_get_priority(s, &prio);
        log->order[log->n++] = (int) prio;
        return sd_event_source_set_enabled(s, SD_EVENT_OFF);
}

static void test_prepare_priority_order(void) {
        sd_event *e = NULL;
        sd_event_source *lo = NULL, *hi = NULL, *mid = NULL;
        struct priority_log log = { { 0 }, 0 };

        ASSERT_EQ_INT(sd_event_new(&e), 0);

        /* Deliberately added out of priority order, to prove the run is
         * sorted rather than list-order. The DEFER source's own dispatch
         * callback is a plain no-op here -- this test only ever drives
         * sd_event_prepare(), never sd_event_dispatch(), so only each
         * source's *prepare* callback (priority_log_cb, sharing the same
         * userdata slot as the dispatch callback) ever runs. */
        ASSERT_EQ_INT(sd_event_add_defer(e, &hi, noop_cb, &log), 0);
        ASSERT_EQ_INT(sd_event_source_set_priority(hi, 100), 0);
        ASSERT_EQ_INT(sd_event_source_set_prepare(hi, priority_log_cb), 0);

        ASSERT_EQ_INT(sd_event_add_defer(e, &lo, noop_cb, &log), 0);
        ASSERT_EQ_INT(sd_event_source_set_priority(lo, -100), 0);
        ASSERT_EQ_INT(sd_event_source_set_prepare(lo, priority_log_cb), 0);

        ASSERT_EQ_INT(sd_event_add_defer(e, &mid, noop_cb, &log), 0);
        ASSERT_EQ_INT(sd_event_source_set_priority(mid, 0), 0);
        ASSERT_EQ_INT(sd_event_source_set_prepare(mid, priority_log_cb), 0);

        /* Each prepare callback disables its own source (SD_EVENT_OFF), so
         * after this one prepare() none of them are left pending. */
        ASSERT_EQ_INT(sd_event_prepare(e), 0);
        ASSERT_EQ_INT(log.n, 3);
        ASSERT_EQ_INT(log.order[0], -100);
        ASSERT_EQ_INT(log.order[1], 0);
        ASSERT_EQ_INT(log.order[2], 100);

        sd_event_source_unref(hi);
        sd_event_source_unref(lo);
        sd_event_source_unref(mid);
        sd_event_unref(e);
}

static void destroy_flag_cb(void *userdata) {
        int *flag = userdata;
        *flag = 1;
}

/*
 * Exercises sd_event_source_set_floating(3)'s documented reference-count
 * direction swap: create non-floating (so this test can still reach it
 * through `s`), attach a destroy callback, float it, then drop this test's
 * own reference. A floating source is only ever freed by the event's own
 * teardown, so `destroyed` must stay 0 across the unref() below and only
 * flip once the event itself goes away.
 */
static void test_floating_source_destroy_callback_runs(void) {
        sd_event *e = NULL;
        sd_event_source *s = NULL;
        int destroyed = 0;

        ASSERT_EQ_INT(sd_event_new(&e), 0);
        ASSERT_EQ_INT(sd_event_add_defer(e, &s, noop_cb, NULL), 0);
        ASSERT_EQ_INT(sd_event_source_set_destroy_callback(s, destroy_flag_cb), 0);
        sd_event_source_set_userdata(s, &destroyed);

        ASSERT_EQ_INT(sd_event_source_get_floating(s), 0);
        ASSERT_EQ_INT(sd_event_source_set_floating(s, 1), 1);
        ASSERT_EQ_INT(sd_event_source_get_floating(s), 1);
        ASSERT_EQ_INT(sd_event_source_set_floating(s, 1), 0); /* no-change -> 0, not 1 */
        sd_event_source_unref(s); /* drop the caller's own ref; the phantom "event owns it" ref survives */

        ASSERT_EQ_INT(destroyed, 0); /* still alive: only the event's teardown frees a floating source */

        sd_event_unref(e);
        ASSERT_EQ_INT(destroyed, 1);
}

static int child_cb(sd_event_source *s, const siginfo_t *si, void *userdata) {
        pid_t *seen = userdata;
        *seen = si->si_pid;
        return sd_event_exit(sd_event_source_get_event(s), 0);
}

static void test_add_child(void) {
        sd_event *e = NULL;
        sd_event_source *s = NULL;
        pid_t child, seen = 0;

        child = fork();
        ASSERT_TRUE(child >= 0);
        if (child == 0)
                _exit(5);

        ASSERT_EQ_INT(sd_event_new(&e), 0);
        ASSERT_EQ_INT(sd_event_add_child(e, &s, child, WEXITED, child_cb, &seen), 0);

        pid_t got_pid = 0;
        ASSERT_EQ_INT(sd_event_source_get_child_pid(s, &got_pid), 0);
        ASSERT_EQ_INT(got_pid, child);

        ASSERT_EQ_INT(sd_event_loop(e), 0);
        ASSERT_EQ_INT(seen, child);

        /* Reaped without WNOWAIT: auto-disabled. */
        int enabled = -1;
        ASSERT_EQ_INT(sd_event_source_get_enabled(s, &enabled), 0);
        ASSERT_EQ_INT(enabled, SD_EVENT_OFF);

        sd_event_source_unref(s);
        sd_event_unref(e);
}

static void test_add_child_rejects_stopped_continued(void) {
        sd_event *e = NULL;
        sd_event_source *s = NULL;

        ASSERT_EQ_INT(sd_event_new(&e), 0);
        ASSERT_EQ_INT(sd_event_add_child(e, &s, getpid() + 1, WEXITED | WSTOPPED, child_cb, NULL),
                      -EOPNOTSUPP);
        sd_event_unref(e);
}

static int inotify_cb(sd_event_source *s, const struct inotify_event *ev, void *userdata) {
        char *seen_name = userdata;
        if (ev->len)
                strncpy(seen_name, ev->name, 63);
        return sd_event_exit(sd_event_source_get_event(s), 0);
}

static void test_inotify(void) {
        sd_event *e = NULL;
        sd_event_source *s = NULL;
        char *dir;
        char seen_name[64] = { 0 };

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(sd_event_new(&e), 0);
        ASSERT_EQ_INT(sd_event_add_inotify(e, &s, dir, IN_CREATE, inotify_cb, seen_name), 0);

        const char *path_ret = NULL;
        ASSERT_EQ_INT(sd_event_source_get_inotify_path(s, &path_ret), 0);
        ASSERT_STREQ(path_ret, dir);

        ASSERT_EQ_INT(test_write_file(dir, "hello", "x"), 0);

        ASSERT_EQ_INT(sd_event_loop(e), 0);
        ASSERT_STREQ(seen_name, "hello");

        sd_event_source_unref(s);
        sd_event_unref(e);
        test_rm_rf(dir);
        free(dir);
}

static void test_error_paths(void) {
        sd_event *e = NULL;
        sd_event_source *s = NULL;

        ASSERT_EQ_INT(sd_event_new(&e), 0);

        /* Wrong-type accessors: -EDOM. */
        ASSERT_EQ_INT(sd_event_add_defer(e, &s, noop_cb, NULL), 0);
        ASSERT_EQ_INT(sd_event_source_get_io_fd(s), -EDOM);
        ASSERT_EQ_INT(sd_event_source_get_signal(s), -EDOM);
        ASSERT_EQ_INT(sd_event_source_get_pending(s), 0); /* DEFER is ON -> pending only after prepare() */
        ASSERT_EQ_INT(sd_event_source_set_prepare(s, NULL), 0);

        /* set_enabled with a bogus mode. */
        ASSERT_EQ_INT(sd_event_source_set_enabled(s, 42), -EINVAL);

        /* add_io with a bad fd/mask. */
        sd_event_source *io = NULL;
        ASSERT_EQ_INT(sd_event_add_io(e, &io, -1, EPOLLIN, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_event_add_io(e, &io, 0, 0xFFFFFFFFu, NULL, NULL), -EINVAL);

        /* add_exit requires a real callback. */
        sd_event_source *ex = NULL;
        ASSERT_EQ_INT(sd_event_add_exit(e, &ex, NULL, NULL), -EINVAL);

        /* Pressure and ratelimit families always fail the same honest way. */
        ASSERT_EQ_INT(sd_event_add_memory_pressure(e, NULL, NULL, NULL), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_event_add_cpu_pressure(e, NULL, NULL, NULL), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_event_add_io_pressure(e, NULL, NULL, NULL), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_event_source_set_memory_pressure_type(s, "some"), -EDOM);
        ASSERT_EQ_INT(sd_event_source_set_ratelimit(s, 1000, 4), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_event_source_is_ratelimited(s), 0);
        ASSERT_EQ_INT(sd_event_source_leave_ratelimit(NULL), 0);
        ASSERT_EQ_INT(sd_event_source_get_ratelimit(s, NULL, NULL),
                      -ENOEXEC); /* DEFER is ratelimitable-shaped */

        /* trim_memory: real on glibc. */
        ASSERT_EQ_INT(sd_event_trim_memory(), 0);

        sd_event_source_unref(s);
        sd_event_unref(e);
}

int main(void) {
        test_new_ref_unref();
        test_default_query_then_create();
        test_exit_on_idle();
        test_defer_runs_and_exits();
        test_io_pipe();
        test_time_relative();
        test_signal();
        test_post_fires_after_other_dispatch();
        test_prepare_priority_order();
        test_floating_source_destroy_callback_runs();
        test_add_child();
        test_add_child_rejects_stopped_continued();
        test_inotify();
        test_error_paths();

        return 0;
}
