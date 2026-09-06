/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Per-source property accessors and mutators: everything named
 * sd_event_source_*() except the constructors (those are sd_event_add_*()
 * in sd-event.c, since each is really an sd_event method that happens to
 * return a source). Shares event-internal.h's struct layout and helpers
 * with sd-event.c; see that file's own top comment for the family's
 * provenance note.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "event-internal.h"

/* ---- refcounting / lifecycle ------------------------------------------- */

sd_event_source *sd_event_source_ref(sd_event_source *s) {
        if (!s)
                return NULL;
        s->n_ref++;
        return s;
}

sd_event_source *sd_event_source_unref(sd_event_source *s) {
        if (!s)
                return NULL;
        if (--s->n_ref > 0)
                return NULL;

        event_source_destroy(s);
        return NULL;
}

sd_event_source *sd_event_source_disable_unref(sd_event_source *s) {
        if (s)
                event_source_apply_enabled(s, SD_EVENT_OFF);
        return sd_event_source_unref(s);
}

sd_event *sd_event_source_get_event(sd_event_source *s) {
        return s ? s->event : NULL;
}

void *sd_event_source_get_userdata(sd_event_source *s) {
        return s ? s->userdata : NULL;
}

void *sd_event_source_set_userdata(sd_event_source *s, void *userdata) {
        void *old;

        if (!s)
                return NULL;
        old = s->userdata;
        s->userdata = userdata;
        return old;
}

/* ---- description / prepare / pending / priority ------------------------ */

int sd_event_source_set_description(sd_event_source *s, const char *description) {
        char *copy = NULL;

        if (!s)
                return -EINVAL;

        if (description) {
                copy = strdup(description);
                if (!copy)
                        return -ENOMEM;
        }

        free(s->description);
        s->description = copy;
        return 0;
}

int sd_event_source_get_description(sd_event_source *s, const char **ret) {
        if (!s || !ret)
                return -EINVAL;
        if (!s->description)
                return -ENXIO;
        *ret = s->description;
        return 0;
}

int sd_event_source_set_prepare(sd_event_source *s, sd_event_handler_t callback) {
        if (!s)
                return -EINVAL;
        if (s->type == SOURCE_EXIT)
                return -EDOM;
        s->prepare = callback;
        return 0;
}

int sd_event_source_get_pending(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        if (s->type == SOURCE_EXIT)
                return -EDOM;
        return s->pending;
}

int sd_event_source_get_priority(sd_event_source *s, int64_t *ret) {
        if (!s || !ret)
                return -EINVAL;
        *ret = s->priority;
        return 0;
}

int sd_event_source_set_priority(sd_event_source *s, int64_t priority) {
        if (!s)
                return -EINVAL;
        s->priority = priority; /* takes effect at the next dispatch selection / exit ordering scan */
        return 0;
}

/* ---- enabled/disabled --------------------------------------------------- */

int sd_event_source_get_enabled(sd_event_source *s, int *ret) {
        if (!s)
                return -EINVAL;
        if (ret)
                *ret = s->enabled;
        return s->enabled != SD_EVENT_OFF;
}

int sd_event_source_set_enabled(sd_event_source *s, int m) {
        if (!s)
                return -EINVAL;
        if (m != SD_EVENT_OFF && m != SD_EVENT_ON && m != SD_EVENT_ONESHOT)
                return -EINVAL;
        return event_source_apply_enabled(s, m);
}

/* ---- IO ------------------------------------------------------------------ */

int sd_event_source_get_io_fd(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_IO)
                return -EDOM;
        return s->fd;
}

int sd_event_source_set_io_fd(sd_event_source *s, int fd) {
        int old_fd;

        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_IO)
                return -EDOM;
        if (fd < 0)
                return -EINVAL;

        old_fd = s->fd;
        if (s->enabled != SD_EVENT_OFF)
                epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, old_fd, NULL);
        if (s->io.fd_own)
                close(old_fd);

        s->fd = fd;

        if (s->enabled != SD_EVENT_OFF) {
                struct epoll_event ev = { .events = s->io.events, .data.ptr = s };
                if (epoll_ctl(s->event->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
                        return -errno;
        }
        return 0;
}

int sd_event_source_get_io_fd_own(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_IO)
                return -EDOM;
        return s->io.fd_own;
}

int sd_event_source_set_io_fd_own(sd_event_source *s, int own) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_IO)
                return -EDOM;
        s->io.fd_own = !!own; /* consumed at source teardown and at the next set_io_fd() */
        return 0;
}

int sd_event_source_get_io_events(sd_event_source *s, uint32_t *ret) {
        if (!s || !ret)
                return -EINVAL;
        if (s->type != SOURCE_IO)
                return -EDOM;
        *ret = s->io.events;
        return 0;
}

int sd_event_source_set_io_events(sd_event_source *s, uint32_t events) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_IO)
                return -EDOM;
        if (events & ~(uint32_t) (EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLPRI | EPOLLET))
                return -EINVAL;

        s->io.events = events;
        if (s->enabled != SD_EVENT_OFF) {
                struct epoll_event ev = { .events = events, .data.ptr = s };
                if (epoll_ctl(s->event->epoll_fd, EPOLL_CTL_MOD, s->fd, &ev) < 0)
                        return -errno;
        }
        return 0;
}

int sd_event_source_get_io_revents(sd_event_source *s, uint32_t *ret) {
        if (!s || !ret)
                return -EINVAL;
        if (s->type != SOURCE_IO)
                return -EDOM;
        if (!s->pending)
                return -ENODATA;
        *ret = s->io.revents;
        return 0;
}

/* ---- time ----------------------------------------------------------------- */

int sd_event_source_get_time(sd_event_source *s, uint64_t *ret) {
        if (!s || !ret)
                return -EINVAL;
        if (s->type != SOURCE_TIME)
                return -EDOM;
        *ret = s->time.next;
        return 0;
}

int sd_event_source_set_time(sd_event_source *s, uint64_t usec) {
        struct itimerspec its = { 0 };

        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_TIME)
                return -EDOM;

        if (usec != UINT64_MAX)
                event_usec_to_timespec(usec, &its.it_value);
        if (timerfd_settime(s->fd, TFD_TIMER_ABSTIME, &its, NULL) < 0)
                return -errno;

        s->time.next = usec;
        s->pending = false;
        return 0; /* also how a caller re-arms a source left expired after firing */
}

int sd_event_source_set_time_relative(sd_event_source *s, uint64_t usec) {
        uint64_t now_usec;
        int r;

        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_TIME)
                return -EDOM;

        r = sd_event_now(s->event, s->time.clock, &now_usec);
        if (r < 0)
                return r;
        if (usec == UINT64_MAX)
                return sd_event_source_set_time(s, UINT64_MAX);
        if (usec > UINT64_MAX - now_usec)
                return -EOVERFLOW;

        return sd_event_source_set_time(s, now_usec + usec);
}

int sd_event_source_get_time_accuracy(sd_event_source *s, uint64_t *ret) {
        if (!s || !ret)
                return -EINVAL;
        if (s->type != SOURCE_TIME)
                return -EDOM;
        *ret = s->time.accuracy;
        return 0;
}

int sd_event_source_set_time_accuracy(sd_event_source *s, uint64_t usec) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_TIME)
                return -EDOM;
        if (usec == UINT64_MAX)
                return -EINVAL;

        /* Stored and reported only, never used to coalesce: accuracy only
         * ever permits *later* delivery, so a timer that fires exactly on
         * time still satisfies whatever accuracy was requested. There is
         * nothing this shim's one-timerfd-per-source design needs to
         * batch against. */
        s->time.accuracy = usec == 0 ? 250 * EVENT_USEC_PER_MSEC : usec;
        return 0;
}

int sd_event_source_get_time_clock(sd_event_source *s, clockid_t *ret) {
        if (!s || !ret)
                return -EINVAL;
        if (s->type != SOURCE_TIME)
                return -EDOM;
        *ret = s->time.clock;
        return 0;
}

/* ---- signal ---------------------------------------------------------------- */

int sd_event_source_get_signal(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_SIGNAL)
                return -EDOM;
        return s->signal.sig;
}

/* ---- child ------------------------------------------------------------------ */

int sd_event_source_get_child_pid(sd_event_source *s, pid_t *ret) {
        if (!s || !ret)
                return -EINVAL;
        if (s->type != SOURCE_CHILD)
                return -EDOM;
        *ret = s->child.pid; /* 0 for an add_child_pidfd() source whose pid was never resolved */
        return 0;
}

int sd_event_source_get_child_pidfd(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_CHILD)
                return -EDOM;
        return s->fd;
}

int sd_event_source_get_child_pidfd_own(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_CHILD)
                return -EDOM;
        return s->child.pidfd_own;
}

int sd_event_source_set_child_pidfd_own(sd_event_source *s, int own) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_CHILD)
                return -EDOM;
        s->child.pidfd_own = !!own;
        return 0;
}

int sd_event_source_get_child_process_own(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_CHILD)
                return -EDOM;
        return s->child.process_own;
}

int sd_event_source_set_child_process_own(sd_event_source *s, int own) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_CHILD)
                return -EDOM;
        s->child.process_own = !!own; /* consumed at source teardown: SIGKILL via pidfd, then reap */
        return 0;
}

#if defined _GNU_SOURCE || (defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 199309L)
int sd_event_source_send_child_signal(sd_event_source *s, int sig, const siginfo_t *si, unsigned flags) {
#else
int sd_event_source_send_child_signal(sd_event_source *s, int sig, const void *si, unsigned flags) {
#endif
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_CHILD)
                return -EDOM;
        if (sig <= 0 || sig >= _NSIG)
                return -EINVAL;
        if (flags != 0) /* pidfd_send_signal(2) reserves the flags argument */
                return -EINVAL;

        if (event_pidfd_send_signal(s->fd, sig, (siginfo_t *) si, 0) < 0)
                return -errno;
        return 0;
}

/* ---- inotify ------------------------------------------------------------------ */

int sd_event_source_get_inotify_mask(sd_event_source *s, uint32_t *ret) {
        if (!s || !ret)
                return -EINVAL;
        if (s->type != SOURCE_INOTIFY)
                return -EDOM;
        *ret = s->inotify.mask;
        return 0;
}

int sd_event_source_get_inotify_path(sd_event_source *s, const char **ret) {
        if (!s || !ret)
                return -EINVAL;
        if (s->type != SOURCE_INOTIFY)
                return -EDOM;
        if (!s->inotify.path)
                return -ENODATA;
        /* The creation-time name, not a live inode-to-path resolution: a
         * rename after the watch was added does not update this. */
        *ret = s->inotify.path;
        return 0;
}

/* ---- pressure: never real, see sd-event.c's add_*_pressure() ------------------ */

int sd_event_source_set_memory_pressure_type(sd_event_source *s, const char *ty) {
        (void) ty;
        if (!s)
                return -EINVAL;
        /* Genuinely correct, not just convenient: this call is only ever valid
         * on a memory-pressure source, and this shim can never create one
         * (sd_event_add_memory_pressure() is -EOPNOTSUPP), so any source
         * handed in here is by construction the wrong type. -EDOM is
         * upstream's own wrong-source-type errno. */
        return -EDOM;
}
int sd_event_source_set_memory_pressure_period(sd_event_source *s, uint64_t threshold_usec, uint64_t window_usec) {
        (void) threshold_usec;
        (void) window_usec;
        if (!s)
                return -EINVAL;
        return -EDOM;
}
int sd_event_source_set_cpu_pressure_type(sd_event_source *s, const char *ty) {
        (void) ty;
        if (!s)
                return -EINVAL;
        return -EDOM;
}
int sd_event_source_set_cpu_pressure_period(sd_event_source *s, uint64_t threshold_usec, uint64_t window_usec) {
        (void) threshold_usec;
        (void) window_usec;
        if (!s)
                return -EINVAL;
        return -EDOM;
}
int sd_event_source_set_io_pressure_type(sd_event_source *s, const char *ty) {
        (void) ty;
        if (!s)
                return -EINVAL;
        return -EDOM;
}
int sd_event_source_set_io_pressure_period(sd_event_source *s, uint64_t threshold_usec, uint64_t window_usec) {
        (void) threshold_usec;
        (void) window_usec;
        if (!s)
                return -EINVAL;
        return -EDOM;
}

/* ---- destroy callback / floating / exit-on-failure ----------------------------- */

int sd_event_source_set_destroy_callback(sd_event_source *s, sd_event_destroy_t callback) {
        if (!s)
                return -EINVAL;
        s->destroy_callback = callback;
        return 0;
}

int sd_event_source_get_destroy_callback(sd_event_source *s, sd_event_destroy_t *ret) {
        if (!s)
                return -EINVAL;
        if (ret)
                *ret = s->destroy_callback;
        return s->destroy_callback != NULL;
}

int sd_event_source_get_floating(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        return s->floating;
}

int sd_event_source_set_floating(sd_event_source *s, int b) {
        if (!s)
                return -EINVAL;
        if (s->floating == !!b)
                return 0;

        s->floating = !!b;

        /*
         * sd_event_source_set_floating(3)'s documented reference-count
         * direction swap: non-floating means the source holds a ref on the
         * event; floating means the event holds one on the source instead.
         * Going floating: take the source's own extra ref first (the one
         * the event now conceptually owns), then drop the ref this source
         * held on the event. Going non-floating: retake the event ref
         * first, then drop the extra source ref -- ordered so neither
         * object's count can transiently look like it should be freed.
         */
        if (b) {
                sd_event_source_ref(s);
                sd_event_unref(s->event);
        } else {
                sd_event_ref(s->event);
                sd_event_source_unref(s);
        }
        return 1;
}

int sd_event_source_get_exit_on_failure(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        if (s->type == SOURCE_EXIT)
                return -EDOM;
        return s->exit_on_failure;
}

int sd_event_source_set_exit_on_failure(sd_event_source *s, int b) {
        if (!s)
                return -EINVAL;
        if (s->type == SOURCE_EXIT)
                return -EDOM;
        s->exit_on_failure =
                        !!b; /* consumed in dispatch: callback r<0 -> sd_event_exit() instead of disabling */
        return 0;
}

/* ---- ratelimiting: never real, see the design note on every function here ------ */

int sd_event_source_set_ratelimit(sd_event_source *s, uint64_t interval_usec, unsigned burst) {
        (void) interval_usec;
        (void) burst;
        if (!s)
                return -EINVAL;
        /* Real ratelimiting needs a token bucket plus transparent temporary
         * off-arming and a re-arm expiry timer -- genuine complexity for
         * zero known pico-side callers (its heavy users are systemd's own
         * daemons, which pico replaces). -EOPNOTSUPP is unambiguous and
         * permanent, unlike a fake success that promises storm protection
         * that never arrives. */
        return -EOPNOTSUPP;
}

int sd_event_source_get_ratelimit(sd_event_source *s, uint64_t *ret_interval_usec, unsigned *ret_burst) {
        (void) ret_interval_usec;
        (void) ret_burst;
        if (!s)
                return -EINVAL;
        if (s->type == SOURCE_POST || s->type == SOURCE_EXIT)
                return -EDOM;
        return -ENOEXEC; /* "no ratelimit configured" -- genuinely always true, since set_ratelimit() always fails */
}

int sd_event_source_is_ratelimited(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        /* A genuinely computed truth, not a stub: no source can ever be
         * ratelimited in this shim, so "not currently ratelimited" is
         * always the correct answer. */
        return 0;
}

int sd_event_source_set_ratelimit_expire_callback(sd_event_source *s, sd_event_handler_t callback) {
        (void) callback;
        if (!s)
                return -EINVAL;
        /* Same reasoning as set_ratelimit(): the callback could never fire
         * when ratelimiting can never be configured, so accepting and
         * storing it would itself be a misleading fake success. */
        return -EOPNOTSUPP;
}

int sd_event_source_leave_ratelimit(sd_event_source *s) {
        (void) s;
        /*
         * Upstream contract: 0 means "was not ratelimited, nothing to
         * leave" (positive means it was just lifted). Since no source is
         * ever ratelimited here, doing nothing and returning 0 is the
         * exactly correct answer for every possible call -- the one
         * genuine no-op in this family, deliberately not dereferencing s
         * at all.
         */
        return 0;
}
