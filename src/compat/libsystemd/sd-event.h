/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-init's own implementation of the sd_event_*() ABI surface, matching
 * the function signatures and documented semantics of systemd's sd-event.h.
 * See event-internal.h for implementation notes.
 *
 * Unlike real sd_event, which multiplexes every timer of a clock onto one
 * shared timerfd and coalesces wakeups system-wide, every timer source here
 * gets its own timerfd (event-internal.h says why).
 *
 * sd_event_add_memory_pressure() and sd_event_source_set_ratelimit() (plus
 * its expire-callback companion) are declared for ABI completeness but
 * always fail; see sd-event.c and sd-event-source.c respectively.
 *
 * pico-init's Manager embeds one sd_event as its PID 1 main loop
 * (src/manager.h). One owning event loop per process is a convention, not
 * an enforced guard: whoever owns the process's signal mask and child
 * reaping owns the loop, and a second sd_event in the same process must not
 * add sources for resources the main loop owns.
 */

#pragma once

#include <signal.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sd_event sd_event;
typedef struct sd_event_source sd_event_source;

/* Passed in place of a real sd_event* to mean "this thread's default loop". */
#define SD_EVENT_DEFAULT ((sd_event *) 1)

enum { SD_EVENT_OFF = 0, SD_EVENT_ON = 1, SD_EVENT_ONESHOT = -1 };

enum {
        SD_EVENT_INITIAL,
        SD_EVENT_ARMED,
        SD_EVENT_PENDING,
        SD_EVENT_RUNNING,
        SD_EVENT_EXITING,
        SD_EVENT_FINISHED,
        SD_EVENT_PREPARING
};

enum { SD_EVENT_PRIORITY_IMPORTANT = -100, SD_EVENT_PRIORITY_NORMAL = 0, SD_EVENT_PRIORITY_IDLE = 100 };

/* OR this into the sig argument of sd_event_add_signal() to have the call
 * itself block the signal, instead of requiring it already blocked. */
#define SD_EVENT_SIGNAL_PROCMASK (1 << 30)

typedef int (*sd_event_handler_t)(sd_event_source *s, void *userdata);
typedef int (*sd_event_io_handler_t)(sd_event_source *s, int fd, uint32_t revents, void *userdata);
typedef int (*sd_event_time_handler_t)(sd_event_source *s, uint64_t usec, void *userdata);
typedef int (*sd_event_signal_handler_t)(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata);
#if defined _GNU_SOURCE || (defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 199309L)
typedef int (*sd_event_child_handler_t)(sd_event_source *s, const siginfo_t *si, void *userdata);
#else
typedef void *sd_event_child_handler_t;
#endif
typedef int (*sd_event_inotify_handler_t)(sd_event_source *s, const struct inotify_event *event, void *userdata);
typedef void (*sd_event_destroy_t)(void *userdata);

int sd_event_new(sd_event **ret);
int sd_event_default(sd_event **ret);
sd_event *sd_event_ref(sd_event *e);
sd_event *sd_event_unref(sd_event *e);

int sd_event_add_io(
                sd_event *e,
                sd_event_source **ret,
                int fd,
                uint32_t events,
                sd_event_io_handler_t callback,
                void *userdata);
int sd_event_add_time(
                sd_event *e,
                sd_event_source **ret,
                clockid_t clock,
                uint64_t usec,
                uint64_t accuracy,
                sd_event_time_handler_t callback,
                void *userdata);
int sd_event_add_time_relative(
                sd_event *e,
                sd_event_source **ret,
                clockid_t clock,
                uint64_t usec,
                uint64_t accuracy,
                sd_event_time_handler_t callback,
                void *userdata);
int sd_event_add_signal(
                sd_event *e, sd_event_source **ret, int sig, sd_event_signal_handler_t callback, void *userdata);
int sd_event_add_child(
                sd_event *e,
                sd_event_source **ret,
                pid_t pid,
                int options,
                sd_event_child_handler_t callback,
                void *userdata);
int sd_event_add_child_pidfd(
                sd_event *e,
                sd_event_source **ret,
                int pidfd,
                int options,
                sd_event_child_handler_t callback,
                void *userdata);
int sd_event_add_inotify(
                sd_event *e,
                sd_event_source **ret,
                const char *path,
                uint32_t mask,
                sd_event_inotify_handler_t callback,
                void *userdata);
int sd_event_add_inotify_fd(
                sd_event *e,
                sd_event_source **ret,
                int fd,
                uint32_t mask,
                sd_event_inotify_handler_t callback,
                void *userdata);
int sd_event_add_defer(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata);
int sd_event_add_post(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata);
int sd_event_add_exit(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata);
int sd_event_add_memory_pressure(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata);

int sd_event_prepare(sd_event *e);
int sd_event_wait(sd_event *e, uint64_t timeout);
int sd_event_dispatch(sd_event *e);
int sd_event_run(sd_event *e, uint64_t timeout);
int sd_event_loop(sd_event *e);
int sd_event_exit(sd_event *e, int code);

int sd_event_now(sd_event *e, clockid_t clock, uint64_t *ret);

int sd_event_get_fd(sd_event *e);
int sd_event_get_state(sd_event *e);
int sd_event_get_tid(sd_event *e, pid_t *ret);
int sd_event_get_exit_code(sd_event *e, int *ret);
int sd_event_set_watchdog(sd_event *e, int b);
int sd_event_get_watchdog(sd_event *e);
int sd_event_get_iteration(sd_event *e, uint64_t *ret);
int sd_event_set_signal_exit(sd_event *e, int b);
int sd_event_set_exit_on_idle(sd_event *e, int b);
int sd_event_get_exit_on_idle(sd_event *e);

sd_event_source *sd_event_source_ref(sd_event_source *s);
sd_event_source *sd_event_source_unref(sd_event_source *s);
sd_event_source *sd_event_source_disable_unref(sd_event_source *s);

sd_event *sd_event_source_get_event(sd_event_source *s);
void *sd_event_source_get_userdata(sd_event_source *s);
void *sd_event_source_set_userdata(sd_event_source *s, void *userdata);

int sd_event_source_set_description(sd_event_source *s, const char *description);
int sd_event_source_get_description(sd_event_source *s, const char **ret);
int sd_event_source_set_prepare(sd_event_source *s, sd_event_handler_t callback);
int sd_event_source_get_pending(sd_event_source *s);
int sd_event_source_get_priority(sd_event_source *s, int64_t *ret);
int sd_event_source_set_priority(sd_event_source *s, int64_t priority);
int sd_event_source_get_enabled(sd_event_source *s, int *ret);
int sd_event_source_set_enabled(sd_event_source *s, int enabled);
int sd_event_source_get_io_fd(sd_event_source *s);
int sd_event_source_set_io_fd(sd_event_source *s, int fd);
int sd_event_source_get_io_fd_own(sd_event_source *s);
int sd_event_source_set_io_fd_own(sd_event_source *s, int own);
int sd_event_source_get_io_events(sd_event_source *s, uint32_t *ret);
int sd_event_source_set_io_events(sd_event_source *s, uint32_t events);
int sd_event_source_get_io_revents(sd_event_source *s, uint32_t *ret);
int sd_event_source_get_time(sd_event_source *s, uint64_t *ret);
int sd_event_source_set_time(sd_event_source *s, uint64_t usec);
int sd_event_source_set_time_relative(sd_event_source *s, uint64_t usec);
int sd_event_source_get_time_accuracy(sd_event_source *s, uint64_t *ret);
int sd_event_source_set_time_accuracy(sd_event_source *s, uint64_t usec);
int sd_event_source_get_time_clock(sd_event_source *s, clockid_t *ret);
int sd_event_source_get_signal(sd_event_source *s);
int sd_event_source_get_child_pid(sd_event_source *s, pid_t *ret);
int sd_event_source_get_child_pidfd(sd_event_source *s);
int sd_event_source_get_child_pidfd_own(sd_event_source *s);
int sd_event_source_set_child_pidfd_own(sd_event_source *s, int own);
int sd_event_source_get_child_process_own(sd_event_source *s);
int sd_event_source_set_child_process_own(sd_event_source *s, int own);
#if defined _GNU_SOURCE || (defined _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 199309L)
int sd_event_source_send_child_signal(sd_event_source *s, int sig, const siginfo_t *si, unsigned flags);
#else
int sd_event_source_send_child_signal(sd_event_source *s, int sig, const void *si, unsigned flags);
#endif
int sd_event_source_get_inotify_mask(sd_event_source *s, uint32_t *ret);
int sd_event_source_get_inotify_path(sd_event_source *s, const char **ret);
int sd_event_source_set_memory_pressure_type(sd_event_source *s, const char *ty);
int sd_event_source_set_memory_pressure_period(sd_event_source *s, uint64_t threshold_usec, uint64_t window_usec);
int sd_event_source_set_destroy_callback(sd_event_source *s, sd_event_destroy_t callback);
int sd_event_source_get_destroy_callback(sd_event_source *s, sd_event_destroy_t *ret);
int sd_event_source_get_floating(sd_event_source *s);
int sd_event_source_set_floating(sd_event_source *s, int b);
int sd_event_source_get_exit_on_failure(sd_event_source *s);
int sd_event_source_set_exit_on_failure(sd_event_source *s, int b);
int sd_event_source_set_ratelimit(sd_event_source *s, uint64_t interval_usec, unsigned burst);
int sd_event_source_get_ratelimit(sd_event_source *s, uint64_t *ret_interval_usec, unsigned *ret_burst);
int sd_event_source_is_ratelimited(sd_event_source *s);
int sd_event_source_set_ratelimit_expire_callback(sd_event_source *s, sd_event_handler_t callback);
int sd_event_source_leave_ratelimit(sd_event_source *s);

int sd_event_trim_memory(void);

/* For __attribute__((cleanup(sd_event_unrefp))) and the two source variants. */
static __inline__ void sd_event_unrefp(sd_event **p) {
        if (*p)
                sd_event_unref(*p);
}
static __inline__ void sd_event_source_unrefp(sd_event_source **p) {
        if (*p)
                sd_event_source_unref(*p);
}
static __inline__ void sd_event_source_disable_unrefp(sd_event_source **p) {
        if (*p)
                sd_event_source_disable_unref(*p);
}

#ifdef __cplusplus
}
#endif
