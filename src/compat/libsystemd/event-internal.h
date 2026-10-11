/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Private layout shared by sd-event.c (the event object and loop mechanics)
 * and sd-event-source.c (per-source property accessors). Never installed;
 * a real program including sd-event.h only ever sees opaque sd_event /
 * sd_event_source pointers.
 *
 * This layout is pico's own, written against the sd-event.h contract rather
 * than upstream's internals.
 *
 * One timerfd per time source. Upstream shares one timerfd per clockid in a
 * priority queue and coalesces nearby deadlines, which pays off with dozens
 * of timers. Callers here have a handful at most, so a plain timerfd per
 * source is enough; firing exactly on time always satisfies
 * sd_event_source_set_time_accuracy(), which only permits later delivery.
 *
 * One SOURCE_TIME type carrying its own clockid_t, instead of upstream's
 * enum value per clock, which only exists to support the shared timerfds.
 *
 * run_prepare_callbacks() (sd-event.c) refs every entry of its scratch array
 * before running any prepare callback and unrefs them all afterward, as
 * sd_event_dispatch() does around its one in-flight source: a prepare
 * callback that destroys a different, still-unvisited source would otherwise
 * leave the array holding a freed pointer.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "sd-event.h"

/* usec_t is uint64_t, as in the public API. Defined here because this
 * library links against nothing else of pico-init's (see meson.build). */
#define EVENT_USEC_PER_SEC ((uint64_t) 1000000ULL)
#define EVENT_USEC_PER_MSEC ((uint64_t) 1000ULL)

typedef enum EventSourceType {
        SOURCE_IO,
        SOURCE_TIME,
        SOURCE_SIGNAL,
        SOURCE_CHILD,
        SOURCE_DEFER,
        SOURCE_POST,
        SOURCE_EXIT,
        SOURCE_INOTIFY,
} EventSourceType;

struct sd_event_source {
        unsigned n_ref;
        sd_event *event;
        EventSourceType type;

        int enabled; /* SD_EVENT_OFF/ON/ONESHOT */
        bool pending;
        bool floating;
        bool exit_on_failure; /* meaningless (accessors -EDOM) for SOURCE_EXIT */
        bool ran;             /* SOURCE_EXIT only: already run during this exit sequence */

        int64_t priority;
        char *description;
        void *userdata;
        sd_event_destroy_t destroy_callback;
        sd_event_handler_t prepare;

        int fd; /* backing fd, or -1 for DEFER/POST/EXIT which have none */

        union {
                struct {
                        sd_event_io_handler_t callback;
                        uint32_t events;
                        uint32_t revents; /* captured at the wait() that made this pending */
                        bool fd_own;
                } io;
                struct {
                        sd_event_time_handler_t callback;
                        clockid_t clock;
                        uint64_t next;     /* absolute deadline last armed, or UINT64_MAX */
                        uint64_t accuracy; /* stored/reported only -- see sd-event.c */
                } time;
                struct {
                        sd_event_signal_handler_t callback;
                        int sig;
                } signal;
                struct {
                        sd_event_child_handler_t callback;
                        pid_t pid; /* 0 if never resolved (add_child_pidfd, best effort) */
                        int options;
                        bool pidfd_own;
                        bool process_own;
                } child;
                struct {
                        sd_event_handler_t callback; /* DEFER, POST, and EXIT all just call this */
                } generic;
                struct {
                        sd_event_inotify_handler_t callback;
                        char *path; /* creation-time name; NULL if never resolved */
                        uint32_t mask;
                } inotify;
        };

        sd_event_source *sources_next; /* singly linked into event->sources, job.c run_queue style */
};

struct sd_event {
        unsigned n_ref;
        int epoll_fd;
        int state; /* an SD_EVENT_* value, identical representation to the public enum */

        pid_t original_pid; /* recorded at sd_event_new(); a mismatch at any entry point is -ECHILD */
        pid_t tid;
        uint64_t iteration;

        bool exit_requested;
        int exit_code;
        bool exit_on_idle;
        bool watchdog;

        bool signal_exit_set;
        sd_event_source *signal_exit_term, *signal_exit_int; /* raw, non-owning: see set_signal_exit */

        bool timestamp_valid;
        uint64_t ts_realtime, ts_monotonic, ts_boottime; /* cached by the last completed wait() */

        sd_event_source *sources;
        size_t n_sources;
};

/* Shared between sd-event.c and sd-event-source.c; none of this is public. */
sd_event *event_resolve(sd_event *e);
sd_event_source *event_source_new(sd_event *e, bool floating, EventSourceType type);
void event_source_free(sd_event_source *s);
void event_source_destroy(sd_event_source *s);
void event_source_unlink(sd_event_source *s);
int event_epoll_add(sd_event *e, sd_event_source *s, uint32_t events);
int event_source_apply_enabled(sd_event_source *s, int enabled);
void event_source_apply_failure(sd_event_source *s, int r);
uint64_t event_timespec_to_usec(const struct timespec *ts);
void event_usec_to_timespec(uint64_t usec, struct timespec *ts);
int event_pidfd_open(pid_t pid, unsigned int flags);
int event_pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags);
int event_pidfd_get_pid(int pidfd, pid_t *ret);
