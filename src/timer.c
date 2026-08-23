/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * One timerfd fronting a deadline-sorted queue. See timer.h for the handle
 * ownership contract, which is the subtle part: the queue remembers where the
 * caller's handle lives and clears it, so a handle is NULL exactly when its
 * event no longer exists.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "timer.h"
#include "util.h"

struct PicoTimerEvent {
        PicoTimerEvent *next; /* singly linked, kept sorted ascending by deadline */
        usec_t deadline;
        pico_timer_callback_t cb;
        void *userdata;

        /*
         * The caller's own handle slot, or NULL if it passed no `ret`. Cleared
         * when this event fires or is cancelled, which is what makes a fired
         * handle impossible to reuse by accident rather than merely documented
         * as unsafe. See timer.h.
         */
        PicoTimerEvent **owner_ref;
};

struct PicoTimer {
        int fd;
        PicoTimerEvent *events; /* head is always the nearest deadline */
};

static void usec_to_timespec(usec_t usec, struct timespec *ts) {
        ts->tv_sec = (time_t) (usec / USEC_PER_SEC);
        ts->tv_nsec = (long) ((usec % USEC_PER_SEC) * 1000);
}

/* Re-arm the timerfd to the current head deadline, or disarm if the queue is
 * empty. An all-zero itimerspec is the kernel's "disarm" encoding, which is
 * why pico_timer_add() must never let a real deadline be 0. */
static int timer_arm(PicoTimer *t) {
        struct itimerspec its = { 0 };

        if (t->events)
                usec_to_timespec(t->events->deadline, &its.it_value);

        if (timerfd_settime(t->fd, TFD_TIMER_ABSTIME, &its, NULL) < 0)
                return -errno;

        return 0;
}

/* Unlink from the queue and clear the owner's handle. Does not free. */
static void timer_event_detach(PicoTimerEvent **slot) {
        PicoTimerEvent *ev = *slot;

        *slot = ev->next;
        ev->next = NULL;

        if (ev->owner_ref) {
                *ev->owner_ref = NULL;
                ev->owner_ref = NULL;
        }
}

int pico_timer_new(PicoTimer **ret) {
        PicoTimer *t;

        if (!ret)
                return -EINVAL;

        t = calloc(1, sizeof(*t));
        if (!t)
                return -ENOMEM;

        t->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (t->fd < 0) {
                int r = -errno;
                free(t);
                return r;
        }

        *ret = t;
        return 0;
}

int pico_timer_fd(PicoTimer *t) {
        if (!t)
                return -EINVAL;

        return t->fd;
}

int pico_timer_add(PicoTimer *t, usec_t deadline, pico_timer_callback_t cb, void *userdata, PicoTimerEvent **ret) {
        PicoTimerEvent *ev, **slot;

        if (!t || !cb)
                return -EINVAL;

        /*
         * USEC_INFINITY means "never". A caller with a disabled timeout should
         * not end up armed at all, so refuse rather than queue an event that
         * can never sensibly fire.
         */
        if (deadline == USEC_INFINITY)
                return -EINVAL;

        /*
         * Clamp 0 to 1. timer_arm() encodes an empty queue as an all-zero
         * itimerspec, so a genuine deadline of 0 would disarm the timerfd
         * instead of firing immediately, and the event would hang forever.
         * Live rather than theoretical: RestartSec=0 means "restart
         * immediately", and a deadline of now-plus-nothing lands here.
         */
        if (deadline == 0)
                deadline = 1;

        ev = calloc(1, sizeof(*ev));
        if (!ev)
                return -ENOMEM;

        ev->deadline = deadline;
        ev->cb = cb;
        ev->userdata = userdata;

        for (slot = &t->events; *slot && (*slot)->deadline <= deadline; slot = &(*slot)->next)
                ;
        ev->next = *slot;
        *slot = ev;

        if (t->events == ev) {
                int r = timer_arm(t);

                if (r < 0) {
                        *slot = ev->next;
                        free(ev);
                        return r;
                }
        }

        if (ret) {
                *ret = ev;
                ev->owner_ref = ret;
        }

        return 0;
}

int pico_timer_cancel(PicoTimer *t, PicoTimerEvent *ev) {
        PicoTimerEvent **slot;
        bool was_head;

        if (!t || !ev)
                return -EINVAL;

        was_head = t->events == ev;

        for (slot = &t->events; *slot; slot = &(*slot)->next) {
                if (*slot == ev) {
                        timer_event_detach(slot);
                        free(ev);

                        if (was_head)
                                timer_arm(t);

                        return 0;
                }
        }

        return -ENOENT;
}

int pico_timer_dispatch(PicoTimer *t) {
        uint64_t expirations;
        usec_t now;
        int n = 0;

        if (!t)
                return -EINVAL;

        if (read(t->fd, &expirations, sizeof(expirations)) < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                return -errno;

        now = now_monotonic();

        while (t->events && t->events->deadline <= now) {
                PicoTimerEvent *ev = t->events;
                pico_timer_callback_t cb = ev->cb;
                void *userdata = ev->userdata;

                /*
                 * Detach and free *before* running the callback. The callback
                 * is free to arm a new event, cancel other pending ones, or
                 * free the object that owned this one -- all of which would be
                 * unsafe while this event was still linked, or still reachable
                 * through its owner's handle.
                 */
                timer_event_detach(&t->events);
                free(ev);

                cb(userdata, now);
                n++;
        }

        timer_arm(t);

        return n;
}

PicoTimer *pico_timer_free(PicoTimer *t) {
        PicoTimerEvent *ev;

        if (!t)
                return NULL;

        ev = t->events;
        while (ev) {
                PicoTimerEvent *next = ev->next;

                /* honour the same contract on teardown: an owner outliving the
                 * queue must not be left holding a freed handle */
                if (ev->owner_ref)
                        *ev->owner_ref = NULL;

                free(ev);
                ev = next;
        }

        if (t->fd >= 0)
                close(t->fd);

        free(t);
        return NULL;
}
