/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

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
};

struct PicoTimer {
        int fd;
        PicoTimerEvent *events; /* head is always the nearest deadline */
};

static void usec_to_timespec(usec_t usec, struct timespec *ts) {
        ts->tv_sec = (time_t) (usec / USEC_PER_SEC);
        ts->tv_nsec = (long) ((usec % USEC_PER_SEC) * 1000);
}

/* Re-arm the timerfd to the current head deadline, or disarm if the queue is empty. */
static int timer_arm(PicoTimer *t) {
        struct itimerspec its = { 0 };

        if (t->events)
                usec_to_timespec(t->events->deadline, &its.it_value);

        if (timerfd_settime(t->fd, TFD_TIMER_ABSTIME, &its, NULL) < 0)
                return -errno;

        return 0;
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

        if (ret)
                *ret = ev;

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
                        *slot = ev->next;
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

                t->events = ev->next;
                ev->cb(ev->userdata, now);
                free(ev);
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

                free(ev);
                ev = next;
        }

        if (t->fd >= 0)
                close(t->fd);

        free(t);
        return NULL;
}
