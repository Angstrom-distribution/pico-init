/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * One timerfd fronting a priority queue of every unit's timeouts and
 * restart delays: a single kernel timer re-armed to the nearest deadline,
 * not one timer per unit.
 */

#pragma once

#include "util.h"

typedef struct PicoTimer PicoTimer;           /* the queue + its timerfd */
typedef struct PicoTimerEvent PicoTimerEvent; /* one queued deadline (handle for cancel) */

typedef void (*pico_timer_callback_t)(void *userdata, usec_t now);

/* Create the queue and its CLOCK_MONOTONIC timerfd. 0 or -errno. */
int pico_timer_new(PicoTimer **ret);

/* The timerfd, for registration in the manager's epoll. */
int pico_timer_fd(PicoTimer *t);

/* Queue cb(userdata) for `deadline` (absolute CLOCK_MONOTONIC usec); re-arms
 * the timerfd if this deadline is now the nearest. Handle out via ret (may be
 * NULL if the caller never cancels). 0 or -errno. */
int pico_timer_add(PicoTimer *t, usec_t deadline, pico_timer_callback_t cb, void *userdata, PicoTimerEvent **ret);

/* Remove a queued event; frees the handle. 0, or -ENOENT if already fired. */
int pico_timer_cancel(PicoTimer *t, PicoTimerEvent *ev);

/* Call on timerfd epoll readiness: drain the fd, fire every due event,
 * re-arm to the next deadline. Returns number fired, or -errno. */
int pico_timer_dispatch(PicoTimer *t);

/* Close the timerfd, drop pending events, free. Returns NULL. */
PicoTimer *pico_timer_free(PicoTimer *t);
