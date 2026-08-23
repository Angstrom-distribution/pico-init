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

/*
 * Queue cb(userdata, now) for `deadline` (absolute CLOCK_MONOTONIC usec);
 * re-arms the timerfd if this deadline is now the nearest. 0 or -errno.
 *
 * A deadline of 0 is clamped to 1: timer_arm() encodes "queue empty, disarm"
 * as an all-zero itimerspec, so a genuine deadline of 0 would disarm the
 * timerfd instead of firing immediately and the event would hang forever.
 *
 * HANDLE LIFETIME. `ret` is not merely an out-parameter -- the queue keeps the
 * address and clears *ret when the event fires or is cancelled. Pass the
 * address of the field that owns the handle (`&s->timer_event`), never the
 * address of a local, and the owner's copy can never dangle: it is NULL
 * exactly when the event no longer exists. Pass NULL for `ret` if the caller
 * genuinely never needs to cancel.
 *
 * The corollary: the storage `ret` points at must outlive the event. Anything
 * holding a live handle must cancel it before being freed (Service's vtable
 * done() does this), or the queue will write into freed memory when it fires.
 */
int pico_timer_add(PicoTimer *t, usec_t deadline, pico_timer_callback_t cb, void *userdata, PicoTimerEvent **ret);

/*
 * Remove a queued event, clear its owner's handle, and free it. Returns 0, or
 * -ENOENT if `ev` is not queued.
 *
 * -ENOENT means "no such queued event", NOT "already fired, so this was a safe
 * no-op": a fired event has been freed, and passing its address here would be
 * a use-after-free rather than a lookup miss. That case cannot arise as long
 * as callers use the handle slot pico_timer_add() manages, since the slot is
 * NULL by then -- and pico_timer_cancel(t, NULL) returns -EINVAL harmlessly.
 */
int pico_timer_cancel(PicoTimer *t, PicoTimerEvent *ev);

/*
 * Call on timerfd epoll readiness: drain the fd, fire every due event, re-arm
 * to the next deadline. Returns number fired, or -errno.
 *
 * Each event is unlinked and its owner's handle cleared *before* its callback
 * runs, so a callback may safely re-arm a new event, cancel other pending
 * events, or free the object that owned the fired one.
 */
int pico_timer_dispatch(PicoTimer *t);

/* Close the timerfd, drop pending events, free. Returns NULL. */
PicoTimer *pico_timer_free(PicoTimer *t);
