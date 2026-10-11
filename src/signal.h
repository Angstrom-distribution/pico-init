/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * signalfd-based signal handling: SIGCHLD/SIGTERM/SIGHUP blocked via
 * sigprocmask before the signalfd is created, then read and handled
 * synchronously in manager-loop context. This header does not include
 * <signal.h>; it is included in quote form, so the libc header is not
 * shadowed for angle-bracket includes.
 */

#pragma once

typedef struct PicoSignal PicoSignal;

/* Block the handled signal set process-wide and create the signalfd. 0 or -errno. */
int pico_signal_new(PicoSignal **ret);

/* The signalfd, for registration in the manager's epoll. */
int pico_signal_fd(PicoSignal *s);

/* Read one pending signal (non-blocking). Signal number via ret_signo.
 * 0 on success, -EAGAIN when drained, other -errno on error. */
int pico_signal_read(PicoSignal *s, int *ret_signo);

/* Close the signalfd and restore the previous signal mask. Returns NULL. */
PicoSignal *pico_signal_free(PicoSignal *s);
