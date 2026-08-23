/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "signal.h"

struct PicoSignal {
        int fd;
        sigset_t old_mask; /* process mask before pico_signal_new(), for restore on free */
};

int pico_signal_new(PicoSignal **ret) {
        PicoSignal *s;
        sigset_t mask;
        int r;

        if (!ret)
                return -EINVAL;

        s = calloc(1, sizeof(*s));
        if (!s)
                return -ENOMEM;

        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGHUP);

        if (sigprocmask(SIG_BLOCK, &mask, &s->old_mask) < 0) {
                r = -errno;
                free(s);
                return r;
        }

        s->fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
        if (s->fd < 0) {
                r = -errno;
                sigprocmask(SIG_SETMASK, &s->old_mask, NULL);
                free(s);
                return r;
        }

        *ret = s;
        return 0;
}

int pico_signal_fd(PicoSignal *s) {
        if (!s)
                return -EINVAL;

        return s->fd;
}

int pico_signal_read(PicoSignal *s, int *ret_signo) {
        struct signalfd_siginfo fdsi;
        ssize_t n;

        if (!s || !ret_signo)
                return -EINVAL;

        n = read(s->fd, &fdsi, sizeof(fdsi));
        if (n < 0)
                return errno == EAGAIN || errno == EWOULDBLOCK ? -EAGAIN : -errno;
        if (n != sizeof(fdsi))
                return -EIO;

        *ret_signo = (int) fdsi.ssi_signo;
        return 0;
}

PicoSignal *pico_signal_free(PicoSignal *s) {
        if (!s)
                return NULL;

        if (s->fd >= 0)
                close(s->fd);

        sigprocmask(SIG_SETMASK, &s->old_mask, NULL);

        free(s);
        return NULL;
}
