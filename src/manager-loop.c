/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The single epoll loop. signalfd and timerfd are always registered (see
 * manager_new()); per-service cgroup.events fds will join the same epoll
 * set via cgroup_v2_monitor() once M3 wires services up, landing in the
 * epoll_wait() below without this file needing to know about them -- any
 * fd not recognised here is a stub no-op for now.
 */

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/wait.h>

#include "manager.h"

#define MANAGER_MAX_EVENTS 16

static int manager_dispatch_sigchld(void) {
        for (;;) {
                int status;
                pid_t pid = waitpid(-1, &status, WNOHANG);
                if (pid <= 0)
                        break;
                /* TODO (M3): route (pid, status) to the owning Service via
                 * service_sigchld_event() once services track their pids. */
        }

        return 0;
}

int manager_dispatch_signal(Manager *m, int signo) {
        if (!m)
                return -EINVAL;

        switch (signo) {
        case SIGCHLD:
                return manager_dispatch_sigchld();
        case SIGTERM:
                return manager_shutdown(m, MANAGER_EXIT);
        case SIGHUP:
                /* TODO (M1+): reload unit fragments */
                return 0;
        default:
                return 0;
        }
}

static int manager_dispatch_epoll_event(Manager *m, int fd) {
        if (fd == pico_signal_fd(m->signal)) {
                for (;;) {
                        int signo;
                        int r = pico_signal_read(m->signal, &signo);
                        if (r == -EAGAIN)
                                return 0;
                        if (r < 0)
                                return r;

                        r = manager_dispatch_signal(m, signo);
                        if (r < 0)
                                return r;
                }
        }

        if (fd == pico_timer_fd(m->timer)) {
                int r = pico_timer_dispatch(m->timer);
                return r < 0 ? r : 0;
        }

        /* Unrecognised fd (future cgroup.events); nothing to do yet. */
        return 0;
}

int manager_loop(Manager *m) {
        if (!m)
                return -EINVAL;

        struct epoll_event events[MANAGER_MAX_EVENTS];

        while (m->objective == MANAGER_RUNNING) {
                int n = epoll_wait(m->epoll_fd, events, MANAGER_MAX_EVENTS, -1);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }

                for (int i = 0; i < n; i++) {
                        int r = manager_dispatch_epoll_event(m, events[i].data.fd);
                        if (r < 0)
                                pico_log(PICO_LOG_WARNING,
                                         "event on fd %d: %s",
                                         events[i].data.fd,
                                         strerror(-r));
                }

                manager_dispatch_run_queue(m);
        }

        return (int) m->objective;
}
