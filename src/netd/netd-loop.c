/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netd's epoll loop. Real rather than stubbed, for the same reason M0's
 * timer.c and signal.c were: at this size a stub is no less code than the
 * implementation, and every later milestone registers against it.
 *
 * The one thing that is not obvious: a reload is acted on *after* the whole
 * epoll batch is dispatched, never inside it. netd_reload() frees every
 * Network, and a callback still holding the borrowed Network* its Link points
 * at would be reading freed memory. This is the same class of bug M5 found in
 * PID 1's run queue, and it is cheaper to design out than to debug on a
 * board.
 */

#include "netd-loop.h"

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "../signal.h"
#include "../timer.h"
#include "../util.h"
#include "netd.h"

#define NETD_EPOLL_MAX_EVENTS 16

static int dispatch_signal_source(Netd *n, struct netd_epoll_tag *tag, uint32_t revents) {
        int r;

        (void) tag;
        (void) revents;

        for (;;) {
                int signo;

                r = pico_signal_read(n->signal, &signo);
                if (r == -EAGAIN)
                        return 0;
                if (r < 0)
                        return r;

                r = netd_loop_dispatch_signal(n, signo);
                if (r < 0)
                        return r;
        }
}

static int dispatch_timer_source(Netd *n, struct netd_epoll_tag *tag, uint32_t revents) {
        int r;

        (void) tag;
        (void) revents;

        r = pico_timer_dispatch(n->timer);
        return r < 0 ? r : 0;
}

int netd_loop_setup(Netd *n) {
        int r;

        if (!n || !n->signal || !n->timer)
                return -EINVAL;

        n->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (n->epoll_fd < 0)
                return -errno;

        r = netd_loop_add_io(
                        n,
                        &n->signal_tag,
                        pico_signal_fd(n->signal),
                        EPOLLIN,
                        NETD_EPOLL_SIGNAL,
                        dispatch_signal_source,
                        n);
        if (r < 0)
                return r;

        return netd_loop_add_io(
                        n,
                        &n->timer_tag,
                        pico_timer_fd(n->timer),
                        EPOLLIN,
                        NETD_EPOLL_TIMER,
                        dispatch_timer_source,
                        n);
}

int netd_loop_add_io(
                Netd *n,
                struct netd_epoll_tag *tag,
                int fd,
                uint32_t events,
                NetdEpollSource source,
                netd_io_callback_t callback,
                void *userdata) {

        struct epoll_event ev;

        if (!n || !tag || !callback || fd < 0 || n->epoll_fd < 0)
                return -EINVAL;

        /* A tag that still names an fd was never removed. Re-registering it
         * would leak the old epoll entry, which keeps firing for whatever
         * that descriptor number becomes next. */
        if (tag->fd >= 0)
                return -EBUSY;

        tag->source = source;
        tag->fd = fd;
        tag->callback = callback;
        tag->userdata = userdata;

        memset(&ev, 0, sizeof(ev));
        ev.events = events;
        ev.data.ptr = tag;

        if (epoll_ctl(n->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                tag->fd = -1;
                return -errno;
        }

        return 0;
}

int netd_loop_modify_io(Netd *n, struct netd_epoll_tag *tag, uint32_t events) {
        struct epoll_event ev;

        if (!n || !tag || tag->fd < 0 || n->epoll_fd < 0)
                return -EINVAL;

        memset(&ev, 0, sizeof(ev));
        ev.events = events;
        ev.data.ptr = tag;

        if (epoll_ctl(n->epoll_fd, EPOLL_CTL_MOD, tag->fd, &ev) < 0)
                return -errno;

        return 0;
}

int netd_loop_remove_io(Netd *n, struct netd_epoll_tag *tag) {
        if (!n || !tag)
                return -EINVAL;

        /* Not an error: teardown of a half-configured link should not have to
         * remember how far configuration got. */
        if (tag->fd < 0)
                return 0;

        if (n->epoll_fd >= 0 && epoll_ctl(n->epoll_fd, EPOLL_CTL_DEL, tag->fd, NULL) < 0 &&
            errno != ENOENT && errno != EBADF)
                return -errno;

        tag->fd = -1;
        tag->callback = NULL;
        tag->userdata = NULL;
        return 0;
}

int netd_loop_dispatch_signal(Netd *n, int signo) {
        if (!n)
                return -EINVAL;

        switch (signo) {

        case SIGTERM:
        case SIGINT:
                /* pico-init stops services with SIGTERM; SIGINT is what a
                 * developer running netd by hand sends. Same outcome. */
                pico_log(PICO_LOG_INFO, "netd: %s, shutting down", strsignal(signo));
                n->objective = NETD_EXIT;
                return 0;

        case SIGHUP:
                /* The whole management API (§2.9). Deferred, see above. */
                pico_log(PICO_LOG_INFO, "netd: SIGHUP, reload queued");
                n->reload_requested = true;
                return 0;

        default:
                pico_log(PICO_LOG_DEBUG, "netd: ignoring signal %d", signo);
                return 0;
        }
}

int netd_loop_run(Netd *n) {
        if (!n || n->epoll_fd < 0)
                return -EINVAL;

        while (n->objective == NETD_RUNNING) {
                struct epoll_event events[NETD_EPOLL_MAX_EVENTS];
                int k;

                k = epoll_wait(n->epoll_fd, events, NETD_EPOLL_MAX_EVENTS, -1);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        return -errno;
                }

                for (int i = 0; i < k; i++) {
                        struct netd_epoll_tag *tag = events[i].data.ptr;
                        int r;

                        /*
                         * Every registration in this set uses data.ptr, so
                         * this cast is always valid -- but a source removed
                         * by an earlier callback in the same batch can still
                         * appear later in it, and its tag is then cleared.
                         */
                        if (!tag || !tag->callback || tag->fd < 0)
                                continue;

                        r = tag->callback(n, tag, events[i].events);
                        if (r < 0)
                                pico_log(PICO_LOG_WARNING,
                                         "netd: %s source failed: %s",
                                         netd_epoll_source_to_string(tag->source),
                                         strerror(-r));
                }

                if (n->reload_requested) {
                        int r;

                        n->reload_requested = false;

                        r = netd_reload(n);
                        if (r < 0)
                                pico_log(PICO_LOG_ERR, "netd: reload failed: %s", strerror(-r));
                }
        }

        return 0;
}

static const char * const netd_epoll_source_table[_NETD_EPOLL_SOURCE_MAX] = {
        [NETD_EPOLL_SIGNAL] = "signal",
        [NETD_EPOLL_TIMER] = "timer",
        [NETD_EPOLL_RTNL] = "rtnl",
        [NETD_EPOLL_DHCP_CLIENT] = "dhcp-client",
        [NETD_EPOLL_DHCP_SERVER] = "dhcp-server",
        [NETD_EPOLL_SNTP] = "sntp",
};

const char *netd_epoll_source_to_string(NetdEpollSource s) {
        if (s < 0 || s >= _NETD_EPOLL_SOURCE_MAX)
                return "invalid";

        return netd_epoll_source_table[s];
}
