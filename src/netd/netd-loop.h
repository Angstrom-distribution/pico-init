/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netd's event loop: one epoll fd multiplexing the shared signalfd, the
 * shared timerfd, the rtnetlink event socket, and every DHCP/SNTP socket the
 * link layer opens (plan §2.3 -- "literally a thin epoll wrapper" over
 * pico-init's own timer.c/signal.c).
 *
 * Registrations are callback-carrying, not switch-dispatched. The manager's
 * loop can afford a switch over PicoEpollSource because PID 1 has three fixed
 * source kinds; netd's sources are dynamic (a DHCP client socket per link, a
 * server socket per link, an SNTP socket) and, more to the point, arrive from
 * four independently-implemented milestones. A dispatch switch here would
 * mean N2, N3 and N4 each editing this file to add a case. The callback in
 * the tag means they never touch it: they hand netd_loop_add_io() their own
 * function and own their fd end to end.
 *
 * netd deliberately does not reuse struct pico_epoll_tag: its PicoEpollSource
 * enumeration names PID 1's sources (cgroup events) and not netd's, and
 * util.h belongs to the PID 1 core. The dispatch rule is the same one util.h
 * spells out, and it is not optional here either -- every registration in
 * this epoll set uses data.ptr, never data.fd, and dispatch always reads
 * data.ptr back.
 */

#pragma once

#include <stdint.h>

typedef struct Netd Netd;

/* What a registration is, for logging and for asserting at dispatch that the
 * pointer we got back is the kind of thing we expected. */
typedef enum NetdEpollSource {
        NETD_EPOLL_SIGNAL,
        NETD_EPOLL_TIMER,
        NETD_EPOLL_RTNL,
        NETD_EPOLL_DHCP_CLIENT,
        NETD_EPOLL_DHCP_SERVER,
        NETD_EPOLL_SNTP,
        _NETD_EPOLL_SOURCE_MAX,
} NetdEpollSource;

struct netd_epoll_tag;

/*
 * Called with the epoll revents mask when the registered fd is ready.
 * Returning a negative errno logs and, for a link-owned source, fails that
 * link -- it never takes the daemon down: a wedged DHCP socket on usb0 must
 * not stop eth0 from working.
 */
typedef int (*netd_io_callback_t)(Netd *n, struct netd_epoll_tag *tag, uint32_t revents);

/*
 * The registration record. It is embedded in whatever owns the fd (Netd for
 * the signal/timer/rtnl sources, the DHCP client/server object for theirs) --
 * never heap-allocated separately, so its lifetime is exactly its owner's and
 * there is nothing to leak. `userdata` is normally the containing object.
 */
struct netd_epoll_tag {
        NetdEpollSource source;
        int fd; /* -1 when not registered */
        netd_io_callback_t callback;
        void *userdata;
};

/* --- netd-loop.c --- */

/* epoll_create1(), then register the signalfd and the timerfd. Called from
 * netd_new(); both fds already exist by then. 0 or -errno. */
int netd_loop_setup(Netd *n);

/*
 * Register `fd` for `events`, filling in `tag` (which the caller owns and
 * must keep alive until netd_loop_remove_io()). 0 or -errno.
 *
 * Registering an fd that is already registered through this tag is -EBUSY,
 * not a silent re-register: it almost always means an object was configured
 * twice, and epoll would otherwise report the old fd forever.
 */
int netd_loop_add_io(
                Netd *n,
                struct netd_epoll_tag *tag,
                int fd,
                uint32_t events,
                NetdEpollSource source,
                netd_io_callback_t callback,
                void *userdata);

/* Change the interest mask of an existing registration. 0 or -errno. */
int netd_loop_modify_io(Netd *n, struct netd_epoll_tag *tag, uint32_t events);

/*
 * Deregister. Safe on a tag that was never registered (returns 0), because
 * the teardown path of a half-configured link should not need to remember
 * how far it got. Does *not* close the fd -- the owner does that, and
 * ordering matters: deregister first, then close, or a still-armed epoll
 * entry can outlive the fd number and be re-used by the next open().
 */
int netd_loop_remove_io(Netd *n, struct netd_epoll_tag *tag);

/*
 * The loop. Blocks until objective != NETD_RUNNING; returns 0 on a clean exit
 * or -errno.
 *
 * Per iteration: epoll_wait(), dispatch every ready tag's callback, then --
 * after the whole batch, not inside it -- act on a pending reload. Deferring
 * the reload is the same rule the manager applies to its cgroup-empty queue:
 * a reload frees every Network, and a callback still holding a borrowed
 * Network* would be reading freed memory.
 */
int netd_loop_run(Netd *n);

/*
 * Synchronous signal handling, from the signalfd callback:
 *   SIGTERM, SIGINT -> NETD_EXIT (pico-init stops services with SIGTERM)
 *   SIGHUP          -> set reload_requested
 * Anything else is logged and ignored. 0 or -errno.
 */
int netd_loop_dispatch_signal(Netd *n, int signo);

const char *netd_epoll_source_to_string(NetdEpollSource s);
