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

#include <stdbool.h>
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
        NETD_EPOLL_LLDP,
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
 *
 * `registered` is the authoritative "is this tag live" flag, checked instead
 * of `fd`'s sign. Every owner of a tag is allocated with calloc()/new0() (this
 * project's universal convention), which zero-initializes `fd` to 0 -- a
 * perfectly valid descriptor number -- rather than -1. A sentinel keyed off
 * `fd >= 0` therefore reads a freshly calloc()'d, never-registered tag as
 * already busy, and every registration attempt on it fails -EBUSY forever.
 * Keying the sentinel off a separately-zeroed bool instead makes the correct
 * initial state the zero state, so no allocator path has to remember to set
 * `fd = -1` by hand. `fd` itself is still maintained (-1 when not
 * registered) purely for logging.
 */
struct netd_epoll_tag {
        NetdEpollSource source;
        int fd;          /* -1 when not registered; see `registered` above */
        bool registered; /* authoritative; false is calloc()'s own default */
        netd_io_callback_t callback;
        void *userdata;
};

/*
 * The reload callback netd.c installs on the Netd object (netd_new()) and
 * netd_loop_run() invokes instead of calling netd_reload() directly.
 *
 * netd_reload() is defined in netd.c, which meson.build deliberately never
 * links into netd-core or any test executable -- a second main() would
 * collide with every test's own, exactly the reason pico-init-core excludes
 * main.c. A direct call from here would leave every netd-core-linked test
 * program with an unresolved symbol at link time. This indirection is what
 * lets a test drive netd_loop_run() with its own reload handler, or leave
 * the field NULL to skip reload handling entirely -- while keeping the
 * deferred-until-after-the-batch contract below entirely inside this file.
 */
typedef int (*netd_reload_handler_t)(Netd *n);

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

/* How a deferred object is destroyed once the batch that may still name it is
 * over. Takes void* so an owner's own unref can be wrapped in one line. */
typedef void (*netd_free_func_t)(void *object);

/* One entry of Netd.pending_free; see netd_loop_defer_free(). */
struct netd_pending_free {
        void *object;
        netd_free_func_t free_func;
};

/*
 * Hand ownership of `object` to the loop, to be destroyed once the current
 * epoll batch has been fully dispatched rather than now.
 *
 * A struct netd_epoll_tag is embedded in whatever owns the fd, so freeing the
 * owner frees the tag -- and epoll_wait() hands netd_loop_run() a whole array
 * of tag pointers before the first callback in the batch runs.
 * netd_loop_run() skips a tag whose `registered` is false, but reading that
 * flag needs the tag's memory to still exist. It always does for the
 * signal/timer/rtnl tags, which live in Netd itself; it does *not* for a DHCP
 * client/server tag, which lives in the per-link object
 * (dhcp-client-internal.h, dhcp-server-internal.h). One batch carrying both
 * an RTM_DELLINK for a link and that link's DHCP socket becoming
 * readable/HUP -- an ordinary hot-unplug of a USB gadget interface -- would
 * otherwise have the rtnl callback free the DHCP object and the loop read
 * tag->registered out of freed memory a few events later.
 *
 * Deferring only the free is enough: the caller stops the object first, so
 * its fd is already deregistered and closed and its timers cancelled, and the
 * tag it still holds reads back as unregistered for the rest of the batch.
 *
 * 0, or -ENOMEM with `object` *not* destroyed -- the caller must then leak it
 * rather than free it, since a stopped DHCP object is inert memory whereas
 * freeing it here is exactly the use-after-free this queue exists to prevent.
 */
int netd_loop_defer_free(Netd *n, void *object, netd_free_func_t free_func);

/* Destroy everything netd_loop_defer_free() queued. netd_loop_run() calls it
 * once per batch, and netd_free() calls it so a teardown outside the loop does
 * not strand the queue. */
void netd_loop_drain_pending_frees(Netd *n);

/*
 * The loop. Blocks until objective != NETD_RUNNING; returns 0 on a clean exit
 * or -errno.
 *
 * Per iteration: epoll_wait(), dispatch every ready tag's callback, then --
 * after the whole batch, not inside it -- drain the deferred-free queue and
 * act on a pending reload. Deferring the reload is the same rule the manager
 * applies to its cgroup-empty queue: a reload frees every Network, and a
 * callback still holding a borrowed Network* would be reading freed memory.
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
