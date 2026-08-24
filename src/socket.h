/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Socket units (plan §1.6). Scaffolding only at this point: the real type,
 * its state machine and its quarried body land with milestones S0-S2, which
 * own this file. What is fixed here is the contract manager-loop.c and unit.c
 * are already written against, so neither has to be edited again to land it.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "unit.h"
#include "util.h"

typedef struct Manager Manager;

/*
 * DEAD -> LISTENING -> RUNNING -> {LISTENING, FAILED}, plus DEAD from an
 * orderly stop out of any state. No socket-side Exec*= collapses v30's
 * eleven states to these four -- see socket.c's header for the full quarry
 * citation and the per-fix backport record.
 */
typedef enum SocketState {
        SOCKET_DEAD,
        SOCKET_LISTENING, /* fds open and in the manager's epoll set */
        SOCKET_RUNNING,   /* fds open, NOT watched -- handed to the service; see H7 in socket.c */
        SOCKET_FAILED,
        _SOCKET_STATE_MAX,
        _SOCKET_STATE_INVALID = -1,
} SocketState;

/*
 * One Listen*= line. `family` is AF_UNIX for a path, or AF_UNSPEC for a bare
 * port until socket_open_fds() resolves it to AF_INET/AF_INET6 at bind time
 * (629abfc23f -- IPv6 availability is a runtime property, not a parse-time
 * one). `type` is SOCK_STREAM (ListenStream=) or SOCK_DGRAM (ListenDatagram=).
 */
typedef struct SocketPort {
        /* First member, so manager-loop.c's epoll dispatch can cast
         * events[i].data.ptr straight back to this -- same discipline as
         * struct pico_cgroup's epoll_tag (see cgroups-v2.h). */
        struct pico_epoll_tag epoll_tag;

        struct SocketPort *next; /* tail-appended: fd order == declared Listen* order (H12) */
        struct Socket *socket;   /* owning unit, borrowed */

        int family;   /* AF_UNIX, or AF_UNSPEC until bound */
        int type;     /* SOCK_STREAM or SOCK_DGRAM */
        int fd;       /* -1 until socket_open_fds() binds it; H13: written only on success */
        bool watched; /* epoll_ctl'd; guards a double ADD/DEL */

        char *path;    /* AF_UNIX only, owned, absolute */
        uint16_t port; /* AF_INET/AF_INET6 only, host byte order */
} SocketPort;

typedef struct Socket {
        Unit unit; /* must be first: a Socket* is a Unit* */

        SocketState state;
        SocketPort *ports; /* singly linked, declaration order; NULL means "no Listen* yet" */

        bool accept;        /* Accept=; must stay false, socket_verify_and_pair() fails the load otherwise */
        Unit *service;      /* the paired service, borrowed; resolved at parse time */
        char *service_name; /* Service= override value, owned; consumed once paired */

        mode_t socket_mode; /* SocketMode=; default 0666 */
        int backlog;        /* Backlog=; default INT_MAX (768fcd779f) -- let the kernel clamp it */

        /*
         * Trigger ratelimit: a hardcoded 20 tokens per 2s window, the same
         * token-bucket shape as service.c's own start-rate limiter
         * (service_start_limit_check()). Deliberately not a parseable
         * TriggerLimitIntervalSec=/TriggerLimitBurst= pair -- see socket.c's
         * header for why these two numbers specifically.
         */
        usec_t trigger_ratelimit_begin;
        unsigned trigger_ratelimit_num;
} Socket;

/* downcast/upcast helpers, valid because Unit is the first member. Named
 * SOCKET_UNIT rather than target.h's UNIT() spelling because service.h
 * already defines UNIT(s) for Service*, and both headers are included
 * together in this file and in unit-parse.c. */
#define SOCKET(u) ((Socket *) (u))
#define SOCKET_UNIT(s) (&(s)->unit)

extern const UnitVTable socket_vtable;

const char *socket_state_to_string(SocketState s);

/*
 * EPOLLIN on a .socket unit's listening fd. Under Accept=no PID 1 never
 * accept()s -- the connection stays queued in the backlog and is handed to
 * the paired service, which is what makes the socket survive a service
 * restart. `tag` is the registration's data.ptr; the implementation casts it
 * back to its own containing struct. 0 or -errno.
 */
int socket_dispatch_io(Manager *m, struct pico_epoll_tag *tag);

/*
 * Collect the fds a starting service should inherit from its paired
 * .socket unit(s), if any. Called on ANY service start, not just a
 * socket-triggered one: a service started at boot with its socket already
 * listening must get the same fds the same way (the journald arrangement,
 * and the one logd relies on).
 *
 * Returns the number of fds written to `fds` (0 when the service has no
 * paired socket), or -errno. `fds` is caller-owned, `n_fds` its capacity.
 */
int socket_collect_fds(Unit *service, int *fds, size_t n_fds);

/*
 * A service that is about to fork with fds collected via socket_collect_fds()
 * above must stop treating any paired socket's LISTENING state as "PID 1
 * owns this fd" -- from here the service does, until it dies (d137a488af).
 * Called from service-exec.c's service_spawn(), before fork(), for both a
 * socket-triggered start (already RUNNING: a no-op) and a boot-ordered start
 * (still LISTENING: unwatches and transitions to RUNNING). Idempotent.
 */
void socket_notify_service_starting(Unit *service);

/* The paired service died: re-arm RUNNING -> LISTENING so the next
 * connection triggers it again -- unless the service's own start-limit is
 * what killed it, in which case the socket goes FAILED instead, so it does
 * not immediately re-trigger the same crash loop (c2f3480897, "so sockets
 * won't act as tarpits"). No-op for a socket not currently RUNNING. */
void socket_notify_service_dead(Unit *service);

/*
 * Called by unit-parse.c once a [Socket] fragment has finished parsing
 * (never on a stub/unloaded unit -- see 75193d4128 in socket.c's header).
 * Validates the section (at least one Listen*, Accept=no) and resolves
 * service pairing: the explicit Service= override if given, else the
 * same-basename suffix swap. Also records the auto-Before= edge onto the
 * paired service (and, via unit_add_dependency()'s inverse, its After= back).
 * 0 or -errno; -errno fails the whole unit's load.
 */
int socket_verify_and_pair(Socket *s);
