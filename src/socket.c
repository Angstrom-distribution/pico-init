/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Socket units, quarried from systemd's ~2011-era src/socket.c and
 * src/socket-util.c (tag v30, commit 501c92c, copyright 2010 Lennart
 * Poettering, GPL-2.0-or-later), trimmed to ListenStream=/ListenDatagram=
 * (unix path or bare port), Accept=, MaxConnections= and DEAD/LISTENING/
 * RUNNING/FAILED -- no socket-side Exec*=, no Symlinks=/PassCredentials=/
 * ListenFIFO=/ListenSpecial=/ListenMessageQueue=/ListenNetlink=/
 * ListenSequentialPacket=. See plans/29-pico-init.md §1.6 for the full scope
 * decision.
 *
 * Accept=yes is v30's socket_enter_running() cfd branch: one accept() per
 * wakeup, a prefix@<instance>.service loaded for it (through unit-load.c's
 * template fallback, so %i expands to the instance), the connection handed
 * over as that instance's only LISTEN_FDS fd, and the socket itself never
 * leaving LISTENING. What v30 got from its general unit GC is done here
 * directly: once an instance is down with no job left, socket_reap_
 * connections() closes PID 1's copy of the fd and drops the instance from
 * the unit table, so a long-lived listener does not grow the table by one
 * unit per connection. Upstream's later StandardInput=socket is not
 * carried; see socket_instance_refused().
 *
 * Quarry-history review: 591 commits touch this file between 501c92c and
 * upstream main (git rev-list --count 501c92c..main -- src/core/socket.c
 * src/socket.c; --follow undercounts to 26 across the 2012 src/->src/core/
 * move). Triage: 267 cosmetic, 284 dropped-surface (Accept=yes, Symlinks=,
 * D-Bus, SELinux, cgroup v1/namespaces, socket-side Exec*=, the tunables this
 * file does not parse), 40 touching logic this file actually carries, ~80
 * read in full.
 *
 * Backported fixes, each in the function it applies to:
 *
 *  - 8b26cdbd2a "add TriggerLimitIntervalSec=/TriggerLimitBurst=" +
 *    1f15ce2846 (default retune) -- socket_trigger_ratelimit_check().
 *    Upstream's parseable directives are not carried; the values are
 *    hardcoded at 20 tokens / 2s (NOT the 2500/5s the plan's §1.6 draft
 *    implied from the commit titles alone -- verified against the actual
 *    diff, corrected here). 1f15ce2846's separate Accept=yes default of 200
 *    is taken too: there every trigger is one accept(), not one start of a
 *    shared service.
 *  - 77b088c211 "socket: make sure that the name for per-connection services
 *    are unique" -- socket_instance_name() prefixes every instance with the
 *    n_accepted counter, which v30's inet names lacked; 2b061f5a4b's
 *    IPv4-in-IPv6 formatting is already in v30 and kept.
 *  - c2f3480897 "fail socket unit when service has reached the start limit,
 *    so sockets won't act as tarpits" -- socket_notify_service_dead(): a
 *    paired service dying with SERVICE_FAILURE_START_LIMIT is terminal for
 *    the socket too, not a re-listen. No new field needed: service.h already
 *    exposes Service.result and SERVICE_FAILURE_START_LIMIT.
 *  - 16ac401407 .. 60d9771c59 "flushing a socket by closing and reopening it
 *    never reopens it" -- NOT lifted. v30's socket_close_fds() sets every
 *    port's fd to -1, and socket_watch_fds() skips every fd < 0, so v30's own
 *    "flush by closing and reopening" branch leaks the listener with nothing
 *    watching it and, for AF_UNIX, a stale path still on disk. socket_dispatch
 *    _io()'s stop-pending branch drains in place instead (accept()+close()
 *    for a stream port, recv(MSG_DONTWAIT) for a datagram one) and never
 *    touches the fd -- see socket_drain_port().
 *  - d54ddab8cb "don't watch listening sockets that are supposed to go away"
 *    -- socket_notify_service_dead() only re-arms a socket whose paired
 *    service reached a GENUINELY terminal state. v30's own notify path (via
 *    service.c:1470-79 in that era) folds SERVICE_STOP/STOP_SIGTERM/
 *    STOP_SIGKILL/STOP_POST into the same set as the real terminal states;
 *    pico's reduced state machine has exactly one function that reaches a
 *    terminal state (service_enter_dead(), plus the direct-to-FAILED
 *    start-limit branch in service_do_start()), so gating on those two call
 *    sites *is* gating on "genuinely terminal" -- no intermediate-stop noise
 *    to filter here in the first place.
 *  - 640ace4a8d "check that unit is not NULL before starting it" --
 *    socket_trigger(): a socket with no resolvable paired service goes
 *    FAILED (fds unwatched and closed), never a bare early return -- a bare
 *    return would leave the fd both open and readable with nothing ever
 *    consuming the event again, spinning epoll_wait() at 100% CPU on real
 *    PID 1. The load-time half of this fix is socket_verify_and_pair()
 *    refusing to load a socket whose service cannot be resolved at all.
 *  - d137a488af "make sure to generate a proper state change when a service
 *    ends up in RUNNING via a start not triggered by its socket" --
 *    socket_notify_service_starting(), called from service-exec.c's
 *    service_spawn() before fork(), for every start (socket-triggered or
 *    boot-ordered alike) that is about to hand fds to a service.
 *  - 768fcd779f "socket: default to accepting up to SOMAXCONN connections,
 *    not overriding the sysctl" -- socket_init() defaults s->backlog to
 *    INT_MAX rather than SOMAXCONN (v30 line 69); listen()'s own kernel-side
 *    clamp against net.core.somaxconn is what should apply, and hardcoding
 *    SOMAXCONN at compile time silently overrides a downward-tuned sysctl.
 *  - a2c7f25aec "socket: fix SocketMode= to not depend on umask" --
 *    socket_bind_unix()'s umask sandwich applies SocketMode= exactly
 *    (`umask(~socket_mode & 0777)`), dropping v30's `| old_mask` fold-in
 *    of the ambient umask (socket-util.c line ~448). SocketMode=0666 under
 *    a 022 umask must still yield 0666, not 0644 -- this directly affects
 *    logd.socket, which specifies 0666.
 *  - 629abfc23f (landed via 7377964d4c) "make IPv6 detection more
 *    fine-grained" -- socket_ipv6_supported() tests /proc/net/if_inet6
 *    directly rather than a compile-time #ifdef, deciding AF_INET6
 *    (dual-stack) vs AF_INET for a bare `ListenStream=<port>` at bind time.
 *  - de3756ab99 "core: make collect_fds() more robust" -- N/A by
 *    construction rather than lifted: v30's version allocates its own
 *    `int*` array (`new(int, n_fds)`, which malloc(0) may legally return
 *    NULL for, misread as -ENOMEM on a socket with zero open ports).
 *    socket_collect_fds() here writes into a caller-owned buffer and never
 *    allocates, so the zero-fds case is simply "returns 0" with nothing to
 *    get wrong.
 *  - 5dcadb4c83 "event source must be disabled before being freed" --
 *    socket_unwatch_port() always issues EPOLL_CTL_DEL before the fd is ever
 *    closed, in every path that closes one (socket_shutdown_fds(),
 *    socket_notify_service_starting()'s RUNNING transition unwatches but
 *    does not close -- see H7 below). manager-loop.c's own pass-1/pass-2
 *    split (see its header) is what makes it safe to unwatch a port from
 *    inside the very socket_dispatch_io() call that fired for it: nothing
 *    else in the current epoll batch can still be holding a stale
 *    events[i].data.ptr into a port this call just closed, because closing
 *    only ever happens on the trigger-ratelimit-exhausted or stop-pending
 *    paths, both of which return immediately afterward.
 *  - 4c2ef32767 "sockets: fix state after reload for sockets that are
 *    supposed to be up" (#4708) -- socket_notify_service_dead() re-arms
 *    unconditionally on a genuinely terminal service death; nothing here
 *    gates on the SOCKET unit's own load state the way the reload-era bug
 *    did, since pico's reload never re-reads a socket unit (unit-reload.c).
 *  - 4c523d62d2 "core: unify how we determine if a unit is "active"" (the
 *    inactive-state-list rewritten three times upstream) -- rather than
 *    hardcoding a list of "the service is down" states at each call site,
 *    socket_notify_service_dead() is the ONE place that inspects
 *    SERVICE(service)->result and decides FAILED-vs-relisten; both service.c
 *    call sites just call it unconditionally on reaching their own terminal
 *    state, with no bespoke logic of their own.
 *  - b50f6dbe57 "socket: if we fail to establish an activation connection
 *    don't stop the socket unit" -- socket_trigger(): only a permanent
 *    failure (no resolvable service at all) is terminal. manager_add_job()
 *    failing to even build/install the start transaction is treated as
 *    transient -- the socket stays LISTENING, so a client's already-queued
 *    connection/datagram is not thrown away, and the very next re-trigger
 *    (or the next real connection) gets another chance.
 *  - 75193d4128 "socket: don't complain if we can't determine a peer's
 *    label because the connection is already gone" -- read for its general
 *    principle (a verify pass must be gated on "the fragment genuinely
 *    parsed") rather than its specific label-lookup fix, which pico does not
 *    carry: socket_verify_and_pair() is only ever invoked by
 *    unit_parse_file() after a successful parse (r == 0), never against a
 *    stub or errored unit, so it can never misreport "no Listen setting" for
 *    what is actually a totally different failure.
 *
 * One further finding, not from the socket.c quarry review but from a
 * design review of logd's receive path (plan §3): §1.6's original
 * PassCredentials=-is-unneeded reasoning ("a receiving daemon can set
 * SO_PASSCRED on its own passed-in fd") is wrong. The kernel decides
 * whether to attach SCM_CREDENTIALS to an AF_UNIX datagram at the moment it
 * is queued, based on the RECEIVING socket's SO_PASSCRED state at that
 * instant -- not at whatever later moment a consumer calls recvmsg(). A
 * datagram queued before the option is set arrives with the cmsg PRESENT
 * but ucred.pid == 0, silently mis-attributable by a naive check, and that
 * is exactly the backlog this project's whole fd-ownership design exists to
 * preserve. Fixed in socket_bind_unix(): SO_PASSCRED is set unconditionally
 * on every AF_UNIX SOCK_DGRAM port, before bind(), so no datagram this
 * process ever queues can be affected. PassCredentials= itself stays
 * accepted-and-ignored -- this needs no per-unit opt-out.
 *
 * H1-H13 (the reviewer's hazard list) and the KEEP-calls list are recorded
 * in the coordinating plan doc, not repeated in full here; each one that
 * changed a design decision in this file is cited above at its landing
 * point. Two more worth naming inline because they are easy to miss on a
 * second read: H8, register every port with bare EPOLLIN (never EPOLLET) --
 * the RUNNING -> LISTENING re-arm in socket_notify_service_dead() depends on
 * an already-readable fd re-firing the instant it is re-armed, which
 * edge-triggering would not do. H11, SOCK_CLOEXEC on every socket() call, so
 * a listening fd this process is not currently handing to a child never
 * leaks into an unrelated fork.
 *
 * NOT carried forward, and why: `bd1fe7c79d` (RemoveOnStop=) is cited only
 * as a reference for socket_stop()'s unlink-on-stop -- v30 has NO
 * unlink-on-stop at all and explicitly argues against one in
 * socket_close_fds()'s own comment ("we should never delete any sockets in
 * the file system here"); this file adds it anyway, deliberately, gated the
 * way H3 requires (AF_UNIX only, only a port this unit actually had open,
 * and an fstat()/lstat() dev+ino comparison against the live path before
 * unlinking it -- see socket_unlink_if_owned()). `2bec84e7a5` (PollLimit*) is
 * structurally inert here: every port is unwatched on leaving LISTENING and
 * re-armed fresh on the way back in, so a per-registration accept burst
 * counter could never accumulate across two live epoll registrations the
 * way it would need to. `12ab94a1e4`+`40f41f34d4` (propagate a failed
 * Condition* to the triggering socket) is explicitly NOT taken -- upstream
 * shipped it and reverted it two months later for making a socket go DEAD
 * (dropping the fd, unbinding the path) over one activation's failed
 * condition.
 */

/* accept4() is a glibc extension, guarded by __USE_GNU; -std=gnu17 alone
 * does not imply _GNU_SOURCE (same reasoning as netd-time.c/
 * test-netd-rtnl.c), so this has to be explicit and first, before any
 * header pulls in <sys/socket.h> under a narrower feature-test setting. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "job.h"
#include "manager.h"
#include "sd-event.h"
#include "service.h"
#include "socket.h"
#include "unit-name.h"
#include "unit.h"
#include "util.h"

/* 8b26cdbd2a/1f15ce2846, corrected against the real diff rather than the
 * plan's draft: 20 triggers per 2s window, hardcoded -- see this file's
 * header for why no TriggerLimitIntervalSec=/TriggerLimitBurst= directive
 * exists to override it. */
#define PICO_SOCKET_TRIGGER_LIMIT_INTERVAL_USEC (2 * USEC_PER_SEC)
#define PICO_SOCKET_TRIGGER_LIMIT_BURST 20
#define PICO_SOCKET_TRIGGER_LIMIT_BURST_ACCEPT 200

/* v30 socket_init(): MaxConnections= default. */
#define PICO_SOCKET_MAX_CONNECTIONS_DEFAULT 64

/* --- string table --- */

static const char * const socket_state_table[_SOCKET_STATE_MAX] = {
        [SOCKET_DEAD] = "dead",
        [SOCKET_LISTENING] = "listening",
        [SOCKET_RUNNING] = "running",
        [SOCKET_FAILED] = "failed",
};

const char *socket_state_to_string(SocketState s) {
        if (s < 0 || s >= _SOCKET_STATE_MAX)
                return "invalid";

        return socket_state_table[s];
}

/* --- IPv6 detection (629abfc23f) --- */

static bool socket_ipv6_supported(void) {
        struct stat st;

        return stat("/proc/net/if_inet6", &st) == 0;
}

/* --- event registration: one port at a time --- */

static int socket_watch_port(Manager *m, SocketPort *p) {
        int r;

        if (p->event_source)
                return 0;

        /* H8: bare EPOLLIN, never EPOLLET -- the RUNNING -> LISTENING
         * re-arm below depends on an already-readable fd re-firing the
         * instant it is re-armed, which edge-triggering would not do. */
        r = sd_event_add_io(m->event, &p->event_source, p->fd, EPOLLIN, socket_dispatch_io, p);
        if (r < 0)
                return r;

        sd_event_source_set_priority(p->event_source, EVENT_PRIORITY_SOCKET);
        return 0;
}

/* 5dcadb4c83: always before the fd is closed. Safe to call on a port never
 * watched (idempotent via p->event_source) and on one that already is.
 * disable_unref, never fd_own on the source itself: the fd stays open,
 * ours to hand to the service or close later -- only the registration
 * goes. */
static void socket_unwatch_port(Manager *m, SocketPort *p) {
        (void) m;

        if (!p->event_source)
                return;

        p->event_source = sd_event_source_disable_unref(p->event_source);
}

static void socket_watch_fds(Socket *s) {
        Manager *m = SOCKET_UNIT(s)->manager;
        SocketPort *p;

        for (p = s->ports; p; p = p->next) {
                int r;

                if (p->fd < 0)
                        continue;

                r = socket_watch_port(m, p);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "%s: failed to watch a listening fd: %s",
                                 SOCKET_UNIT(s)->id,
                                 strerror(-r));
        }
}

/* H7: unwatch WITHOUT closing -- this is the whole difference between
 * RUNNING (fd open, handed to the service, not ours to read from any more)
 * and DEAD/FAILED (fd fully closed). Collapsing the two loses the property
 * that makes socket_notify_service_dead()'s re-arm possible without
 * reopening anything. */
static void socket_unwatch_fds(Socket *s) {
        Manager *m = SOCKET_UNIT(s)->manager;
        SocketPort *p;

        for (p = s->ports; p; p = p->next) {
                if (p->fd < 0)
                        continue;
                socket_unwatch_port(m, p);
        }
}

/* --- H3: unlink-on-stop, gated --- */

/*
 * Only ever called on an AF_UNIX port this unit itself still has open.
 * fstat()s the live fd and lstat()s the path, and unlinks only if they name
 * the same inode -- the guard against the race bd1fe7c79d's own commit
 * message calls out: a stop racing a fresh instance's bind() must never
 * delete the new listener's path out from under it, only ever the exact
 * inode this port bound.
 */
static void socket_unlink_if_owned(SocketPort *p) {
        struct stat fd_st, path_st;

        if (p->family != AF_UNIX || !p->path) /* H5: family, never sun_path bytes */
                return;

        if (fstat(p->fd, &fd_st) < 0)
                return;

        if (lstat(p->path, &path_st) < 0)
                return;

        if (fd_st.st_dev == path_st.st_dev && fd_st.st_ino == path_st.st_ino)
                unlink(p->path);
}

/*
 * Unwatch and close every open port. `unlink_owned` additionally removes an
 * AF_UNIX path this unit still owns (socket_stop()'s orderly-stop path);
 * never passed true from the ratelimit-exhausted or "no service" failure
 * paths -- an unowned crash should not also start deleting files, and
 * socket_bind_unix()'s stale-unlink-at-bind (H6) already recovers the path
 * safely the next time this unit starts.
 */
static void socket_shutdown_fds(Socket *s, bool unlink_owned) {
        Manager *m = SOCKET_UNIT(s)->manager;
        SocketPort *p;

        for (p = s->ports; p; p = p->next) {
                if (p->fd < 0)
                        continue;

                socket_unwatch_port(m, p);

                if (unlink_owned)
                        socket_unlink_if_owned(p);

                close(p->fd);
                p->fd = -1;
        }
}

/* --- binding --- */

static int socket_mkdir_parents(const char *path, mode_t mode) {
        char buf[PATH_MAX];
        char *slash;
        int n;

        n = snprintf(buf, sizeof(buf), "%s", path);
        if (n < 0 || (size_t) n >= sizeof(buf))
                return -ENAMETOOLONG;

        for (slash = strchr(buf + 1, '/'); slash; slash = strchr(slash + 1, '/')) {
                *slash = '\0';
                if (mkdir(buf, mode) < 0 && errno != EEXIST) {
                        int e = errno;
                        *slash = '/';
                        return -e;
                }
                *slash = '/';
        }

        return 0;
}

/*
 * H6: the one security-relevant finding on this path. bind() returns
 * EADDRINUSE for AF_UNIX whenever ANYTHING already exists at the target
 * path, not only a stale socket -- so retrying after an unconditional
 * unlink() would let `ListenStream=/etc/passwd` make PID 1 delete
 * /etc/passwd. S_ISSOCK() must be checked before the retry-unlink, not
 * after: this is the gate, not the retry itself.
 */
static int socket_bind_unix(SocketPort *p, mode_t socket_mode, int backlog) {
        struct sockaddr_un addr;
        struct stat st;
        mode_t old_mask;
        int fd, one = 1, r;

        if (strlen(p->path) >= sizeof(addr.sun_path))
                return -ENAMETOOLONG;

        r = socket_mkdir_parents(p->path, 0755);
        if (r < 0)
                return r;

        /* H11: SOCK_CLOEXEC so this fd never leaks into a child this
         * process forks for anything other than socket_collect_fds(). */
        fd = socket(AF_UNIX, p->type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        /* H9: unconditional, before bind(), matching v30 -- harmless no-op
         * for AF_UNIX, but kept uniform with the AF_INET/6 path below. */
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        /*
         * SO_PASSCRED, before bind(), for a datagram port only. Not merely
         * a convenience over the receiving daemon setting it on its own
         * inherited fd: the kernel decides whether to attach SCM_CREDENTIALS
         * to an AF_UNIX datagram at the moment it is QUEUED to this socket,
         * based on THIS socket's SO_PASSCRED state at that instant -- not at
         * whatever later moment a service calls recvmsg(). A datagram
         * queued before the service sets the option arrives with the cmsg
         * PRESENT but ucred.pid == 0, which is worse than absent (a naive
         * "cmsg found -> trust it" check silently attributes the record to
         * pid 0). Those are exactly the datagrams that queued while the
         * service was dead -- the backlog the whole fd-ownership design
         * exists to preserve -- so setting this on the receiver's own
         * inherited fd is always too late for them. PassCredentials= stays
         * an accepted-and-ignored directive (no per-unit opt-out needed:
         * every consumer either reads ucred or does not).
         */
        if (p->type == SOCK_DGRAM) {
                if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0) {
                        r = -errno;
                        close(fd);
                        return r;
                }
        }

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        memcpy(addr.sun_path, p->path, strlen(p->path) + 1);

        /*
         * H10/a2c7f25aec: the umask sandwich, not a post-bind chmod() -- a
         * literal chmod after bind() opens a TOCTOU window where the socket
         * is live at its final path under the process's ambient umask
         * (typically world-connectable). SocketMode= is applied exactly:
         * no "| old_mask" fold-in the way v30 had it, so SocketMode=0666
         * under a 022 umask still yields 0666, not 0644.
         */
        old_mask = umask(~socket_mode & 0777);

        r = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
        if (r < 0 && errno == EADDRINUSE && stat(p->path, &st) == 0 && S_ISSOCK(st.st_mode)) {
                unlink(p->path);
                r = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
        }

        umask(old_mask);

        if (r < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        if (p->type == SOCK_STREAM && listen(fd, backlog) < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        p->family = AF_UNIX;
        p->fd = fd; /* H13: written only on success */
        return 0;
}

static int socket_bind_inet(SocketPort *p, int backlog) {
        union {
                struct sockaddr_in in;
                struct sockaddr_in6 in6;
        } addr;
        socklen_t addrlen;
        int family, fd, one = 1, r;

        /* 629abfc23f: decided here, at bind time, not at parse time -- IPv6
         * availability is a kernel/runtime property. */
        family = socket_ipv6_supported() ? AF_INET6 : AF_INET;

        fd = socket(family, p->type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        /* H9: unconditional, before bind() -- without it a TCP listener
         * cannot rebind through TIME_WAIT and every restart of this socket
         * unit fails EADDRINUSE. */
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        memset(&addr, 0, sizeof(addr));
        if (family == AF_INET6) {
                addr.in6.sin6_family = AF_INET6;
                addr.in6.sin6_addr = in6addr_any;
                addr.in6.sin6_port = htons(p->port);
                addrlen = sizeof(addr.in6);
        } else {
                addr.in.sin_family = AF_INET;
                addr.in.sin_addr.s_addr = INADDR_ANY;
                addr.in.sin_port = htons(p->port);
                addrlen = sizeof(addr.in);
        }

        if (bind(fd, (struct sockaddr *) &addr, addrlen) < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        if (p->type == SOCK_STREAM && listen(fd, backlog) < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        p->family = family;
        p->fd = fd;
        return 0;
}

/* Idempotent (v30 socket.c:875): a port whose fd is already open is left
 * alone. On any failure, every port this call itself opened is rolled back
 * -- a partially-bound socket unit must never look started. */
static int socket_open_fds(Socket *s) {
        SocketPort *p;

        for (p = s->ports; p; p = p->next) {
                int r;

                if (p->fd >= 0)
                        continue;

                r = p->path ? socket_bind_unix(p, s->socket_mode, s->backlog) :
                              socket_bind_inet(p, s->backlog);

                if (r < 0) {
                        pico_log(PICO_LOG_ERR, "%s: failed to listen: %s", SOCKET_UNIT(s)->id, strerror(-r));
                        socket_shutdown_fds(s, false);
                        return r;
                }
        }

        return 0;
}

/* --- state machine --- */

static UnitActiveState socket_active_state_of(SocketState state) {
        switch (state) {
        case SOCKET_DEAD:
                return UNIT_INACTIVE;
        case SOCKET_LISTENING:
        case SOCKET_RUNNING:
                return UNIT_ACTIVE;
        case SOCKET_FAILED:
                return UNIT_FAILED;
        default:
                return UNIT_INACTIVE;
        }
}

static void socket_set_state(Socket *s, SocketState state) {
        UnitActiveState old_active, new_active;

        if (s->state == state)
                return;

        old_active = socket_active_state_of(s->state);
        s->state = state;
        new_active = socket_active_state_of(s->state);

        unit_notify(SOCKET_UNIT(s), old_active, new_active);
}

/* Used both for a fresh start (fds just opened) and for re-arming after a
 * paired service dies (fds already open, only unwatched) -- watching an
 * already-watched port is a no-op, so this is safe either way. */
static void socket_enter_listening(Socket *s) {
        socket_watch_fds(s);
        socket_set_state(s, SOCKET_LISTENING);
}

static void socket_enter_running_state(Socket *s) {
        socket_unwatch_fds(s); /* H7: open, but no longer ours to watch */
        socket_set_state(s, SOCKET_RUNNING);
}

static void socket_enter_failed(Socket *s) {
        socket_shutdown_fds(s, false);
        socket_set_state(s, SOCKET_FAILED);
}

static int socket_start_impl(Unit *u) {
        Socket *s = SOCKET(u);
        int r;

        switch (s->state) {
        case SOCKET_LISTENING:
        case SOCKET_RUNNING:
                return 0; /* idempotent */
        case SOCKET_DEAD:
        case SOCKET_FAILED:
                break;
        default:
                return -EINVAL;
        }

        r = socket_open_fds(s);
        if (r < 0) {
                socket_set_state(s, SOCKET_FAILED);
                return r;
        }

        socket_enter_listening(s);
        return 0;
}

static int socket_stop_impl(Unit *u) {
        Socket *s = SOCKET(u);

        switch (s->state) {
        case SOCKET_DEAD:
        case SOCKET_FAILED:
                return 0; /* already stopped */
        default:
                break;
        }

        /* Orderly stop: close AND unlink whatever AF_UNIX path this unit
         * still owns (H3/bd1fe7c79d) -- the one path that unlinks on stop,
         * deliberately not shared with the ratelimit/no-service failure
         * paths above. */
        socket_shutdown_fds(s, true);
        socket_set_state(s, SOCKET_DEAD);
        return 0;
}

static UnitActiveState socket_active_state_thunk(Unit *u) {
        return socket_active_state_of(SOCKET(u)->state);
}

static void socket_init(Unit *u) {
        Socket *s = SOCKET(u);

        s->state = SOCKET_DEAD;
        s->socket_mode = 0666;
        s->backlog = INT_MAX; /* 768fcd779f: let the kernel clamp against the real sysctl */
        s->max_connections = PICO_SOCKET_MAX_CONNECTIONS_DEFAULT;
}

static void socket_done(Unit *u) {
        Socket *s = SOCKET(u);

        /* Teardown, not an orderly stop: never unlinks. A unit being freed
         * (manager_free() tearing down the whole table, or a load error)
         * is not the deliberate stop socket_stop_impl() is for. */
        socket_shutdown_fds(s, false);

        while (s->ports) {
                SocketPort *p = s->ports;

                s->ports = p->next;
                pico_mfree(p->path);
                free(p);
        }

        s->service_name = pico_mfree(s->service_name);
        /* s->service is borrowed: never freed here. */

        /* Only PID 1's fd copies: an instance may already be gone
         * (manager_free() frees in table order), so none is touched. */
        while (s->connections) {
                SocketConnection *c = s->connections;

                s->connections = c->next;
                close(c->fd);
                free(c);
        }
        s->n_connections = 0;

        s->reap_source = sd_event_source_disable_unref(s->reap_source);
}

const UnitVTable socket_vtable = {
        /*
         * S0's one hard requirement: this must be sizeof(Socket), never
         * sizeof(Unit) -- unit_new() calloc()s exactly this many bytes, and
         * the scaffolding's placeholder value would corrupt the heap on the
         * first write to a Socket-only field.
         */
        .object_size = sizeof(Socket), .init = socket_init,      .done = socket_done,
        .start = socket_start_impl,    .stop = socket_stop_impl, .active_state = socket_active_state_thunk,
};

/* --- triggering --- */

/* Same token-bucket shape as service.c's service_start_limit_check(); see
 * this file's header for why the numbers are hardcoded rather than
 * parseable. */
static unsigned socket_trigger_limit_burst(const Socket *s) {
        return s->accept ? PICO_SOCKET_TRIGGER_LIMIT_BURST_ACCEPT : PICO_SOCKET_TRIGGER_LIMIT_BURST;
}

static bool socket_trigger_ratelimit_check(Socket *s) {
        usec_t now = now_monotonic();

        if (s->trigger_ratelimit_begin == 0 ||
            now - s->trigger_ratelimit_begin > PICO_SOCKET_TRIGGER_LIMIT_INTERVAL_USEC) {
                s->trigger_ratelimit_begin = now;
                s->trigger_ratelimit_num = 1;
                return true;
        }

        return ++s->trigger_ratelimit_num <= socket_trigger_limit_burst(s);
}

/* H1/16ac401407..60d9771c59: what v30's broken close-and-reopen was trying
 * to do, done correctly -- drain whatever is queued without ever touching
 * the listening fd itself. */
static void socket_drain_port(SocketPort *p) {
        if (p->type == SOCK_STREAM) {
                for (;;) {
                        int cfd = accept4(p->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);

                        if (cfd < 0)
                                break;
                        close(cfd);
                }
        } else {
                for (;;) {
                        char buf[256];
                        ssize_t n = recv(p->fd, buf, sizeof(buf), MSG_DONTWAIT);

                        if (n < 0)
                                break;
                }
        }
}

/*
 * H2: v30's "is a start already pending" scan (LIST_FOREACH over every
 * service checking service->configured_sockets) is dead code for basename
 * pairing -- that set is only ever populated from Sockets= in [Service],
 * which pico does not parse, so the set is always empty and the scan never
 * finds anything. Worse, this project's job model has no JOB_REPLACE merge:
 * a second manager_add_job(JOB_START) for a unit that already has one
 * installed would silently overwrite unit->job and leak the first Job
 * object (see job.c's job_install()). So: if the service already has any
 * job in flight, or is already active/activating, there is nothing new to
 * queue -- just note that we are (still) RUNNING and return.
 */
static int socket_trigger(Socket *s) {
        Unit *svc = s->service;
        UnitActiveState st;
        int r;

        if (!svc) {
                /* 640ace4a8d: never a bare return -- that would leave the fd
                 * both open and readable with nothing left to ever consume
                 * the event again. */
                pico_log(PICO_LOG_ERR, "%s: no paired service, failing", SOCKET_UNIT(s)->id);
                socket_enter_failed(s);
                return -ENOENT;
        }

        st = unit_active_state(svc);
        if (svc->job || st == UNIT_ACTIVE || st == UNIT_ACTIVATING) {
                socket_enter_running_state(s);
                return 0;
        }

        r = manager_add_job(SOCKET_UNIT(s)->manager, JOB_START, svc, NULL);
        if (r < 0) {
                /* b50f6dbe57: only a permanent failure (no service at all,
                 * handled above) is terminal -- a transient failure to even
                 * build the start transaction (e.g. -ENOMEM) must not throw
                 * away the client data already queued in the backlog, so
                 * stay LISTENING and let the next trigger try again. */
                pico_log(PICO_LOG_WARNING,
                         "%s: failed to queue start of %s: %s",
                         SOCKET_UNIT(s)->id,
                         svc->id,
                         strerror(-r));
                return r;
        }

        socket_enter_running_state(s);
        return 0;
}

/* --- Accept=yes: one instance per connection --- */

/*
 * v30 instance_from_socket(), plus 77b088c211's leading connection number:
 * "<nr>-<local>-<remote>" for IP, "<nr>-<pid>-<uid>" of the peer for
 * AF_UNIX, written into `ret` as the full prefix@<instance>.service name.
 * 0 or -errno.
 */
static int socket_instance_name(Socket *s, int cfd, char *ret, size_t size) {
        union {
                struct sockaddr sa;
                struct sockaddr_in in;
                struct sockaddr_in6 in6;
                struct sockaddr_storage storage;
        } local, remote;
        static const uint8_t ipv4_prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
        char instance[UNIT_NAME_MAX + 1];
        unsigned nr = s->n_accepted;
        socklen_t l;
        char *prefix;
        int n;

        l = sizeof(local);
        if (getsockname(cfd, &local.sa, &l) < 0)
                return -errno;

        l = sizeof(remote);
        if (getpeername(cfd, &remote.sa, &l) < 0)
                return -errno;

        switch (local.sa.sa_family) {
        case AF_INET: {
                uint32_t a = ntohl(local.in.sin_addr.s_addr), b = ntohl(remote.in.sin_addr.s_addr);

                n = snprintf(instance,
                             sizeof(instance),
                             "%u-%u.%u.%u.%u:%u-%u.%u.%u.%u:%u",
                             nr,
                             a >> 24,
                             (a >> 16) & 0xFF,
                             (a >> 8) & 0xFF,
                             a & 0xFF,
                             ntohs(local.in.sin_port),
                             b >> 24,
                             (b >> 16) & 0xFF,
                             (b >> 8) & 0xFF,
                             b & 0xFF,
                             ntohs(remote.in.sin_port));
                break;
        }
        case AF_INET6:
                /* 2b061f5a4b: a dual-stack listener sees IPv4 peers as
                 * ::ffff:a.b.c.d -- name them the way AF_INET would. */
                if (memcmp(local.in6.sin6_addr.s6_addr, ipv4_prefix, sizeof(ipv4_prefix)) == 0 &&
                    memcmp(remote.in6.sin6_addr.s6_addr, ipv4_prefix, sizeof(ipv4_prefix)) == 0) {
                        const uint8_t *a = local.in6.sin6_addr.s6_addr + 12,
                                      *b = remote.in6.sin6_addr.s6_addr + 12;

                        n = snprintf(instance,
                                     sizeof(instance),
                                     "%u-%u.%u.%u.%u:%u-%u.%u.%u.%u:%u",
                                     nr,
                                     a[0],
                                     a[1],
                                     a[2],
                                     a[3],
                                     ntohs(local.in6.sin6_port),
                                     b[0],
                                     b[1],
                                     b[2],
                                     b[3],
                                     ntohs(remote.in6.sin6_port));
                } else {
                        char a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];

                        if (!inet_ntop(AF_INET6, &local.in6.sin6_addr, a, sizeof(a)) ||
                            !inet_ntop(AF_INET6, &remote.in6.sin6_addr, b, sizeof(b)))
                                return -errno;

                        n = snprintf(instance,
                                     sizeof(instance),
                                     "%u-%s:%u-%s:%u",
                                     nr,
                                     a,
                                     ntohs(local.in6.sin6_port),
                                     b,
                                     ntohs(remote.in6.sin6_port));
                }
                break;
        case AF_UNIX: {
                struct ucred ucred;

                l = sizeof(ucred);
                if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &ucred, &l) < 0)
                        return -errno;

                n = snprintf(instance,
                             sizeof(instance),
                             "%u-%lu-%lu",
                             nr,
                             (unsigned long) ucred.pid,
                             (unsigned long) ucred.uid);
                break;
        }
        default:
                return -EAFNOSUPPORT;
        }

        if (n < 0 || (size_t) n >= sizeof(instance))
                return -ENAMETOOLONG;

        prefix = unit_name_to_prefix(SOCKET_UNIT(s)->id);
        if (!prefix)
                return -ENOMEM;

        n = snprintf(ret, size, "%s@%s.service", prefix, instance);
        free(prefix);
        if (n < 0 || (size_t) n >= size)
                return -ENAMETOOLONG;

        return 0;
}

/*
 * The connection reaches an instance only as its one LISTEN_FDS fd.
 * StandardInput= is not parsed, so it lands in the degradation record, and
 * an inetd-style template asking for the connection on stdin (oe-core's
 * dropbear@.service, StandardInput=socket) would run with the console there
 * instead -- the silently wrong per-connection behaviour Accept=yes used to
 * be refused outright to prevent. Refuse that connection loudly instead.
 */
static bool socket_instance_refused(Unit *svc) {
        char **p;

        for (p = svc->degraded_directives; p && *p; p++)
                if (strcmp(*p, "StandardInput") == 0)
                        return true;

        return false;
}

/* Drop an instance from the unit table: finished, or never startable. Kept,
 * harmlessly, while another unit Requires=/Wants= it by name. */
static void socket_drop_instance(Manager *m, Unit *u) {
        int r;

        if (u->job)
                return;

        r = unit_dependency_unlink(u);
        if (r < 0) {
                pico_log(PICO_LOG_DEBUG, "%s: still referenced, keeping it: %s", u->id, strerror(-r));
                return;
        }

        manager_dequeue_cgroup_empty(m, u);
        (void) manager_remove_unit(m, u);
}

/*
 * Deferred, never called from socket_notify_service_dead() itself: that runs
 * inside service.c's and job.c's own handling of the very unit this frees,
 * which both keep using it after the notify returns. At
 * EVENT_PRIORITY_SOCKET_REAP every other source is done with it. An
 * instance still running, restarting or holding a job is left for the next
 * notify.
 */
static int socket_reap_connections(sd_event_source *es, void *userdata) {
        Socket *s = userdata;
        SocketConnection **c = &s->connections;

        (void) es;

        while (*c) {
                SocketConnection *conn = *c;
                UnitActiveState st = unit_active_state(conn->service);

                if (conn->service->job || (st != UNIT_INACTIVE && st != UNIT_FAILED)) {
                        c = &conn->next;
                        continue;
                }

                *c = conn->next;
                s->n_connections--;
                close(conn->fd);
                socket_drop_instance(SOCKET_UNIT(s)->manager, conn->service);
                free(conn);
        }

        return 0;
}

static void socket_schedule_reap(Socket *s) {
        Manager *m = SOCKET_UNIT(s)->manager;
        int r;

        if (!m || !m->event)
                return;

        if (!s->reap_source) {
                r = sd_event_add_defer(m->event, &s->reap_source, socket_reap_connections, s);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: cannot schedule connection cleanup: %s",
                                 SOCKET_UNIT(s)->id,
                                 strerror(-r));
                        return;
                }
                sd_event_source_set_priority(s->reap_source, EVENT_PRIORITY_SOCKET_REAP);
        }

        sd_event_source_set_enabled(s->reap_source, SD_EVENT_ONESHOT);
}

static bool socket_has_connection(Socket *s, Unit *service) {
        SocketConnection *c;

        for (c = s->connections; c; c = c->next)
                if (c->service == service)
                        return true;

        return false;
}

/*
 * v30 socket_enter_running()'s cfd branch. Any failure closes this one
 * connection and leaves the socket LISTENING: one bad connection is not a
 * reason to stop serving the next.
 */
static void socket_accept_one(Socket *s, SocketPort *p) {
        Manager *m = SOCKET_UNIT(s)->manager;
        char name[UNIT_NAME_MAX + 1];
        SocketConnection *c;
        Unit *svc = NULL;
        bool existed;
        int cfd, r;

        cfd = accept4(p->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != ECONNABORTED)
                        pico_log(PICO_LOG_WARNING,
                                 "%s: accept() failed: %s",
                                 SOCKET_UNIT(s)->id,
                                 strerror(errno));
                return;
        }

        if (s->n_connections >= s->max_connections) {
                pico_log(PICO_LOG_WARNING,
                         "%s: too many incoming connections (%u), refusing",
                         SOCKET_UNIT(s)->id,
                         s->n_connections);
                close(cfd);
                return;
        }

        r = socket_instance_name(s, cfd, name, sizeof(name));
        s->n_accepted++;
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s: cannot name an instance for a connection: %s",
                         SOCKET_UNIT(s)->id,
                         strerror(-r));
                close(cfd);
                return;
        }

        existed = manager_get_unit(m, name) != NULL;
        r = manager_load_unit(m, name, &svc);
        if (r < 0 || !svc || svc->type != UNIT_SERVICE || svc->load_state != UNIT_LOADED) {
                pico_log(PICO_LOG_ERR,
                         "%s: could not load %s for a connection, closing it",
                         SOCKET_UNIT(s)->id,
                         name);
                goto fail;
        }

        if (existed) {
                /* only after n_accepted wraps; never share a live instance */
                pico_log(PICO_LOG_ERR, "%s: %s already exists, closing the connection", SOCKET_UNIT(s)->id, name);
                goto fail;
        }

        if (socket_instance_refused(svc)) {
                pico_log(PICO_LOG_ERR,
                         "%s: %s wants the connection on stdin (StandardInput=), which is not supported, closing it",
                         SOCKET_UNIT(s)->id,
                         name);
                goto fail;
        }

        c = calloc(1, sizeof(*c));
        if (!c)
                goto fail;

        c->service = svc;
        c->fd = cfd;
        c->next = s->connections;
        s->connections = c;
        s->n_connections++;

        r = manager_add_job(m, JOB_START, svc, NULL);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s: failed to queue start of %s: %s",
                         SOCKET_UNIT(s)->id,
                         name,
                         strerror(-r));
                s->connections = c->next;
                s->n_connections--;
                free(c);
                goto fail;
        }

        return;

fail:
        close(cfd);
        if (svc && !existed)
                socket_drop_instance(m, svc);
}

/*
 * The events_source io callback (EVENT_PRIORITY_SOCKET). Manager is reached
 * via p->socket's unit, never through a passed-in parameter -- this IS the
 * sd_event_io_handler_t the source was registered with, so its shape is
 * fixed. Never returns < 0: the shim disables a source whose callback fails,
 * and a transient trigger failure must not permanently stop listening.
 */
int socket_dispatch_io(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        SocketPort *p = userdata;
        Socket *s;
        Job *j;
        int r;

        (void) es;
        (void) fd;
        (void) revents;

        if (!p || !p->socket)
                return 0;

        s = p->socket;

        if (s->state != SOCKET_LISTENING)
                return 0; /* stale wakeup: e.g. a sibling port in the same
                           * epoll batch already triggered RUNNING */

        j = SOCKET_UNIT(s)->job;
        if (j && (j->type == JOB_STOP || j->type == JOB_RESTART)) {
                /* H1/H4: a stop is already queued for this unit. Draining
                 * what is queued, without touching the fd, is the correct
                 * "flush" -- and per H4, this is the ONLY place a flush ever
                 * happens; FlushPending= itself is out of scope and off by
                 * default upstream for good reason (it eats a client's first
                 * datagram), so an ordinary re-trigger never drains. */
                socket_drain_port(p);
                return 0;
        }

        /* Trigger ratelimit checked AFTER the stop-pending check, BEFORE the
         * start decision -- this is what actually bounds the datagram/
         * unaccepted-backlog livelock H4 describes: readable -> RUNNING ->
         * service dies without consuming it -> re-armed LISTENING -> still
         * readable -> re-dispatch, forever, without this check. */
        if (!socket_trigger_ratelimit_check(s)) {
                pico_log(PICO_LOG_WARNING,
                         "%s: triggered too quickly (limit %u per %llu us), failing",
                         SOCKET_UNIT(s)->id,
                         socket_trigger_limit_burst(s),
                         (unsigned long long) PICO_SOCKET_TRIGGER_LIMIT_INTERVAL_USEC);
                socket_enter_failed(s);
                return 0;
        }

        if (s->accept) {
                socket_accept_one(s, p);
                return 0;
        }

        r = socket_trigger(s);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "%s: failed to trigger: %s", SOCKET_UNIT(s)->id, strerror(-r));

        return 0;
}

/* --- fd collection and the service-side notifications --- */

int socket_collect_fds(Unit *service, int *fds, size_t n_fds) {
        Manager *m;
        size_t i, n = 0;

        if (!service || !fds)
                return -EINVAL;

        m = service->manager;
        if (!m)
                return 0;

        for (i = 0; i < m->n_units; i++) {
                Unit *u = m->units[i];
                Socket *s;
                SocketPort *p;

                if (u->type != UNIT_SOCKET)
                        continue;

                s = SOCKET(u);
                if (s->accept) {
                        SocketConnection *c;

                        for (c = s->connections; c; c = c->next) {
                                if (c->service != service)
                                        continue;
                                if (n >= n_fds)
                                        return -ENOBUFS;
                                fds[n++] = c->fd;
                        }
                        continue;
                }

                if (s->service != service)
                        continue;

                for (p = s->ports; p; p = p->next) {
                        if (p->fd < 0)
                                continue;
                        if (n >= n_fds)
                                return -ENOBUFS;
                        fds[n++] = p->fd;
                }
        }

        return (int) n;
}

void socket_notify_service_starting(Unit *service) {
        Manager *m;
        size_t i;

        if (!service)
                return;

        m = service->manager;
        if (!m)
                return;

        for (i = 0; i < m->n_units; i++) {
                Unit *u = m->units[i];
                Socket *s;

                if (u->type != UNIT_SOCKET)
                        continue;

                s = SOCKET(u);
                if (s->service != service)
                        continue;

                if (s->state == SOCKET_LISTENING)
                        socket_enter_running_state(s);
        }
}

void socket_notify_service_dead(Unit *service) {
        Manager *m;
        size_t i;

        if (!service)
                return;

        m = service->manager;
        if (!m)
                return;

        for (i = 0; i < m->n_units; i++) {
                Unit *u = m->units[i];
                Socket *s;

                if (u->type != UNIT_SOCKET)
                        continue;

                s = SOCKET(u);
                if (s->accept) {
                        if (socket_has_connection(s, service))
                                socket_schedule_reap(s);
                        continue;
                }

                if (s->service != service)
                        continue;

                if (s->state != SOCKET_RUNNING)
                        continue; /* never triggered us, or already DEAD/FAILED */

                /* c2f3480897/4c523d62d2: the ONE derived predicate -- a
                 * service whose own start-limit is what killed it must not
                 * be re-listened for, or the very next connection re-drives
                 * the same crash loop it just exhausted. Any other death
                 * (a single crash, a resources failure, a clean exit with no
                 * Restart=) is not terminal for the socket -- b50f6dbe57's
                 * principle applied here too, not just at trigger time. */
                if (SERVICE(service)->result == SERVICE_FAILURE_START_LIMIT) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: paired service hit its own start limit, failing rather than re-listening",
                                 SOCKET_UNIT(s)->id);
                        socket_enter_failed(s);
                        continue;
                }

                pico_log(PICO_LOG_DEBUG, "%s: paired service died, re-listening", SOCKET_UNIT(s)->id);
                socket_enter_listening(s);
        }
}

void socket_notify_service_job_finished(Unit *service) {
        UnitActiveState st;

        if (!service || service->type != UNIT_SERVICE || service->job)
                return;

        st = unit_active_state(service);
        if (st == UNIT_INACTIVE || st == UNIT_FAILED)
                socket_notify_service_dead(service);
}

/* --- load-time verification and pairing --- */

int socket_verify_and_pair(Socket *s) {
        Manager *m = SOCKET_UNIT(s)->manager;
        char target[UNIT_NAME_MAX + 1];
        const char *suffix;
        Unit *svc = NULL;
        int r;

        if (!s->ports) {
                pico_log(PICO_LOG_ERR, "%s: lacks a Listen* setting, refusing to load", SOCKET_UNIT(s)->id);
                return -EINVAL;
        }

        /*
         * v30 socket_verify(). Accept=yes pairs with no service here: each
         * connection loads its own prefix@<instance>.service at accept time
         * (socket_accept_one()), so there is no one unit for Service= to
         * name, and only a stream port has connections to accept. Whether
         * the template exists is found out per connection, as in v30.
         */
        if (s->accept) {
                SocketPort *p;

                if (s->service_name) {
                        pico_log(PICO_LOG_ERR,
                                 "%s: Service= is not supported with Accept=yes, refusing to load",
                                 SOCKET_UNIT(s)->id);
                        return -EINVAL;
                }

                for (p = s->ports; p; p = p->next)
                        if (p->type != SOCK_STREAM) {
                                pico_log(PICO_LOG_ERR,
                                         "%s: Accept=yes needs ListenStream= ports only, refusing to load",
                                         SOCKET_UNIT(s)->id);
                                return -EINVAL;
                        }

                return 0;
        }

        if (s->service_name) {
                if (unit_type_from_name(s->service_name) != UNIT_SERVICE) {
                        pico_log(PICO_LOG_ERR,
                                 "%s: Service=%s does not name a .service unit, refusing to load",
                                 SOCKET_UNIT(s)->id,
                                 s->service_name);
                        return -EINVAL;
                }
                r = snprintf(target, sizeof(target), "%s", s->service_name);
        } else {
                size_t idlen = strlen(SOCKET_UNIT(s)->id);

                /* suffix-swap pairing: "foo.socket" -> "foo.service" */
                suffix = strrchr(SOCKET_UNIT(s)->id, '.');
                if (!suffix || (size_t) (suffix - SOCKET_UNIT(s)->id) >= sizeof(target)) {
                        pico_log(PICO_LOG_ERR, "%s: cannot derive a paired service name", SOCKET_UNIT(s)->id);
                        return -EINVAL;
                }

                r = snprintf(target,
                             sizeof(target),
                             "%.*s.service",
                             (int) (idlen - strlen(suffix)),
                             SOCKET_UNIT(s)->id);
        }

        if (r < 0 || (size_t) r >= sizeof(target))
                return -ENAMETOOLONG;

        r = manager_load_unit(m, target, &svc);
        if (r < 0 || !svc) {
                pico_log(PICO_LOG_ERR,
                         "%s: could not resolve paired service '%s': %s, refusing to load",
                         SOCKET_UNIT(s)->id,
                         target,
                         strerror(r < 0 ? -r : ENOENT));
                return r < 0 ? r : -ENOENT;
        }

        if (svc->type != UNIT_SERVICE) {
                pico_log(PICO_LOG_ERR,
                         "%s: '%s' is not a service unit, refusing to load",
                         SOCKET_UNIT(s)->id,
                         target);
                return -EINVAL;
        }

        s->service = svc;

        /*
         * v30 socket.c:344-345: the socket auto-orders itself Before= its
         * service (unit_add_dependency()'s inverse gives the service its
         * After= back in the same call -- see unit-dependency.c's
         * dependency_inverse()).
         *
         * A start job that ends without the service ever running (its own
         * load failure, an unmet condition, a failed requirement) never
         * reaches service_enter_dead(); job.c re-arms the socket through
         * socket_notify_service_job_finished() instead.
         */
        return unit_add_dependency(SOCKET_UNIT(s), UNIT_BEFORE, svc);
}
