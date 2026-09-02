/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netd: angstrom-pico's network daemon (plan §2). It speaks .network-file
 * syntax, does DHCPv4 client and server for ethernet and the usb-gadget
 * CDC-Subset link, and carries an integrated SNTP client with a DHCP option
 * 42/101 hook -- replacing systemd-networkd, systemd-timesyncd and timedated
 * together.
 *
 * netd is an ordinary Type=simple service supervised by pico-init, not part
 * of PID 1, and runs its own epoll loop (netd-loop.c) deliberately separate
 * from the manager's -- upstream's own networkd-as-a-separate-daemon shape.
 * What it does *not* do is duplicate PID 1's plumbing: timer.c, signal.c and
 * util.c are linked from the shared static library, so the loop here is a
 * thin epoll wrapper over already-tested code (§2.3).
 *
 * The Netd object below is the whole daemon: the link table, the parsed
 * .network set, the rtnetlink socket, the timer queue, the signalfd and the
 * epoll fd. Everything else takes a Netd* and reaches through it, so there is
 * exactly one owner of every fd and every allocation.
 *
 * Implemented across netd.c (main, startup, reload, teardown), netd-loop.c
 * (the epoll loop), netd-link.c (link table and per-link state machine),
 * netd-network.c (.network parser), netd-rtnl.c (the hand-rolled netlink
 * layer), netd-resolv.c (/etc/resolv.conf), netd-sntp.c and netd-time.c
 * (time), and src/netd/dhcp/ (the lifted DHCPv4 implementation).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "../signal.h"
#include "../timer.h"
#include "../util.h"
#include "netd-loop.h"

typedef struct Netd Netd;

/* full definitions in netd-link.h / netd-network.h / netd-rtnl.h / netd-sntp.h */
typedef struct Link Link;
typedef struct Network Network;
typedef struct NetdRtnl NetdRtnl;
typedef struct NetdSntp NetdSntp;

/*
 * Runtime and state paths. All of them are fields on Netd rather than
 * compile-time constants at the use site, for the same reason the manager's
 * search paths are settable: the netns-based tests (§2.8) need to point netd
 * at a temporary tree instead of the host's real /etc, /run and /var, and
 * a test that mutated the container's actual /etc/localtime would be a test
 * nobody can run twice.
 */
#define NETD_RUNTIME_DIR "/run/netd"
#define NETD_LEASE_DIR NETD_RUNTIME_DIR "/leases"
#define NETD_STATE_DIR "/var/lib/netd"

/* Why the loop ended. netd is a plain service, so unlike the manager there is
 * no reboot/poweroff outcome -- it either keeps running or exits. */
typedef enum NetdObjective {
        NETD_RUNNING, /* keep looping */
        NETD_EXIT,    /* SIGTERM/SIGINT: leave the loop and exit 0 */
        _NETD_OBJECTIVE_MAX,
} NetdObjective;

struct Netd {
        /* --- event plumbing (netd-loop.c) --- */
        int epoll_fd;
        PicoSignal *signal; /* SIGTERM/SIGINT/SIGHUP, blocked + read via signalfd */
        PicoTimer *timer;   /* the shared timerfd-fronted deadline queue */

        struct netd_epoll_tag signal_tag;
        struct netd_epoll_tag timer_tag;

        /*
         * Objects handed to netd_loop_defer_free() (netd-loop.h) because
         * their epoll tag may still be sitting in the batch netd_loop_run()
         * is dispatching. Reused across batches: the drain resets the count
         * and keeps the capacity, so the steady state allocates nothing.
         */
        struct netd_pending_free *pending_free; /* owned */
        size_t n_pending_free;
        size_t n_pending_free_allocated;

        /* --- kernel interface (netd-rtnl.c) --- */
        NetdRtnl *rtnl;
        struct netd_epoll_tag rtnl_tag;

        /*
         * True for the duration of a netd_rtnl_enumerate_links() call
         * (netd-loop.c). netd_link_rtnl_handler() (netd-link.c) checks this
         * and, while it is set, only builds/updates the Link table --
         * link_configure() is deferred until the dump has fully drained.
         * Configuring inline from inside the dump's own ADDED callback would
         * issue a synchronous rtnl request/ACK on the very same private
         * socket the dump is still mid-read on (netd-rtnl.h: dump and writes
         * share one request socket by design), and nl_execute()'s own
         * recv loop would silently swallow the dump's remaining messages --
         * including the terminating NLMSG_DONE -- hanging the dump forever
         * waiting for a message that already went by. Reproduced live: a
         * static Address=/Gateway= link discovered by the startup dump hung
         * netd_startup() indefinitely before this flag existed.
         */
        bool rtnl_dump_in_progress;

        /*
         * --- configuration (netd-network.c) ---
         *
         * `networks` is the resolved set after shadowing, sorted
         * lexicographically by basename: matching walks it front to back and
         * the first [Match] that hits wins for that interface, which is
         * networkd's rule and the reason the existing 15-usb0.network naming
         * convention keeps meaning here.
         */
        char **network_path; /* NULL-terminated, owned; the three-entry search path */
        Network **networks;  /* owned */
        size_t n_networks;

        /*
         * --- interfaces (netd-link.c) ---
         *
         * Flat array, not a hashmap: an embedded board has a handful of
         * interfaces, and the manager's unit table already made the same call
         * for the same reason.
         */
        Link **links; /* owned */
        size_t n_links;

        /* --- time (netd-sntp.c / netd-time.c) --- */
        NetdSntp *sntp; /* owned; NULL until a server list exists */

        /* --- paths, all owned and all settable for tests --- */
        char *runtime_dir;    /* NETD_RUNTIME_DIR */
        char *state_dir;      /* NETD_STATE_DIR */
        char *resolv_conf;    /* NETD_RESOLV_CONF */
        char *zoneinfo_dir;   /* NETD_ZONEINFO_DIR */
        char *localtime_path; /* NETD_LOCALTIME_PATH */

        /*
         * SIGHUP sets this rather than reconfiguring from signal-dispatch
         * context: a reload frees and reallocates every Network, and doing
         * that underneath a link callback that still holds a borrowed
         * Network* is the obvious way to write a use-after-free. The loop
         * acts on it once the current epoll batch has drained.
         */
        bool reload_requested;

        /*
         * Installed by netd_new() to netd_reload(). netd_loop_run() calls
         * through this rather than netd_reload() directly, so a test can
         * observe or replace reload behaviour, or skip it, without
         * netd_loop_run() itself ever needing to know. See netd-loop.h's
         * netd_reload_handler_t.
         */
        netd_reload_handler_t reload_handler;

        NetdObjective objective;
};

/*
 * Every function below is declared here (the contract callers compile
 * against) but implemented in netd-loop.c, not netd.c -- meson.build links
 * netd-loop.c into netd_core, which every netd test executable links, and
 * deliberately never links netd.c itself (the same exclusion main.c gets
 * from pico-init-core). netd.c holds only main(); see netd-loop.c's header
 * comment for the full reasoning. A caller never needs to know this --
 * #include "netd.h" and link netd-core, as every test already does.
 */

/* Allocate, create epoll/signalfd/timerfd, install the default paths. 0 or -errno. */
int netd_new(Netd **ret);

/* Tear down every link, network, socket and fd. Returns NULL. */
Netd *netd_free(Netd *n);

/*
 * The startup sequence, in this order and for these reasons:
 *   1. apply the clock-file floor (netd-time.c) -- before anything timestamps
 *      anything, so an RTC-less board does not start in 1970;
 *   2. load every .network file in the search path;
 *   3. open the rtnetlink socket and *subscribe* to link events;
 *   4. only then enumerate existing links.
 *
 * 3 before 4 is the load-bearing part: an interface that appears between the
 * dump and the subscription would be missed forever, and netd has no
 * After=eudev.service to fall back on (§2.5, §2.7).
 *
 * Loopback is brought up here too. Upstream leaves that to PID 1
 * (src/core/loopback-setup.c); pico-init deliberately does not do it, and
 * nothing else will.
 *
 * 0 or -errno.
 */
int netd_startup(Netd *n);

/*
 * SIGHUP: re-read every .network file and re-match/reconfigure every link.
 * This is the entire management API -- there is no networkctl equivalent, no
 * bus and no varlink (§2.9), so `cp` + `kill -HUP` is what replaces
 * `networkctl reload` + `networkctl reconfigure`.
 *
 * 0 or -errno. A parse failure in one file does not abort the reload: the
 * running configuration is only replaced once the new set has been built.
 */
int netd_reload(Netd *n);

/* Bring interface `lo` up. Called from netd_startup(); separate so the rtnl
 * test can exercise it on its own. 0 or -errno. */
int netd_bring_up_loopback(Netd *n);

/* Replace a path with an owned copy. For tests. 0 or -errno. */
int netd_set_network_path(Netd *n, const char * const *path);
int netd_set_runtime_dir(Netd *n, const char *dir);
int netd_set_state_dir(Netd *n, const char *dir);
int netd_set_resolv_conf(Netd *n, const char *path);
int netd_set_zoneinfo_dir(Netd *n, const char *dir);
int netd_set_localtime_path(Netd *n, const char *path);

/* Build "<dir>/<name>", creating `dir` first when `mkdir_parent`. Malloc'd
 * path via ret. Every runtime file netd writes goes through this so the
 * test-root indirection above cannot be bypassed by accident. 0 or -errno. */
int netd_runtime_path(Netd *n, const char *subdir, const char *name, bool mkdir_parent, char **ret);
