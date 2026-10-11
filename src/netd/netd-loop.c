/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netd's epoll loop and the Netd object's whole lifecycle: allocation, the
 * settable paths, netd_startup()/netd_reload()/netd_bring_up_loopback(), and
 * netd_runtime_path().
 *
 * These live here rather than in netd.c because meson.build links this file
 * into netd-core and every netd test binary, but never links netd.c (a
 * second main() would collide with each test's own). netd.c holds only
 * main(), as main.c does for PID 1.
 *
 * A reload is acted on *after* the whole epoll batch is dispatched, never
 * inside it: netd_reload() frees every Network, and a callback still holding
 * the borrowed Network* its Link points at would read freed memory.
 * netd_loop_run() reaches netd_reload() through Netd.reload_handler so a test
 * can install a spy, or nothing at all.
 */

#include "netd-loop.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../signal.h"
#include "../timer.h"
#include "../util.h"
#include "netd-link.h"
#include "netd-network.h"
#include "netd-resolv.h"
#include "netd-rtnl.h"
#include "netd-sntp.h"
#include "netd-time.h"
#include "netd.h"

#define NETD_EPOLL_MAX_EVENTS 16

/* --- Netd object lifecycle (moved from netd.c; see this file's header) --- */

static const char * const default_network_path[] = {
        NETD_NETWORK_DIR,
        NETD_RUNTIME_NETWORK_DIR,
        NETD_PACKAGED_NETWORK_DIR,
        NULL,
};

/* Replace *field with an owned copy of `value`. 0 or -errno. */
static int set_string(char **field, const char *value) {
        char *copy;

        if (!field || !value)
                return -EINVAL;

        copy = pico_strdup(value);
        if (!copy)
                return -ENOMEM;

        free(*field);
        *field = copy;
        return 0;
}

int netd_new(Netd **ret) {
        Netd *n;
        int r;

        if (!ret)
                return -EINVAL;

        n = calloc(1, sizeof(*n));
        if (!n)
                return -ENOMEM;

        n->epoll_fd = -1;
        n->objective = NETD_RUNNING;
        /* See netd-loop.h's comment on netd_reload_handler_t: this is the
         * real thing, wired here so main()'s netd_new()/netd_loop_run()
         * pair works without knowing this indirection exists. A test that
         * wants different (or no) reload behaviour can overwrite this field
         * after netd_new() returns. */
        n->reload_handler = netd_reload;

        r = netd_set_network_path(n, default_network_path);
        if (r < 0)
                goto fail;

        r = set_string(&n->runtime_dir, NETD_RUNTIME_DIR);
        if (r < 0)
                goto fail;

        r = set_string(&n->state_dir, NETD_STATE_DIR);
        if (r < 0)
                goto fail;

        r = set_string(&n->resolv_conf, NETD_RESOLV_CONF);
        if (r < 0)
                goto fail;

        r = set_string(&n->zoneinfo_dir, NETD_ZONEINFO_DIR);
        if (r < 0)
                goto fail;

        r = set_string(&n->localtime_path, NETD_LOCALTIME_PATH);
        if (r < 0)
                goto fail;

        r = pico_signal_new(&n->signal);
        if (r < 0)
                goto fail;

        r = pico_timer_new(&n->timer);
        if (r < 0)
                goto fail;

        r = netd_loop_setup(n);
        if (r < 0)
                goto fail;

        *ret = n;
        return 0;

fail:
        netd_free(n);
        return r;
}

Netd *netd_free(Netd *n) {
        if (!n)
                return NULL;

        /* Links first: each one deregisters its own epoll entries and removes
         * what it put in the kernel, and both need the rtnl socket and the
         * epoll fd to still be open. */
        while (n->n_links > 0)
                (void) link_free(n->links[n->n_links - 1]);
        free(n->links);

        /* Those link_free()s queue their DHCP objects rather than freeing
         * them (netd_loop_defer_free()); nothing will run the loop again, so
         * drain here, while the epoll fd they deregister against is open. */
        netd_loop_drain_pending_frees(n);
        free(n->pending_free);

        n->sntp = netd_sntp_free(n->sntp);

        network_free_all(n);
        n->network_path = pico_strv_free(n->network_path);

        n->rtnl = netd_rtnl_free(n->rtnl);
        n->timer = pico_timer_free(n->timer);
        n->signal = pico_signal_free(n->signal);

        if (n->epoll_fd >= 0)
                (void) close(n->epoll_fd);

        free(n->runtime_dir);
        free(n->state_dir);
        free(n->resolv_conf);
        free(n->zoneinfo_dir);
        free(n->localtime_path);

        free(n);
        return NULL;
}

int netd_set_network_path(Netd *n, const char * const *path) {
        char **copy = NULL;
        int r;

        if (!n || !path)
                return -EINVAL;

        for (size_t i = 0; path[i]; i++) {
                r = pico_strv_extend(&copy, path[i]);
                if (r < 0) {
                        pico_strv_free(copy);
                        return r;
                }
        }

        pico_strv_free(n->network_path);
        n->network_path = copy;
        return 0;
}

int netd_set_runtime_dir(Netd *n, const char *dir) {
        return n ? set_string(&n->runtime_dir, dir) : -EINVAL;
}

int netd_set_state_dir(Netd *n, const char *dir) {
        return n ? set_string(&n->state_dir, dir) : -EINVAL;
}

int netd_set_resolv_conf(Netd *n, const char *path) {
        return n ? set_string(&n->resolv_conf, path) : -EINVAL;
}

int netd_set_zoneinfo_dir(Netd *n, const char *dir) {
        return n ? set_string(&n->zoneinfo_dir, dir) : -EINVAL;
}

int netd_set_localtime_path(Netd *n, const char *path) {
        return n ? set_string(&n->localtime_path, path) : -EINVAL;
}

int netd_runtime_path(Netd *n, const char *subdir, const char *name, bool mkdir_parent, char **ret) {
        char dir[PATH_MAX], path[PATH_MAX];
        char *copy;
        int len;

        if (!n || !n->runtime_dir || !ret)
                return -EINVAL;

        if (subdir)
                len = snprintf(dir, sizeof(dir), "%s/%s", n->runtime_dir, subdir);
        else
                len = snprintf(dir, sizeof(dir), "%s", n->runtime_dir);
        if (len < 0 || (size_t) len >= sizeof(dir))
                return -ENAMETOOLONG;

        if (mkdir_parent) {
                /* The runtime directory itself may be missing too, so create
                 * both levels rather than assuming a tmpfiles.d dropped one
                 * in: netd is the only thing that writes here. */
                if (subdir && mkdir(n->runtime_dir, 0755) < 0 && errno != EEXIST)
                        return -errno;

                if (mkdir(dir, 0755) < 0 && errno != EEXIST)
                        return -errno;
        }

        if (name)
                len = snprintf(path, sizeof(path), "%s/%s", dir, name);
        else
                len = snprintf(path, sizeof(path), "%s", dir);
        if (len < 0 || (size_t) len >= sizeof(path))
                return -ENAMETOOLONG;

        copy = pico_strdup(path);
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return 0;
}

/* --- startup / reload sequencing --- */

/*
 * Enumerate links, deferring per-link configuration until the dump itself
 * has fully drained. See Netd.rtnl_dump_in_progress (netd.h) and
 * netd_link_rtnl_handler()'s comment (netd-link.c) for why: configuring
 * inline from inside the dump's own ADDED callback would issue a
 * synchronous rtnl request/ACK on the very same private socket the dump is
 * still mid-read on, and the reply-matching loop in netd-rtnl.c's
 * nl_execute() would silently swallow the dump's remaining messages --
 * including the terminating NLMSG_DONE -- hanging this function forever.
 * Used both by netd_startup() and by dispatch_rtnl_source()'s ENOBUFS
 * recovery (netd-rtnl.h: the only way back to a correct link table after
 * the event socket overruns is a fresh dump).
 */
static int netd_rtnl_reenumerate(Netd *n) {
        int r;

        n->rtnl_dump_in_progress = true;
        r = netd_rtnl_enumerate_links(n->rtnl);
        n->rtnl_dump_in_progress = false;

        if (r < 0)
                return r;

        for (size_t i = 0; i < n->n_links; i++) {
                int rr = link_configure(n->links[i]);

                if (rr < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: configure failed: %s",
                                 n->links[i]->ifname,
                                 strerror(-rr));
        }

        return 0;
}

static int dispatch_rtnl_source(Netd *n, struct netd_epoll_tag *tag, uint32_t revents) {
        int r;

        (void) tag;
        (void) revents;

        r = netd_rtnl_process(n->rtnl);
        if (r == -ENOBUFS) {
                pico_log(PICO_LOG_WARNING, "netd: rtnl: event socket overran, re-enumerating");
                return netd_rtnl_reenumerate(n);
        }

        return r < 0 ? r : 0;
}

/*
 * [Network] NTP=, across every loaded .network file (netd-sntp.h: "Called
 * from netd_startup() with [Network] NTP= and from link_apply_lease() with
 * DHCP option 42, so the two sources cannot accumulate stale entries across a
 * lease change"). There is exactly one NetdSntp on Netd, not one per link --
 * a single daemon-wide server list, rebuilt from scratch each time this
 * runs so a reload can't leave a stale entry from a file that no longer
 * lists it. Best-effort throughout: a board with no NTP configured anywhere
 * is not a startup failure.
 */
static void netd_apply_static_ntp(Netd *n) {
        struct in_addr servers[NETD_SNTP_MAX_SERVERS];
        size_t count = 0;

        for (size_t i = 0; i < n->n_networks && count < NETD_SNTP_MAX_SERVERS; i++) {
                Network *nw = n->networks[i];

                for (size_t j = 0; j < nw->n_ntp && count < NETD_SNTP_MAX_SERVERS; j++) {
                        bool dup = false;

                        for (size_t k = 0; k < count; k++)
                                if (servers[k].s_addr == nw->ntp[j].s_addr) {
                                        dup = true;
                                        break;
                                }

                        if (!dup)
                                servers[count++] = nw->ntp[j];
                }
        }

        if (count == 0) {
                /* No NTP= left anywhere: stop querying rather than leave a
                 * stale server list running (netd-sntp.h). */
                if (n->sntp)
                        (void) netd_sntp_set_servers(n->sntp, NULL, 0);
                return;
        }

        if (!n->sntp) {
                int r = netd_sntp_new(n, &n->sntp);

                if (r < 0) {
                        pico_log(PICO_LOG_WARNING, "netd: static NTP=: failed to start sntp: %s", strerror(-r));
                        return;
                }
        }

        (void) netd_sntp_set_servers(n->sntp, servers, count);
        (void) netd_sntp_start(n->sntp);
}

/*
 * net.core.default_qdisc / net.ipv4.tcp_congestion_control: applied once,
 * system-wide, rather than per-link -- the kernel's own dev_init_scheduler()
 * reads net.core.default_qdisc for every interface at creation time,
 * including one a DHCP lease or a bnep PAN connection creates long after
 * boot, so this needs no per-link rtnetlink work (netd-rtnl.c has no
 * TCA_QDISC support).
 *
 * Each list is tried in order and the first value the kernel actually
 * accepts wins; a value failing just means that qdisc/congestion-control
 * module is not built into this kernel, not a bug here. Only logged at debug
 * level: a better qdisc or congestion control is never worth failing boot
 * over.
 */
static void netd_set_default_qdisc_and_congestion_control(void) {
        static const char * const qdiscs[] = { "fq_codel", "fq", "cake" };
        static const char * const congestion_control[] = { "bbr" };
        size_t i;

        for (i = 0; i < sizeof(qdiscs) / sizeof(qdiscs[0]); i++) {
                int fd = open("/proc/sys/net/core/default_qdisc", O_WRONLY | O_CLOEXEC);

                if (fd < 0) {
                        pico_log(PICO_LOG_DEBUG, "netd: default_qdisc: %s", strerror(errno));
                        break; /* no /proc/sys/net/core/default_qdisc at all: CONFIG_NET_SCHED unset */
                }

                if (write(fd, qdiscs[i], strlen(qdiscs[i])) == (ssize_t) strlen(qdiscs[i])) {
                        close(fd);
                        pico_log(PICO_LOG_INFO, "netd: default_qdisc: %s", qdiscs[i]);
                        break;
                }

                close(fd);
        }

        for (i = 0; i < sizeof(congestion_control) / sizeof(congestion_control[0]); i++) {
                int fd = open("/proc/sys/net/ipv4/tcp_congestion_control", O_WRONLY | O_CLOEXEC);

                if (fd < 0) {
                        pico_log(PICO_LOG_DEBUG, "netd: tcp_congestion_control: %s", strerror(errno));
                        break;
                }

                if (write(fd, congestion_control[i], strlen(congestion_control[i])) ==
                    (ssize_t) strlen(congestion_control[i])) {
                        close(fd);
                        pico_log(PICO_LOG_INFO, "netd: tcp_congestion_control: %s", congestion_control[i]);
                        break;
                }

                close(fd);
        }
}

int netd_startup(Netd *n) {
        int r;

        if (!n)
                return -EINVAL;

        /* 0. System-wide, not per-link -- see the function's own comment for
         * why this needs no rtnetlink work. Best-effort, logged either way. */
        netd_set_default_qdisc_and_congestion_control();

        /*
         * 1. Clock floor, before anything timestamps anything (netd.h). Never
         * fatal: an RTC-less board with no clock file yet still has
         * NETD_TIME_EPOCH_SEC as a floor (netd-time.h), and a failure here
         * is a reason to log, not to refuse to bring the network up.
         */
        r = netd_time_clock_floor_apply(n);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "netd: startup: clock floor: %s", strerror(-r));

        /* 2. Load every .network file in the search path. */
        r = network_load_all(n);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "netd: startup: failed to load .network files: %s", strerror(-r));
                return r;
        }

        /*
         * 3. Open rtnetlink and *subscribe* before enumerating -- the
         * load-bearing part of this whole function (netd.h): an interface
         * that appears between the dump and the subscription would be missed
         * forever, and netd has no After=eudev.service to fall back on.
         */
        r = netd_rtnl_new(&n->rtnl);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "netd: startup: rtnl: %s", strerror(-r));
                return r;
        }

        netd_rtnl_set_link_handler(n->rtnl, netd_link_rtnl_handler, n);

        r = netd_loop_add_io(
                        n,
                        &n->rtnl_tag,
                        netd_rtnl_event_fd(n->rtnl),
                        EPOLLIN,
                        NETD_EPOLL_RTNL,
                        dispatch_rtnl_source,
                        n);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "netd: startup: failed to register rtnl in the loop: %s", strerror(-r));
                return r;
        }

        /*
         * Loopback: netd's job explicitly, upstream leaves it to PID 1 and
         * pico-init does not do it (netd.h). Bringing it up
         * here, before enumeration, keeps it independent of whether any
         * .network file happens to match "lo" (none is expected to).
         */
        r = netd_bring_up_loopback(n);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "netd: startup: failed to bring lo up: %s", strerror(-r));

        /* 4. Only now enumerate -- every link already seen gets ADDED, and
         * netd_link_rtnl_handler() (subscribed above) has already been live
         * for anything that shows up in between. Configuration itself is
         * deferred until the dump drains; see netd_rtnl_reenumerate(). */
        r = netd_rtnl_reenumerate(n);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "netd: startup: link enumeration failed: %s", strerror(-r));
                return r;
        }

        netd_apply_static_ntp(n);

        return 0;
}

int netd_reload(Netd *n) {
        int r;

        if (!n)
                return -EINVAL;

        /*
         * network_load_all() replaces n->networks wholesale on success, which
         * frees every Network a Link may be pointing at -- every Link->network
         * is dangling from this line until link_reconfigure() re-matches it
         * below. Safe because netd_reload() only ever runs from
         * netd_loop_run()'s post-batch check (via n->reload_handler), never
         * nested inside a callback still holding a borrowed Network*
         * (netd-loop.h's whole reason for deferring the reload).
         */
        r = network_load_all(n);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "netd: reload: failed to load .network files: %s", strerror(-r));
                return r;
        }

        for (size_t i = 0; i < n->n_links; i++) {
                int rr = link_reconfigure(n->links[i]);

                if (rr < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: reload: %s: reconfigure failed: %s",
                                 n->links[i]->ifname,
                                 strerror(-rr));
        }

        netd_apply_static_ntp(n);

        return 0;
}

int netd_bring_up_loopback(Netd *n) {
        if (!n)
                return -EINVAL;

        if (!n->rtnl)
                return -EINVAL;

        /*
         * Loopback is always ifindex 1 on Linux -- upstream's own convention.
         * This bypasses the .network match path on purpose: "lo" is netd's
         * job explicitly (netd.h), not something any [Match] Name= is
         * expected to name, so it never goes through link_configure().
         */
        return netd_rtnl_link_up(n->rtnl, 1);
}

/* --- the epoll loop --- */

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

        /* A tag still marked registered was never removed. Re-registering it
         * would leak the old epoll entry, which keeps firing for whatever
         * that descriptor number becomes next. Keyed off `registered`, not
         * `fd >= 0`: every tag lives inside a calloc()'d/new0()'d owner, so a
         * freshly allocated tag has fd == 0 (a valid descriptor number) and
         * only `registered` is guaranteed zero -- see netd-loop.h. */
        if (tag->registered)
                return -EBUSY;

        tag->source = source;
        tag->fd = fd;
        tag->callback = callback;
        tag->userdata = userdata;
        tag->registered = true;

        memset(&ev, 0, sizeof(ev));
        ev.events = events;
        ev.data.ptr = tag;

        if (epoll_ctl(n->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                tag->fd = -1;
                tag->registered = false;
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
        if (!tag->registered)
                return 0;

        if (n->epoll_fd >= 0 && epoll_ctl(n->epoll_fd, EPOLL_CTL_DEL, tag->fd, NULL) < 0 &&
            errno != ENOENT && errno != EBADF)
                return -errno;

        tag->fd = -1;
        tag->registered = false;
        tag->callback = NULL;
        tag->userdata = NULL;
        return 0;
}

int netd_loop_defer_free(Netd *n, void *object, netd_free_func_t free_func) {
        if (!n || !object || !free_func)
                return -EINVAL;

        if (n->n_pending_free == n->n_pending_free_allocated) {
                size_t want = n->n_pending_free_allocated ? n->n_pending_free_allocated * 2 : 4;
                struct netd_pending_free *grown;

                grown = realloc(n->pending_free, want * sizeof(*grown));
                if (!grown)
                        return -ENOMEM;

                n->pending_free = grown;
                n->n_pending_free_allocated = want;
        }

        n->pending_free[n->n_pending_free++] = (struct netd_pending_free){
                .object = object,
                .free_func = free_func,
        };
        return 0;
}

void netd_loop_drain_pending_frees(Netd *n) {
        if (!n)
                return;

        /* Re-read the array and the count every iteration rather than
         * caching either: a free_func may itself defer something (the last
         * reference to a DHCP object can be the one a link teardown drops),
         * appending here and possibly reallocating the array underneath us. */
        for (size_t i = 0; i < n->n_pending_free; i++)
                n->pending_free[i].free_func(n->pending_free[i].object);

        n->n_pending_free = 0;
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
                /* The whole management API. Deferred, see above. */
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
                         *
                         * Reading the cleared tag is only safe because the
                         * memory is still there: a tag lives inside the
                         * object that owns the fd, and for the DHCP
                         * client/server sources that object is per-link and
                         * can be destroyed by an earlier callback in this
                         * very batch (an RTM_DELLINK reaching link_free()).
                         * Those destructions go through
                         * netd_loop_defer_free(), which is why the queue is
                         * drained below rather than inside the loop.
                         */
                        if (!tag || !tag->callback || !tag->registered)
                                continue;

                        r = tag->callback(n, tag, events[i].events);
                        if (r < 0)
                                pico_log(PICO_LOG_WARNING,
                                         "netd: %s source failed: %s",
                                         netd_epoll_source_to_string(tag->source),
                                         strerror(-r));
                }

                /* No tag pointer from this batch is live any more, so
                 * anything a callback deferred can finally go away. */
                netd_loop_drain_pending_frees(n);

                if (n->reload_requested) {
                        n->reload_requested = false;

                        if (n->reload_handler) {
                                int r = n->reload_handler(n);

                                if (r < 0)
                                        pico_log(PICO_LOG_ERR, "netd: reload failed: %s", strerror(-r));
                        }
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
        [NETD_EPOLL_LLDP] = "lldp",
};

const char *netd_epoll_source_to_string(NetdEpollSource s) {
        if (s < 0 || s >= _NETD_EPOLL_SOURCE_MAX)
                return "invalid";

        return netd_epoll_source_table[s];
}
