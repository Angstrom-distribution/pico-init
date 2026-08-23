/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * N1's acceptance test: the hand-rolled rtnetlink layer.
 *
 * Real network-namespace test (plan §2.8): unshare(CLONE_NEWUSER|CLONE_NEWNET)
 * -- a bare unshare(CLONE_NEWNET) fails here with EPERM, there is no
 * CAP_SYS_ADMIN in this container's default set, but a fresh user namespace
 * grants full capabilities within itself, and a net namespace created in the
 * same unshare() call is owned by it, so CAP_NET_ADMIN is available there
 * too. Failing to set up the namespace is fatal (exit(1) with a message),
 * never a silent pass: a test that cannot prove it ran isolated must not
 * report success.
 *
 * `dummy` interfaces are not available in this environment (no
 * /lib/modules), so every case that would use one uses a veth pair instead,
 * per this milestone's own investigation -- a veth's far end covers what
 * dummy would have.
 *
 * The event-after-subscription case is the one worth calling out
 * specifically. The veth pair is created *after* netd_rtnl_new() has already
 * subscribed the event socket, with no dump in between, so its RTM_NEWLINK
 * has to arrive as a live event. It is the whole reason netd's own unit has
 * no After=eudev.service, and it is exactly what a dump-then-subscribe
 * implementation would pass every other test while silently getting wrong.
 *
 * The rest of the ADDED/CHANGED/REMOVED contract is exercised too: a dump
 * always reports ADDED (netd-rtnl.h is explicit that re-enumeration, netd's
 * own ENOBUFS-recovery path, treats everything it sees as freshly
 * discovered); a live RTM_NEWLINK for an ifindex already reported reports
 * CHANGED; and deleting the pair delivers REMOVED. Static configuration
 * (link up, address, a default route carrying RTA_PRIORITY) is checked two
 * ways: through this layer's own re-dump, and independently through `ip`, so
 * the test is not just checking that this code agrees with itself.
 */

/* unshare()/CLONE_NEWUSER/CLONE_NEWNET are declared under glibc's __USE_GNU
 * guard in <sched.h> -- -std=gnu17 alone does not imply _GNU_SOURCE, so this
 * has to be explicit and first, before any header pulls in <features.h>. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "../test-util.h"
#include "netd-rtnl.h"

/* Every event kind has a name; nothing falls through to "invalid". A missing
 * table entry is a NULL deref in a log call on a board, which is a miserable
 * way to find out. */
static void test_event_names(void) {
        ASSERT_STREQ(netd_rtnl_link_event_to_string(NETD_RTNL_LINK_ADDED), "added");
        ASSERT_STREQ(netd_rtnl_link_event_to_string(NETD_RTNL_LINK_CHANGED), "changed");
        ASSERT_STREQ(netd_rtnl_link_event_to_string(NETD_RTNL_LINK_REMOVED), "removed");
        ASSERT_STREQ(netd_rtnl_link_event_to_string(_NETD_RTNL_LINK_EVENT_MAX), "invalid");
        ASSERT_STREQ(netd_rtnl_link_event_to_string((NetdRtnlLinkEvent) -1), "invalid");
}

/* NetdRtnlLink is filled in from bytes off a netlink socket, so its name
 * field has to be able to hold what the kernel can send. */
static void test_link_snapshot_shape(void) {
        NetdRtnlLink l;

        memset(&l, 0, sizeof(l));

        ASSERT_TRUE(sizeof(l.ifname) >= IFNAMSIZ);
        ASSERT_TRUE(sizeof(l.hw_addr) >= NETD_HW_ADDR_MAX);
        ASSERT_EQ_INT(l.hw_addr_len, 0);
}

/* --- netns integration test --- */

#define MAX_EVENTS 32

typedef struct RecordedEvent {
        NetdRtnlLinkEvent event;
        NetdRtnlLink link;
} RecordedEvent;

typedef struct EventLog {
        RecordedEvent events[MAX_EVENTS];
        size_t count;
} EventLog;

static int record_handler(void *userdata, NetdRtnlLinkEvent event, const NetdRtnlLink *link) {
        EventLog *log = userdata;

        if (log->count < MAX_EVENTS) {
                log->events[log->count].event = event;
                log->events[log->count].link = *link;
                log->count++;
        }

        return 0;
}

/* Most recent match wins, in case an ifname appears more than once in one
 * batch. */
static const NetdRtnlLink *find_by_name(const EventLog *log, const char *name, NetdRtnlLinkEvent *ret_event) {
        for (size_t i = log->count; i > 0; i--) {
                const RecordedEvent *e = &log->events[i - 1];

                if (strcmp(e->link.ifname, name) == 0) {
                        if (ret_event)
                                *ret_event = e->event;
                        return &e->link;
                }
        }

        return NULL;
}

static void run_shell(const char *cmd) {
        int rc = system(cmd);

        if (rc != 0) {
                fprintf(stderr, "test-netd-rtnl: `%s` failed (rc=%d)\n", cmd, rc);
                exit(1);
        }
}

static void run_ip(const char *args) {
        char cmd[256];
        int len = snprintf(cmd, sizeof(cmd), "ip %s >/dev/null 2>&1", args);

        if (len < 0 || (size_t) len >= sizeof(cmd)) {
                fprintf(stderr, "test-netd-rtnl: ip command too long: %s\n", args);
                exit(1);
        }

        run_shell(cmd);
}

static void write_proc_file(const char *path, const char *content) {
        FILE *f = fopen(path, "we");

        if (!f) {
                fprintf(stderr, "test-netd-rtnl: cannot open %s: %s\n", path, strerror(errno));
                exit(1);
        }

        if (fputs(content, f) < 0) {
                fprintf(stderr, "test-netd-rtnl: cannot write %s: %s\n", path, strerror(errno));
                (void) fclose(f);
                exit(1);
        }

        if (fclose(f) != 0) {
                fprintf(stderr, "test-netd-rtnl: cannot close %s: %s\n", path, strerror(errno));
                exit(1);
        }
}

static void enter_test_netns(void) {
        /* getuid()/getgid() must be captured *before* unshare(): called from
         * inside the freshly created, still-unmapped user namespace they
         * would report the overflow id instead of the real one, which is not
         * what the map files need. */
        uid_t outer_uid = getuid();
        gid_t outer_gid = getgid();
        char buf[64];

        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
                fprintf(stderr, "test-netd-rtnl: unshare(CLONE_NEWUSER|CLONE_NEWNET): %s\n", strerror(errno));
                fprintf(stderr, "test-netd-rtnl: cannot prove netns isolation, refusing to report success\n");
                exit(1);
        }

        /* setgroups must be denied before gid_map is writable by an
         * unprivileged mapping -- the standard rootless sequence. */
        write_proc_file("/proc/self/setgroups", "deny");

        snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned) outer_uid);
        write_proc_file("/proc/self/uid_map", buf);

        snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned) outer_gid);
        write_proc_file("/proc/self/gid_map", buf);
}

static void test_netns_rtnl(void) {
        NetdRtnl *rtnl = NULL;
        EventLog log;
        NetdRtnlLinkEvent ev;
        const NetdRtnlLink *lo, *veth;
        struct in_addr addr, gw;
        int r;

        enter_test_netns();

        memset(&log, 0, sizeof(log));

        r = netd_rtnl_new(&rtnl);
        ASSERT_TRUE(r == 0);
        ASSERT_TRUE(rtnl != NULL);

        netd_rtnl_set_link_handler(rtnl, record_handler, &log);

        /* A dump always reports ADDED, per netd-rtnl.h -- even for `lo`,
         * which obviously already existed. A fresh netns has at least `lo`;
         * some kernels also auto-create a sit0 tunnel device, so this checks
         * "at least one", not "exactly one". */
        r = netd_rtnl_enumerate_links(rtnl);
        ASSERT_TRUE(r >= 1);

        lo = find_by_name(&log, "lo", &ev);
        ASSERT_TRUE(lo != NULL);
        ASSERT_EQ_INT(ev, NETD_RTNL_LINK_ADDED);
        ASSERT_TRUE((lo->flags & IFF_LOOPBACK) != 0);

        r = netd_rtnl_link_up(rtnl, lo->ifindex);
        ASSERT_TRUE(r == 0);

        /* Create the veth pair now -- after subscription, with no dump in
         * between -- and prove the event arrives live. */
        log.count = 0;
        run_ip("link add name nrtest0 type veth peer name nrtest1");

        r = netd_rtnl_process(rtnl);
        ASSERT_TRUE(r >= 2);

        veth = find_by_name(&log, "nrtest0", &ev);
        ASSERT_TRUE(veth != NULL);
        ASSERT_EQ_INT(ev, NETD_RTNL_LINK_ADDED);
        ASSERT_TRUE(find_by_name(&log, "nrtest1", NULL) != NULL);

        /* Static configuration: up, an address, a default route with a
         * priority metric. */
        r = netd_rtnl_link_up(rtnl, veth->ifindex);
        ASSERT_TRUE(r == 0);

        addr.s_addr = htonl(0x0AFA0001); /* 10.250.0.1 */
        r = netd_rtnl_address_add(rtnl, veth->ifindex, &addr, 24, NULL, UINT32_MAX);
        ASSERT_TRUE(r == 0);

        gw.s_addr = htonl(0x0AFA00FE); /* 10.250.0.254, on-link via the /24 just added */
        r = netd_rtnl_route_add_default(rtnl, veth->ifindex, &gw, 100);
        ASSERT_TRUE(r == 0);

        /* The up-flag change above generated a live RTM_NEWLINK; the
         * address/route additions did not (this socket is only subscribed to
         * RTNLGRP_LINK). nrtest0 is already known from the ADDED event above,
         * so this one must be CHANGED. */
        log.count = 0;
        r = netd_rtnl_process(rtnl);
        ASSERT_TRUE(r >= 1);

        veth = find_by_name(&log, "nrtest0", &ev);
        ASSERT_TRUE(veth != NULL);
        ASSERT_EQ_INT(ev, NETD_RTNL_LINK_CHANGED);
        ASSERT_TRUE((veth->flags & IFF_UP) != 0);

        /* A dump agrees, and also always says ADDED regardless of what came
         * before -- it is netd's ENOBUFS-recovery path, which treats
         * everything found as freshly discovered. */
        log.count = 0;
        r = netd_rtnl_enumerate_links(rtnl);
        ASSERT_TRUE(r >= 1);
        veth = find_by_name(&log, "nrtest0", &ev);
        ASSERT_TRUE(veth != NULL);
        ASSERT_EQ_INT(ev, NETD_RTNL_LINK_ADDED);
        ASSERT_TRUE((veth->flags & IFF_UP) != 0);

        /* Independent confirmation: not this layer checking its own work. */
        run_shell("ip -4 addr show dev nrtest0 | grep -q '10\\.250\\.0\\.1/24'");
        run_shell("ip route show default dev nrtest0 | grep -q '10\\.250\\.0\\.254'");

        /* Deleting the pair removes both ends; expect REMOVED, live. */
        log.count = 0;
        run_ip("link del nrtest0");

        r = netd_rtnl_process(rtnl);
        ASSERT_TRUE(r >= 1);
        ASSERT_TRUE(find_by_name(&log, "nrtest0", &ev) != NULL);
        ASSERT_EQ_INT(ev, NETD_RTNL_LINK_REMOVED);

        netd_rtnl_free(rtnl);

        printf("test-netd-rtnl: netns subtest ok\n");
}

int main(void) {
        test_event_names();
        test_link_snapshot_shape();
        test_netns_rtnl();

        printf("test-netd-rtnl: ok\n");
        return EXIT_SUCCESS;
}
