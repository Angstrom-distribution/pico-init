/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Tests for the hand-rolled rtnetlink layer and for a static .network file
 * end to end: configuring a veth interface and reconfiguring on SIGHUP
 * (test_netns_static_network_and_sighup()).
 *
 * Real network-namespace test: unshare(CLONE_NEWUSER|CLONE_NEWNET) -- a bare
 * unshare(CLONE_NEWNET) fails with EPERM without CAP_SYS_ADMIN, but a fresh
 * user namespace grants full capabilities within itself, and a net namespace
 * created in the same unshare() call is owned by it, so CAP_NET_ADMIN is
 * available there too. Failing to set up the namespace is fatal (exit(1) with
 * a message), never a silent pass. Each netns-using test function calls
 * enter_test_netns() itself (nested unshare()s are fine), so the test
 * functions stay independent of each other's ordering in main().
 *
 * `dummy` interfaces may be unavailable (no /lib/modules), so every case
 * that would use one uses a veth pair instead.
 *
 * The event-after-subscription case is the one worth calling out. The veth
 * pair is created *after* netd_rtnl_new() has subscribed the event socket,
 * with no dump in between, so its RTM_NEWLINK has to arrive as a live event.
 * It is the reason netd's unit has no After=eudev.service, and what a
 * dump-then-subscribe implementation would silently get wrong.
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
#include <limits.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../test-util.h"
#include "dhcp/dhcp-lease-internal.h"
#include "netd-link.h"
#include "netd-network.h"
#include "netd-rtnl.h"
#include "netd.h"

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

/* --- static .network file end to end, and SIGHUP ---
 *
 * A static .network file configures an interface, and SIGHUP reconfigures
 * it. This drives the whole stack through its real public entry points --
 * netd_new()/netd_startup()/netd_loop_dispatch_signal()/the reload handler --
 * against a temporary tree (netd's paths are settable so a test never
 * touches the real /etc, /run, /var), inside a fresh netns as in
 * test_netns_rtnl() above, with a veth pair standing in for `dummy`.
 */

static void write_network_file(
                const char *dir,
                const char *name,
                const char *ifname,
                const char *address,
                const char *gateway,
                const char *dns) {
        char content[512];
        int len;

        len = snprintf(content,
                       sizeof(content),
                       "[Match]\nName=%s\n\n[Network]\nAddress=%s\nGateway=%s\nDNS=%s\n",
                       ifname,
                       address,
                       gateway,
                       dns);
        if (len < 0 || (size_t) len >= sizeof(content)) {
                fprintf(stderr, "test-netd-rtnl: network file content too long\n");
                exit(1);
        }

        if (test_write_file(dir, name, content) < 0) {
                fprintf(stderr, "test-netd-rtnl: failed to write %s/%s: %s\n", dir, name, strerror(errno));
                exit(1);
        }
}

static void read_file_into(const char *path, char *buf, size_t bufsz) {
        FILE *f = fopen(path, "re");
        size_t n;

        if (!f) {
                fprintf(stderr, "test-netd-rtnl: cannot open %s: %s\n", path, strerror(errno));
                exit(1);
        }

        n = fread(buf, 1, bufsz - 1, f);
        buf[n] = '\0';
        fclose(f);
}

static void test_netns_static_network_and_sighup(void) {
        char *tmp;
        char netdir[PATH_MAX], rundir[PATH_MAX], statedir[PATH_MAX], resolv[PATH_MAX];
        const char *netpath[2];
        Netd *n = NULL;
        Link *l;
        char buf[4096];
        int r, signo;

        enter_test_netns();

        tmp = test_tmpdir_new();
        ASSERT_TRUE(tmp != NULL);

        ASSERT_TRUE(test_mkdir(tmp, "network") == 0);
        ASSERT_TRUE(test_mkdir(tmp, "run") == 0);
        ASSERT_TRUE(test_mkdir(tmp, "state") == 0);

        snprintf(netdir, sizeof(netdir), "%s/network", tmp);
        snprintf(rundir, sizeof(rundir), "%s/run", tmp);
        snprintf(statedir, sizeof(statedir), "%s/state", tmp);
        snprintf(resolv, sizeof(resolv), "%s/resolv.conf", tmp);

        write_network_file(
                        netdir, "10-nettest.network", "nettest0", "10.252.0.5/24", "10.252.0.254", "10.252.0.1");

        /* The interface exists before netd_startup() runs, exercising the
         * enumeration-dump path (live-event ordering is test_netns_rtnl()'s
         * job above). */
        run_ip("link add name nettest0 type veth peer name nettest1");

        r = netd_new(&n);
        ASSERT_TRUE(r == 0);
        ASSERT_TRUE(n != NULL);

        netpath[0] = netdir;
        netpath[1] = NULL;
        ASSERT_TRUE(netd_set_network_path(n, netpath) == 0);
        ASSERT_TRUE(netd_set_runtime_dir(n, rundir) == 0);
        ASSERT_TRUE(netd_set_state_dir(n, statedir) == 0);
        ASSERT_TRUE(netd_set_resolv_conf(n, resolv) == 0);

        r = netd_startup(n);
        ASSERT_TRUE(r == 0);

        /* lo is netd's own job, independent of any .network match. A fresh
         * netns's lo starts administratively down -- grep -w UP matches the
         * IFF_UP flag inside the <...,UP,...> bracket regardless of the
         * separately-reported (and, for loopback, always UNKNOWN) operstate. */
        run_shell("ip link show lo | grep -qw UP");

        l = netd_find_link_by_name(n, "nettest0");
        ASSERT_TRUE(l != NULL);
        ASSERT_EQ_INT(l->state, LINK_CONFIGURED);
        ASSERT_TRUE(l->address_configured);
        ASSERT_TRUE(l->gateway_configured);

        run_shell("ip -4 addr show dev nettest0 | grep -q '10\\.252\\.0\\.5/24'");
        run_shell("ip route show default dev nettest0 | grep -q '10\\.252\\.0\\.254'");

        read_file_into(resolv, buf, sizeof(buf));
        ASSERT_TRUE(strstr(buf, "nameserver 10.252.0.1") != NULL);

        /* --- SIGHUP: rewrite the .network file and reconfigure --- */

        write_network_file(
                        netdir, "10-nettest.network", "nettest0", "10.252.0.9/24", "10.252.0.253", "10.252.0.2");

        ASSERT_TRUE(raise(SIGHUP) == 0);

        /* Mirrors netd_loop_run()'s own two steps for a signalfd-ready event
         * followed by a post-batch reload -- driven directly here so the test
         * does not need to block in epoll_wait(). */
        r = pico_signal_read(n->signal, &signo);
        ASSERT_TRUE(r == 0);
        ASSERT_EQ_INT(signo, SIGHUP);

        r = netd_loop_dispatch_signal(n, signo);
        ASSERT_TRUE(r == 0);
        ASSERT_TRUE(n->reload_requested);

        ASSERT_TRUE(n->reload_handler != NULL);
        r = n->reload_handler(n);
        ASSERT_TRUE(r == 0);
        n->reload_requested = false;

        l = netd_find_link_by_name(n, "nettest0");
        ASSERT_TRUE(l != NULL);
        ASSERT_EQ_INT(l->state, LINK_CONFIGURED);

        run_shell("ip -4 addr show dev nettest0 | grep -q '10\\.252\\.0\\.9/24'");
        run_shell("! ip -4 addr show dev nettest0 | grep -q '10\\.252\\.0\\.5/24'");
        run_shell("ip route show default dev nettest0 | grep -q '10\\.252\\.0\\.253'");
        run_shell("! ip route show default dev nettest0 | grep -q '10\\.252\\.0\\.254'");

        read_file_into(resolv, buf, sizeof(buf));
        ASSERT_TRUE(strstr(buf, "nameserver 10.252.0.2") != NULL);

        /* A second reload with nothing changed on disk must leave a working
         * interface strictly alone (netd-link.h on link_reconfigure()), not
         * merely succeed. */
        r = n->reload_handler(n);
        ASSERT_TRUE(r == 0);
        run_shell("ip -4 addr show dev nettest0 | grep -q '10\\.252\\.0\\.9/24'");

        run_ip("link del nettest0");

        /* Let netd see the REMOVED event before tearing down, the way it
         * would in real operation -- otherwise netd_free()'s own teardown
         * tries to remove kernel state for an interface already gone and
         * logs a harmless but confusing "No such device" warning. */
        r = netd_rtnl_process(n->rtnl);
        ASSERT_TRUE(r >= 1);
        ASSERT_TRUE(netd_find_link_by_name(n, "nettest0") == NULL);

        netd_free(n);
        test_rm_rf(tmp);
        free(tmp);

        printf("test-netd-rtnl: static .network + SIGHUP subtest ok\n");
}

/*
 * A real DHCP lease, acquired end to end through netd-link.c's wiring --
 * test-netd-dhcp.c drives the server directly; this proves link_configure()
 * arms the client and server and link_apply_lease() lands the result. One
 * Netd instance runs both ends of a veth pair: a DHCPServer=yes side with a
 * static Address= (the usb0 gadget shape), and a DHCP=yes client side with
 * none. netd_loop_run() is the real loop; a forked timer process sends this
 * process a SIGTERM after a bounded wait so the loop returns as in
 * production.
 */
static void test_netns_dhcp_end_to_end(void) {
        char *tmp;
        char netdir[PATH_MAX], rundir[PATH_MAX], statedir[PATH_MAX], resolv[PATH_MAX];
        const char *netpath[2];
        Netd *n = NULL;
        Link *client_link;
        pid_t timeout_pid;
        int r;

        enter_test_netns();

        tmp = test_tmpdir_new();
        ASSERT_TRUE(tmp != NULL);
        ASSERT_TRUE(test_mkdir(tmp, "network") == 0);
        ASSERT_TRUE(test_mkdir(tmp, "run") == 0);
        ASSERT_TRUE(test_mkdir(tmp, "state") == 0);

        snprintf(netdir, sizeof(netdir), "%s/network", tmp);
        snprintf(rundir, sizeof(rundir), "%s/run", tmp);
        snprintf(statedir, sizeof(statedir), "%s/state", tmp);
        snprintf(resolv, sizeof(resolv), "%s/resolv.conf", tmp);

        if (test_write_file(netdir,
                            "10-dhcps.network",
                            "[Match]\nName=dhcps0\n\n[Network]\nAddress=10.253.0.1/24\nDHCPServer=yes\n") < 0 ||
            test_write_file(netdir, "10-dhcpc.network", "[Match]\nName=dhcpc0\n\n[Network]\nDHCP=yes\n") < 0) {
                fprintf(stderr, "test-netd-rtnl: failed to write .network fixtures\n");
                exit(1);
        }

        run_ip("link add name dhcps0 type veth peer name dhcpc0");

        r = netd_new(&n);
        ASSERT_TRUE(r == 0);

        netpath[0] = netdir;
        netpath[1] = NULL;
        ASSERT_TRUE(netd_set_network_path(n, netpath) == 0);
        ASSERT_TRUE(netd_set_runtime_dir(n, rundir) == 0);
        ASSERT_TRUE(netd_set_state_dir(n, statedir) == 0);
        ASSERT_TRUE(netd_set_resolv_conf(n, resolv) == 0);

        r = netd_startup(n);
        ASSERT_TRUE(r == 0);

        /* dhcps0 (the server side) converges immediately: starting the
         * server successfully *is* full convergence for DHCPServer=yes,
         * unlike the client side of a DHCP=yes link. */
        {
                Link *server_link = netd_find_link_by_name(n, "dhcps0");

                ASSERT_TRUE(server_link != NULL);
                ASSERT_EQ_INT(server_link->state, LINK_CONFIGURED);
        }

        client_link = netd_find_link_by_name(n, "dhcpc0");
        ASSERT_TRUE(client_link != NULL);
        ASSERT_TRUE(client_link->dhcp_client != NULL);

        /* Real production teardown path: a forked process sends this one a
         * real SIGTERM after a bounded wait, so netd_loop_run() below is
         * exercised completely unmodified -- the same way pico-init stops
         * the netd.service unit. */
        timeout_pid = fork();
        ASSERT_TRUE(timeout_pid >= 0);
        if (timeout_pid == 0) {
                sleep(10);
                kill(getppid(), SIGTERM);
                _exit(0);
        }

        r = netd_loop_run(n);
        ASSERT_TRUE(r == 0);

        /* The timeout process either already fired (harmless) or is still
         * sleeping -- reap it either way rather than leaking a zombie. */
        kill(timeout_pid, SIGKILL);
        waitpid(timeout_pid, NULL, 0);

        client_link = netd_find_link_by_name(n, "dhcpc0");
        ASSERT_TRUE(client_link != NULL);

        if (!client_link->lease) {
                fprintf(stderr,
                        "test-netd-rtnl: no DHCP lease acquired within the timeout -- "
                        "see the test's own comment for known environment caveats "
                        "(veth broadcast delivery, checksum offload) before assuming a code bug\n");
                exit(1);
        }

        ASSERT_TRUE(client_link->address_configured);
        ASSERT_EQ_INT(client_link->prefixlen, 24);
        /* Must land somewhere in the server's pool: 10.253.0.0/24, excluding
         * the server's own .1 and the subnet/broadcast addresses. */
        run_shell("ip -4 addr show dev dhcpc0 | grep -qE '10\\.253\\.0\\.[0-9]+/24'");
        run_shell("! ip -4 addr show dev dhcpc0 | grep -q '10\\.253\\.0\\.1/24'");

        /*
         * A reload (SIGHUP, `networkctl reload`) must not throw the lease's
         * address away: DHCP=yes with no Address= must not take the
         * "no static address wanted" branch and delete it.
         */
        ASSERT_TRUE(netd_reload(n) == 0);
        client_link = netd_find_link_by_name(n, "dhcpc0");
        ASSERT_TRUE(client_link != NULL);
        ASSERT_TRUE(client_link->lease != NULL);
        ASSERT_TRUE(client_link->address_configured);
        run_shell("ip -4 addr show dev dhcpc0 | grep -qE '10\\.253\\.0\\.[0-9]+/24'");

        run_ip("link del dhcps0");
        netd_free(n);
        test_rm_rf(tmp);
        free(tmp);

        printf("test-netd-rtnl: DHCP client-vs-server end-to-end subtest ok\n");
}

static DhcpLease *make_lease(const char *addr, const char *mask, const char *router) {
        DhcpLease *lease = calloc(1, sizeof(*lease));

        ASSERT_TRUE(lease != NULL);
        lease->n_ref = 1;
        ASSERT_EQ_INT(inet_pton(AF_INET, addr, &lease->address), 1);
        ASSERT_EQ_INT(inet_pton(AF_INET, mask, &lease->subnet_mask), 1);

        if (router) {
                /* A zero entry first: the first usable router is the one that counts. */
                lease->router = calloc(2, sizeof(*lease->router));
                ASSERT_TRUE(lease->router != NULL);
                lease->router_size = 2;
                ASSERT_EQ_INT(inet_pton(AF_INET, router, &lease->router[1]), 1);
        }
        return lease;
}

/*
 * A router outside the leased subnet needs a link-scope host route before the
 * default route will install, and a renewed lease without a router must take
 * the default route away again.
 */
static void test_netns_lease_gateway(void) {
        char *tmp;
        char netdir[PATH_MAX], rundir[PATH_MAX], statedir[PATH_MAX], resolv[PATH_MAX];
        const char *netpath[2];
        Netd *n = NULL;
        Link *l;

        enter_test_netns();

        tmp = test_tmpdir_new();
        ASSERT_TRUE(tmp != NULL);
        ASSERT_TRUE(test_mkdir(tmp, "network") == 0);
        ASSERT_TRUE(test_mkdir(tmp, "run") == 0);
        ASSERT_TRUE(test_mkdir(tmp, "state") == 0);

        snprintf(netdir, sizeof(netdir), "%s/network", tmp);
        snprintf(rundir, sizeof(rundir), "%s/run", tmp);
        snprintf(statedir, sizeof(statedir), "%s/state", tmp);
        snprintf(resolv, sizeof(resolv), "%s/resolv.conf", tmp);

        ASSERT_TRUE(test_write_file(netdir, "10-gw.network", "[Match]\nName=gwtest0\n\n[Network]\nDHCP=yes\n") == 0);
        run_ip("link add name gwtest0 type veth peer name gwtest1");

        ASSERT_TRUE(netd_new(&n) == 0);
        netpath[0] = netdir;
        netpath[1] = NULL;
        ASSERT_TRUE(netd_set_network_path(n, netpath) == 0);
        ASSERT_TRUE(netd_set_runtime_dir(n, rundir) == 0);
        ASSERT_TRUE(netd_set_state_dir(n, statedir) == 0);
        ASSERT_TRUE(netd_set_resolv_conf(n, resolv) == 0);
        ASSERT_TRUE(netd_startup(n) == 0);

        l = netd_find_link_by_name(n, "gwtest0");
        ASSERT_TRUE(l != NULL);

        /* /32 lease: the router is off-subnet. */
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.60.0.2", "255.255.255.255", "10.60.0.1")) == 0);
        ASSERT_TRUE(l->gateway_configured);
        run_shell("ip route show dev gwtest0 | grep -q '^10\\.60\\.0\\.1 .*scope link'");
        run_shell("ip route show default dev gwtest0 | grep -q 'via 10\\.60\\.0\\.1'");

        /* Renewal without a router. */
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.60.0.2", "255.255.255.255", NULL)) == 0);
        ASSERT_TRUE(!l->gateway_configured);
        run_shell("test -z \"$(ip route show default dev gwtest0)\"");
        run_shell("! ip route show dev gwtest0 | grep -q '^10\\.60\\.0\\.1 '");

        /* A router inside the subnet needs no host route. */
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.60.0.2", "255.255.255.0", "10.60.0.1")) == 0);
        ASSERT_TRUE(l->gateway_configured);
        run_shell("ip route show default dev gwtest0 | grep -q 'via 10\\.60\\.0\\.1'");
        run_shell("! ip route show dev gwtest0 | grep -q '^10\\.60\\.0\\.1 '");

        run_ip("link del gwtest0");
        netd_free(n);
        test_rm_rf(tmp);
        free(tmp);

        printf("test-netd-rtnl: lease gateway subtest ok\n");
}

static int reload_calls;

static int count_reload(Netd *n) {
        (void) n;
        reload_calls++;
        return 0;
}

/* SIGHUP read in the same batch as (or before) SIGTERM must not reconfigure
 * links while the daemon is going down. */
static void test_reload_dropped_after_exit_request(void) {
        Netd *n = NULL;

        enter_test_netns();

        ASSERT_TRUE(netd_new(&n) == 0);
        n->reload_handler = count_reload;

        ASSERT_TRUE(raise(SIGHUP) == 0);
        ASSERT_TRUE(raise(SIGTERM) == 0);

        ASSERT_TRUE(netd_loop_run(n) == 0);
        ASSERT_EQ_INT(n->objective, NETD_EXIT);
        ASSERT_EQ_INT(reload_calls, 0);

        netd_free(n);

        printf("test-netd-rtnl: reload after SIGTERM subtest ok\n");
}

int main(void) {
        test_event_names();
        test_link_snapshot_shape();
        test_netns_rtnl();
        test_netns_static_network_and_sighup();
        test_netns_dhcp_end_to_end();
        test_netns_lease_gateway();
        test_reload_dropped_after_exit_request();

        printf("test-netd-rtnl: ok\n");
        return EXIT_SUCCESS;
}
