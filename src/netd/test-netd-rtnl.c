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
 *
 * Route metrics follow systemd-networkd: links sharing a metric keep separate
 * routes, each removed on its own, whether two leases at the default 1024 or
 * two Gateway= routes at the kernel's 0; RouteMetric= sets a lease's default,
 * host and prefix routes exactly; a reload that changes RouteMetric= moves
 * them at once; and a route at the Gateway= address stays static through
 * leases and reloads. The default route comes back after a same-subnet
 * renumber and a lease loss, an unchanged reload leaves a lease's route
 * alone, turning DHCP= off drops the lease, and Gateway= with DHCP starts the
 * client without an Address=.
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
#include <stdarg.h>
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

static void run_shellf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void run_shellf(const char *fmt, ...) {
        char cmd[512];
        va_list ap;
        int len;

        va_start(ap, fmt);
        len = vsnprintf(cmd, sizeof(cmd), fmt, ap);
        va_end(ap);

        if (len < 0 || (size_t) len >= sizeof(cmd)) {
                fprintf(stderr, "test-netd-rtnl: shell command too long: %s\n", fmt);
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
        r = netd_rtnl_address_add(rtnl, veth->ifindex, &addr, 24, NULL, UINT32_MAX, 0);
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

        ASSERT_TRUE(test_write_file(netdir, "10-gw.network", "[Match]\nName=gwtest0\n\n[Network]\nDHCP=yes\n") ==
                    0);
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

/* --- route metrics --- */

static unsigned ifindex_of(const char *name) {
        unsigned idx = if_nametoindex(name);

        ASSERT_TRUE(idx > 0);
        return idx;
}

/* Exactly one default route on `dev`, via `gw` at `metric`. The metric goes
 * through ip's own filter, which also matches 0, a metric ip never prints. */
static void assert_one_default(const char *dev, const char *gw, unsigned metric) {
        run_shellf("test \"$(ip route show default dev %s | wc -l)\" -eq 1", dev);
        run_shellf("ip route show default dev %s metric %u | grep -q 'via %s '", dev, metric, gw);
}

/*
 * The raw layer: two links' default routes at one metric are two routes.
 * With NLM_F_REPLACE the second add overwrote the first and its later delete
 * found nothing.
 */
static void test_netns_route_same_metric(void) {
        NetdRtnl *rtnl = NULL;
        struct in_addr addr, gwa, gwb;
        int ia, ib;

        enter_test_netns();

        ASSERT_TRUE(netd_rtnl_new(&rtnl) == 0);

        run_ip("link add name rma0 type veth peer name rma1");
        run_ip("link add name rmb0 type veth peer name rmb1");
        run_ip("link set rma0 up");
        run_ip("link set rma1 up");
        run_ip("link set rmb0 up");
        run_ip("link set rmb1 up");
        ia = (int) ifindex_of("rma0");
        ib = (int) ifindex_of("rmb0");

        ASSERT_EQ_INT(inet_pton(AF_INET, "10.70.0.2", &addr), 1);
        ASSERT_TRUE(netd_rtnl_address_add(rtnl, ia, &addr, 24, NULL, UINT32_MAX, 0) == 0);
        ASSERT_EQ_INT(inet_pton(AF_INET, "10.71.0.2", &addr), 1);
        ASSERT_TRUE(netd_rtnl_address_add(rtnl, ib, &addr, 24, NULL, UINT32_MAX, 0) == 0);
        ASSERT_EQ_INT(inet_pton(AF_INET, "10.70.0.1", &gwa), 1);
        ASSERT_EQ_INT(inet_pton(AF_INET, "10.71.0.1", &gwb), 1);

        ASSERT_EQ_INT(netd_rtnl_route_add_default(rtnl, ia, &gwa, 100), 0);
        ASSERT_EQ_INT(netd_rtnl_route_add_default(rtnl, ib, &gwb, 100), 0);
        run_shell("ip -4 route show default metric 100 | grep -q 'dev rma0'");
        run_shell("ip -4 route show default metric 100 | grep -q 'dev rmb0'");

        ASSERT_EQ_INT(netd_rtnl_route_add_default(rtnl, ia, &gwa, 100), -EEXIST);

        /* rmb0's gateway on rma0 is nobody's route. */
        ASSERT_EQ_INT(netd_rtnl_route_del(rtnl, ia, NULL, 0, &gwb, 100), -ESRCH);
        run_shell("ip -4 route show default metric 100 | grep -q 'dev rma0'");
        run_shell("ip -4 route show default metric 100 | grep -q 'dev rmb0'");

        ASSERT_EQ_INT(netd_rtnl_route_del(rtnl, ia, NULL, 0, &gwa, 100), 0);
        run_shell("test -z \"$(ip -4 route show default dev rma0)\"");
        run_shell("ip -4 route show default metric 100 | grep -q 'dev rmb0'");

        ASSERT_EQ_INT(netd_rtnl_route_add_default(rtnl, ia, &gwa, 100), 0);
        ASSERT_EQ_INT(netd_rtnl_route_del(rtnl, ib, NULL, 0, &gwb, 100), 0);
        run_shell("ip -4 route show default metric 100 | grep -q 'dev rma0'");
        run_shell("test -z \"$(ip -4 route show default dev rmb0)\"");

        run_ip("link del rma0");
        run_ip("link del rmb0");
        netd_rtnl_free(rtnl);

        printf("test-netd-rtnl: same-metric routes subtest ok\n");
}

/* A temporary netd tree; .network files go in netdir before netd_start(). */
typedef struct NetdFixture {
        char *tmp;
        char netdir[PATH_MAX];
        Netd *n;
} NetdFixture;

static void fixture_init(NetdFixture *f) {
        memset(f, 0, sizeof(*f));
        f->tmp = test_tmpdir_new();
        ASSERT_TRUE(f->tmp != NULL);
        ASSERT_TRUE(test_mkdir(f->tmp, "network") == 0);
        ASSERT_TRUE(test_mkdir(f->tmp, "run") == 0);
        ASSERT_TRUE(test_mkdir(f->tmp, "state") == 0);
        snprintf(f->netdir, sizeof(f->netdir), "%s/network", f->tmp);
}

static void fixture_write(NetdFixture *f, const char *name, const char *content) {
        if (test_write_file(f->netdir, name, content) < 0) {
                fprintf(stderr, "test-netd-rtnl: failed to write %s/%s: %s\n", f->netdir, name, strerror(errno));
                exit(1);
        }
}

static void fixture_start(NetdFixture *f) {
        char rundir[PATH_MAX], statedir[PATH_MAX], resolv[PATH_MAX];
        const char *netpath[2] = { f->netdir, NULL };

        snprintf(rundir, sizeof(rundir), "%s/run", f->tmp);
        snprintf(statedir, sizeof(statedir), "%s/state", f->tmp);
        snprintf(resolv, sizeof(resolv), "%s/resolv.conf", f->tmp);

        ASSERT_TRUE(netd_new(&f->n) == 0);
        ASSERT_TRUE(netd_set_network_path(f->n, netpath) == 0);
        ASSERT_TRUE(netd_set_runtime_dir(f->n, rundir) == 0);
        ASSERT_TRUE(netd_set_state_dir(f->n, statedir) == 0);
        ASSERT_TRUE(netd_set_resolv_conf(f->n, resolv) == 0);
        ASSERT_TRUE(netd_startup(f->n) == 0);
}

static void fixture_stop(NetdFixture *f) {
        netd_free(f->n);
        test_rm_rf(f->tmp);
        free(f->tmp);
}

static Link *fixture_link(NetdFixture *f, const char *name) {
        Link *l = netd_find_link_by_name(f->n, name);

        ASSERT_TRUE(l != NULL);
        return l;
}

/* Two leases at one metric through the Link layer: renew, router change,
 * lease loss and link removal on one link never touch the other's route. */
static void test_netns_lease_same_metric_two_links(void) {
        NetdFixture f;
        Link *la, *lb;

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f,
                      "10-lsa.network",
                      "[Match]\nName=lsa0\n\n[Network]\nDHCP=yes\n\n[DHCPv4]\nRouteMetric=100\n");
        fixture_write(&f,
                      "10-lsb.network",
                      "[Match]\nName=lsb0\n\n[Network]\nDHCP=yes\n\n[DHCP]\nRouteMetric=100\n");
        run_ip("link add name lsa0 type veth peer name lsa1");
        run_ip("link add name lsb0 type veth peer name lsb1");
        fixture_start(&f);

        la = fixture_link(&f, "lsa0");
        lb = fixture_link(&f, "lsb0");

        ASSERT_TRUE(link_apply_lease(la, make_lease("10.72.0.2", "255.255.255.0", "10.72.0.1")) == 0);
        ASSERT_TRUE(link_apply_lease(lb, make_lease("10.73.0.2", "255.255.255.0", "10.73.0.1")) == 0);
        run_shell("ip route show default dev lsa0 | grep -qE 'via 10\\.72\\.0\\.1 .*metric 100( |$)'");
        run_shell("ip route show default dev lsb0 | grep -qE 'via 10\\.73\\.0\\.1 .*metric 100( |$)'");
        ASSERT_EQ_INT(la->gateway_metric, 100);
        ASSERT_EQ_INT(lb->gateway_metric, 100);

        /* Renewal changes nothing. */
        ASSERT_TRUE(link_apply_lease(la, make_lease("10.72.0.2", "255.255.255.0", "10.72.0.1")) == 0);
        run_shell("test \"$(ip route show default dev lsa0 | wc -l)\" -eq 1");
        run_shell("ip route show default dev lsb0 | grep -q 'via 10\\.73\\.0\\.1'");

        ASSERT_TRUE(link_apply_lease(la, make_lease("10.72.0.2", "255.255.255.0", "10.72.0.254")) == 0);
        run_shell("test \"$(ip route show default dev lsa0 | wc -l)\" -eq 1");
        run_shell("ip route show default dev lsa0 | grep -q 'via 10\\.72\\.0\\.254'");
        run_shell("ip route show default dev lsb0 | grep -qE 'via 10\\.73\\.0\\.1 .*metric 100( |$)'");

        ASSERT_TRUE(link_lose_lease(la) == 0);
        run_shell("test -z \"$(ip route show default dev lsa0)\"");
        run_shell("ip route show default dev lsb0 | grep -qE 'via 10\\.73\\.0\\.1 .*metric 100( |$)'");

        /* The kernel flushes lsa0's routes; netd's own delete then names a
         * gone ifindex and cannot reach lsb0's route. */
        ASSERT_TRUE(link_apply_lease(la, make_lease("10.72.0.2", "255.255.255.0", "10.72.0.1")) == 0);
        run_ip("link del lsa0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        ASSERT_TRUE(netd_find_link_by_name(f.n, "lsa0") == NULL);
        run_shell("ip route show default dev lsb0 | grep -qE 'via 10\\.73\\.0\\.1 .*metric 100( |$)'");

        run_ip("link del lsb0");
        fixture_stop(&f);

        printf("test-netd-rtnl: two leases at one metric subtest ok\n");
}

/* No RouteMetric= gives a lease networkd's 1024; Gateway= ignores
 * [DHCPv4] RouteMetric= and gets the kernel's 0, as in networkd. */
static void test_netns_route_metric_default_and_static(void) {
        NetdFixture f;
        Link *l;

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f, "10-mdf.network", "[Match]\nName=mdf0\n\n[Network]\nDHCP=yes\n");
        fixture_write(&f,
                      "10-mst.network",
                      "[Match]\nName=mst0\n\n[Network]\nAddress=10.75.0.2/24\nGateway=10.75.0.1\n\n"
                      "[DHCPv4]\nRouteMetric=10\n");
        run_ip("link add name mdf0 type veth peer name mdf1");
        run_ip("link add name mst0 type veth peer name mst1");
        fixture_start(&f);

        l = fixture_link(&f, "mdf0");
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.74.0.2", "255.255.255.0", "10.74.0.1")) == 0);
        ASSERT_EQ_INT(l->gateway_metric, 1024);
        assert_one_default("mdf0", "10\\.74\\.0\\.1", 1024);

        l = fixture_link(&f, "mst0");
        ASSERT_TRUE(l->gateway_configured);
        ASSERT_EQ_INT(l->gateway_metric, 0);
        assert_one_default("mst0", "10\\.75\\.0\\.1", 0);

        run_ip("link del mdf0");
        run_ip("link del mst0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: default and static metric subtest ok\n");
}

/* A reload that changes RouteMetric= moves the lease's default and host
 * routes at once, and leaves another link's route alone. */
static void test_netns_route_metric_reload(void) {
        NetdFixture f;
        Link *l, *other;

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f,
                      "10-mrl.network",
                      "[Match]\nName=mrl0\n\n[Network]\nDHCP=yes\n\n[DHCPv4]\nRouteMetric=100\n");
        fixture_write(&f,
                      "10-mro.network",
                      "[Match]\nName=mro0\n\n[Network]\nDHCP=yes\n\n[DHCPv4]\nRouteMetric=100\n");
        run_ip("link add name mrl0 type veth peer name mrl1");
        run_ip("link add name mro0 type veth peer name mro1");
        fixture_start(&f);

        /* /32 lease: the router is off-subnet, so a host route goes in too. */
        l = fixture_link(&f, "mrl0");
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.76.0.2", "255.255.255.255", "10.76.0.1")) == 0);
        other = fixture_link(&f, "mro0");
        ASSERT_TRUE(link_apply_lease(other, make_lease("10.77.0.2", "255.255.255.0", "10.77.0.1")) == 0);
        run_shell("ip route show default dev mrl0 | grep -qE 'metric 100( |$)'");
        run_shell("ip route show dev mrl0 | grep -qE '^10\\.76\\.0\\.1 .*metric 100( |$)'");

        fixture_write(&f,
                      "10-mrl.network",
                      "[Match]\nName=mrl0\n\n[Network]\nDHCP=yes\n\n[DHCPv4]\nRouteMetric=300\n");
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);

        for (int pass = 0; pass < 2; pass++) {
                l = fixture_link(&f, "mrl0");
                ASSERT_TRUE(l->gateway_configured);
                ASSERT_TRUE(l->gateway_host_route);
                ASSERT_EQ_INT(l->gateway_metric, 300);
                run_shell("ip route show default dev mrl0 | grep -qE 'via 10\\.76\\.0\\.1 .*metric 300( |$)'");
                run_shell("ip route show dev mrl0 | grep -qE '^10\\.76\\.0\\.1 .*metric 300( |$)'");
                run_shell("! ip route show dev mrl0 | grep -qE 'metric 100( |$)'");
                run_shell("test \"$(ip route show default dev mrl0 | wc -l)\" -eq 1");
                run_shell("ip route show default dev mro0 | grep -qE 'via 10\\.77\\.0\\.1 .*metric 100( |$)'");

                /* Nothing changed on disk: the second pass sees the same. */
                ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        }

        run_ip("link del mrl0");
        run_ip("link del mro0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: RouteMetric= reload subtest ok\n");
}

/* The raw layer: IFA_RT_PRIORITY sets the prefix route's metric, and the
 * same address sent again with another metric moves it. */
static void test_netns_address_prefix_metric(void) {
        NetdRtnl *rtnl = NULL;
        struct in_addr addr;
        int i;

        enter_test_netns();

        ASSERT_TRUE(netd_rtnl_new(&rtnl) == 0);
        run_ip("link add name pm0 type veth peer name pm1");
        run_ip("link set pm0 up");
        i = (int) ifindex_of("pm0");
        ASSERT_EQ_INT(inet_pton(AF_INET, "10.78.0.2", &addr), 1);

        ASSERT_EQ_INT(netd_rtnl_address_add(rtnl, i, &addr, 24, NULL, UINT32_MAX, 1024), 0);
        run_shell("ip -4 route show dev pm0 metric 1024 | grep -q '^10\\.78\\.0\\.0/24 '");

        ASSERT_EQ_INT(netd_rtnl_address_add(rtnl, i, &addr, 24, NULL, UINT32_MAX, 300), 0);
        run_shell("ip -4 route show dev pm0 metric 300 | grep -q '^10\\.78\\.0\\.0/24 '");
        run_shell("test \"$(ip -4 route show dev pm0 | wc -l)\" -eq 1");

        ASSERT_EQ_INT(netd_rtnl_address_add(rtnl, i, &addr, 24, NULL, UINT32_MAX, 0), 0);
        run_shell("ip -4 route show dev pm0 metric 0 | grep -q '^10\\.78\\.0\\.0/24 '");
        run_shell("test \"$(ip -4 route show dev pm0 | wc -l)\" -eq 1");

        run_ip("link del pm0");
        netd_rtnl_free(rtnl);

        printf("test-netd-rtnl: prefix route metric subtest ok\n");
}

/* A lease without RouteMetric= puts its default route, its host route to an
 * off-subnet router and its prefix route at 1024; a reload moves all three
 * and back. Address= keeps the kernel's prefix metric 0. */
static void test_netns_lease_default_metric_routes(void) {
        static const char dhcp[] = "[Match]\nName=dmh0 dmp0\n\n[Network]\nDHCP=yes\n";
        NetdFixture f;
        Link *l;

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f, "10-dm.network", dhcp);
        fixture_write(&f, "05-ds.network", "[Match]\nName=ds0\n\n[Network]\nAddress=10.104.0.2/24\n");
        run_ip("link add name dmh0 type veth peer name dmh1");
        run_ip("link add name dmp0 type veth peer name dmp1");
        run_ip("link add name ds0 type veth peer name ds1");
        fixture_start(&f);

        l = fixture_link(&f, "dmh0");
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.102.0.2", "255.255.255.255", "10.102.0.1")) == 0);
        ASSERT_TRUE(l->gateway_host_route);
        assert_one_default("dmh0", "10\\.102\\.0\\.1", 1024);
        run_shell("ip -4 route show dev dmh0 metric 1024 | grep -q '^10\\.102\\.0\\.1 .*scope link'");

        l = fixture_link(&f, "dmp0");
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.103.0.2", "255.255.255.0", "10.103.0.1")) == 0);
        ASSERT_EQ_INT(l->address_metric, 1024);
        assert_one_default("dmp0", "10\\.103\\.0\\.1", 1024);
        run_shell("ip -4 route show dev dmp0 metric 1024 | grep -q '^10\\.103\\.0\\.0/24 '");

        run_shell("ip -4 route show dev ds0 metric 0 | grep -q '^10\\.104\\.0\\.0/24 '");

        fixture_write(&f,
                      "10-dm.network",
                      "[Match]\nName=dmh0 dmp0\n\n[Network]\nDHCP=yes\n\n[DHCPv4]\nRouteMetric=300\n");
        for (int pass = 0; pass < 2; pass++) {
                ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
                l = fixture_link(&f, "dmp0");
                ASSERT_EQ_INT(l->address_metric, 300);
                assert_one_default("dmp0", "10\\.103\\.0\\.1", 300);
                run_shell("ip -4 route show dev dmp0 metric 300 | grep -q '^10\\.103\\.0\\.0/24 '");
                run_shell("test -z \"$(ip -4 route show dev dmp0 metric 1024)\"");
                assert_one_default("dmh0", "10\\.102\\.0\\.1", 300);
                run_shell("ip -4 route show dev dmh0 metric 300 | grep -q '^10\\.102\\.0\\.1 .*scope link'");
                run_shell("test -z \"$(ip -4 route show dev dmh0 metric 1024)\"");
        }

        fixture_write(&f, "10-dm.network", dhcp);
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        assert_one_default("dmp0", "10\\.103\\.0\\.1", 1024);
        run_shell("ip -4 route show dev dmp0 metric 1024 | grep -q '^10\\.103\\.0\\.0/24 '");
        run_shell("test -z \"$(ip -4 route show dev dmp0 metric 300)\"");
        run_shell("ip -4 route show dev ds0 metric 0 | grep -q '^10\\.104\\.0\\.0/24 '");

        /* DHCP= off with Address= at the leased address: Address='s metric. */
        fixture_write(&f, "05-dmp.network", "[Match]\nName=dmp0\n\n[Network]\nAddress=10.103.0.2/24\n");
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        ASSERT_EQ_INT(fixture_link(&f, "dmp0")->address_metric, 0);
        run_shell("ip -4 route show dev dmp0 metric 0 | grep -q '^10\\.103\\.0\\.0/24 '");
        run_shell("test \"$(ip -4 route show dev dmp0 | wc -l)\" -eq 1");

        run_ip("link del dmh0");
        run_ip("link del dmp0");
        run_ip("link del ds0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: lease default metric routes subtest ok\n");
}

/* Two links without RouteMetric=, leased into one subnet with one router:
 * both default routes sit at 1024, and losing either lease leaves the other. */
static void test_netns_default_metric_two_links(void) {
        NetdFixture f;
        Link *la, *lb;

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f, "10-u.network", "[Match]\nName=ua0 ub0\n\n[Network]\nDHCP=yes\n");
        run_ip("link add name ua0 type veth peer name ua1");
        run_ip("link add name ub0 type veth peer name ub1");
        fixture_start(&f);

        la = fixture_link(&f, "ua0");
        lb = fixture_link(&f, "ub0");
        ASSERT_TRUE(link_apply_lease(la, make_lease("10.105.0.2", "255.255.255.0", "10.105.0.1")) == 0);
        ASSERT_TRUE(link_apply_lease(lb, make_lease("10.105.0.3", "255.255.255.0", "10.105.0.1")) == 0);
        assert_one_default("ua0", "10\\.105\\.0\\.1", 1024);
        assert_one_default("ub0", "10\\.105\\.0\\.1", 1024);

        ASSERT_TRUE(link_lose_lease(la) == 0);
        run_shell("test -z \"$(ip route show default dev ua0)\"");
        assert_one_default("ub0", "10\\.105\\.0\\.1", 1024);

        ASSERT_TRUE(link_apply_lease(la, make_lease("10.105.0.2", "255.255.255.0", "10.105.0.1")) == 0);
        ASSERT_TRUE(link_lose_lease(lb) == 0);
        run_shell("test -z \"$(ip route show default dev ub0)\"");
        assert_one_default("ua0", "10\\.105\\.0\\.1", 1024);

        run_ip("link del ua0");
        run_ip("link del ub0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: two leases at the default metric subtest ok\n");
}

/* Two Gateway= routes at the kernel's 0 to one router: a delete at metric 0
 * matches any metric, but only on its own link. */
static void test_netns_static_gateway_two_links(void) {
        static const char a_gw[] = "[Match]\nName=sa0\n\n[Network]\nAddress=10.106.0.2/24\nGateway=10.106.0.1\n";
        static const char a_nogw[] = "[Match]\nName=sa0\n\n[Network]\nAddress=10.106.0.2/24\n";
        NetdFixture f;

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f, "10-sa.network", a_gw);
        fixture_write(&f,
                      "10-sb.network",
                      "[Match]\nName=sb0\n\n[Network]\nAddress=10.106.0.3/24\nGateway=10.106.0.1\n");
        run_ip("link add name sa0 type veth peer name sa1");
        run_ip("link add name sb0 type veth peer name sb1");
        fixture_start(&f);

        ASSERT_EQ_INT(fixture_link(&f, "sa0")->gateway_metric, 0);
        assert_one_default("sa0", "10\\.106\\.0\\.1", 0);
        assert_one_default("sb0", "10\\.106\\.0\\.1", 0);

        fixture_write(&f, "10-sa.network", a_nogw);
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        run_shell("test -z \"$(ip route show default dev sa0)\"");
        assert_one_default("sb0", "10\\.106\\.0\\.1", 0);

        fixture_write(&f, "10-sa.network", a_gw);
        fixture_write(&f, "10-sb.network", "[Match]\nName=sb0\n\n[Network]\nAddress=10.106.0.3/24\n");
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        run_shell("test -z \"$(ip route show default dev sb0)\"");
        assert_one_default("sa0", "10\\.106\\.0\\.1", 0);

        run_ip("link del sa0");
        run_ip("link del sb0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: two Gateway= routes at metric 0 subtest ok\n");
}

/* A Gateway= route at 0 that is already gone when a lease takes over at the
 * same router: the delete at 0 must not take the lease's new route. */
static void test_netns_metric0_gone_before_lease(void) {
        NetdFixture f;
        Link *l;

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f,
                      "10-zg.network",
                      "[Match]\nName=zg0\n\n[Network]\nAddress=10.107.0.2/24\nGateway=10.107.0.1\nDHCP=yes\n\n"
                      "[DHCPv4]\nRouteMetric=300\n");
        run_ip("link add name zg0 type veth peer name zg1");
        fixture_start(&f);

        l = fixture_link(&f, "zg0");
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.107.0.2", "255.255.255.0", "10.107.0.1")) == 0);
        ASSERT_TRUE(!l->gateway_from_lease);
        assert_one_default("zg0", "10\\.107\\.0\\.1", 0);

        run_ip("route del default via 10.107.0.1 dev zg0 metric 0");
        fixture_write(&f,
                      "10-zg.network",
                      "[Match]\nName=zg0\n\n[Network]\nAddress=10.107.0.2/24\nDHCP=yes\n\n"
                      "[DHCPv4]\nRouteMetric=300\n");
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        l = fixture_link(&f, "zg0");
        ASSERT_TRUE(l->gateway_configured && l->gateway_from_lease);
        assert_one_default("zg0", "10\\.107\\.0\\.1", 300);

        run_ip("link del zg0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: metric 0 route gone before a lease subtest ok\n");
}

/*
 * A lease whose router is the Gateway= address leaves that route static, at
 * the kernel's metric 0, so a later lease without a router cannot remove it.
 * A lease route that replaced Gateway= gives way to it again when it goes.
 */
static void test_netns_lease_router_is_static_gateway(void) {
        NetdFixture f;
        Link *l;
        const unsigned m = 0; /* Gateway= */

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f,
                      "10-ps.network",
                      "[Match]\nName=ps0\n\n[Network]\nAddress=10.80.0.2/24\nGateway=10.80.0.1\nDHCP=yes\n\n"
                      "[DHCPv4]\nRouteMetric=10\n");
        run_ip("link add name ps0 type veth peer name ps1");
        fixture_start(&f);

        l = fixture_link(&f, "ps0");
        ASSERT_EQ_INT(l->gateway_metric, m);
        assert_one_default("ps0", "10\\.80\\.0\\.1", m);

        ASSERT_TRUE(link_apply_lease(l, make_lease("10.80.0.2", "255.255.255.0", "10.80.0.1")) == 0);
        ASSERT_TRUE(!l->gateway_from_lease);
        ASSERT_EQ_INT(l->gateway_metric, m);
        assert_one_default("ps0", "10\\.80\\.0\\.1", m);

        ASSERT_TRUE(link_apply_lease(l, make_lease("10.80.0.2", "255.255.255.0", NULL)) == 0);
        ASSERT_TRUE(l->gateway_configured);
        assert_one_default("ps0", "10\\.80\\.0\\.1", m);

        ASSERT_TRUE(link_apply_lease(l, make_lease("10.80.0.2", "255.255.255.0", "10.80.0.254")) == 0);
        ASSERT_TRUE(l->gateway_from_lease);
        assert_one_default("ps0", "10\\.80\\.0\\.254", 10);

        /* Back to the Gateway= router: static again, not the lease's. */
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.80.0.2", "255.255.255.0", "10.80.0.1")) == 0);
        ASSERT_TRUE(!l->gateway_from_lease);
        assert_one_default("ps0", "10\\.80\\.0\\.1", m);

        ASSERT_TRUE(link_apply_lease(l, make_lease("10.80.0.2", "255.255.255.0", "10.80.0.254")) == 0);
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.80.0.2", "255.255.255.0", NULL)) == 0);
        ASSERT_TRUE(l->gateway_configured && !l->gateway_from_lease);
        assert_one_default("ps0", "10\\.80\\.0\\.1", m);

        run_ip("link del ps0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: lease router at Gateway= subtest ok\n");
}

/*
 * Reloads between a lease route and Gateway= at the same router move the
 * route to the owner's metric in both directions, with DHCP on and off.
 */
static void test_netns_reload_gateway_owner(void) {
        static const char dhcp[] = "[Match]\nName=pu0\n\n[Network]\nDHCP=yes\n\n[DHCPv4]\nRouteMetric=300\n";
        static const char dhcp_gw[] =
                        "[Match]\nName=pu0\n\n[Network]\nDHCP=yes\nGateway=10.84.0.1\n\n"
                        "[DHCPv4]\nRouteMetric=300\n";
        NetdFixture f;
        Link *l;
        const unsigned m = 0; /* Gateway= */

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f, "10-pu.network", dhcp);
        run_ip("link add name pu0 type veth peer name pu1");
        fixture_start(&f);

        l = fixture_link(&f, "pu0");
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.84.0.2", "255.255.255.0", "10.84.0.1")) == 0);
        ASSERT_TRUE(l->gateway_from_lease);
        assert_one_default("pu0", "10\\.84\\.0\\.1", 300);

        /* DHCP off, Gateway= at the lease's router. */
        fixture_write(&f,
                      "10-pu.network",
                      "[Match]\nName=pu0\n\n[Network]\nAddress=10.84.0.2/24\nGateway=10.84.0.1\n");
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        l = fixture_link(&f, "pu0");
        ASSERT_TRUE(l->gateway_configured && !l->gateway_from_lease);
        ASSERT_EQ_INT(l->gateway_metric, m);
        assert_one_default("pu0", "10\\.84\\.0\\.1", m);

        /* DHCP back on without Gateway=: no route until a new lease, which
         * owns it. */
        fixture_write(&f, "10-pu.network", dhcp);
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        l = fixture_link(&f, "pu0");
        ASSERT_TRUE(l->lease == NULL && !l->gateway_configured);
        run_shell("test -z \"$(ip route show default dev pu0)\"");
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.84.0.2", "255.255.255.0", "10.84.0.1")) == 0);
        ASSERT_TRUE(l->gateway_configured && l->gateway_from_lease);
        ASSERT_EQ_INT(l->gateway_metric, 300);
        assert_one_default("pu0", "10\\.84\\.0\\.1", 300);

        /* Gateway= added with the lease held: static, and a lease without
         * a router leaves it. */
        fixture_write(&f, "10-pu.network", dhcp_gw);
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        l = fixture_link(&f, "pu0");
        ASSERT_TRUE(l->gateway_configured && !l->gateway_from_lease);
        ASSERT_EQ_INT(l->gateway_metric, m);
        assert_one_default("pu0", "10\\.84\\.0\\.1", m);
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.84.0.2", "255.255.255.0", "10.84.0.1")) == 0);
        assert_one_default("pu0", "10\\.84\\.0\\.1", m);
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.84.0.2", "255.255.255.0", NULL)) == 0);
        assert_one_default("pu0", "10\\.84\\.0\\.1", m);

        /* Gateway= dropped while the lease has no router: no route. */
        fixture_write(&f, "10-pu.network", dhcp);
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        l = fixture_link(&f, "pu0");
        ASSERT_TRUE(!l->gateway_configured);
        run_shell("test -z \"$(ip route show default dev pu0)\"");

        ASSERT_TRUE(link_apply_lease(l, make_lease("10.84.0.2", "255.255.255.0", "10.84.0.1")) == 0);
        assert_one_default("pu0", "10\\.84\\.0\\.1", 300);

        /* Gateway= dropped while the lease has the same router: the lease's. */
        fixture_write(&f, "10-pu.network", dhcp_gw);
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        assert_one_default("pu0", "10\\.84\\.0\\.1", m);
        fixture_write(&f, "10-pu.network", dhcp);
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        l = fixture_link(&f, "pu0");
        ASSERT_TRUE(l->gateway_configured && l->gateway_from_lease);
        assert_one_default("pu0", "10\\.84\\.0\\.1", 300);

        /* DHCP and Gateway= both gone. */
        fixture_write(&f, "10-pu.network", "[Match]\nName=pu0\n\n[Network]\nAddress=10.84.0.2/24\n");
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        l = fixture_link(&f, "pu0");
        ASSERT_TRUE(!l->gateway_configured);
        run_shell("test -z \"$(ip route show default dev pu0)\"");

        run_ip("link del pu0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: reload between lease and Gateway= subtest ok\n");
}

/*
 * Deleting a link's only address makes the kernel flush its routes, so a new
 * address in the same subnet, which is put in delete-first, must bring the
 * default route back: from a lease, and from Address= on reload.
 */
static void test_netns_same_subnet_renumber_keeps_default(void) {
        NetdFixture f;
        Link *l;

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f, "10-rna.network", "[Match]\nName=rna0\n\n[Network]\nDHCP=yes\n");
        fixture_write(&f,
                      "10-rnb.network",
                      "[Match]\nName=rnb0\n\n[Network]\nAddress=10.97.0.2/24\nGateway=10.97.0.1\n");
        run_ip("link add name rna0 type veth peer name rna1");
        run_ip("link add name rnb0 type veth peer name rnb1");
        fixture_start(&f);

        l = fixture_link(&f, "rna0");
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.90.0.2", "255.255.255.0", "10.90.0.1")) == 0);
        assert_one_default("rna0", "10\\.90\\.0\\.1", 1024);
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.90.0.3", "255.255.255.0", "10.90.0.1")) == 0);
        ASSERT_TRUE(l->gateway_configured);
        run_shell("ip -4 addr show dev rna0 | grep -q '10\\.90\\.0\\.3/24'");
        assert_one_default("rna0", "10\\.90\\.0\\.1", 1024);

        assert_one_default("rnb0", "10\\.97\\.0\\.1", 0);
        fixture_write(&f,
                      "10-rnb.network",
                      "[Match]\nName=rnb0\n\n[Network]\nAddress=10.97.0.3/24\nGateway=10.97.0.1\n");
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        l = fixture_link(&f, "rnb0");
        ASSERT_EQ_INT(l->state, LINK_CONFIGURED);
        ASSERT_TRUE(l->gateway_configured);
        run_shell("ip -4 addr show dev rnb0 | grep -q '10\\.97\\.0\\.3/24'");
        assert_one_default("rnb0", "10\\.97\\.0\\.1", 0);

        /* Address= dropped, Gateway= kept: the route is gone and netd says so. */
        fixture_write(&f, "10-rnb.network", "[Match]\nName=rnb0\n\n[Network]\nGateway=10.97.0.1\n");
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        l = fixture_link(&f, "rnb0");
        ASSERT_TRUE(!l->gateway_configured);
        ASSERT_EQ_INT(l->state, LINK_FAILED);
        run_shell("test -z \"$(ip route show default dev rnb0)\"");

        run_ip("link del rna0");
        run_ip("link del rnb0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: same-subnet renumber subtest ok\n");
}

/*
 * With Gateway= and DHCP, a reload that changes nothing leaves a lease's
 * route at its router and RouteMetric=; a lease without a router then puts
 * Gateway= back.
 */
static void test_netns_reload_keeps_lease_route(void) {
        NetdFixture f;
        Link *l;
        const unsigned m = 0; /* Gateway= */

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f,
                      "10-kl.network",
                      "[Match]\nName=kl0\n\n[Network]\nAddress=10.91.0.2/24\nGateway=10.91.0.1\nDHCP=yes\n\n"
                      "[DHCPv4]\nRouteMetric=20\n");
        run_ip("link add name kl0 type veth peer name kl1");
        fixture_start(&f);

        l = fixture_link(&f, "kl0");
        assert_one_default("kl0", "10\\.91\\.0\\.1", m);
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.91.0.2", "255.255.255.0", "10.91.0.254")) == 0);
        assert_one_default("kl0", "10\\.91\\.0\\.254", 20);

        for (int pass = 0; pass < 2; pass++) {
                ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
                l = fixture_link(&f, "kl0");
                ASSERT_TRUE(l->gateway_configured && l->gateway_from_lease);
                ASSERT_EQ_INT(l->gateway_metric, 20);
                assert_one_default("kl0", "10\\.91\\.0\\.254", 20);
        }

        ASSERT_TRUE(link_apply_lease(l, make_lease("10.91.0.2", "255.255.255.0", NULL)) == 0);
        ASSERT_TRUE(l->gateway_configured && !l->gateway_from_lease);
        assert_one_default("kl0", "10\\.91\\.0\\.1", m);

        run_ip("link del kl0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: reload keeps the lease route subtest ok\n");
}

/* Gateway= that cannot be added before the first lease does not stop the
 * DHCP client from starting; the lease brings it in. */
static void test_netns_gateway_dhcp_no_address(void) {
        NetdFixture f;
        Link *l;

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f, "10-gn.network", "[Match]\nName=gn0\n\n[Network]\nGateway=10.93.0.1\nDHCP=yes\n");
        run_ip("link add name gn0 type veth peer name gn1");
        fixture_start(&f);

        l = fixture_link(&f, "gn0");
        ASSERT_EQ_INT(l->state, LINK_CONFIGURING);
        ASSERT_TRUE(l->dhcp_client != NULL);
        ASSERT_TRUE(!l->gateway_configured);
        run_shell("test -z \"$(ip route show default dev gn0)\"");

        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        l = fixture_link(&f, "gn0");
        ASSERT_EQ_INT(l->state, LINK_CONFIGURING);
        ASSERT_TRUE(l->dhcp_client != NULL);

        ASSERT_TRUE(link_apply_lease(l, make_lease("10.93.0.2", "255.255.255.0", NULL)) == 0);
        ASSERT_EQ_INT(l->state, LINK_CONFIGURED);
        assert_one_default("gn0", "10\\.93\\.0\\.1", 0);

        run_ip("link del gn0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: Gateway= with DHCP and no Address= subtest ok\n");
}

/* Losing a lease puts the static Address= and Gateway= back. */
static void test_netns_lose_lease_restores_static(void) {
        NetdFixture f;
        Link *l;
        const unsigned m = 0; /* Gateway= */

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f,
                      "10-ll.network",
                      "[Match]\nName=ll0\n\n[Network]\nAddress=10.95.0.2/24\nGateway=10.95.0.1\nDHCP=yes\n");
        run_ip("link add name ll0 type veth peer name ll1");
        fixture_start(&f);

        l = fixture_link(&f, "ll0");

        ASSERT_TRUE(link_apply_lease(l, make_lease("10.95.0.3", "255.255.255.0", "10.95.0.254")) == 0);
        assert_one_default("ll0", "10\\.95\\.0\\.254", 1024);
        ASSERT_TRUE(link_lose_lease(l) == 0);
        ASSERT_TRUE(l->lease == NULL);
        run_shell("ip -4 addr show dev ll0 | grep -q '10\\.95\\.0\\.2/24'");
        run_shell("! ip -4 addr show dev ll0 | grep -q '10\\.95\\.0\\.3/'");
        ASSERT_TRUE(l->gateway_configured && !l->gateway_from_lease);
        assert_one_default("ll0", "10\\.95\\.0\\.1", m);

        /* A lease whose router is Gateway=: the route survives the loss. */
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.95.0.3", "255.255.255.0", "10.95.0.1")) == 0);
        ASSERT_TRUE(link_lose_lease(l) == 0);
        run_shell("ip -4 addr show dev ll0 | grep -q '10\\.95\\.0\\.2/24'");
        assert_one_default("ll0", "10\\.95\\.0\\.1", m);

        run_ip("link del ll0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: lease loss restores Address= and Gateway= subtest ok\n");
}

/* DHCP= turned off by reload drops the lease and its file, so turning it on
 * again does not route through a stale lease's router. */
static void test_netns_dhcp_off_drops_lease(void) {
        static const char dhcp[] = "[Match]\nName=do0\n\n[Network]\nDHCP=yes\n";
        NetdFixture f;
        Link *l;
        char path[PATH_MAX];

        enter_test_netns();
        fixture_init(&f);
        fixture_write(&f, "10-do.network", dhcp);
        run_ip("link add name do0 type veth peer name do1");
        fixture_start(&f);

        l = fixture_link(&f, "do0");
        ASSERT_TRUE(link_apply_lease(l, make_lease("10.96.0.2", "255.255.255.0", "10.96.0.1")) == 0);
        snprintf(path, sizeof(path), "%s/run/leases/%u", f.tmp, ifindex_of("do0"));
        ASSERT_TRUE(access(path, F_OK) == 0);

        fixture_write(&f, "10-do.network", "[Match]\nName=do0\n\n[Network]\nAddress=10.98.0.2/24\n");
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        l = fixture_link(&f, "do0");
        ASSERT_TRUE(l->dhcp_client == NULL);
        ASSERT_TRUE(l->lease == NULL);
        ASSERT_TRUE(access(path, F_OK) < 0 && errno == ENOENT);
        run_shell("test -z \"$(ip route show default dev do0)\"");

        fixture_write(&f, "10-do.network", dhcp);
        ASSERT_TRUE(f.n->reload_handler(f.n) == 0);
        l = fixture_link(&f, "do0");
        ASSERT_TRUE(l->dhcp_client != NULL);
        ASSERT_TRUE(l->lease == NULL);
        ASSERT_TRUE(!l->gateway_configured);
        run_shell("test -z \"$(ip route show default dev do0)\"");

        run_ip("link del do0");
        ASSERT_TRUE(netd_rtnl_process(f.n->rtnl) >= 1);
        fixture_stop(&f);

        printf("test-netd-rtnl: DHCP= off drops the lease subtest ok\n");
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
        test_netns_route_same_metric();
        test_netns_lease_same_metric_two_links();
        test_netns_route_metric_default_and_static();
        test_netns_route_metric_reload();
        test_netns_address_prefix_metric();
        test_netns_lease_default_metric_routes();
        test_netns_default_metric_two_links();
        test_netns_static_gateway_two_links();
        test_netns_metric0_gone_before_lease();
        test_netns_lease_router_is_static_gateway();
        test_netns_reload_gateway_owner();
        test_netns_same_subnet_renumber_keeps_default();
        test_netns_reload_keeps_lease_route();
        test_netns_gateway_dhcp_no_address();
        test_netns_lose_lease_restores_static();
        test_netns_dhcp_off_drops_lease();
        test_reload_dropped_after_exit_request();

        printf("test-netd-rtnl: ok\n");
        return EXIT_SUCCESS;
}
