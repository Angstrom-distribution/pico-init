/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Router advertisements end to end: netd started in-process on one end of a
 * veth pair in a fresh network namespace (as test-netd-rtnl.c does), the test
 * playing the router on the other end with a raw ICMPv6 socket, and the
 * result read back with `ip` and from resolv.conf.
 *
 * Covered: a SLAAC address from a static token with noprefixroute, the
 * default route via the router and the on-link route with RouteMetric=,
 * protocol ra and an expiry, the RDNSS server and DNSSL domain in
 * resolv.conf, a 2 s RDNSS lifetime expiring out of it, a reload that moves
 * the routes to a new metric, Token=prefixstable renumbering the address,
 * two routers at one preference of which one withdraws (the other's route
 * stays), router lifetime 0, carrier loss flushing everything,
 * IPv6AcceptRA=no removing everything, a SLAAC address another host already
 * holds with a static token (given up) and with Token=prefixstable (made
 * again with the next counter), a short preferred lifetime that never
 * lapses in the kernel while it is advertised, and a [Route] default route
 * that is also the advertised one, through a reload, the router's expiry,
 * carrier loss and the link losing its match.
 *
 * netd turns off the kernel's own handling of advertisements (accept_ra=0).
 * Where /proc/sys is read-only, as in some containers, the kernel of the
 * namespace acts on the same advertisements; the test then uses metrics and
 * a token the kernel does not, and checks only netd's own routes and
 * address. The checks that need the kernel quiet run only when the write
 * took effect; without them the test exits 77 once the rest has passed.
 */

/* unshare()/CLONE_NEWUSER/CLONE_NEWNET need __USE_GNU; must be first. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../test-util.h"
#include "dhcp/dhcp-lease-internal.h"
#include "ndisc/ndisc-iid.h"
#include "ndisc/ndisc-link.h"
#include "netd-link.h"
#include "netd-loop.h"
#include "netd.h"

static void die(const char *what) {
        fprintf(stderr, "test-netd-ra: %s: %s\n", what, strerror(errno));
        exit(1);
}

static void write_proc_file(const char *path, const char *content) {
        FILE *f = fopen(path, "we");

        if (!f)
                die(path);
        fputs(content, f);
        if (fclose(f) != 0)
                die(path);
}

/* As test-netd-rtnl.c: a namespace that cannot be made is a failure, not a skip. */
static void enter_test_netns(void) {
        uid_t uid = getuid();
        gid_t gid = getgid();
        char buf[64];

        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
                die("unshare(CLONE_NEWUSER|CLONE_NEWNET)");
        write_proc_file("/proc/self/setgroups", "deny");
        snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned) uid);
        write_proc_file("/proc/self/uid_map", buf);
        snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned) gid);
        write_proc_file("/proc/self/gid_map", buf);
}

static int shellf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static int shellf(const char *fmt, ...) {
        char cmd[512];
        va_list ap;

        va_start(ap, fmt);
        vsnprintf(cmd, sizeof(cmd), fmt, ap);
        va_end(ap);
        return system(cmd);
}

static void run_ip(const char *args) {
        if (shellf("ip %s >/dev/null 2>&1", args) != 0) {
                fprintf(stderr, "test-netd-ra: `ip %s` failed\n", args);
                exit(1);
        }
}

/* --- netd in a temporary tree --- */

static char tmp_dir[128], net_dir[160], resolv_path[160];
static Netd *netd;

static void write_network(const char *content) {
        if (test_write_file(net_dir, "10-ra.network", content) < 0)
                die("write .network");
}

static void netd_start(void) {
        char *t = test_tmpdir_new();

        ASSERT_TRUE(t != NULL && strlen(t) < sizeof(tmp_dir));
        snprintf(tmp_dir, sizeof(tmp_dir), "%s", t);
        free(t);
        ASSERT_EQ_INT(test_mkdir(tmp_dir, "network"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp_dir, "run"), 0);
        ASSERT_EQ_INT(test_mkdir(tmp_dir, "state"), 0);
        snprintf(net_dir, sizeof(net_dir), "%s/network", tmp_dir);
        snprintf(resolv_path, sizeof(resolv_path), "%s/resolv.conf", tmp_dir);
}

static void netd_go(void) {
        char run[160], state[160];
        const char *path[2] = { net_dir, NULL };

        snprintf(run, sizeof(run), "%s/run", tmp_dir);
        snprintf(state, sizeof(state), "%s/state", tmp_dir);
        ASSERT_EQ_INT(netd_new(&netd), 0);
        ASSERT_EQ_INT(netd_set_network_path(netd, path), 0);
        ASSERT_EQ_INT(netd_set_runtime_dir(netd, run), 0);
        ASSERT_EQ_INT(netd_set_state_dir(netd, state), 0);
        ASSERT_EQ_INT(netd_set_resolv_conf(netd, resolv_path), 0);
        ASSERT_EQ_INT(netd_startup(netd), 0);
}

static void reload(const char *content) {
        write_network(content);
        ASSERT_EQ_INT(netd->reload_handler(netd), 0);
}

static void pump_once(int timeout_ms) {
        struct epoll_event events[16];
        int k = epoll_wait(netd->epoll_fd, events, 16, timeout_ms);

        for (int i = 0; i < k; i++) {
                struct netd_epoll_tag *tag = events[i].data.ptr;

                if (tag && tag->callback && tag->registered)
                        (void) tag->callback(netd, tag, events[i].events);
        }
        netd_loop_drain_pending_frees(netd);
}

/* The router that keeps advertising, as a real one does every few seconds,
 * so a first advertisement lost before the veth carrier settles does not
 * fail the test. -1 for none. */
static int adv_fd = -1;
static uint16_t adv_lifetime;
static usec_t adv_next;

static void send_full(int fd, uint16_t router_lifetime, bool must);

static void advertise(int fd, uint16_t router_lifetime) {
        adv_fd = fd;
        adv_lifetime = router_lifetime;
        send_full(fd, router_lifetime, true);
        adv_next = now_monotonic() + 500 * USEC_PER_MSEC;
}

/* Runs the loop for `ms` of real time: every shell command the test runs
 * ends in a SIGCHLD that wakes netd's signalfd at once. */
static void pump_for(int ms) {
        usec_t end = now_monotonic() + (usec_t) ms * USEC_PER_MSEC, now;

        while ((now = now_monotonic()) < end) {
                if (adv_fd >= 0 && now >= adv_next) {
                        send_full(adv_fd, adv_lifetime, false);
                        adv_next = now + 500 * USEC_PER_MSEC;
                }
                pump_once((int) ((end - now) / USEC_PER_MSEC) + 1);
        }
}

/* Pumps netd until the shell condition holds, for at most `ms`. */
static bool pump_until_shell(int ms, const char *cond) {
        usec_t end = now_monotonic() + (usec_t) ms * USEC_PER_MSEC;

        for (;;) {
                if (shellf("%s", cond) == 0)
                        return true;
                if (now_monotonic() >= end)
                        return false;
                pump_for(50);
        }
}

/* A default route at `metric` through `gw`, alone or as one next hop of
 * several. */
#define DEFAULT_VIA(gw, metric) \
        "ip -6 -o route show default | grep 'proto ra metric " metric " ' | grep -q 'via " gw " dev ra0'"

#define EXPECT(ms, ...)                                                                               \
        do {                                                                                          \
                char cond_[1024];                                                                     \
                snprintf(cond_, sizeof(cond_), __VA_ARGS__);                                          \
                if (!pump_until_shell((ms), cond_)) {                                                 \
                        fprintf(stderr, "test-netd-ra:%d: never true: %s\n", __LINE__, cond_);        \
                        if (system("ip -6 addr show dev ra0 >&2; ip -6 route show dev ra0 >&2") != 0) \
                                fprintf(stderr, "test-netd-ra: no state to show\n");                  \
                        exit(1);                                                                      \
                }                                                                                     \
        } while (0)

/* --- the router --- */

static int router_socket(const char *src) {
        struct sockaddr_in6 sa = { .sin6_family = AF_INET6 };
        struct icmp6_filter filter;
        int fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6), hops = 255,
            ifindex = (int) if_nametoindex("ra1");

        if (fd < 0)
                die("socket");

        ICMP6_FILTER_SETBLOCKALL(&filter);
        if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0 ||
            setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0 ||
            setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0)
                die("setsockopt");

        ASSERT_EQ_INT(inet_pton(AF_INET6, src, &sa.sin6_addr), 1);
        sa.sin6_scope_id = (uint32_t) ifindex;
        if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
                die("bind");

        return fd;
}

typedef struct Ra {
        uint8_t buf[512];
        size_t len;
} Ra;

static void put32(uint8_t *p, uint32_t v) {
        p[0] = (uint8_t) (v >> 24);
        p[1] = (uint8_t) (v >> 16);
        p[2] = (uint8_t) (v >> 8);
        p[3] = (uint8_t) v;
}

static void ra_init(Ra *ra, uint16_t router_lifetime) {
        memset(ra, 0, sizeof(*ra));
        ra->buf[0] = ND_ROUTER_ADVERT;
        ra->buf[4] = 64;
        ra->buf[6] = (uint8_t) (router_lifetime >> 8);
        ra->buf[7] = (uint8_t) router_lifetime;
        ra->len = 16;
}

static void ra_prefix(Ra *ra, const char *prefix, uint32_t valid, uint32_t preferred) {
        uint8_t *p = ra->buf + ra->len;

        p[0] = 3;
        p[1] = 4;
        p[2] = 64;
        p[3] = 0xc0;
        put32(p + 4, valid);
        put32(p + 8, preferred);
        ASSERT_EQ_INT(inet_pton(AF_INET6, prefix, p + 16), 1);
        ra->len += 32;
}

static void ra_rdnss(Ra *ra, const char *server, uint32_t lifetime) {
        uint8_t *p = ra->buf + ra->len;

        p[0] = 25;
        p[1] = 3;
        put32(p + 4, lifetime);
        ASSERT_EQ_INT(inet_pton(AF_INET6, server, p + 8), 1);
        ra->len += 24;
}

/* One name of up to 15 characters, two labels. */
static void ra_dnssl(Ra *ra, const char *label1, const char *label2, uint32_t lifetime) {
        uint8_t *p = ra->buf + ra->len;
        size_t a = strlen(label1), b = strlen(label2);

        ASSERT_TRUE(a + b + 3 <= 16);
        memset(p, 0, 24);
        p[0] = 31;
        p[1] = 3;
        put32(p + 4, lifetime);
        p[8] = (uint8_t) a;
        memcpy(p + 9, label1, a);
        p[9 + a] = (uint8_t) b;
        memcpy(p + 10 + a, label2, b);
        ra->len += 24;
}

/* A periodic resend (`must` false) may find the router's link down. */
static void ra_send(int fd, const Ra *ra, bool must) {
        struct sockaddr_in6 dst = { .sin6_family = AF_INET6 };

        ASSERT_EQ_INT(inet_pton(AF_INET6, "ff02::1", &dst.sin6_addr), 1);
        dst.sin6_scope_id = if_nametoindex("ra1");
        if (sendto(fd, ra->buf, ra->len, 0, (struct sockaddr *) &dst, sizeof(dst)) != (ssize_t) ra->len && must)
                die("sendto");
}

static void ra_mtu(Ra *ra, uint32_t mtu) {
        uint8_t *p = ra->buf + ra->len;

        memset(p, 0, 8);
        p[0] = 5;
        p[1] = 1;
        put32(p + 4, mtu);
        ra->len += 8;
}

static void send_full(int fd, uint16_t router_lifetime, bool must) {
        Ra ra;

        ra_init(&ra, router_lifetime);
        ra_mtu(&ra, 1400);
        ra_prefix(&ra, "2001:db8:50::", 3600, 1800);
        ra_rdnss(&ra, "2001:db8::53", 600);
        ra_dnssl(&ra, "example", "net", 600);
        ra_send(fd, &ra, must);
}

/* The prefixstable address netd makes for 2001:db8:50::/64 on ra0, or its
 * EUI-64 fallback without a machine ID. */
static void expected_stable(char buf[INET6_ADDRSTRLEN]) {
        struct in6_addr prefix, a;
        NetdId128 mid;
        Link *l = netd_find_link_by_name(netd, "ra0");
        uint8_t secret[16], used;
        bool have_mid = netd_machine_id(&mid) >= 0;

        ASSERT_TRUE(l != NULL);
        ASSERT_EQ_INT(inet_pton(AF_INET6, "2001:db8:50::", &prefix), 1);

        for (size_t i = 0; have_mid && i < sizeof(mid.bytes); i++)
                if (mid.bytes[i])
                        goto stable;
        ASSERT_EQ_INT(ndisc_iid_eui64(&prefix, l->hw_addr, l->hw_addr_len, &a), 0);
        goto out;

stable:
        ndisc_stable_secret(mid.bytes, secret);
        ASSERT_EQ_INT(ndisc_iid_stable_from(secret, &prefix, "ra0", l->hw_addr, l->hw_addr_len, 0, &used, &a),
                      0);

out:
        ASSERT_TRUE(inet_ntop(AF_INET6, &a, buf, INET6_ADDRSTRLEN) != NULL);
}

#define BASE_NETWORK                                                           \
        "[Match]\nName=ra0\n\n[Network]\nIPv6AcceptRA=yes\nDNS=192.0.2.53\n\n" \
        "[IPv6AcceptRA]\nToken=static:::1:2:3:4\nRouteMetric=10:20:30\nUseDomains=yes\n"

static const char *base_network = BASE_NETWORK;

static bool test_ra_end_to_end(void) {
        char addr[INET6_ADDRSTRLEN], accept_ra[8] = "";
        bool kernel_quiet;
        int r1, r2;
        FILE *f;

        enter_test_netns();
        run_ip("link add name ra0 type veth peer name ra1");
        run_ip("link set ra1 up");
        run_ip("-6 addr add fe80::1/64 dev ra1 nodad");
        run_ip("-6 addr add fe80::2/64 dev ra1 nodad");

        netd_start();
        write_network(base_network);
        netd_go();

        f = fopen("/proc/sys/net/ipv6/conf/ra0/accept_ra", "re");
        if (f) {
                if (!fgets(accept_ra, sizeof(accept_ra), f))
                        accept_ra[0] = '\0';
                fclose(f);
        }
        kernel_quiet = accept_ra[0] == '0';
        if (!kernel_quiet)
                fprintf(stderr,
                        "test-netd-ra: accept_ra could not be written here (read-only /proc/sys); the kernel also "
                        "acts on the advertisements, so the checks for no other proto ra routes, the IPv6 MTU "
                        "and accept_ra=0 do not run\n");

        r1 = router_socket("fe80::1");
        r2 = router_socket("fe80::2");

        /* An address from the token, the routes at the medium metric with
         * protocol ra and an expiry, the server and the domain. */
        advertise(r1, 1800);
        EXPECT(3000, "ip -6 addr show dev ra0 | grep '2001:db8:50:0:1:2:3:4/64' | grep -q noprefixroute");
        EXPECT(3000, "ip -6 route show dev ra0 | grep -q '^default via fe80::1 proto ra metric 20 .*expires'");
        EXPECT(100,
               "ip -6 route show dev ra0 | grep '^default via fe80::1 proto ra metric 20 ' | grep -q 'pref medium'");
        EXPECT(3000, "ip -6 route show dev ra0 | grep -q '^2001:db8:50::/64 proto ra metric 20 .*expires'");
        EXPECT(3000, "grep -q '^nameserver 192.0.2.53$' %s", resolv_path);
        EXPECT(3000, "grep -q '^nameserver 2001:db8::53$' %s", resolv_path);
        EXPECT(3000, "grep -q '^search example.net$' %s", resolv_path);
        if (kernel_quiet) {
                EXPECT(100, "test -z \"$(ip -6 route show dev ra0 proto ra | grep -v 'metric 20')\"");
                EXPECT(100, "grep -q '^1400$' /proc/sys/net/ipv6/conf/ra0/mtu");
        }

        /* A server whose two seconds run out. */
        {
                Ra ra;

                ra_init(&ra, 1800);
                ra_rdnss(&ra, "2001:db8::54", 2);
                ra_send(r1, &ra, true);
        }
        EXPECT(2000, "grep -q '^nameserver 2001:db8::54$' %s", resolv_path);
        EXPECT(4000, "! grep -q '2001:db8::54' %s", resolv_path);
        EXPECT(100, "grep -q '^nameserver 2001:db8::53$' %s", resolv_path);

        /* A reload moves the routes and makes no other change. */
        reload("[Match]\nName=ra0\n\n[Network]\nIPv6AcceptRA=yes\nDNS=192.0.2.53\n\n"
               "[IPv6AcceptRA]\nToken=static:::1:2:3:4\nRouteMetric=5\nUseDomains=yes\n");
        EXPECT(100, "ip -6 route show dev ra0 | grep -q '^default via fe80::1 proto ra metric 5 '");
        EXPECT(100, "ip -6 route show dev ra0 | grep -q '^2001:db8:50::/64 proto ra metric 5 '");
        EXPECT(100, "! ip -6 route show dev ra0 | grep -q 'proto ra metric 20 '");
        EXPECT(100, "ip -6 addr show dev ra0 | grep -q '2001:db8:50:0:1:2:3:4/64'");

        /* A new token renumbers. */
        reload("[Match]\nName=ra0\n\n[Network]\nIPv6AcceptRA=yes\nDNS=192.0.2.53\n\n"
               "[IPv6AcceptRA]\nToken=prefixstable\nRouteMetric=5\nUseDomains=yes\n");
        expected_stable(addr);
        EXPECT(100, "ip -6 addr show dev ra0 | grep '%s/64' | grep -q noprefixroute", addr);
        EXPECT(100, "! ip -6 addr show dev ra0 | grep -q '2001:db8:50:0:1:2:3:4'");

        /* Two routers at one preference: the kernel joins the two routes
         * into one with two next hops, as it does for networkd. The router
         * that withdraws takes only its own next hop. */
        advertise(r2, 1800);
        EXPECT(3000, DEFAULT_VIA("fe80::2", "5"));
        EXPECT(100, DEFAULT_VIA("fe80::1", "5"));
        advertise(r2, 0);
        EXPECT(3000, "! " DEFAULT_VIA("fe80::2", "5"));
        EXPECT(100, DEFAULT_VIA("fe80::1", "5"));

        /* Router lifetime 0: no default route; the prefix stays. */
        advertise(r1, 0);
        EXPECT(3000, "! ip -6 -o route show default | grep -q 'proto ra metric 5 '");
        EXPECT(100, "ip -6 route show dev ra0 | grep -q '^2001:db8:50::/64 proto ra metric 5 '");

        /* Carrier loss forgets everything learnt. */
        advertise(r1, 1800);
        EXPECT(3000, "ip -6 route show dev ra0 | grep -q '^default via fe80::1 proto ra metric 5 '");
        adv_fd = -1;
        run_ip("link set ra1 down");
        EXPECT(3000, "! ip -6 addr show dev ra0 | grep -q '%s'", addr);
        EXPECT(100, "! ip -6 route show dev ra0 | grep -q 'metric 5 '");
        EXPECT(100, "! grep -q '2001:db8::53' %s", resolv_path);

        /* Back, then IPv6AcceptRA=no takes everything away. */
        run_ip("link set ra1 up");
        run_ip("-6 addr add fe80::1/64 dev ra1 nodad");
        close(r1);
        r1 = router_socket("fe80::1");
        EXPECT(3000, "ip link show dev ra0 | grep -q 'LOWER_UP'");
        advertise(r1, 1800);
        EXPECT(3000, "ip -6 route show dev ra0 | grep -q '^default via fe80::1 proto ra metric 5 '");
        EXPECT(3000, "grep -q '^nameserver 2001:db8::53$' %s", resolv_path);
        reload("[Match]\nName=ra0\n\n[Network]\nIPv6AcceptRA=no\nDNS=192.0.2.53\n");
        EXPECT(100, "! ip -6 route show dev ra0 | grep -q 'metric 5 '");
        EXPECT(100, "! ip -6 addr show dev ra0 | grep -q '%s'", addr);
        EXPECT(100, "! grep -q '2001:db8::53\\|^search' %s", resolv_path);
        EXPECT(100, "grep -q '^nameserver 192.0.2.53$' %s", resolv_path);
        ASSERT_TRUE(netd_find_link_by_name(netd, "ra0")->ndisc == NULL);
        if (kernel_quiet)
                EXPECT(100, "grep -q '^0$' /proc/sys/net/ipv6/conf/ra0/accept_ra");

        adv_fd = -1;
        close(r1);
        close(r2);
        run_ip("link del ra0");
        (void) netd_rtnl_process(netd->rtnl);
        netd_free(netd);
        test_rm_rf(tmp_dir);

        printf("test-netd-ra: end to end subtest ok%s\n", kernel_quiet ? "" : " (kernel not quiet)");
        return kernel_quiet;
}

static bool prefix_given_up(void) {
        Link *l = netd_find_link_by_name(netd, "ra0");

        return l && l->ndisc && l->ndisc->n_prefixes == 1 && l->ndisc->prefixes[0].dad_given_up &&
                        l->n_ra_addrs == 0;
}

/* Another host already holds the address the token makes: duplicate address
 * detection fails, the kernel deletes the tentative address, and netd gives
 * up on the prefix instead of adding it again. */
static void test_ra_dad_failure(void) {
        int r1;

        enter_test_netns();
        run_ip("link add name ra0 type veth peer name ra1");
        run_ip("link set ra1 up");
        run_ip("-6 addr add fe80::1/64 dev ra1 nodad");
        run_ip("-6 addr add 2001:db8:50:0:1:2:3:4/64 dev ra1 nodad");

        netd_start();
        write_network(base_network);
        netd_go();
        r1 = router_socket("fe80::1");

        /* The tentative address lives only until ra1 answers the first
         * solicitation, too short to poll for: netd's own record of the
         * failure is the outcome checked. */
        advertise(r1, 1800);
        for (int ms = 0; ms < 10000 && !prefix_given_up(); ms += 50)
                pump_for(50);
        ASSERT_TRUE(prefix_given_up());
        EXPECT(3000, "! ip -6 addr show dev ra0 | grep -q '2001:db8:50:0:1:2:3:4/64'");

        /* The next advertisement does not try again; the routes stay. */
        advertise(r1, 1800);
        pump_for(300);
        ASSERT_TRUE(prefix_given_up());
        EXPECT(100, "ip -6 route show dev ra0 | grep -q '^2001:db8:50::/64 proto ra metric 20 '");

        adv_fd = -1;
        close(r1);
        run_ip("link del ra0");
        (void) netd_rtnl_process(netd->rtnl);
        netd_free(netd);
        test_rm_rf(tmp_dir);

        printf("test-netd-ra: duplicate address subtest ok\n");
}

/* The default route of the medium preference, as a [Route] too: onlink,
 * as netd adds it in a file without a static address, which the kernel does
 * not count as another route. */
#define ROUTE_NETWORK BASE_NETWORK "\n[Route]\nGateway=fe80::1\nMetric=20\n"
#define SHARED_DEFAULT "ip -6 route show dev ra0 | grep -q '^default via fe80::1 proto [a-z]* metric 20 '"

static bool ra_holds_default(void) {
        Link *l = netd_find_link_by_name(netd, "ra0");

        for (size_t i = 0; l && i < l->n_ra_routes; i++)
                if (l->ra_routes[i].has_gw && l->ra_routes[i].installed)
                        return true;

        return false;
}

static void wait_ra_default(bool want) {
        for (int ms = 0; ms < 6000 && ra_holds_default() != want; ms += 50)
                pump_for(50);
        ASSERT_TRUE(ra_holds_default() == want);
}

/* A [Route] default route and an advertised one through the same router at
 * the same metric are one kernel route: it stays while either holds it and
 * goes with the last, whichever of the two put it in first. */
static void test_ra_static_route(void) {
        int r1;

        enter_test_netns();
        run_ip("link add name ra0 type veth peer name ra1");
        run_ip("link set ra1 up");
        run_ip("-6 addr add fe80::1/64 dev ra1 nodad");

        netd_start();
        write_network(ROUTE_NETWORK);
        netd_go();
        r1 = router_socket("fe80::1");

        /* The [Route] first. A reload that drops it leaves the route to the
         * router, and router lifetime 0 then removes it. */
        EXPECT(3000, "ip -6 route show dev ra0 | grep -q '^default via fe80::1 proto static metric 20 '");
        advertise(r1, 1800);
        wait_ra_default(true);
        reload(base_network);
        pump_for(500);
        EXPECT(100, SHARED_DEFAULT);
        advertise(r1, 0);
        wait_ra_default(false);
        EXPECT(3000, "! " SHARED_DEFAULT);

        /* The advertisement first, with a 3 s router lifetime. The [Route]
         * keeps the route past it, in netd and in the kernel, which drops
         * the expiry; a reload that drops the [Route] then removes it. */
        adv_fd = -1;
        {
                Ra ra;

                ra_init(&ra, 3);
                ra_send(r1, &ra, true);
        }
        EXPECT(3000, "ip -6 route show dev ra0 | grep -q '^default via fe80::1 proto ra metric 20 .*expires'");
        reload(ROUTE_NETWORK);
        wait_ra_default(false);
        pump_for(1000);
        EXPECT(100, SHARED_DEFAULT);
        reload(base_network);
        EXPECT(100, "! " SHARED_DEFAULT);

        /* The advertisement first again. Carrier loss takes only the
         * router's hold; the link losing its match takes the route. */
        advertise(r1, 1800);
        wait_ra_default(true);
        reload(ROUTE_NETWORK);
        adv_fd = -1;
        run_ip("link set ra1 down");
        wait_ra_default(false);
        pump_for(300);
        EXPECT(100, SHARED_DEFAULT);
        run_ip("link set ra1 up");
        run_ip("-6 addr add fe80::1/64 dev ra1 nodad");
        close(r1);
        r1 = router_socket("fe80::1");
        EXPECT(3000, "ip link show dev ra0 | grep -q 'LOWER_UP'");
        advertise(r1, 1800);
        wait_ra_default(true);
        reload("[Match]\nName=other\n");
        EXPECT(1000, "! " SHARED_DEFAULT);

        adv_fd = -1;
        close(r1);
        run_ip("link del ra0");
        (void) netd_rtnl_process(netd->rtnl);
        netd_free(netd);
        test_rm_rf(tmp_dir);

        printf("test-netd-ra: [Route] and advertised route subtest ok\n");
}

#define SLAAC_STATIC "2001:db8:50:0:1:2:3:4/64"

/* A preferred lifetime of 8 s refreshed every 3 s, shorter than half the
 * valid one: the kernel's copy must be sent again before it runs out, or the
 * kernel marks the address deprecated while the router still prefers it. */
static void test_ra_preferred_refresh(void) {
        usec_t end, next = 0, now;
        bool seen = false;
        int r1;

        enter_test_netns();
        run_ip("link add name ra0 type veth peer name ra1");
        run_ip("link set ra1 up");
        run_ip("-6 addr add fe80::1/64 dev ra1 nodad");

        netd_start();
        write_network(base_network);
        netd_go();
        r1 = router_socket("fe80::1");

        /* The address can take a few seconds to show: the first solicitation
         * is delayed by up to a second and duplicate address detection takes
         * about a second, longer under load.
         *
         * Four advertisements from the first sight of the address. With the
         * refresh the lifetime is sent again at 6 s, 2 s before the kernel
         * would deprecate the address; without it the kernel deprecates it
         * at 8 s, until the advertisement at 9 s. Neither moves when an
         * advertisement is handled a little late: netd counts whole seconds,
         * and both thresholds lie a second away from a multiple of 3 s. */
        for (end = now_monotonic() + 15 * USEC_PER_SEC; (now = now_monotonic()) < end;) {
                if (now >= next) {
                        Ra ra;

                        ra_init(&ra, 1800);
                        ra_prefix(&ra, "2001:db8:50::", 60, 8);
                        ra_send(r1, &ra, false);
                        next = now + 3000 * USEC_PER_MSEC;
                }
                pump_once(50);
                if (!seen) {
                        if (shellf("ip -6 -o addr show dev ra0 | grep -q '" SLAAC_STATIC "'") != 0)
                                continue;
                        seen = true;
                        end = now + 10500 * USEC_PER_MSEC;
                }
                if (shellf("ip -6 -o addr show dev ra0 | grep '" SLAAC_STATIC "' | grep -q deprecated") == 0) {
                        fprintf(stderr, "test-netd-ra: the address went deprecated while still advertised\n");
                        exit(1);
                }
        }
        ASSERT_TRUE(seen);

        /* With the router gone the kernel's copy runs out by itself. */
        EXPECT(12000, "ip -6 -o addr show dev ra0 | grep '" SLAAC_STATIC "' | grep -q deprecated");

        close(r1);
        run_ip("link del ra0");
        (void) netd_rtnl_process(netd->rtnl);
        netd_free(netd);
        test_rm_rf(tmp_dir);

        printf("test-netd-ra: preferred lifetime subtest ok\n");
}

/* The address Token=prefixstable makes for 2001:db8:50::/64 on ra0 with
 * `secret`, from counter `from` on; the counter used in *used. */
static void stable_from(const uint8_t secret[16], uint8_t from, uint8_t *used, char buf[INET6_ADDRSTRLEN]) {
        Link *l = netd_find_link_by_name(netd, "ra0");
        struct in6_addr prefix, a;

        ASSERT_TRUE(l != NULL);
        ASSERT_EQ_INT(inet_pton(AF_INET6, "2001:db8:50::", &prefix), 1);
        ASSERT_EQ_INT(ndisc_iid_stable_from(secret, &prefix, "ra0", l->hw_addr, l->hw_addr_len, from, used, &a),
                      0);
        ASSERT_TRUE(inet_ntop(AF_INET6, &a, buf, INET6_ADDRSTRLEN) != NULL);
}

/* A machine ID of the test's own over /etc/machine-id, in a private mount
 * namespace: Token=prefixstable needs one, and a build host may have none.
 * False with the reason printed when the bind mount is refused. */
static bool fake_machine_id(void) {
        char path[192];

        if (unshare(CLONE_NEWNS) < 0 || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
                fprintf(stderr, "test-netd-ra: no private mount namespace: %s\n", strerror(errno));
                return false;
        }

        if (test_write_file(tmp_dir, "machine-id", "0123456789abcdef0123456789abcdef\n") < 0)
                die("write machine-id");
        snprintf(path, sizeof(path), "%s/machine-id", tmp_dir);
        if (mount(path, "/etc/machine-id", NULL, MS_BIND, NULL) < 0) {
                fprintf(stderr,
                        "test-netd-ra: cannot bind a machine ID over /etc/machine-id: %s\n",
                        strerror(errno));
                return false;
        }

        return true;
}

static bool regenerated(void) {
        Link *l = netd_find_link_by_name(netd, "ra0");

        return l && l->ndisc && l->ndisc->n_prefixes == 1 && l->ndisc->prefixes[0].dad_counter > 0 &&
                        !l->ndisc->prefixes[0].dad_given_up;
}

/* Token=prefixstable after a lost duplicate address detection: the next
 * RFC 7217 counter makes another address, which is kept. */
static bool test_ra_dad_regenerate(void) {
        char first[INET6_ADDRSTRLEN], second[INET6_ADDRSTRLEN];
        uint8_t secret[16], used0, used1;
        NetdId128 mid;
        Link *l;
        int r1;

        enter_test_netns();
        netd_start();
        if (!fake_machine_id()) {
                test_rm_rf(tmp_dir);
                return false;
        }

        run_ip("link add name ra0 type veth peer name ra1");
        run_ip("link set ra1 up");
        run_ip("-6 addr add fe80::1/64 dev ra1 nodad");

        write_network("[Match]\nName=ra0\n\n[Network]\nIPv6AcceptRA=yes\n\n"
                      "[IPv6AcceptRA]\nToken=prefixstable\nRouteMetric=10:20:30\n");
        netd_go();

        ASSERT_EQ_INT(netd_machine_id(&mid), 0);
        ndisc_stable_secret(mid.bytes, secret);
        stable_from(secret, 0, &used0, first);
        stable_from(secret, (uint8_t) (used0 + 1), &used1, second);
        if (shellf("ip -6 addr add %s/64 dev ra1 nodad >/dev/null 2>&1", first) != 0)
                die("ip addr add");

        r1 = router_socket("fe80::1");
        advertise(r1, 1800);
        for (int ms = 0; ms < 6000 && !regenerated(); ms += 50)
                pump_for(50);
        ASSERT_TRUE(regenerated());
        l = netd_find_link_by_name(netd, "ra0");
        ASSERT_EQ_INT(l->ndisc->prefixes[0].dad_counter, used1);

        /* The second address passes and stays; the first is gone. */
        EXPECT(6000,
               "ip -6 -o addr show dev ra0 | grep '%s/64' | grep -v tentative | grep -q noprefixroute",
               second);
        EXPECT(100, "! ip -6 addr show dev ra0 | grep -q '%s/64'", first);
        pump_for(1000);
        EXPECT(100, "ip -6 -o addr show dev ra0 | grep -q '%s/64'", second);
        ASSERT_EQ_INT(l->ndisc->prefixes[0].dad_counter, used1);

        adv_fd = -1;
        close(r1);
        run_ip("link del ra0");
        (void) netd_rtnl_process(netd->rtnl);
        netd_free(netd);
        test_rm_rf(tmp_dir);

        printf("test-netd-ra: duplicate address regeneration subtest ok\n");
        return true;
}

int main(void) {
        bool full = true;

        if (access("/proc/net/if_inet6", F_OK) < 0) {
                fprintf(stderr, "test-netd-ra: kernel without IPv6, skipping\n");
                return 77;
        }

        full = test_ra_end_to_end() && full;
        test_ra_dad_failure();
        test_ra_static_route();
        test_ra_preferred_refresh();
        /* Last: it leaves this process in a private mount namespace. */
        full = test_ra_dad_regenerate() && full;

        if (!full) {
                fprintf(stderr, "test-netd-ra: some checks could not run here, see above; skipping\n");
                return 77;
        }

        printf("test-netd-ra: all checks passed\n");
        return 0;
}
