/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The router advertisement engine on a real veth pair in a fresh network
 * namespace (the mechanism of test-netd-lldp-link.c). The test plays the
 * router on the peer with its own raw ICMPv6 socket: it sees the
 * solicitations and sends advertisements from link-local addresses it adds
 * without duplicate address detection.
 *
 * Covered: a solicitation carrying the source link-layer address it was
 * given; advertisements from a global source, with hop limit 64 or with code
 * 1 ignored; routers, prefixes and servers learnt; a 2 s RDNSS lifetime
 * expiring; a router lifetime of 0 withdrawing the router; six routers capped
 * at four; carrier loss forgetting everything.
 *
 * The kernel of the namespace also acts on these advertisements
 * (accept_ra cannot be assumed writable here); the test looks only at what
 * the engine learnt.
 */

/* unshare()/CLONE_NEWUSER/CLONE_NEWNET need __USE_GNU; must be first. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../test-util.h"
#include "ndisc/ndisc-link.h"
#include "netd-loop.h"
#include "netd.h"

static void die(const char *what) {
        fprintf(stderr, "test-netd-ndisc-link: %s: %s\n", what, strerror(errno));
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

/* The same isolation as test-netd-lldp-link.c; a test that cannot prove it must fail, not skip. */
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

static void run_ip(const char *args) {
        char cmd[256];

        snprintf(cmd, sizeof(cmd), "ip %s >/dev/null 2>&1", args);
        if (system(cmd) != 0) {
                fprintf(stderr, "test-netd-ndisc-link: `%s` failed\n", cmd);
                exit(1);
        }
}

static const uint8_t fake_hw[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
static int notified;

static void on_notify(void *userdata) {
        (void) userdata;
        notified++;
}

/* --- driving the loop by hand, the way netd_loop_run() dispatches --- */

static void pump_once(Netd *n, int timeout_ms) {
        struct epoll_event events[16];
        int k = epoll_wait(n->epoll_fd, events, 16, timeout_ms);

        for (int i = 0; i < k; i++) {
                struct netd_epoll_tag *tag = events[i].data.ptr;

                if (tag && tag->callback && tag->registered)
                        (void) tag->callback(n, tag, events[i].events);
        }
}

static bool pump_until(Netd *n, bool (*done)(const NdiscLink *), const NdiscLink *l, int ms) {
        for (; ms > 0; ms -= 20) {
                if (done(l))
                        return true;
                pump_once(n, 20);
        }

        return done(l);
}

/* --- the router side --- */

static int router_socket(const char *ifname, const char *src, int hops) {
        struct sockaddr_in6 sa = { .sin6_family = AF_INET6 };
        struct icmp6_filter filter;
        int fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6),
            ifindex = (int) if_nametoindex(ifname);

        if (fd < 0)
                die("socket");

        ICMP6_FILTER_SETBLOCKALL(&filter);
        if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0 ||
            setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0 ||
            setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0)
                die("setsockopt");

        ASSERT_EQ_INT(inet_pton(AF_INET6, src, &sa.sin6_addr), 1);
        if (IN6_IS_ADDR_LINKLOCAL(&sa.sin6_addr))
                sa.sin6_scope_id = (uint32_t) ifindex;
        if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
                die("bind");

        return fd;
}

/* Solicitations go to ff02::2, which a host joins only when asked to. */
static int solicitation_listener(const char *ifname) {
        struct ipv6_mreq all_routers = { .ipv6mr_interface = if_nametoindex(ifname) };
        struct icmp6_filter filter;
        int fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);

        if (fd < 0)
                die("socket");

        ASSERT_EQ_INT(inet_pton(AF_INET6, "ff02::2", &all_routers.ipv6mr_multiaddr), 1);
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
        if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0 ||
            setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, (socklen_t) strlen(ifname)) < 0 ||
            setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &all_routers, sizeof(all_routers)) < 0)
                die("setsockopt");

        return fd;
}

static void router_send(int fd, const char *ifname, const uint8_t *ra, size_t len) {
        struct sockaddr_in6 dst = { .sin6_family = AF_INET6 };

        ASSERT_EQ_INT(inet_pton(AF_INET6, "ff02::1", &dst.sin6_addr), 1);
        dst.sin6_scope_id = if_nametoindex(ifname);
        if (sendto(fd, ra, len, 0, (struct sockaddr *) &dst, sizeof(dst)) != (ssize_t) len)
                die("sendto");
}

typedef struct Ra {
        uint8_t buf[512];
        size_t len;
} Ra;

static void ra_init(Ra *ra, uint16_t router_lifetime, uint8_t code) {
        memset(ra, 0, sizeof(*ra));
        ra->buf[0] = ND_ROUTER_ADVERT;
        ra->buf[1] = code;
        ra->buf[4] = 64;
        ra->buf[6] = (uint8_t) (router_lifetime >> 8);
        ra->buf[7] = (uint8_t) router_lifetime;
        ra->len = 16;
}

static void put32(uint8_t *p, uint32_t v) {
        p[0] = (uint8_t) (v >> 24);
        p[1] = (uint8_t) (v >> 16);
        p[2] = (uint8_t) (v >> 8);
        p[3] = (uint8_t) v;
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

/* Reads solicitations until one carries `fake_hw`; the kernel of the
 * namespace sends its own too. The first one may find no usable source
 * address yet, and the next follows 4 s later. */
static bool saw_our_solicitation(int fd, Netd *n) {
        for (int ms = 0; ms < 6000; ms += 20) {
                uint8_t buf[128];
                ssize_t len;

                pump_once(n, 20);
                while ((len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0)
                        if (len == 16 && buf[0] == ND_ROUTER_SOLICIT && buf[8] == 1 && buf[9] == 1 &&
                            memcmp(buf + 10, fake_hw, 6) == 0)
                                return true;
        }

        return false;
}

static bool one_router(const NdiscLink *l) {
        return l->n_routers == 1;
}

static bool no_router(const NdiscLink *l) {
        return l->n_routers == 0;
}

static bool no_rdnss(const NdiscLink *l) {
        return l->n_rdnss == 0;
}

static bool four_routers(const NdiscLink *l) {
        return l->n_routers == 4;
}

static void test_engine(void) {
        Netd *n = NULL;
        NdiscLink *l = NULL;
        Ra ra;
        int router, listener, bad, ifindex;
        char addr[64];

        enter_test_netns();
        run_ip("link add name na0 type veth peer name na1");
        run_ip("link set na1 up");
        run_ip("-6 addr add fe80::1/64 dev na1 nodad");
        run_ip("-6 addr add fd40::1/64 dev na1 nodad");
        run_ip("link set na0 up");
        ifindex = (int) if_nametoindex("na0");

        ASSERT_EQ_INT(netd_new(&n), 0);
        ASSERT_EQ_INT(ndisc_link_new(n, ifindex, "na0", on_notify, NULL, &l), 0);
        ASSERT_EQ_INT(ndisc_link_start(l, fake_hw, 6), 0);
        ASSERT_TRUE(ndisc_link_is_running(l));

        router = router_socket("na1", "fe80::1", 255);
        listener = solicitation_listener("na1");

        /* A solicitation goes out within a second. */
        ndisc_link_set_state(l, true, true);
        ASSERT_TRUE(l->soliciting);
        ASSERT_TRUE(saw_our_solicitation(listener, n));
        close(listener);

        /* Not from a router on this link: ignored. */
        ra_init(&ra, 1800, 0);
        bad = router_socket("na1", "fd40::1", 255);
        router_send(bad, "na1", ra.buf, ra.len);
        close(bad);
        bad = router_socket("na1", "fe80::1", 64);
        router_send(bad, "na1", ra.buf, ra.len);
        close(bad);
        ra_init(&ra, 1800, 1);
        router_send(router, "na1", ra.buf, ra.len);
        notified = 0;
        for (int i = 0; i < 25; i++)
                pump_once(n, 20);
        ASSERT_EQ_INT(l->n_routers, 0);
        ASSERT_EQ_INT(notified, 0);

        /* A router with a prefix and a server whose lifetime runs out. */
        ra_init(&ra, 1800, 0);
        ra_prefix(&ra, "2001:db8:40::", 86400, 14400);
        ra_rdnss(&ra, "2001:db8::53", 2);
        router_send(router, "na1", ra.buf, ra.len);
        ASSERT_TRUE(pump_until(n, one_router, l, 2000));
        ASSERT_TRUE(!l->soliciting);
        ASSERT_EQ_INT(l->n_prefixes, 1);
        ASSERT_TRUE(l->prefixes[0].onlink_until != 0 && l->prefixes[0].valid_until != 0);
        ASSERT_EQ_INT(l->n_rdnss, 1);
        ASSERT_TRUE(notified >= 1);

        notified = 0;
        ASSERT_TRUE(pump_until(n, no_rdnss, l, 4000));
        ASSERT_TRUE(notified >= 1);
        ASSERT_EQ_INT(l->n_routers, 1);

        /* Router lifetime 0 withdraws the router; its prefix stays. */
        ra_init(&ra, 0, 0);
        router_send(router, "na1", ra.buf, ra.len);
        ASSERT_TRUE(pump_until(n, no_router, l, 2000));
        ASSERT_EQ_INT(l->n_prefixes, 1);

        /* Six routers, four kept. */
        for (int i = 1; i <= 6; i++) {
                int fd;

                snprintf(addr, sizeof(addr), "-6 addr add fe80::1%d/64 dev na1 nodad", i);
                run_ip(addr);
                snprintf(addr, sizeof(addr), "fe80::1%d", i);
                fd = router_socket("na1", addr, 255);
                ra_init(&ra, 600, 0);
                router_send(fd, "na1", ra.buf, ra.len);
                close(fd);
        }
        ASSERT_TRUE(pump_until(n, four_routers, l, 2000));
        for (int i = 0; i < 25; i++)
                pump_once(n, 20);
        ASSERT_EQ_INT(l->n_routers, 4);

        /* Carrier loss forgets everything. */
        notified = 0;
        ndisc_link_set_state(l, false, true);
        ASSERT_EQ_INT(l->n_routers, 0);
        ASSERT_EQ_INT(l->n_prefixes, 0);
        ASSERT_EQ_INT(notified, 1);
        ndisc_link_set_state(l, false, true);
        ASSERT_EQ_INT(notified, 1);

        close(router);
        ndisc_link_free(l);
        netd_free(n);
        run_ip("link del na0");

        printf("test-netd-ndisc-link: engine subtest ok\n");
}

int main(void) {
        if (access("/proc/net/if_inet6", F_OK) < 0) {
                fprintf(stderr, "test-netd-ndisc-link: kernel without IPv6, skipping\n");
                return 77;
        }

        test_engine();

        printf("test-netd-ndisc-link: all checks passed\n");
        return 0;
}
