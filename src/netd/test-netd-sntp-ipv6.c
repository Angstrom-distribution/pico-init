/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * IPv6 NTP servers, in a fresh user and network namespace.
 *
 * Covered: a full exchange with a fake server on [::1]:123, a reply from
 * another port of the same address refused, an accepted reply ending the
 * request, and a mixed list asked in turn over the IPv4 and the IPv6 socket.
 *
 * An accepted reply makes netd_sntp_process() call clock_adjtime(). The user
 * namespace is what makes that safe: CAP_SYS_TIME is checked against the
 * initial namespace, so the call fails with EPERM, which the test checks
 * before it sends such a reply. Without a namespace the test exits 77.
 */

/* unshare()/CLONE_NEWUSER/CLONE_NEWNET need __USE_GNU; must be first. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <time.h>
#include <unistd.h>

#include "../test-util.h"
#include "netd-loop.h"
#include "netd-sntp.h"
#include "netd.h"

static void die(const char *what) {
        fprintf(stderr, "test-netd-sntp-ipv6: %s: %s\n", what, strerror(errno));
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

static int enter_test_netns(void) {
        uid_t uid = getuid();
        gid_t gid = getgid();
        char buf[64];

        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
                fprintf(stderr,
                        "test-netd-sntp-ipv6: unshare(CLONE_NEWUSER|CLONE_NEWNET): %s; an accepted reply "
                        "is only safe without CAP_SYS_TIME, skipping\n",
                        strerror(errno));
                return -1;
        }
        write_proc_file("/proc/self/setgroups", "deny");
        snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned) uid);
        write_proc_file("/proc/self/uid_map", buf);
        snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned) gid);
        write_proc_file("/proc/self/gid_map", buf);
        return 0;
}

/* Rewriting the clock's own maximum error changes nothing, and needs the
 * capability an accepted reply would use. */
static void assert_no_cap_sys_time(void) {
        struct timex tmx = { 0 };

        ASSERT_TRUE(clock_adjtime(CLOCK_REALTIME, &tmx) >= 0);
        tmx.modes = ADJ_MAXERROR;
        ASSERT_TRUE(clock_adjtime(CLOCK_REALTIME, &tmx) < 0);
        ASSERT_EQ_INT(errno, EPERM);
}

static void loopback_up(void) {
        struct ifreq ifr = { 0 };
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

        if (fd < 0)
                die("socket");
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "lo");
        if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
                die("SIOCGIFFLAGS lo");
        ifr.ifr_flags |= IFF_UP;
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
                die("SIOCSIFFLAGS lo");
        close(fd);
}

/* A blocking UDP socket on `addr` port `port`, with a receive timeout so a
 * missing request fails the test instead of hanging it. */
static int fake_server(int family, const char *addr, uint16_t port) {
        struct timeval tv = { .tv_sec = 5 };
        NetdSntpAddr sa = { 0 };
        socklen_t len;
        int fd, one = 1;

        fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                die("socket");
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
                die("SO_RCVTIMEO");
        if (family == AF_INET6) {
                if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) < 0)
                        die("IPV6_V6ONLY");
                sa.in6.sin6_family = AF_INET6;
                sa.in6.sin6_port = htons(port);
                ASSERT_EQ_INT(inet_pton(AF_INET6, addr, &sa.in6.sin6_addr), 1);
                len = sizeof(sa.in6);
        } else {
                sa.in.sin_family = AF_INET;
                sa.in.sin_port = htons(port);
                ASSERT_EQ_INT(inet_pton(AF_INET, addr, &sa.in.sin_addr), 1);
                len = sizeof(sa.in);
        }
        if (bind(fd, &sa.sa, len) < 0)
                die("bind");
        return fd;
}

/* Reads one request; returns its transmit timestamp, the nonce a reply must
 * echo, and where it came from. */
static NetdNtpTs read_request(int fd, int family, NetdSntpAddr *client, socklen_t *client_len) {
        NetdNtpMsg m;
        ssize_t len;

        *client_len = sizeof(*client);
        len = recvfrom(fd, &m, sizeof(m), 0, &client->sa, client_len);
        if (len < 0)
                die("no request at the fake server");
        ASSERT_EQ_INT(len, sizeof(NetdNtpMsg));
        ASSERT_EQ_INT(client->sa.sa_family, family);
        ASSERT_EQ_INT(NETD_NTP_FIELD_MODE(m.field), NETD_NTP_MODE_CLIENT);
        ASSERT_EQ_INT(NETD_NTP_FIELD_VERSION(m.field), 4);
        return m.trans_time;
}

/* A reply a client must accept: the nonce echoed and the server's clock
 * equal to ours, so the offset is close to zero. */
static void send_reply(int fd, const NetdNtpTs *nonce, const NetdSntpAddr *client, socklen_t client_len) {
        NetdNtpMsg m = { 0 };
        struct timespec ts;
        usec_t now;

        ASSERT_TRUE(clock_gettime(CLOCK_REALTIME, &ts) == 0);
        now = (usec_t) ts.tv_sec * USEC_PER_SEC + (usec_t) ts.tv_nsec / 1000;

        m.field = NETD_NTP_FIELD(0, 4, NETD_NTP_MODE_SERVER);
        m.stratum = 2;
        m.origin_time = *nonce;
        netd_ntp_ts_from_usec(&m.recv_time, now);
        netd_ntp_ts_from_usec(&m.trans_time, now);
        ASSERT_EQ_INT(sendto(fd, &m, sizeof(m), 0, &client->sa, client_len), sizeof(m));
}

static void wait_readable(int fd) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };

        if (poll(&pfd, 1, 2000) != 1) {
                fprintf(stderr, "test-netd-sntp-ipv6: client socket never became readable\n");
                exit(1);
        }
}

/* netd_sntp_*() touch only the epoll set and the timer queue of Netd, as in
 * test-netd-sntp.c. */
static void bare_netd(Netd *n) {
        memset(n, 0, sizeof(*n));
        n->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (n->epoll_fd < 0)
                die("epoll_create1");
        if (pico_timer_new(&n->timer) < 0)
                die("pico_timer_new");
}

static void bare_netd_free(Netd *n) {
        (void) pico_timer_free(n->timer);
        (void) close(n->epoll_fd);
}

static NetdSntpAddr server_addr(int family, const char *literal) {
        NetdSntpAddr a;
        NetdInAddr ia = { 0 };

        ASSERT_EQ_INT(inet_pton(family, literal, &ia), 1);
        ASSERT_EQ_INT(netd_sntp_addr_set(&a, family, &ia, 0), 0);
        return a;
}

static void test_exchange_loopback(void) {
        Netd n;
        NetdSntp *s = NULL;
        NetdSntpAddr servers[1], client;
        socklen_t client_len;
        NetdNtpTs nonce;
        int server_fd, stray_fd;

        bare_netd(&n);
        server_fd = fake_server(AF_INET6, "::1", NETD_NTP_PORT);
        stray_fd = fake_server(AF_INET6, "::1", 10123);

        ASSERT_EQ_INT(netd_sntp_new(&n, &s), 0);
        ASSERT_EQ_INT(s->fd6, -1); /* no IPv6 socket before an IPv6 server */
        servers[0] = server_addr(AF_INET6, "::1");
        ASSERT_EQ_INT(netd_sntp_set_server_addrs(s, servers, 1), 0);
        ASSERT_EQ_INT(netd_sntp_start(s), 0);
        ASSERT_TRUE(s->fd6 >= 0);

        nonce = read_request(server_fd, AF_INET6, &client, &client_len);

        /* The right nonce from the right address, but not from port 123. */
        send_reply(stray_fd, &nonce, &client, client_len);
        wait_readable(s->fd6);
        ASSERT_EQ_INT(netd_sntp_process(s), 0);
        ASSERT_TRUE(s->request.pending);
        ASSERT_TRUE(!s->synchronised);

        assert_no_cap_sys_time();
        send_reply(server_fd, &nonce, &client, client_len);
        wait_readable(s->fd6);
        ASSERT_EQ_INT(netd_sntp_process(s), 0);
        ASSERT_TRUE(!s->request.pending);
        ASSERT_TRUE(s->synchronised);

        netd_sntp_free(s);
        close(stray_fd);
        close(server_fd);
        bare_netd_free(&n);
        printf("test-netd-sntp-ipv6: loopback exchange ok\n");
}

/* Servers are asked in turn, each over the socket of its family. */
static void test_mixed_families(void) {
        Netd n;
        NetdSntp *s = NULL;
        NetdSntpAddr servers[2], client;
        socklen_t client_len;
        int fd4, fd6;

        bare_netd(&n);
        fd4 = fake_server(AF_INET, "127.0.0.1", NETD_NTP_PORT);
        fd6 = fake_server(AF_INET6, "::1", NETD_NTP_PORT);

        ASSERT_EQ_INT(netd_sntp_new(&n, &s), 0);
        servers[0] = server_addr(AF_INET, "127.0.0.1");
        servers[1] = server_addr(AF_INET6, "::1");
        ASSERT_EQ_INT(netd_sntp_set_server_addrs(s, servers, 2), 0);

        ASSERT_EQ_INT(netd_sntp_start(s), 0);
        (void) read_request(fd4, AF_INET, &client, &client_len);
        ASSERT_TRUE(netd_sntp_addr_eq(&s->request.server, &servers[0]));

        ASSERT_EQ_INT(netd_sntp_start(s), 0);
        (void) read_request(fd6, AF_INET6, &client, &client_len);
        ASSERT_TRUE(netd_sntp_addr_eq(&s->request.server, &servers[1]));

        netd_sntp_free(s);
        close(fd4);
        close(fd6);
        bare_netd_free(&n);
        printf("test-netd-sntp-ipv6: mixed families ok\n");
}

int main(void) {
        if (access("/proc/net/if_inet6", F_OK) < 0) {
                fprintf(stderr, "test-netd-sntp-ipv6: kernel without IPv6, skipping\n");
                return 77;
        }

        if (enter_test_netns() < 0)
                return 77;
        loopback_up();

        test_exchange_loopback();
        test_mixed_families();

        printf("test-netd-sntp-ipv6: all checks passed\n");
        return 0;
}
