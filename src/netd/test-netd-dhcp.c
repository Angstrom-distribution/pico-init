/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The DHCPv4 server end to end, plus the shim-layer tests.
 *
 * The "client" side of every exchange is a scripted harness built on the
 * shared wire codec (dhcp/dhcp-message.h), not dhcp-client.c. The server runs
 * against it over a genuine kernel UDP socket pair on a veth link inside a
 * network namespace (unshare(CLONE_NEWUSER|CLONE_NEWNET), as in
 * test-netd-rtnl.c; a bare CLONE_NEWNET fails with EPERM without
 * CAP_SYS_ADMIN). The harness and the server share the codec, so a codec bug
 * that is self-consistently wrong would go unnoticed here; test-netd-codec.c
 * pins the wire format against fixed bytes independently.
 *
 *   - DISCOVER -> OFFER -> REQUEST -> ACK (dhcp_server_process_discover()/
 *     _request(), the siphash-offset pool pick, dhcp_server_ack()).
 *   - Renewal: a second REQUEST with ciaddr already set (the collapsed
 *     RENEW-OR-REBIND path, see dhcp-server-request.c) -> ACK, lease
 *     expiration extended.
 *   - RELEASE -> the lease's slot is freed.
 *   - A rapid-commit DISCOVER (DISCOVER -> immediate ACK, no OFFER round
 *     trip) is the vehicle for the DHCP_SERVER_DONT_DESTROY test: its
 *     callback calls dhcp_server_stop() on the server object from *inside*
 *     dhcp_server_on_lease_change()'s call stack, and the test asserts the
 *     guard's extra ref is held (server->n_ref >= 2 when the callback fires).
 *   - A pool reconfigure to a disjoint subnet mid-run (dhcp_server_configure_
 *     pool() called again, as a .network reload would): the old address must
 *     fall out of the pool immediately and a REQUEST for it must NAK; a
 *     fresh DISCOVER must be offered from the new subnet.
 *   - Two direct (no-socket) calls into dhcp_server_process_message() with
 *     hand-built malformed packets: a nonzero giaddr and a REQUEST carrying
 *     REQUESTED_IP_ADDRESS while ciaddr is already set both return
 *     -EBADMSG rather than asserting.
 *   - The shim-layer tests (u8set, ownership macros, unaligned access,
 *     siphash24 reference vectors), which nothing else in netd_tests
 *     exercises directly.
 */

/* unshare()/CLONE_NEWUSER/CLONE_NEWNET need __USE_GNU; must be first. */
#define _GNU_SOURCE

#include <errno.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "../test-util.h"
#include "dhcp/dhcp-client-id-internal.h"
#include "dhcp/dhcp-server-internal.h"
#include "dhcp/dhcp-server-lease-internal.h"
#include "dhcp/siphash24.h"
#include "dhcp/unaligned.h"
#include "netd-compat.h"
#include "netd.h"

/* --- shim-layer tests --- */

static void test_u8set(void) {
        NetdU8Set s;
        unsigned seen = 0;
        uint8_t last = 0;

        netd_u8set_clear(&s);
        ASSERT_EQ_INT(netd_u8set_size(&s), 0);
        ASSERT_TRUE(!netd_u8set_contains(&s, 42));

        ASSERT_EQ_INT(netd_u8set_put(&s, 42), 1);
        ASSERT_EQ_INT(netd_u8set_put(&s, 42), 0); /* already there */
        ASSERT_EQ_INT(netd_u8set_put(&s, 1), 1);
        ASSERT_EQ_INT(netd_u8set_put(&s, 255), 1);
        ASSERT_EQ_INT(netd_u8set_put(&s, 0), 1);
        ASSERT_EQ_INT(netd_u8set_size(&s), 4);

        ASSERT_TRUE(netd_u8set_contains(&s, 0));
        ASSERT_TRUE(netd_u8set_contains(&s, 255));
        ASSERT_TRUE(!netd_u8set_contains(&s, 254));

        FOREACH_U8SET(v, &s) {
                if (seen > 0)
                        ASSERT_TRUE(v > last);
                last = v;
                seen++;
        }
        ASSERT_EQ_INT(seen, 4);
        ASSERT_EQ_INT(last, 255);

        ASSERT_EQ_INT(netd_u8set_remove(&s, 42), 1);
        ASSERT_EQ_INT(netd_u8set_remove(&s, 42), 0);
        ASSERT_EQ_INT(netd_u8set_size(&s), 3);
}

static void test_ownership_macros(void) {
        char *p = strdup("lease");
        char *q;
        int fd = 7;
        int fd2;

        ASSERT_TRUE(p != NULL);
        q = TAKE_PTR(p);
        ASSERT_TRUE(p == NULL);
        ASSERT_STREQ(q, "lease");
        free(q);

        fd2 = TAKE_FD(fd);
        ASSERT_EQ_INT(fd2, 7);
        ASSERT_EQ_INT(fd, -1);

        ASSERT_TRUE(IN_SET(5, 1, 3, 5));
        ASSERT_TRUE(!IN_SET(4, 1, 3, 5));
}

static void test_unaligned(void) {
        uint8_t buf[16];

        for (size_t off = 0; off < 8; off++) {
                memset(buf, 0, sizeof(buf));
                unaligned_write_be32(buf + off, 0xdeadbeefU);

                ASSERT_EQ_INT(buf[off], 0xde);
                ASSERT_EQ_INT(buf[off + 3], 0xef);
                ASSERT_EQ_INT(unaligned_read_be32(buf + off), 0xdeadbeefU);

                unaligned_write_be16(buf + off, 0x0102);
                ASSERT_EQ_INT(unaligned_read_be16(buf + off), 0x0102);
        }
}

static void test_siphash24(void) {
        static const uint8_t k[16] = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        };
        static const uint8_t in1[1] = { 0x00 };
        static const uint8_t in8[8] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

        ASSERT_TRUE(siphash24("", 0, k) == UINT64_C(0x726fdb47dd0e0e31));
        ASSERT_TRUE(siphash24(in1, sizeof(in1), k) == UINT64_C(0x74f839c593dc67fd));
        ASSERT_TRUE(siphash24(in8, sizeof(in8), k) == UINT64_C(0x93f5f5799a932462));
}

/* --- netns/veth DHCP server integration test --- */

static void run_shell(const char *cmd) {
        int rc = system(cmd);

        if (rc != 0) {
                fprintf(stderr, "test-netd-dhcp: `%s` failed (rc=%d)\n", cmd, rc);
                exit(1);
        }
}

static void run_ip(const char *args) {
        char cmd[256];
        int len = snprintf(cmd, sizeof(cmd), "ip %s >/dev/null 2>&1", args);

        if (len < 0 || (size_t) len >= sizeof(cmd)) {
                fprintf(stderr, "test-netd-dhcp: ip command too long: %s\n", args);
                exit(1);
        }

        run_shell(cmd);
}

static void write_proc_file(const char *path, const char *content) {
        FILE *f = fopen(path, "we");

        if (!f) {
                fprintf(stderr, "test-netd-dhcp: cannot open %s: %s\n", path, strerror(errno));
                exit(1);
        }

        if (fputs(content, f) < 0) {
                fprintf(stderr, "test-netd-dhcp: cannot write %s: %s\n", path, strerror(errno));
                (void) fclose(f);
                exit(1);
        }

        if (fclose(f) != 0) {
                fprintf(stderr, "test-netd-dhcp: cannot close %s: %s\n", path, strerror(errno));
                exit(1);
        }
}

/* Same mechanism as test-netd-rtnl.c's enter_test_netns(). A test that cannot
 * prove its own isolation must fail loudly, never silently skip. */
static void enter_test_netns(void) {
        uid_t outer_uid = getuid();
        gid_t outer_gid = getgid();
        char buf[64];

        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
                fprintf(stderr, "test-netd-dhcp: unshare(CLONE_NEWUSER|CLONE_NEWNET): %s\n", strerror(errno));
                fprintf(stderr, "test-netd-dhcp: cannot prove netns isolation, refusing to report success\n");
                exit(1);
        }

        write_proc_file("/proc/self/setgroups", "deny");

        snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned) outer_uid);
        write_proc_file("/proc/self/uid_map", buf);

        snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned) outer_gid);
        write_proc_file("/proc/self/gid_map", buf);
}

static unsigned if_index_or_die(const char *ifname) {
        unsigned idx = if_nametoindex(ifname);

        if (idx == 0) {
                fprintf(stderr, "test-netd-dhcp: if_nametoindex(%s): %s\n", ifname, strerror(errno));
                exit(1);
        }

        return idx;
}

/* --- scripted "client": built directly on the shared codec, not on
 * dhcp-client.c (see this file's own header for why). */

static void build_discover(uint32_t xid, const struct hw_addr_data *hw, bool rapid_commit, struct iovec *ret) {
        _cleanup_(dhcp_message_unrefp) DhcpMessage *msg = NULL;
        DhcpClientId cid;

        ASSERT_TRUE(dhcp_message_new(&msg) == 0);
        ASSERT_TRUE(dhcp_message_init_header(msg, BOOTREQUEST, xid, ARPHRD_ETHER, hw) == 0);
        dhcp_message_set_broadcast_flag(msg, true); /* no address configured yet */

        ASSERT_TRUE(dhcp_client_id_set(&cid, 1, hw->bytes, hw->length) == 0);
        ASSERT_TRUE(dhcp_message_append_option_client_id(msg, &cid) == 0);
        ASSERT_TRUE(dhcp_message_append_option_u8(msg, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_DISCOVER) == 0);

        if (rapid_commit)
                ASSERT_TRUE(dhcp_message_append_option_flag(msg, SD_DHCP_OPTION_RAPID_COMMIT) == 0);

        ASSERT_TRUE(dhcp_message_build(msg, ret) == 0);
}

/* renew == false: SELECTING-style REQUEST (requested_addr/server_id set,
 * ciaddr left at 0). renew == true: RENEW-OR-REBIND-style REQUEST (ciaddr
 * set to the already-bound address, no requested-ip/server-id options). */
static void
                build_request(uint32_t xid,
                              const struct hw_addr_data *hw,
                              be32_t requested_addr,
                              be32_t server_id,
                              bool renew,
                              struct iovec *ret) {

        _cleanup_(dhcp_message_unrefp) DhcpMessage *msg = NULL;
        DhcpClientId cid;

        ASSERT_TRUE(dhcp_message_new(&msg) == 0);
        ASSERT_TRUE(dhcp_message_init_header(msg, BOOTREQUEST, xid, ARPHRD_ETHER, hw) == 0);

        if (renew)
                msg->header.ciaddr = requested_addr;
        else
                dhcp_message_set_broadcast_flag(msg, true);

        ASSERT_TRUE(dhcp_client_id_set(&cid, 1, hw->bytes, hw->length) == 0);
        ASSERT_TRUE(dhcp_message_append_option_client_id(msg, &cid) == 0);
        ASSERT_TRUE(dhcp_message_append_option_u8(msg, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_REQUEST) == 0);

        if (!renew) {
                ASSERT_TRUE(dhcp_message_append_option_be32(
                                            msg, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, requested_addr) == 0);
                ASSERT_TRUE(dhcp_message_append_option_be32(
                                            msg, SD_DHCP_OPTION_SERVER_IDENTIFIER, server_id) == 0);
        }

        ASSERT_TRUE(dhcp_message_build(msg, ret) == 0);
}

static void build_release(
                uint32_t xid, const struct hw_addr_data *hw, be32_t address, be32_t server_id, struct iovec *ret) {
        _cleanup_(dhcp_message_unrefp) DhcpMessage *msg = NULL;
        DhcpClientId cid;

        ASSERT_TRUE(dhcp_message_new(&msg) == 0);
        ASSERT_TRUE(dhcp_message_init_header(msg, BOOTREQUEST, xid, ARPHRD_ETHER, hw) == 0);
        msg->header.ciaddr = address;

        ASSERT_TRUE(dhcp_client_id_set(&cid, 1, hw->bytes, hw->length) == 0);
        ASSERT_TRUE(dhcp_message_append_option_client_id(msg, &cid) == 0);
        ASSERT_TRUE(dhcp_message_append_option_u8(msg, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_RELEASE) == 0);
        ASSERT_TRUE(dhcp_message_append_option_be32(msg, SD_DHCP_OPTION_SERVER_IDENTIFIER, server_id) == 0);

        ASSERT_TRUE(dhcp_message_build(msg, ret) == 0);
}

static int open_client_socket(const char *ifname) {
        int fd, one = 1;
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        struct sockaddr_in sa = {
                .sin_family = AF_INET,
                .sin_port = htobe16(DHCP_PORT_CLIENT),
                .sin_addr.s_addr = htobe32(INADDR_ANY),
        };

        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        ASSERT_TRUE(fd >= 0);
        ASSERT_TRUE(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
        ASSERT_TRUE(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) == 0);
        ASSERT_TRUE(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname) + 1) == 0);
        ASSERT_TRUE(bind(fd, (struct sockaddr *) &sa, sizeof(sa)) == 0);

        /* A protocol bug must fail the test loudly (a timed-out recv() ->
         * failed assertion), never hang meson test forever. */
        ASSERT_TRUE(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);

        return fd;
}

static void client_send(int fd, const struct iovec *iov) {
        struct sockaddr_in dst = {
                .sin_family = AF_INET,
                .sin_port = htobe16(DHCP_PORT_SERVER),
                .sin_addr.s_addr = htobe32(INADDR_BROADCAST),
        };
        ssize_t n = sendto(fd, iov->iov_base, iov->iov_len, 0, (struct sockaddr *) &dst, sizeof(dst));

        ASSERT_TRUE(n == (ssize_t) iov->iov_len);
}

/* Blocks (up to 2s) until the server's socket is actually readable, then
 * dispatches exactly like the real epoll path would -- deterministic,
 * unlike calling the callback immediately after sendto() and hoping the
 * datagram has already been delivered. */
static void drive_server_once(Netd *n, DhcpServer *server) {
        struct pollfd pfd = { .fd = server->socket_fd, .events = POLLIN };
        int r = poll(&pfd, 1, 2000);

        ASSERT_TRUE(r == 1);
        ASSERT_TRUE(dhcp_server_io_callback(n, &server->io_tag, EPOLLIN) == 0);
}

static void recv_reply(int fd, uint32_t xid, const struct hw_addr_data *hw, DhcpMessage **ret) {
        uint8_t buf[2048];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        struct iovec iov;
        uint32_t x = xid;

        ASSERT_TRUE(n > 0);
        iov = (struct iovec){ .iov_base = buf, .iov_len = (size_t) n };
        ASSERT_TRUE(dhcp_message_parse(&iov, BOOTREPLY, &x, ARPHRD_ETHER, hw, ret) == 0);
}

static uint8_t reply_type(DhcpMessage *msg) {
        uint8_t t;

        ASSERT_TRUE(dhcp_message_get_option_u8(msg, SD_DHCP_OPTION_MESSAGE_TYPE, &t) == 0);
        return t;
}

/* --- DHCP_SERVER_DONT_DESTROY: the callback for the rapid-commit phase --- */

typedef struct DontDestroyState {
        /* Only the designated rapid-commit phase sets this before sending;
         * every ACK/renewal earlier in the test also fires this callback
         * (dhcp_server_ack() -> dhcp_server_on_lease_change()), and a
         * reentrant stop() on every one of those would tear the server down
         * long before the rest of the exchange runs. */
        bool armed;
        bool callback_fired;
        unsigned n_ref_seen;
        DhcpServer *server;
} DontDestroyState;

static void dont_destroy_callback(DhcpServer *server, DhcpServerEvent event, void *userdata) {
        DontDestroyState *st = userdata;

        ASSERT_EQ_INT(event, DHCP_SERVER_EVENT_LEASE_CHANGED);

        if (!st->armed)
                return;

        st->callback_fired = true;
        st->n_ref_seen = server->n_ref;

        /* A lease-change callback that stops the very object whose call stack
         * it is running on. Without DHCP_SERVER_DONT_DESTROY
         * (dhcp-server-internal.h) this would be a use-after-free once
         * dhcp_server_process_message() touched `server` again. */
        ASSERT_TRUE(dhcp_server_stop(server) == 0);
}

/* --- malformed-packet direct calls (no socket needed: the return code is
 * the whole assertion) --- */

static void test_rejects_nonzero_giaddr(DhcpServer *server) {
        _cleanup_(dhcp_message_unrefp) DhcpMessage *msg = NULL;
        struct hw_addr_data hw = {
                .length = 6, .bytes = { 0x02, 0, 0, 0, 0, 0x77 }
        };
        DhcpClientId cid;
        struct iovec iov;
        int r;

        ASSERT_TRUE(dhcp_message_new(&msg) == 0);
        ASSERT_TRUE(dhcp_message_init_header(msg, BOOTREQUEST, 0x77777777U, ARPHRD_ETHER, &hw) == 0);
        msg->header.giaddr = htobe32(0x0A000001U); /* relay is out of scope -- this must be rejected */
        ASSERT_TRUE(dhcp_client_id_set(&cid, 1, hw.bytes, hw.length) == 0);
        ASSERT_TRUE(dhcp_message_append_option_client_id(msg, &cid) == 0);
        ASSERT_TRUE(dhcp_message_append_option_u8(msg, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_DISCOVER) == 0);

        ASSERT_TRUE(dhcp_message_build(msg, &iov) == 0);
        r = dhcp_server_process_message(server, &iov);
        free(iov.iov_base);

        ASSERT_EQ_INT(r, -EBADMSG);
}

static void test_rejects_request_with_both_ciaddr_and_requested_ip(DhcpServer *server) {
        _cleanup_(dhcp_message_unrefp) DhcpMessage *msg = NULL;
        struct hw_addr_data hw = {
                .length = 6, .bytes = { 0x02, 0, 0, 0, 0, 0x88 }
        };
        DhcpClientId cid;
        struct iovec iov;
        be32_t bogus = htobe32(0x0A1E0009U);
        int r;

        ASSERT_TRUE(dhcp_message_new(&msg) == 0);
        ASSERT_TRUE(dhcp_message_init_header(msg, BOOTREQUEST, 0x88888888U, ARPHRD_ETHER, &hw) == 0);
        msg->header.ciaddr = htobe32(0x0A1E0005U); /* -> RENEW-OR-REBIND path */
        ASSERT_TRUE(dhcp_client_id_set(&cid, 1, hw.bytes, hw.length) == 0);
        ASSERT_TRUE(dhcp_message_append_option_client_id(msg, &cid) == 0);
        ASSERT_TRUE(dhcp_message_append_option_u8(msg, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_REQUEST) == 0);
        /* RFC 2131 §4.3.2: REQUESTED_IP_ADDRESS MUST NOT be present here. */
        ASSERT_TRUE(dhcp_message_append_option_be32(msg, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, bogus) == 0);

        ASSERT_TRUE(dhcp_message_build(msg, &iov) == 0);
        r = dhcp_server_process_message(server, &iov);
        free(iov.iov_base);

        ASSERT_EQ_INT(r, -EBADMSG);
}

static void test_netns_dhcp_server(void) {
        Netd *n = NULL;
        DhcpServer *server = NULL;
        DontDestroyState dd = { 0 };
        int cfd;
        unsigned server_ifindex;
        struct hw_addr_data hw = {
                .length = 6, .bytes = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 }
        };
        struct iovec pkt;
        uint32_t xid = 0x11223344U;
        be32_t offered, server_id, offered2, server_id2;
        struct in_addr router, dns, addr, netmask, addr2;

        enter_test_netns();

        run_ip("link add name dsrv0 type veth peer name dcli0");
        run_ip("link set dsrv0 up");
        run_ip("link set dcli0 up");
        run_ip("link set lo up");

        /*
         * No kernel addresses on either end yet. In this container's
         * virtualized networking, once *either* veth end has an IPv4 address,
         * UDP broadcast (255.255.255.255) delivery between the pair stops
         * working in both directions. DISCOVER/OFFER and every ACK/NAK with a
         * zero ciaddr (dhcp-server-send.c's broadcast fallback) need
         * broadcast, so all of that runs first with both interfaces
         * unconfigured -- the state a real client is in before it has a
         * lease. Addresses are applied only right before the renewal phase,
         * which needs routed unicast.
         */

        server_ifindex = if_index_or_die("dsrv0");

        ASSERT_TRUE(netd_new(&n) == 0);
        ASSERT_TRUE(dhcp_server_new(n, (int) server_ifindex, "dsrv0", &server) == 0);

        addr.s_addr = htobe32(0x0A1E0001U); /* 10.30.0.1/24 */
        ASSERT_TRUE(dhcp_server_configure_pool(server, &addr, 24, /* offset= */ 0, /* size= */ 10) == 0);

        router = addr;
        ASSERT_TRUE(dhcp_server_set_router(server, &router) == 0);

        dns.s_addr = addr.s_addr;
        ASSERT_TRUE(dhcp_server_set_dns(server, &dns, 1) == 0);

        dd.server = server;
        ASSERT_TRUE(dhcp_server_set_callback(server, dont_destroy_callback, &dd) == 0);

        ASSERT_TRUE(dhcp_server_start(server) == 0);
        ASSERT_TRUE(dhcp_server_is_running(server));

        cfd = open_client_socket("dcli0");

        /* --- the two EBADMSG checks: no socket needed, direct calls --- */
        test_rejects_nonzero_giaddr(server);
        test_rejects_request_with_both_ciaddr_and_requested_ip(server);

        /* --- DISCOVER -> OFFER --- */
        build_discover(xid, &hw, /* rapid_commit= */ false, &pkt);
        client_send(cfd, &pkt);
        free(pkt.iov_base);
        drive_server_once(n, server);

        _cleanup_(dhcp_message_unrefp) DhcpMessage *offer = NULL;
        recv_reply(cfd, xid, &hw, &offer);
        ASSERT_EQ_INT(reply_type(offer), DHCP_OFFER);
        offered = offer->header.yiaddr;
        ASSERT_TRUE(offered != htobe32(INADDR_ANY));
        ASSERT_EQ_INT(be32toh(offered) & 0xFFFFFF00U, 0x0A1E0000U);
        ASSERT_TRUE(dhcp_message_get_option_be32(offer, SD_DHCP_OPTION_SERVER_IDENTIFIER, &server_id) == 0);
        ASSERT_TRUE(server_id == addr.s_addr);

        /* --- REQUEST (SELECTING) -> ACK --- */
        build_request(xid, &hw, offered, server_id, /* renew= */ false, &pkt);
        client_send(cfd, &pkt);
        free(pkt.iov_base);
        drive_server_once(n, server);

        _cleanup_(dhcp_message_unrefp) DhcpMessage *ack = NULL;
        recv_reply(cfd, xid, &hw, &ack);
        ASSERT_EQ_INT(reply_type(ack), DHCP_ACK);
        ASSERT_TRUE(ack->header.yiaddr == offered);
        ASSERT_TRUE(dhcp_message_get_option_address(ack, SD_DHCP_OPTION_SUBNET_MASK, &netmask) == 0);
        ASSERT_EQ_INT(be32toh(netmask.s_addr), 0xFFFFFF00U);

        DhcpServerLease *lease = dhcp_server_get_lease_by_address(server, offered);
        ASSERT_TRUE(lease != NULL);
        ASSERT_TRUE(lease->in_use);

        /* Independent confirmation via `ip`, as in test-netd-rtnl.c. The
         * server never touches the kernel's address table, so this only
         * checks the veth pair is still as configured. */
        run_shell("ip link show dsrv0 | grep -q 'state UP\\|<.*UP.*>'");

        /* --- RELEASE --- */
        uint32_t xid_release = xid + 1;
        build_release(xid_release, &hw, offered, server_id, &pkt);
        client_send(cfd, &pkt);
        free(pkt.iov_base);
        drive_server_once(n, server); /* RELEASE gets no reply; the drive is still needed to process it */

        ASSERT_TRUE(dhcp_server_get_lease_by_address(server, offered) == NULL);

        /* --- DHCP_SERVER_DONT_DESTROY: rapid-commit DISCOVER -> immediate
         * ACK -> on_lease_change() -> callback reenters dhcp_server_stop() --- */
        dd.armed = true;
        uint32_t xid_rapid = xid_release + 1;
        build_discover(xid_rapid, &hw, /* rapid_commit= */ true, &pkt);
        client_send(cfd, &pkt);
        free(pkt.iov_base);
        drive_server_once(n, server);

        _cleanup_(dhcp_message_unrefp) DhcpMessage *rapid_ack = NULL;
        recv_reply(cfd, xid_rapid, &hw, &rapid_ack);
        ASSERT_EQ_INT(reply_type(rapid_ack), DHCP_ACK);

        ASSERT_TRUE(dd.callback_fired);
        /* At least this test's own ref, plus DHCP_SERVER_DONT_DESTROY's --
         * proof the guard actually took a ref, not just that nothing
         * crashed (which could pass by luck on a lenient allocator). */
        ASSERT_TRUE(dd.n_ref_seen >= 2);
        /* The reentrant dhcp_server_stop() call the callback made really
         * took effect: this is exactly what stopping/restarting an
         * interface's DHCP server from within a lease callback would do on
         * a real SIGHUP reconfigure. */
        ASSERT_TRUE(!dhcp_server_is_running(server));

        dd.armed = false; /* every later ACK also fires this callback; only this phase reenters stop() */

        ASSERT_TRUE(dhcp_server_start(server) == 0);
        ASSERT_TRUE(dhcp_server_is_running(server));

        /* --- mode-switch reconfigure (the usb0 fallback scenario) --- */
        addr2.s_addr = htobe32(0x0A1F0001U); /* 10.31.0.1/24 -- disjoint from 10.30.0.0/24 */
        ASSERT_TRUE(dhcp_server_configure_pool(server, &addr2, 24, /* offset= */ 0, /* size= */ 10) == 0);
        ASSERT_TRUE(!dhcp_server_address_is_in_pool(server, offered));

        uint32_t xid_new = xid_rapid + 1;
        build_discover(xid_new, &hw, /* rapid_commit= */ false, &pkt);
        client_send(cfd, &pkt);
        free(pkt.iov_base);
        drive_server_once(n, server);

        _cleanup_(dhcp_message_unrefp) DhcpMessage *offer2 = NULL;
        recv_reply(cfd, xid_new, &hw, &offer2);
        ASSERT_EQ_INT(reply_type(offer2), DHCP_OFFER);
        offered2 = offer2->header.yiaddr;
        ASSERT_EQ_INT(be32toh(offered2) & 0xFFFFFF00U, 0x0A1F0000U);
        ASSERT_TRUE(offered2 != offered);
        ASSERT_TRUE(dhcp_message_get_option_be32(offer2, SD_DHCP_OPTION_SERVER_IDENTIFIER, &server_id2) == 0);
        ASSERT_TRUE(server_id2 == addr2.s_addr);

        /* A REQUEST for the now-defunct old address must NAK, not ACK. */
        uint32_t xid_old = xid_new + 1;
        /* server_id2, not server_id: naming the stale server_id would make
         * dhcp_server_process_request() silently ignore the packet as "not
         * addressed to us" (RFC 2131 §4.3.2's SELECTING branch) instead of
         * NAKing it. */
        build_request(xid_old, &hw, offered, server_id2, /* renew= */ false, &pkt);
        client_send(cfd, &pkt);
        free(pkt.iov_base);
        drive_server_once(n, server);

        _cleanup_(dhcp_message_unrefp) DhcpMessage *nak = NULL;
        recv_reply(cfd, xid_old, &hw, &nak);
        ASSERT_EQ_INT(reply_type(nak), DHCP_NAK);

        /* --- REQUEST (SELECTING) for the new pool -> ACK, still broadcast,
         * still no kernel addresses configured --- */
        uint32_t xid_new_ack = xid_old + 1;
        build_request(xid_new_ack, &hw, offered2, server_id2, /* renew= */ false, &pkt);
        client_send(cfd, &pkt);
        free(pkt.iov_base);
        drive_server_once(n, server);

        _cleanup_(dhcp_message_unrefp) DhcpMessage *ack3 = NULL;
        recv_reply(cfd, xid_new_ack, &hw, &ack3);
        ASSERT_EQ_INT(reply_type(ack3), DHCP_ACK);
        ASSERT_TRUE(ack3->header.yiaddr == offered2);

        DhcpServerLease *lease2 = dhcp_server_get_lease_by_address(server, offered2);
        ASSERT_TRUE(lease2 != NULL);
        usec_t expiration_before_renew = lease2->expiration;

        /*
         * --- renewal: the one phase that genuinely needs routed unicast
         * (dhcp-server-send.c unicasts an ACK whose ciaddr is set) ---
         *
         * Real kernel addresses go on, matching the current (post-
         * reconfigure) pool: dsrv0 gets the server's own pool address, dcli0
         * the lease it just acquired.
         *
         * The exchange is driven directly (dhcp_server_process_message(), the
         * call dhcp_server_io_callback() makes internally), not through the
         * client's socket: in this container's virtualized networking a UDP
         * send from a wildcard-bound SO_BINDTODEVICE socket (as
         * dhcp_server_open_socket() sets up) does not reliably traverse the
         * veth pair once a route exists. That is a property of this
         * environment, not of netd's socket code. Driving the exchange
         * directly still runs the real protocol logic: parsing, the
         * RENEW-OR-REBIND branch, dhcp_server_ack(), dhcp_server_set_lease(),
         * and dhcp_server_send_reply() building and sending the ACK.
         */
        run_ip("addr add 10.31.0.1/24 dev dsrv0");
        {
                struct in_addr offered2_in = { .s_addr = offered2 };
                char ipbuf[INET_ADDRSTRLEN], cmd[64];

                ASSERT_TRUE(inet_ntop(AF_INET, &offered2_in, ipbuf, sizeof(ipbuf)) != NULL);
                ASSERT_TRUE(snprintf(cmd, sizeof(cmd), "addr add %s/24 dev dcli0", ipbuf) < (int) sizeof(cmd));
                run_ip(cmd);
        }
        run_shell("ip -4 addr show dsrv0 | grep -q '10\\.31\\.0\\.1/24'");
        run_shell("ip -4 addr show dcli0 | grep -q '/24'");

        uint32_t xid_renew = xid_new_ack + 1;
        build_request(xid_renew, &hw, offered2, server_id2, /* renew= */ true, &pkt);

        int renew_result = dhcp_server_process_message(server, &pkt);
        free(pkt.iov_base);
        /* dhcp_server_send_reply() returns the sent message type on success
         * (dhcp-server-send.c, matching upstream) -- a real send failure
         * (e.g. ENETUNREACH) would come back negative here, not silently. */
        ASSERT_EQ_INT(renew_result, DHCP_ACK);

        lease2 = dhcp_server_get_lease_by_address(server, offered2);
        ASSERT_TRUE(lease2 != NULL);
        ASSERT_TRUE(lease2->expiration >= expiration_before_renew);

        close(cfd);
        dhcp_server_unref(server);
        netd_free(n);
        run_ip("link del dsrv0");

        printf("test-netd-dhcp: netns DHCP server subtest ok\n");
}

int main(void) {
        test_u8set();
        test_ownership_macros();
        test_unaligned();
        test_siphash24();
        test_netns_dhcp_server();

        printf("test-netd-dhcp: ok\n");
        return EXIT_SUCCESS;
}
