/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/dhcp-client-send.c plus
 * dhcp_message_send_udp()/dhcp_message_send_raw() from dhcp-message.c and the
 * IPv4/UDP header build and verify from ip-util.c. dhcp_message_build()
 * (dhcp-message.h) hands back the wire bytes; putting them on the wire is
 * this file's job.
 *
 * Two sockets only: AF_PACKET / SOCK_DGRAM bound through sockaddr_ll before
 * a lease exists, and plain AF_INET / SOCK_DGRAM once one does. There is no
 * netlink dependency in the client.
 *
 * The BPF filter is not an optimisation to trim: without it an AF_PACKET
 * socket wakes the daemon for every IPv4 frame on the segment. It also does
 * the xid/chaddr correlation in the kernel, so a reply meant for another
 * host never reaches the parser.
 *
 * Divergences from upstream, argued at their site:
 *  - the Internet checksum is computed over one contiguous buffer instead of
 *    a scattered-iovec walk;
 *  - a computed UDP checksum of zero is transmitted as 0xffff, per RFC 768;
 *  - the UDP send is a plain sendto() rather than a sendmsg() carrying an
 *    IP_PKTINFO control message.
 */

#include "dhcp-client-internal.h"

#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "unaligned.h"

/* The smallest thing that can be a DHCP datagram once the IP header is off:
 * a UDP header plus a full BOOTP header. Used by the filter's length test. */
#define DHCP_MINIMUM_UDP_SIZE (sizeof(struct udphdr) + sizeof(DHCPMessageHeader))

/* RFC 791: every host must be able to reassemble a 576-octet datagram, which
 * is the floor for what we may advertise as Maximum Message Size (57). */
#define IPV4_MIN_REASSEMBLY_SIZE 576u

/* --- the Internet checksum (RFC 1071) --- */

/*
 * Upstream's ip-util.c accumulates 64 bits at a time over an iovec_wrapper.
 * Here the packet is one contiguous buffer, so the plain 16-bit form of
 * RFC 1071 is enough.
 *
 * The accumulation is in big-endian word order, so the folded result is the
 * checksum as a network-order *value*; storing it means htobe16(). Verifying
 * means summing the whole structure, stored checksum included, and expecting
 * zero.
 */
static uint64_t checksum_add(uint64_t sum, const void *data, size_t len) {
        const uint8_t *p = data;

        while (len >= 2) {
                sum += ((uint32_t) p[0] << 8) | (uint32_t) p[1];
                p += 2;
                len -= 2;
        }

        /* An odd trailing byte is the high half of a final word. */
        if (len == 1)
                sum += (uint32_t) p[0] << 8;

        return sum;
}

static uint16_t checksum_finish(uint64_t sum) {
        while ((sum >> 16) != 0)
                sum = (sum & 0xffffU) + (sum >> 16);

        return (uint16_t) ~sum;
}

/* RFC 768's pseudo-header: the UDP checksum covers these source/destination
 * addresses too, which is what makes it detect a misdelivered datagram. */
struct udp_pseudo_header {
        be32_t saddr;
        be32_t daddr;
        uint8_t unused;
        uint8_t protocol;
        be16_t len;
} _packed_;

static uint16_t udp_checksum(
                be32_t saddr, be32_t daddr, const struct udphdr *udp, const void *payload, size_t payload_len) {

        struct udp_pseudo_header pseudo = {
                .saddr = saddr,
                .daddr = daddr,
                .protocol = IPPROTO_UDP,
                .len = udp->len,
        };
        uint64_t sum = 0;

        sum = checksum_add(sum, &pseudo, sizeof(pseudo));
        sum = checksum_add(sum, udp, sizeof(struct udphdr));
        sum = checksum_add(sum, payload, payload_len);

        return checksum_finish(sum);
}

/* --- receive-side IPv4/UDP verification (upstream's udp_packet_verify) --- */

/* Every check here is on peer-controlled bytes, so each is an -EBADMSG
 * return, never an assert (see netd-compat.h's assertion policy). */
static int client_verify_udp_packet(
                DhcpClient *client, const struct iovec *packet, bool checksum, struct iovec *ret_payload) {

        struct iphdr ip;
        struct udphdr udp;
        const uint8_t *base;
        size_t iphdrlen, totlen, udplen;

        assert(client);
        assert(packet);
        assert(ret_payload);

        base = packet->iov_base;

        if (!base || packet->iov_len < sizeof(struct iphdr))
                return -EBADMSG;

        memcpy(&ip, base, sizeof(ip));

        if (ip.version != IPVERSION)
                return -EBADMSG;

        iphdrlen = (size_t) ip.ihl * 4;
        if (iphdrlen < sizeof(struct iphdr) || packet->iov_len < iphdrlen)
                return -EBADMSG;

        totlen = be16toh(ip.tot_len);
        if (totlen < iphdrlen || packet->iov_len < totlen)
                return -EBADMSG;

        if (ip.protocol != IPPROTO_UDP)
                return -EBADMSG;

        /* Over the whole header including its own check field: zero means
         * good. IP options, if any, are inside iphdrlen and are covered. */
        if (checksum_finish(checksum_add(0, base, iphdrlen)) != 0)
                return -EBADMSG;

        if (totlen < iphdrlen + sizeof(struct udphdr))
                return -EBADMSG;

        memcpy(&udp, base + iphdrlen, sizeof(udp));

        udplen = be16toh(udp.len);
        if (udplen < sizeof(struct udphdr))
                return -EBADMSG;

        /* The two length fields must agree, or a truncated datagram could be
         * read past its real end. */
        if (totlen != iphdrlen + udplen)
                return -EBADMSG;

        if (be16toh(udp.dest) != client->port)
                return -EBADMSG;

        /* Length from the UDP header, not from what was received: an
         * AF_PACKET read can legitimately carry trailing padding. */
        ret_payload->iov_base = (void *) (base + iphdrlen + sizeof(struct udphdr));
        ret_payload->iov_len = udplen - sizeof(struct udphdr);

        /* RFC 768: a zero checksum field means the sender did not compute
         * one, which is legal for IPv4. `checksum` is false when the kernel
         * told us via PACKET_AUXDATA that the checksum had not been
         * calculated yet for a locally-generated frame. */
        if (checksum && udp.check != 0 &&
            udp_checksum(ip.saddr, ip.daddr, &udp, ret_payload->iov_base, ret_payload->iov_len) != 0)
                return -EBADMSG;

        return 0;
}

/* --- the BPF filter --- */

static int client_set_bpf(DhcpClient *client, int fd) {
        uint32_t mac_hi = 0;
        uint16_t mac_lo = 0;
        size_t hlen;

        assert(client);
        assert(fd >= 0);

        /* Infiniband is refused at dhcp_client_set_mac(), so the hardware
         * address length is always the one that goes in the header. */
        hlen = client->hw_addr.length;
        if (hlen == ETH_ALEN) {
                mac_hi = unaligned_read_be32(client->hw_addr.bytes);
                mac_lo = unaligned_read_be16(client->hw_addr.bytes + 4);
        }

        struct sock_filter filter[] = {
                /* 1. Length: at least an IP header plus UDP plus a BOOTP
                 * header. BPF_MSH extracts the IHL nibble and multiplies by
                 * four, so this works with IP options present. */
                BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 0),
                BPF_STMT(BPF_MISC + BPF_TXA, 0),
                BPF_STMT(BPF_ALU + BPF_ADD + BPF_K, DHCP_MINIMUM_UDP_SIZE),
                BPF_STMT(BPF_MISC + BPF_TAX, 0),
                BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),
                BPF_JUMP(BPF_JMP + BPF_JGE + BPF_X, 0, 1, 0),
                BPF_STMT(BPF_RET + BPF_K, 0),

                /* 2. Protocol. */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct iphdr, protocol)),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),
                BPF_STMT(BPF_RET + BPF_K, 0),

                /* 3. Fragments. A BPF program cannot reassemble, and only the
                 * first fragment carries the UDP header, so anything
                 * fragmented has to be dropped rather than parsed as if the
                 * payload were a header. 3a: More Fragments set. */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct iphdr, frag_off)),
                BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x20),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),
                BPF_STMT(BPF_RET + BPF_K, 0),

                /* 3b: a non-zero fragment offset. */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct iphdr, frag_off)),
                BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x1fff),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),
                BPF_STMT(BPF_RET + BPF_K, 0),

                /* 4. Everything past here is at a variable offset, because
                 * the IP header length is variable. Reload it into X. */
                BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 0),

                /* 4a. UDP destination port. */
                BPF_STMT(BPF_LD + BPF_H + BPF_IND, offsetof(struct udphdr, dest)),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, client->port, 1, 0),
                BPF_STMT(BPF_RET + BPF_K, 0),

                /* 4b. BOOTREPLY, not somebody else's request. */
                BPF_STMT(BPF_LD + BPF_B + BPF_IND, sizeof(struct udphdr) + offsetof(DHCPMessageHeader, op)),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, BOOTREPLY, 1, 0),
                BPF_STMT(BPF_RET + BPF_K, 0),

                /* 4c. Hardware type. */
                BPF_STMT(BPF_LD + BPF_B + BPF_IND, sizeof(struct udphdr) + offsetof(DHCPMessageHeader, htype)),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, client->arp_type, 1, 0),
                BPF_STMT(BPF_RET + BPF_K, 0),

                /* 4d. Our transaction. This is the correlation RFC 2131 4.1
                 * relies on, done in the kernel. */
                BPF_STMT(BPF_LD + BPF_W + BPF_IND, sizeof(struct udphdr) + offsetof(DHCPMessageHeader, xid)),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, client->xid, 1, 0),
                BPF_STMT(BPF_RET + BPF_K, 0),

                /* 4e. Hardware address length. */
                BPF_STMT(BPF_LD + BPF_B + BPF_IND, sizeof(struct udphdr) + offsetof(DHCPMessageHeader, hlen)),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, hlen, 1, 0),
                BPF_STMT(BPF_RET + BPF_K, 0),

                /* 4f. And the address itself, when it is an Ethernet one. */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_ALEN, 0, 6),
                BPF_STMT(BPF_LD + BPF_W + BPF_IND, sizeof(struct udphdr) + offsetof(DHCPMessageHeader, chaddr)),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac_hi, 1, 0),
                BPF_STMT(BPF_RET + BPF_K, 0),
                BPF_STMT(BPF_LD + BPF_H + BPF_IND,
                         sizeof(struct udphdr) + offsetof(DHCPMessageHeader, chaddr) + 4),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, mac_lo, 1, 0),
                BPF_STMT(BPF_RET + BPF_K, 0),

                /* 4g. The magic cookie. */
                BPF_STMT(BPF_LD + BPF_W + BPF_IND, sizeof(struct udphdr) + offsetof(DHCPMessageHeader, magic)),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, DHCP_MAGIC_COOKIE, 1, 0),
                BPF_STMT(BPF_RET + BPF_K, 0),

                BPF_STMT(BPF_RET + BPF_K, UINT32_MAX),
        };

        struct sock_fprog fprog = {
                .len = (unsigned short) ELEMENTSOF(filter),
                .filter = filter,
        };

        if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0)
                return -errno;

        return 0;
}

/* --- sockets --- */

static int client_setsockopt_int(int fd, int level, int optname, int value) {
        if (setsockopt(fd, level, optname, &value, sizeof(value)) < 0)
                return -errno;

        return 0;
}

static int client_open_raw_socket(DhcpClient *client) {
        _cleanup_close_ int fd = -1;
        struct sockaddr_ll sa;
        int r;

        assert(client);

        fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        /* bind() with sockaddr_ll below is strictly sufficient for AF_PACKET;
         * SO_BINDTOIFINDEX additionally initialises the kernel's
         * sk_bound_dev_if, which is what cgroup/eBPF filters look at.
         * Upstream sets both for that reason. */
        r = client_setsockopt_int(fd, SOL_SOCKET, SO_BINDTOIFINDEX, client->ifindex);
        if (r < 0)
                return r;

        r = client_set_bpf(client, fd);
        if (r < 0)
                return r;

        r = client_setsockopt_int(fd, SOL_SOCKET, SO_PRIORITY, client->socket_priority);
        if (r < 0)
                return r;

        /* PACKET_AUXDATA is how the kernel tells us a checksum has not been
         * computed yet (TP_STATUS_CSUMNOTREADY), which happens for frames
         * looped back from a local sender -- exactly netd's own server over a
         * veth pair. Without it those packets fail checksum verification. */
        r = client_setsockopt_int(fd, SOL_PACKET, PACKET_AUXDATA, 1);
        if (r < 0)
                return r;

        sa = (struct sockaddr_ll){
                .sll_family = AF_PACKET,
                .sll_protocol = htobe16(ETH_P_IP),
                .sll_ifindex = client->ifindex,
        };

        if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
                return -errno;

        return TAKE_FD(fd);
}

static int client_open_udp_socket(DhcpClient *client) {
        _cleanup_close_ int fd = -1;
        struct sockaddr_in sa;
        int r;

        assert(client);
        assert(client->lease);

        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        r = client_setsockopt_int(fd, SOL_SOCKET, SO_BINDTOIFINDEX, client->ifindex);
        if (r < 0)
                return r;

        r = client_setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1);
        if (r < 0)
                return r;

        r = client_setsockopt_int(fd, SOL_SOCKET, SO_PRIORITY, client->socket_priority);
        if (r < 0)
                return r;

        r = client_setsockopt_int(fd, IPPROTO_IP, IP_TOS, client->ip_service_type);
        if (r < 0)
                return r;

        /* IP_FREEBIND: a renewal can be reached before the kernel has the
         * leased address (slow apply, bounced link); without it the bind
         * fails with EADDRNOTAVAIL and the renewal never happens. */
        r = client_setsockopt_int(fd, IPPROTO_IP, IP_FREEBIND, 1);
        if (r < 0)
                return r;

        sa = (struct sockaddr_in){
                .sin_family = AF_INET,
                .sin_port = htobe16(client->port),
                .sin_addr.s_addr = client->lease->address,
        };

        if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
                return -errno;

        return TAKE_FD(fd);
}

void dhcp_client_disable_io(DhcpClient *client) {
        assert(client);

        /* netd-loop.h: deregister first, then close. An epoll entry that
         * outlives its fd number can be re-armed by the next open(). */
        (void) netd_loop_remove_io(client->netd, &client->io_tag);

        if (client->fd >= 0) {
                (void) close(client->fd);
                client->fd = -1;
        }

        client->fd_domain = AF_UNSPEC;
}

/* Upstream asks the kernel (getsockopt(SO_DOMAIN)) which kind of socket is
 * registered; here the fd is always our own, so client->fd_domain records it.
 * Returns the reusable fd, or -EBADF when a new socket is needed. */
static int client_get_socket(DhcpClient *client, int domain) {
        assert(client);
        assert(IN_SET(domain, AF_PACKET, AF_INET));

        if (client->fd >= 0 && client->io_tag.registered && client->fd_domain == domain)
                return client->fd;

        return -EBADF;
}

static int client_setup_io(DhcpClient *client, int fd, int domain) {
        int r;

        assert(client);
        assert(fd >= 0);

        /* Replaces whatever was registered, closing it. This is also the path
         * that retires a stale AF_PACKET socket after a new xid: the BPF
         * filter is compiled with the xid baked in. */
        dhcp_client_disable_io(client);

        r = netd_loop_add_io(
                        client->netd,
                        &client->io_tag,
                        fd,
                        EPOLLIN,
                        NETD_EPOLL_DHCP_CLIENT,
                        dhcp_client_io_callback,
                        client);
        if (r < 0)
                return r;

        client->fd = fd;
        client->fd_domain = domain;
        return 0;
}

/* --- transmission --- */

static int client_transmit_raw(DhcpClient *client, DhcpMessage *message, int fd) {
        _cleanup_free_ void *payload = NULL;
        _cleanup_free_ uint8_t *packet = NULL;
        struct iovec built = { .iov_base = NULL, .iov_len = 0 };
        struct sockaddr_ll sa;
        struct iphdr ip;
        struct udphdr udp;
        struct iovec iov;
        struct msghdr mh;
        size_t len;
        uint16_t sum;
        int r;

        assert(client);
        assert(message);
        assert(fd >= 0);

        r = dhcp_message_build(message, &built);
        if (r < 0)
                return r;

        payload = built.iov_base;

        /* iphdr.tot_len is 16 bits, so the whole packet has to fit. */
        if (built.iov_len > UINT16_MAX - sizeof(struct iphdr) - sizeof(struct udphdr))
                return -E2BIG;

        len = sizeof(struct iphdr) + sizeof(struct udphdr) + built.iov_len;

        packet = new (uint8_t, len);
        if (!packet)
                return -ENOMEM;

        ip = (struct iphdr){
                .version = IPVERSION,
                .ihl = sizeof(struct iphdr) / 4,
                .tos = client->ip_service_type,
                .tot_len = htobe16((uint16_t) len),
                .ttl = IPDEFTTL,
                .protocol = IPPROTO_UDP,
                .saddr = INADDR_ANY,
                .daddr = INADDR_BROADCAST,
        };
        ip.check = (uint16_t) htobe16(checksum_finish(checksum_add(0, &ip, sizeof(ip))));

        udp = (struct udphdr){
                .source = htobe16(client->port),
                .dest = htobe16(client->server_port),
                .len = htobe16((uint16_t) (sizeof(struct udphdr) + built.iov_len)),
        };

        sum = udp_checksum(ip.saddr, ip.daddr, &udp, built.iov_base, built.iov_len);

        /* RFC 768: a computed zero is transmitted as all ones; an all-zero
         * field means "no checksum". Upstream stores the computed value
         * unconditionally. */
        udp.check = (uint16_t) htobe16(sum != 0 ? sum : 0xffffU);

        memcpy(packet, &ip, sizeof(ip));
        memcpy(packet + sizeof(ip), &udp, sizeof(udp));
        memcpy(packet + sizeof(ip) + sizeof(udp), built.iov_base, built.iov_len);

        sa = (struct sockaddr_ll){
                .sll_family = AF_PACKET,
                .sll_protocol = htobe16(ETH_P_IP),
                .sll_ifindex = client->ifindex,
                .sll_halen = (unsigned char) client->bcast_addr.length,
        };

        /* sll_addr is 8 bytes and netd is Ethernet-only (6), so the full
         * struct length is always valid here -- upstream trims it because it
         * also supports Infiniband's 20-byte addresses. */
        assert(client->bcast_addr.length <= sizeof(sa.sll_addr));
        memcpy(sa.sll_addr, client->bcast_addr.bytes, client->bcast_addr.length);

        iov = (struct iovec){ .iov_base = packet, .iov_len = len };
        mh = (struct msghdr){
                .msg_name = &sa,
                .msg_namelen = sizeof(sa),
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };

        if (sendmsg(fd, &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        return 0;
}

static int client_transmit_udp(DhcpClient *client, DhcpMessage *message, int fd) {
        _cleanup_free_ void *payload = NULL;
        struct iovec built = { .iov_base = NULL, .iov_len = 0 };
        struct sockaddr_in sa;
        int r;

        assert(client);
        assert(message);
        assert(client->lease);
        assert(fd >= 0);

        r = dhcp_message_build(message, &built);
        if (r < 0)
                return r;

        payload = built.iov_base;

        sa = (struct sockaddr_in){
                .sin_family = AF_INET,
                .sin_port = htobe16(client->server_port),
                .sin_addr.s_addr = client->lease->server_address,
        };

        /* Upstream uses sendmsg() with an IP_PKTINFO control message so a
         * caller can pin the source address; the client only ever passes
         * INADDR_ANY there, which takes the same branch as this. The socket
         * is already bound to the leased address, so the source is right. */
        if (sendto(fd, built.iov_base, built.iov_len, MSG_NOSIGNAL, (struct sockaddr *) &sa, sizeof(sa)) < 0)
                return -errno;

        return 0;
}

static int client_send_raw(DhcpClient *client, DhcpMessage *message, bool expect_reply) {
        _cleanup_close_ int fd_close = -1;
        int r, fd;

        assert(client);
        assert(message);

        fd = client_get_socket(client, AF_PACKET);
        if (fd < 0) {
                fd_close = client_open_raw_socket(client);
                if (fd_close < 0)
                        return fd_close;

                fd = fd_close;
        }

        r = client_transmit_raw(client, message, fd);
        if (r < 0)
                return r;

        if (!expect_reply) {
                /* DHCPDECLINE and DHCPRELEASE are terminal: stop listening
                 * rather than leave a socket armed for a reply that is not
                 * coming. */
                dhcp_client_disable_io(client);
                return 0;
        }

        if (fd_close < 0)
                return 0; /* the already-registered socket was reused */

        r = client_setup_io(client, fd, AF_PACKET);
        if (r < 0)
                return r;

        TAKE_FD(fd_close);
        return 0;
}

static int client_send_udp(DhcpClient *client, DhcpMessage *message, bool expect_reply) {
        _cleanup_close_ int fd_close = -1;
        int r, fd;

        assert(client);
        assert(message);

        /* Without a leased address there is nothing to send from and nowhere
         * to send to: the UDP path is unicast to the server that issued the
         * lease. */
        if (!client->lease || client->lease->address == 0)
                return -EADDRNOTAVAIL;

        fd = client_get_socket(client, AF_INET);
        if (fd < 0) {
                fd_close = client_open_udp_socket(client);
                if (fd_close < 0)
                        return fd_close;

                fd = fd_close;
        }

        r = client_transmit_udp(client, message, fd);
        if (r < 0)
                return r;

        if (!expect_reply) {
                dhcp_client_disable_io(client);
                return 0;
        }

        if (fd_close < 0)
                return 0;

        r = client_setup_io(client, fd, AF_INET);
        if (r < 0)
                return r;

        TAKE_FD(fd_close);
        return 0;
}

/* --- message construction --- */

static int client_new_message(DhcpClient *client, uint8_t type, DhcpMessage **ret) {
        _cleanup_(dhcp_message_unrefp) DhcpMessage *message = NULL;
        usec_t now_usec, elapsed;
        be32_t addr = INADDR_ANY;
        uint32_t max_size;
        int r;

        assert(client);
        assert(IN_SET(type, DHCP_DISCOVER, DHCP_REQUEST, DHCP_RELEASE, DHCP_DECLINE));
        assert(ret);

        r = dhcp_message_new(&message);
        if (r < 0)
                return r;

        r = dhcp_message_init_header(message, BOOTREQUEST, client->xid, client->arp_type, &client->hw_addr);
        if (r < 0)
                return r;

        /*
         * RFC 2131 §2, 'secs': "Filled in by client, seconds elapsed since
         * client began address acquisition or renewal process." It is a
         * SHOULD in the RFC, but some servers refuse to hand out a lease when
         * it is zero, so the elapsed time is floored at one second rather
         * than reported honestly as zero. client->start_time is re-based at
         * the start of every acquisition *and* every renewal, which is where
         * netd differs from upstream -- see dhcp-client.c's
         * client_timeout_t1().
         */
        now_usec = now_monotonic();
        elapsed = usec_sub_unsigned(now_usec, client->start_time);
        message->header.secs = usec_to_be16_sec(elapsed != 0 ? elapsed : USEC_PER_SEC);

        /*
         * RFC 2131 4.1: "A client that cannot receive unicast IP datagrams
         * until its protocol software has been configured with an IP address
         * SHOULD set the BROADCAST bit". That is exactly our situation before
         * a lease exists. It is a hint, not a guarantee, and some networks
         * filter broadcasts, which is why it is also settable.
         *
         * The arp_type test carries upstream's reasoning for non-Ethernet
         * links, where a unicast reply cannot be received at all.
         */
        dhcp_message_set_broadcast_flag(message, client->request_broadcast || client->arp_type != ARPHRD_ETHER);

        /* Plain BOOTP stops here: no magic-cookie options at all. */
        if (client->bootp) {
                *ret = TAKE_PTR(message);
                return 0;
        }

        /* Message Type (53): mandatory. */
        r = dhcp_message_append_option_u8(message, SD_DHCP_OPTION_MESSAGE_TYPE, type);
        if (r < 0)
                return r;

        /*
         * Server Identifier (54). RFC 2131 Table 5: mandatory in a
         * DHCPREQUEST sent from REQUESTING (it is what selects one server out
         * of several that offered), and in DHCPDECLINE and DHCPRELEASE. It
         * MUST NOT be sent in a renewing/rebinding REQUEST, because those are
         * not selecting anything.
         */
        if ((type == DHCP_REQUEST && client->state == DHCP_STATE_REQUESTING) ||
            IN_SET(type, DHCP_RELEASE, DHCP_DECLINE)) {
                if (!client->lease)
                        return -EADDRNOTAVAIL;

                r = dhcp_message_append_option_be32(
                                message, SD_DHCP_OPTION_SERVER_IDENTIFIER, client->lease->server_address);
                if (r < 0)
                        return r;
        }

        /* Client Identifier (61). Not mandatory, but servers exist that drop
         * messages without one, so it is always sent. */
        r = dhcp_message_append_option_client_id(message, &client->client_id);
        if (r < 0)
                return r;

        /*
         * Requested IP Address (50) versus ciaddr. RFC 2131 4.3.2's table is
         * the whole of this switch, and getting it wrong is the classic way
         * to have a server ignore a renewal: a REQUEST in RENEWING or
         * REBINDING must carry the address in ciaddr and MUST NOT carry
         * option 50, while one in REQUESTING or REBOOTING must do the exact
         * opposite. (The RFC's own text has a well-known typo here, saying
         * SELECTING where it means REQUESTING.)
         */
        switch (type) {
        case DHCP_DISCOVER:
                /* RFC 2131 3.1: the client "may include the 'requested IP
                 * address' option to suggest that a particular IP address be
                 * assigned" -- the remembered address, when there is one. */
                addr = client->last_addr;
                break;

        case DHCP_REQUEST:
                switch (client->state) {

                case DHCP_STATE_REQUESTING:
                        /* ciaddr MUST be zero; option 50 MUST be the yiaddr
                         * from the chosen OFFER. */
                        if (!client->lease)
                                return -EADDRNOTAVAIL;
                        addr = client->lease->address;
                        break;

                case DHCP_STATE_REBOOTING:
                        /* Option 50 MUST be the client's notion of its
                         * previously assigned address; ciaddr MUST be zero. */
                        addr = client->last_addr;
                        break;

                case DHCP_STATE_RENEWING:
                case DHCP_STATE_REBINDING:
                        /* Option 50 MUST NOT be present; ciaddr MUST be the
                         * client's current address. */
                        if (!client->lease)
                                return -EADDRNOTAVAIL;
                        message->header.ciaddr = client->lease->address;
                        break;

                default:
                        /* Internal invariant: dhcp_client_send_message() is
                         * only ever reached for DHCP_REQUEST from one of the
                         * four states above. */
                        assert(false);
                        return -EINVAL;
                }
                break;

        case DHCP_RELEASE:
                /* RFC 2131 4.4.6: the released address goes in ciaddr. */
                if (!client->lease)
                        return -EADDRNOTAVAIL;
                message->header.ciaddr = client->lease->address;
                break;

        case DHCP_DECLINE:
                /* RFC 2131 4.4.4: the refused address goes in option 50. */
                if (!client->lease)
                        return -EADDRNOTAVAIL;
                addr = client->lease->address;
                break;

        default:
                assert(false);
                return -EINVAL;
        }

        if (addr != INADDR_ANY) {
                r = dhcp_message_append_option_be32(message, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, addr);
                if (r < 0)
                        return r;
        }

        /* RFC 2131 4.4.4/4.4.6: DHCPDECLINE and DHCPRELEASE MUST NOT contain
         * any other options. */
        if (IN_SET(type, DHCP_RELEASE, DHCP_DECLINE)) {
                *ret = TAKE_PTR(message);
                return 0;
        }

        /*
         * Parameter Request List (55). RFC 2131 3.5: "If the client includes
         * a list of parameters in a DHCPDISCOVER message, it MUST include
         * that list in any subsequent DHCPREQUEST messages" -- which is why
         * this is unconditional rather than DISCOVER-only.
         *
         * netd's list is the same set every time and is emitted in ascending
         * option order by the NetdU8Set bitmap, so the bytes are
         * reproducible; upstream's Set* emitted hash order.
         */
        r = dhcp_message_append_option_parameter_request_list(message, &client->req_opts);
        if (r < 0)
                return r;

        /*
         * Maximum Message Size (57). RFC 2131 3.5 makes it a SHOULD, and
         * RFC 3442 sharpens it: a client that understands Classless Static
         * Routes SHOULD send this, set to at least the interface MTU, because
         * a routing table does not fit in the 576-octet default.
         */
        max_size = client->mtu;
        if (max_size < IPV4_MIN_REASSEMBLY_SIZE)
                max_size = IPV4_MIN_REASSEMBLY_SIZE;
        if (max_size > UINT16_MAX)
                max_size = UINT16_MAX;

        r = dhcp_message_append_option_u16(message, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, (uint16_t) max_size);
        if (r < 0)
                return r;

        /* Host Name (12). RFC 2131 does not say whether a client should send
         * this in a DISCOVER; dhclient does, so upstream does, so netd does.
         * NULL is a no-op, which is netd's normal case -- nothing in the
         * `.network` subset sets a hostname. */
        r = dhcp_message_append_option_hostname(message, client->hostname);
        if (r < 0)
                return r;

        /* Vendor Class Identifier (60). Also NULL by default. */
        r = dhcp_message_append_option_string(
                        message, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, client->vendor_class_identifier);
        if (r < 0)
                return r;

        /* Rapid Commit (80), RFC 4039: only ever in a DISCOVER, and only when
         * the caller asked for it. The matching check on the way back in
         * (an ACK straight from SELECTING is refused unless the server echoed
         * this option) is in dhcp-client.c's client_parse_ack(). */
        if (client->rapid_commit && type == DHCP_DISCOVER) {
                r = dhcp_message_append_option_flag(message, SD_DHCP_OPTION_RAPID_COMMIT);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(message);
        return 0;
}

int dhcp_client_send_message(DhcpClient *client, uint8_t type) {
        _cleanup_(dhcp_message_unrefp) DhcpMessage *message = NULL;
        int r;

        assert(client);

        r = client_new_message(client, type, &message);
        if (r < 0)
                return r;

        switch (type) {
        case DHCP_DISCOVER:
                /* No address yet, so nothing but the raw path can work. */
                r = client_send_raw(client, message, /* expect_reply= */ true);
                break;

        case DHCP_REQUEST:
                /*
                 * RFC 2131 4.4.5, and the one place the transport is chosen
                 * by state rather than by message type: RENEWING sends
                 * "directly to the server", i.e. unicast UDP from the leased
                 * address, while REBINDING broadcasts "to the 0xffffffff IP
                 * broadcast address" because the original server is presumed
                 * gone. REQUESTING and REBOOTING broadcast too -- the address
                 * is not configured yet in either.
                 */
                if (client->state == DHCP_STATE_RENEWING)
                        r = client_send_udp(client, message, /* expect_reply= */ true);
                else
                        r = client_send_raw(client, message, /* expect_reply= */ true);
                break;

        case DHCP_RELEASE:
                /* RFC 2131 4.4.6: unicast to the server, and no reply is
                 * defined. */
                r = client_send_udp(client, message, /* expect_reply= */ false);
                break;

        case DHCP_DECLINE:
                /* RFC 2131 4.4.4: broadcast, because the address we were
                 * given is unusable, so there is no source to unicast from. */
                r = client_send_raw(client, message, /* expect_reply= */ false);
                break;

        default:
                r = -EINVAL;
        }
        if (r < 0)
                return r;

        if (client->bootp)
                log_client_debug(client, "sent BOOTREQUEST");
        else if (type == DHCP_REQUEST)
                log_client_debug(
                                client,
                                "sent %s (%s)",
                                dhcp_message_type_to_string(type),
                                dhcp_state_to_string(client->state));
        else
                log_client_debug(client, "sent %s", dhcp_message_type_to_string(type));

        return 0;
}

/* --- reception --- */

static int client_receive_message(DhcpClient *client) {
        _cleanup_free_ void *buf = NULL;
        struct iovec payload;
        struct iovec iov;
        struct msghdr msg;
        struct cmsghdr *cmsg;
        union {
                struct cmsghdr align;
                uint8_t space[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
        } control;
        bool checksum = true;
        bool raw;
        ssize_t buflen, len;
        int r;

        assert(client);

        if (client->fd < 0)
                return 0;

        raw = client->fd_domain == AF_PACKET;

        /* MSG_PEEK|MSG_TRUNC on a datagram socket reports the real size
         * without consuming the datagram, so the buffer is exactly right and
         * a large reply is never silently truncated. */
        buflen = recv(client->fd, NULL, 0, MSG_PEEK | MSG_TRUNC);
        if (buflen < 0) {
                if (ERRNO_IS_NEG_TRANSIENT(-errno) || ERRNO_IS_NEG_DISCONNECT(-errno))
                        return 0;

                log_client_debug(client, "could not size the datagram (%s), ignoring", strerror(errno));
                return 0;
        }

        /* A zero-length datagram still has to be consumed, or epoll reports
         * the fd ready forever. */
        buf = malloc(buflen > 0 ? (size_t) buflen : 1);
        if (!buf)
                return -ENOMEM;

        memset(&control, 0, sizeof(control));

        iov = (struct iovec){ .iov_base = buf, .iov_len = (size_t) buflen };
        msg = (struct msghdr){
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        len = recvmsg(client->fd, &msg, MSG_DONTWAIT);
        if (len < 0) {
                if (ERRNO_IS_NEG_TRANSIENT(-errno) || ERRNO_IS_NEG_DISCONNECT(-errno))
                        return 0;

                log_client_debug(
                                client,
                                "could not receive from the %s socket (%s), ignoring",
                                raw ? "raw" : "UDP",
                                strerror(errno));
                return 0;
        }

        payload = (struct iovec){ .iov_base = buf, .iov_len = (size_t) len };

        if (raw) {
                for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
                        if (cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_AUXDATA &&
                            cmsg->cmsg_len == CMSG_LEN(sizeof(struct tpacket_auxdata))) {
                                struct tpacket_auxdata aux;

                                memcpy(&aux, CMSG_DATA(cmsg), sizeof(aux));
                                checksum = !(aux.tp_status & TP_STATUS_CSUMNOTREADY);
                                break;
                        }

                if (client_verify_udp_packet(client, &payload, checksum, &payload) < 0)
                        return 0; /* malformed: ignored, never fatal */
        }

        log_client_debug(client, "received a message on the %s socket", raw ? "raw" : "UDP");

        r = dhcp_client_handle_message(client, &payload);
        if (r < 0)
                dhcp_client_fail(client, r);

        return 0;
}

int dhcp_client_io_callback(Netd *netd, struct netd_epoll_tag *tag, uint32_t revents) {
        DhcpClient *client;

        assert(tag);
        assert(tag->userdata);

        (void) netd;
        (void) revents;

        client = tag->userdata;

        /*
         * A hold on the client for the duration of the dispatch, for the same
         * reason the nine upstream functions take one: everything below can
         * reach the link layer's callback, and the link layer may stop or
         * drop this client from inside it.
         */
        DHCP_CLIENT_DONT_DESTROY(client);

        return client_receive_message(client);
}
