/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/dhcp-server-send.c:
 * building and transmitting OFFER/ACK/NAK.
 *
 * Deviation: upstream's dhcp_server_send_message() has a fourth transport,
 * dhcp_server_send_unicast_raw(), an AF_PACKET send with a hand-built
 * Ethernet frame used when giaddr == 0, ciaddr == 0, the client's broadcast
 * flag is unset and its hardware address is known (unicast by MAC to a host
 * that has no IP yet). That would need a second raw-socket framer next to the
 * client's, so dhcp_server_send_message() below always broadcasts when
 * ciaddr == 0. This is RFC 2131 §4.1-legal (a server MAY always broadcast
 * DHCPOFFER/DHCPACK) and clients listen on the UDP broadcast address anyway;
 * the cost is a broadcast where a unicast would have done.
 *
 * The NAK broadcast and ciaddr-unicast transports are kept. The giaddr relay
 * transport is not carried, since giaddr must be INADDR_ANY (see
 * dhcp-server-request.c).
 */

#include "dhcp-server-lease-internal.h"

#include <netinet/in.h>
#include <sys/socket.h>

#include "../util.h"

static int dhcp_server_send_udp(DhcpServer *server, be32_t address, uint16_t port, DhcpMessage *message) {
        struct iovec iov;
        ssize_t n;
        int r;

        assert(server);
        assert(message);

        r = dhcp_message_build(message, &iov);
        if (r < 0)
                return r;

        struct sockaddr_in sa = {
                .sin_family = AF_INET,
                .sin_port = htobe16(port),
                .sin_addr.s_addr = address,
        };

        n = sendto(server->socket_fd, iov.iov_base, iov.iov_len, 0, (struct sockaddr *) &sa, sizeof(sa));
        r = n < 0 ? -errno : 0;
        free(iov.iov_base);
        return r;
}

static int dhcp_server_send_message(DhcpServer *server, uint8_t type, DhcpMessage *message) {
        assert(server);
        assert(message);

        /* RFC 2131 §4.1: the server always broadcasts a DHCPNAK, regardless
         * of ciaddr (a NAK typically means the client's idea of its own
         * address is wrong, so ciaddr cannot be trusted as a destination). */
        if (type == DHCP_NAK)
                return dhcp_server_send_udp(server, htobe32(INADDR_BROADCAST), DHCP_PORT_CLIENT, message);

        /* ciaddr set (RENEWING/REBINDING/INIT-REBOOT already had an address
         * and can receive routed unicast): reply there directly. */
        if (message->header.ciaddr != htobe32(INADDR_ANY))
                return dhcp_server_send_udp(server, message->header.ciaddr, DHCP_PORT_CLIENT, message);

        /* No routable address yet: broadcast. See this file's header for
         * why there is no raw-unicast fallback here. */
        return dhcp_server_send_udp(server, htobe32(INADDR_BROADCAST), DHCP_PORT_CLIENT, message);
}

static int dhcp_server_new_reply(DhcpServer *server, DHCPRequest *req, uint8_t type, DhcpMessage **ret) {
        _cleanup_(dhcp_message_unrefp) DhcpMessage *message = NULL;
        int r;

        assert(server);
        assert(req);
        assert(IN_SET(type, DHCP_OFFER, DHCP_ACK, DHCP_NAK));
        assert(ret);

        r = dhcp_message_new(&message);
        if (r < 0)
                return r;

        r = dhcp_message_init_header(
                        message,
                        BOOTREPLY,
                        be32toh(req->message->header.xid),
                        req->message->header.htype,
                        &req->hw_addr);
        if (r < 0)
                return r;

        /* giaddr is always INADDR_ANY (no relay, dhcp-server-request.c's
         * header) -- upstream's own "set broadcast if giaddr was set"
         * clause therefore never fires and is dropped, not carried dead. */
        dhcp_message_set_broadcast_flag(
                        message, dhcp_message_has_broadcast_flag(req->message) || type == DHCP_NAK);

        r = dhcp_message_append_option_u8(message, SD_DHCP_OPTION_MESSAGE_TYPE, type);
        if (r < 0)
                return r;

        r = dhcp_message_append_option_be32(message, SD_DHCP_OPTION_SERVER_IDENTIFIER, server->address);
        if (r < 0)
                return r;

        if (type == DHCP_NAK) {
                *ret = TAKE_PTR(message);
                return 0;
        }

        assert(req->address != htobe32(INADDR_ANY));
        message->header.yiaddr = req->address;

        if (type == DHCP_ACK)
                message->header.ciaddr = req->message->header.ciaddr;

        r = dhcp_message_append_option_sec(message, SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME, req->lifetime);
        if (r < 0)
                return r;

        r = dhcp_message_append_option_be32(message, SD_DHCP_OPTION_SUBNET_MASK, server->netmask);
        if (r < 0)
                return r;

        if (server->emit_router) {
                struct in_addr router = in4_addr_is_set(&server->router_address) ?
                                server->router_address :
                                (struct in_addr){ .s_addr = server->address };

                r = dhcp_message_append_option_address(message, SD_DHCP_OPTION_ROUTER, &router);
                if (r < 0)
                        return r;
        }

        /* DhcpLeaseServerType (dhcp-lease-internal.h) only defines
         * DNS/NTP/SIP; POP3/SMTP/LPR are cut. */
        static const uint8_t option_map[_DHCP_LEASE_SERVER_TYPE_MAX] = {
                [DHCP_LEASE_DNS] = SD_DHCP_OPTION_DOMAIN_NAME_SERVER,
                [DHCP_LEASE_NTP] = SD_DHCP_OPTION_NTP_SERVER,
                [DHCP_LEASE_SIP] = SD_DHCP_OPTION_SIP_SERVER,
        };

        for (DhcpLeaseServerType k = 0; k < _DHCP_LEASE_SERVER_TYPE_MAX; k++) {
                if (server->servers[k].size == 0)
                        continue;

                r = dhcp_message_append_option_addresses(
                                message, option_map[k], server->servers[k].size, server->servers[k].addr);
                if (r < 0)
                        return r;
        }

        if (server->timezone) {
                r = dhcp_message_append_option_string(message, SD_DHCP_OPTION_TZDB_TIMEZONE, server->timezone);
                if (r < 0)
                        return r;
        }

        if (server->domain_name) {
                r = dhcp_message_append_option_string(message, SD_DHCP_OPTION_DOMAIN_NAME, server->domain_name);
                if (r < 0)
                        return r;
        }

        if (type == DHCP_ACK && req->type == DHCP_DISCOVER) {
                assert(server->rapid_commit);
                r = dhcp_message_append_option_flag(message, SD_DHCP_OPTION_RAPID_COMMIT);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(message);
        return 0;
}

int dhcp_server_send_reply(DhcpServer *server, DHCPRequest *req, uint8_t type) {
        _cleanup_(dhcp_message_unrefp) DhcpMessage *message = NULL;
        int r;

        assert(server);
        assert(req);
        assert(IN_SET(type, DHCP_OFFER, DHCP_ACK, DHCP_NAK));

        r = dhcp_server_new_reply(server, req, type, &message);
        if (r < 0)
                return r;

        if (dhcp_message_payload_size(message) > req->max_message_size)
                return -E2BIG;

        r = dhcp_server_send_message(server, type, message);
        if (r < 0)
                return r;

        pico_log(PICO_LOG_DEBUG,
                 "netd: dhcp-server: %s (0x%x)",
                 dhcp_message_type_to_string(type),
                 be32toh(message->header.xid));
        return type; /* the sent message type, to make testing easier -- matches upstream */
}
