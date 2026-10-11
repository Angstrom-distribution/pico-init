/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/dhcp-message.{c,h}: the
 * DHCPv4 wire codec API. It has no sd_event dependency upstream and is a
 * near-verbatim port.
 *
 * Cut: FQDN (81), DNR (162), Domain Search (119), the sd-json block, and
 *  - 6RD (option 212, RFC 5969): needs struct in6_addr masking, and netd has
 *    no IPv6 support;
 *  - Relay Agent Information (option 82) sub-TLV get/append and the generic
 *    length-prefixed-data helpers: relay is not supported;
 *  - dhcp_message_send_udp()/dhcp_message_send_raw(): raw-socket I/O belongs
 *    to the socket layer (dhcp-client-send.c). dhcp_message_build() is the
 *    boundary: it returns the BOOTP-padded header+options wire bytes.
 *
 * Everything else keeps upstream's name and shape, except that
 * dhcp_message_get_option_parameter_request_list() takes/returns a
 * NetdU8Set* (netd-compat.h) instead of a Set*.
 */

#pragma once

/* Self-sufficient: needs bool/usec_t/macros from netd-compat.h. */
#include "netd-compat.h"

#include "dhcp-protocol.h"
#include "dhcp-route.h"
#include "tlv-util.h"

/* Forward declaration; the definition is in dhcp-client-id-internal.h. */
typedef struct DhcpClientId DhcpClientId;

typedef struct DhcpMessage {
        unsigned n_ref;

        DHCPMessageHeader header;
        DhcpTlv options;
} DhcpMessage;

DhcpMessage *dhcp_message_ref(DhcpMessage *p);
DhcpMessage *dhcp_message_unref(DhcpMessage *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(DhcpMessage *, dhcp_message_unref);

int dhcp_message_new(DhcpMessage **ret);

int dhcp_message_init_header(
                DhcpMessage *message,
                uint8_t op,
                uint32_t xid,
                uint16_t arp_type,
                const struct hw_addr_data *hw_addr);

void dhcp_message_set_broadcast_flag(DhcpMessage *message, bool b);
bool dhcp_message_has_broadcast_flag(DhcpMessage *message);
int dhcp_message_get_hw_addr(DhcpMessage *message, struct hw_addr_data *ret);

bool dhcp_message_has_option(DhcpMessage *message, uint8_t code);
void dhcp_message_remove_option(DhcpMessage *message, uint8_t code);

int dhcp_message_append_option(DhcpMessage *message, uint8_t code, size_t length, const void *data);
int dhcp_message_append_option_flag(DhcpMessage *message, uint8_t code);
int dhcp_message_append_option_u8(DhcpMessage *message, uint8_t code, uint8_t data);
int dhcp_message_append_option_u16(DhcpMessage *message, uint8_t code, uint16_t data);
int dhcp_message_append_option_be32(DhcpMessage *message, uint8_t code, be32_t data);
int dhcp_message_append_option_sec(DhcpMessage *message, uint8_t code, usec_t usec);
int dhcp_message_append_option_address(DhcpMessage *message, uint8_t code, const struct in_addr *addr);
int dhcp_message_append_option_addresses(
                DhcpMessage *message, uint8_t code, size_t n_addr, const struct in_addr *addr);
int dhcp_message_append_option_string(DhcpMessage *message, uint8_t code, const char *data);
int dhcp_message_append_option_routes(
                DhcpMessage *message, uint8_t code, size_t n_routes, const DhcpRoute *routes);
int dhcp_message_append_option_client_id(DhcpMessage *message, const DhcpClientId *id);
int dhcp_message_append_option_parameter_request_list(DhcpMessage *message, const NetdU8Set *prl);
/* Option 12 (Host Name) only: FQDN/81 is cut, so a multi-label name (which
 * upstream would encode as FQDN) is rejected with -EOPNOTSUPP. */
int dhcp_message_append_option_hostname(DhcpMessage *message, const char *hostname);

int dhcp_message_get_option(DhcpMessage *message, uint8_t code, size_t length, void *ret);
int dhcp_message_get_option_alloc(DhcpMessage *message, uint8_t code, struct iovec *ret);
int dhcp_message_get_option_flag(DhcpMessage *message, uint8_t code);
int dhcp_message_get_option_u8(DhcpMessage *message, uint8_t code, uint8_t *ret);
int dhcp_message_get_option_u16(DhcpMessage *message, uint8_t code, uint16_t *ret);
int dhcp_message_get_option_be32(DhcpMessage *message, uint8_t code, be32_t *ret);
int dhcp_message_get_option_sec(DhcpMessage *message, uint8_t code, bool max_as_infinity, usec_t *ret);
int dhcp_message_get_option_address(DhcpMessage *message, uint8_t code, struct in_addr *ret);
int dhcp_message_get_option_addresses(
                DhcpMessage *message, uint8_t code, size_t *ret_n_addr, struct in_addr **ret_addr);
int dhcp_message_get_option_string(DhcpMessage *message, uint8_t code, char **ret);
int dhcp_message_get_option_routes(
                DhcpMessage *message, uint8_t code, size_t *ret_n_routes, DhcpRoute **ret_routes);
int dhcp_message_get_option_client_id(DhcpMessage *message, DhcpClientId *ret);
int dhcp_message_get_option_parameter_request_list(DhcpMessage *message, NetdU8Set *ret);
/* Mainly for Host Name (12) or Domain Name (15): validates + normalizes
 * through dns-name.h. */
int dhcp_message_get_option_dns_name(DhcpMessage *message, uint8_t code, char **ret);
int dhcp_message_get_option_hostname(DhcpMessage *message, char **ret);

int dhcp_message_parse(
                const struct iovec *iov,
                uint8_t op,
                const uint32_t *xid,
                uint16_t arp_type,
                const struct hw_addr_data *hw_addr,
                DhcpMessage **ret);

size_t dhcp_message_payload_size(DhcpMessage *message);

/* Builds the header+options wire form (BOOTP_MESSAGE_SIZE-padded). The
 * returned iovec's iov_base is malloc'd; the caller frees it. */
int dhcp_message_build(DhcpMessage *message, struct iovec *ret);
