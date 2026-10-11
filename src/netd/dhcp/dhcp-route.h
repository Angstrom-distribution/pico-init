/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/dhcp-route.h: the entry
 * type for the static-route options (33, 121 and the private variant 249).
 * The RFC 3442 compact destination-descriptor encode/decode logic lives in
 * dhcp-message.c, as upstream.
 */

#pragma once

/* Self-sufficient: needs bool/usec_t/macros from netd-compat.h. */
#include "netd-compat.h"


#include <netinet/in.h>
#include <stdint.h>

typedef struct DhcpRoute {
        struct in_addr dst_addr;
        struct in_addr gw_addr;
        uint8_t dst_prefixlen;
} DhcpRoute;

int dhcp_route_get_destination(const DhcpRoute *route, struct in_addr *ret);
int dhcp_route_get_destination_prefix_length(const DhcpRoute *route, uint8_t *ret);
int dhcp_route_get_gateway(const DhcpRoute *route, struct in_addr *ret);
