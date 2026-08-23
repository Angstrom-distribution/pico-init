/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from src/libsystemd-network/dhcp-route.h (12 lines, not the 35
 * this file's own placeholder guessed -- verified against the real v261.2
 * tree). The classless-static-route option (121, also 33 and the private
 * variant 249) entry type. The RFC 3442 compact destination-descriptor
 * encode/decode logic itself lives in dhcp-message.c, exactly as it does
 * upstream (dhcp-route.c/.h only carry the type and three trivial getters).
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. History review
 * (4925d9f07f..main, plan §2.2): no fix in the 26-commit lift-set window
 * touches this file.
 */

#pragma once

/* Self-sufficient regardless of what a consumer includes first (a real
 * cross-agent bug: netd-resolv.c included dhcp-lease-internal.h without
 * netd-compat.h first, and this header needs its bool/usec_t/macros) --
 * safe to include redundantly, netd-compat.h has its own #pragma once. */
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
