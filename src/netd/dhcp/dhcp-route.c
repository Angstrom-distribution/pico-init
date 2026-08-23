/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported near-verbatim from src/libsystemd-network/dhcp-route.c (29 lines,
 * not the 153 this file's own placeholder guessed -- the RFC 3442 compact
 * encode/decode logic it described actually lives in dhcp-message.c, as it
 * does upstream; verified against the real v261.2 tree).
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. History review
 * (4925d9f07f..main, plan §2.2): no fix in the 26-commit lift-set window
 * touches this file.
 */

#include "netd-compat.h"

#include "dhcp-route.h"

int dhcp_route_get_destination(const DhcpRoute *route, struct in_addr *ret) {
        assert_return(route, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = route->dst_addr;
        return 0;
}

int dhcp_route_get_destination_prefix_length(const DhcpRoute *route, uint8_t *ret) {
        assert_return(route, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = route->dst_prefixlen;
        return 0;
}

int dhcp_route_get_gateway(const DhcpRoute *route, struct in_addr *ret) {
        assert_return(route, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = route->gw_addr;
        return 0;
}
