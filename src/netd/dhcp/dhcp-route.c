/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported near-verbatim from systemd v261.2
 * src/libsystemd-network/dhcp-route.c. The RFC 3442 compact encode/decode
 * logic lives in dhcp-message.c, as upstream.
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
