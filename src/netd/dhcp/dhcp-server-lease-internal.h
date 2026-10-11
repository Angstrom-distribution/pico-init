/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2
 * src/libsystemd-network/dhcp-server-lease-internal.h, redesigned around
 * dhcp-server-internal.h's flat lease array instead of upstream's four
 * Hashmaps:
 *
 *  - No lease refcounting: a slot is owned by the array and "removing" a
 *    lease is dhcp_server_lease_clear() zeroing it in place.
 *  - No hash_ops and no by-address Hashmap: address lookup is direct array
 *    indexing, client-id lookup is a linear scan over pool_size slots (a
 *    usb-gadget pool is typically size 1).
 *  - No static leases (dhcp_server_get_static_lease(), the is_static
 *    parameter of dhcp_server_put_lease()).
 *  - No JSON append/save/load: leases live in memory only.
 */

#pragma once

/* Self-sufficient: needs bool/usec_t/macros from netd-compat.h. */
#include "netd-compat.h"

#include "dhcp-server-internal.h"

struct DhcpServerLease {
        bool in_use;

        DhcpClientId client_id;
        uint8_t htype; /* e.g. ARPHRD_ETHER */
        struct hw_addr_data hw_addr;

        usec_t expiration; /* CLOCK_MONOTONIC, matching dhcp-lease-internal.h's own client-side choice */

        char *hostname; /* owned; NULL if the client sent none */
};

/* Zero a slot back to its unused state, freeing its hostname. Does not
 * touch DhcpServer.leases itself -- the caller indexes into the array. */
void dhcp_server_lease_clear(DhcpServerLease *lease);

/* Record/update the lease for req->client_id at req->address, from a
 * DHCPREQUEST about to be ACKed. 0 or -errno. */
int dhcp_server_set_lease(DhcpServer *server, DHCPRequest *req);

/* Zero every slot whose expiration is in the past. Never fails: an
 * unreachable clock is a programming error (assert), not a runtime
 * condition -- now_monotonic() cannot fail on a system with a working
 * CLOCK_MONOTONIC, which every target this project boots on has. */
void dhcp_server_cleanup_expired_leases(DhcpServer *server);

/* NULL if no lease is bound to this client-id. */
DhcpServerLease *dhcp_server_get_lease_by_client_id(DhcpServer *server, const DhcpClientId *client_id);

/* NULL if `address` is out of the pool or its slot is unused. */
DhcpServerLease *dhcp_server_get_lease_by_address(DhcpServer *server, be32_t address);
