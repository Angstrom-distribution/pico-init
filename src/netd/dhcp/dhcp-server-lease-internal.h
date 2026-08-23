/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from src/libsystemd-network/dhcp-server-lease-internal.h (44
 * lines). No real copyright line upstream (rests on the project default,
 * plan §2.11).
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. History review
 * (4925d9f07f..main, plan §2.2): no fix in the 26-commit lift-set window
 * touches this file.
 *
 * Redesigned around dhcp-server-internal.h's flat lease array rather than
 * upstream's four Hashmaps -- see that file's header for the full
 * rationale. The consequences for this header specifically:
 *
 *  - No sd_dhcp_server_lease refcounting. Upstream's lease objects are
 *    individually heap-allocated and shared through four different
 *    Hashmaps, so DEFINE_TRIVIAL_REF_UNREF_FUNC earns its keep there. A
 *    flat-array slot is neither individually allocated nor referenced from
 *    more than one place, so it is a plain struct the array owns outright;
 *    "removing" a lease is dhcp_server_lease_clear() zeroing a slot in
 *    place, not an unref that might or might not free something.
 *  - No hash_ops (client_id_hash_func()/_compare_func(), already cut in
 *    dhcp-client-id-internal.h's own header) and no by-address Hashmap:
 *    address lookup is direct array indexing (O(1)), client-id lookup is a
 *    linear scan over pool_size slots (O(pool_size), acceptable at embedded
 *    pool scale -- a usb-gadget pool is typically size 1).
 *  - No static-lease functions (dhcp_server_get_static_lease(),
 *    dhcp_server_put_lease()'s is_static parameter) -- static leases are
 *    cut entirely, see dhcp-server-internal.h's header for why.
 *  - No JSON append/save/load functions -- persistence is dropped, not
 *    ported (plan §2.1/§2.2's single biggest hidden-depth finding: saving a
 *    lease file upstream pulls in 10,346 LOC of sd-json). Leases live in
 *    memory only.
 */

#pragma once

/* Self-sufficient regardless of what a consumer includes first -- see any
 * lifted header's near-identical note for why. */
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
