/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from src/libsystemd-network/sd-dhcp-server-lease.c (573 lines,
 * ~390 of it lease-table logic -- the rest is the sd-json persistence
 * block cut entirely, see dhcp-server-internal.h's header). No real
 * copyright line upstream.
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. History review
 * (4925d9f07f..main, plan §2.2): no fix in the 26-commit lift-set window
 * touches sd-dhcp-server-lease.c.
 *
 * Rewritten onto the flat lease array (dhcp-server-lease-internal.h's
 * header has the full rationale): dhcp_server_put_lease()'s two
 * hashmap_ensure_put() calls become one array-index write;
 * dhcp_server_set_lease()'s "find existing lease, update in place, or
 * allocate a new hashmap entry" becomes "find or claim a slot"; and
 * dhcp_server_cleanup_expired_leases() drops its sd_event_now()
 * dependency for now_monotonic() (util.h), matching dhcp-lease-internal.h's
 * own monotonic-only choice on the client side.
 */

#include "dhcp-server-lease-internal.h"

#include "../util.h"

static bool client_id_equal(const DhcpClientId *a, const DhcpClientId *b) {
        assert(a);
        assert(b);

        return a->size == b->size && memcmp(a->raw, b->raw, a->size) == 0;
}

void dhcp_server_lease_clear(DhcpServerLease *lease) {
        assert(lease);

        lease->hostname = pico_mfree(lease->hostname);
        *lease = (DhcpServerLease){ 0 };
}

/* -1 if `address` is outside the pool. */
static ssize_t lease_index(DhcpServer *server, be32_t address) {
        uint32_t pool_base, off;

        assert(server);

        if (!server->leases || server->pool_size == 0)
                return -1;

        pool_base = be32toh(server->subnet) | server->pool_offset;
        off = be32toh(address) - pool_base;

        if (off >= server->pool_size)
                return -1;

        return (ssize_t) off;
}

DhcpServerLease *dhcp_server_get_lease_by_address(DhcpServer *server, be32_t address) {
        ssize_t idx;

        assert(server);

        idx = lease_index(server, address);
        if (idx < 0)
                return NULL;

        return server->leases[idx].in_use ? &server->leases[idx] : NULL;
}

DhcpServerLease *dhcp_server_get_lease_by_client_id(DhcpServer *server, const DhcpClientId *client_id) {
        assert(server);
        assert(client_id);

        if (!server->leases)
                return NULL;

        FOREACH_ARRAY(lease, server->leases, server->pool_size)
        if (lease->in_use && client_id_equal(&lease->client_id, client_id))
                return lease;

        return NULL;
}

int dhcp_server_set_lease(DhcpServer *server, DHCPRequest *req) {
        DhcpServerLease *lease;
        ssize_t idx;
        char *hostname = NULL;

        assert(server);
        assert(req);
        assert(req->message);
        assert(req->address != htobe32(INADDR_ANY));

        idx = lease_index(server, req->address);
        /* Internal invariant: every caller (dhcp_server_process_discover()/
         * _request()) only ever sets req->address to something
         * dhcp_server_address_is_in_pool()/_available() already confirmed
         * is in range. A miss here is netd's own bug, not bad packet data. */
        assert(idx >= 0);

        lease = &server->leases[idx];

        /* If this client already holds a different slot (e.g. the server's
         * pool moved under it across a reconfigure), release the old one --
         * a flat array has no by-client-id index to update in place the way
         * upstream's hashmap_ensure_put() does; freeing and re-claiming a
         * slot is the array equivalent. */
        DhcpServerLease *existing = dhcp_server_get_lease_by_client_id(server, &req->client_id);
        if (existing && existing != lease)
                dhcp_server_lease_clear(existing);

        (void) dhcp_message_get_option_hostname(req->message, &hostname);

        pico_mfree(lease->hostname);

        *lease = (DhcpServerLease){
                .in_use = true,
                .client_id = req->client_id,
                .htype = req->message->header.htype,
                .hw_addr = req->hw_addr,
                .expiration = usec_add(now_monotonic(), req->lifetime),
                .hostname = hostname,
        };

        return 0;
}

void dhcp_server_cleanup_expired_leases(DhcpServer *server) {
        usec_t now;

        assert(server);

        if (!server->leases)
                return;

        now = now_monotonic();

        FOREACH_ARRAY(lease, server->leases, server->pool_size) {
                if (!lease->in_use || lease->expiration >= now)
                        continue;

                uint32_t off = (uint32_t) (lease - server->leases);
                struct in_addr a = { .s_addr = htobe32(be32toh(server->subnet) | (server->pool_offset + off)) };
                pico_log(PICO_LOG_DEBUG, "netd: dhcp-server: CLEAN (%s)", IN4_ADDR_TO_STRING(&a));
                dhcp_server_lease_clear(lease);
        }
}
