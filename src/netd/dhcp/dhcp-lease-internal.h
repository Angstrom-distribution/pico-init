/* SPDX-FileCopyrightText: 2013 Intel Corporation */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from src/libsystemd-network/dhcp-lease-internal.h (67 lines). One
 * of the six files in the lift set carrying a real 2013 Intel copyright
 * line (plan §2.11) -- verified against the real v261.2 file, which still
 * has it.
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. History review
 * (4925d9f07f..main, plan §2.2): no fix in the 26-commit lift-set window
 * touches sd-dhcp-lease.c/dhcp-lease-internal.h. That window's one
 * backport-worthy commit, 7bd9f0f805 ("dhcp-server: reject pool offsets
 * beyond the subnet"), reorders sd_dhcp_server_configure_pool() so a pool
 * offset beyond the subnet cannot underflow uint32_t and pass validation --
 * it lives in sd-dhcp-server.c, which this milestone does not own, so it is
 * not applied here. Flagged for the server agent (also in the final
 * report): nothing in this lease object does the same unvalidated
 * subtraction, so there is nothing here to double-check against the same
 * pattern, but sd-dhcp-server.c's own pool-offset arithmetic should be
 * checked against it.
 *
 * Trimmed relative to upstream:
 *  - No search-domain list (option 119/Domain Search is cut, plan §2.1).
 *  - No DNR resolver list (option 162 is cut, plan §2.1).
 *  - No 6RD fields (needs IPv6 masking; netd carries no IPv6 at all,
 *    plan §2.9 -- missed by the plan's own cut list, same as
 *    dhcp-message.h's 6RD note).
 *  - No sd-json serialization state (persistence dropped entirely, plan
 *    §2.2's Lease object row -- leases live in memory; netd-link.c writes
 *    its own trivial /run/netd/leases/<ifindex> text format instead).
 *  - triple_timestamp (CLOCK_REALTIME + CLOCK_MONOTONIC + CLOCK_BOOTTIME,
 *    three clocks captured together) becomes a single CLOCK_MONOTONIC
 *    usec_t: netd's timer queue (src/timer.c) is monotonic-only by design,
 *    so T1/T2/expiry deadlines only ever need the monotonic clock, and a
 *    wall-clock jump (e.g. the DHCP-driven SNTP step in §2.6) can never
 *    retroactively move a lease's expiry the way a CLOCK_REALTIME base
 *    would.
 *  - No SD_DHCP_OPTION_IPV6_ONLY_PREFERRED handling: upstream's version
 *    gates this on the client's own `anonymize` flag and requested-option
 *    set, both sd_dhcp_client fields this milestone's client agent owns
 *    (dhcp-client-internal.h, not lifted here). netd does not request
 *    option 108 (plan's DHCP option set, §2.5/§2.6), so there is nothing to
 *    gate.
 *
 * API boundary redesign (not in the plan, found while lifting): upstream's
 * dhcp_lease_new_from_message() and dhcp_client_parse_message() take a
 * `sd_dhcp_client *client` and read client->state/bootp/rapid_commit/xid/
 * arp_type/hw_addr/fallback_lease_lifetime/anonymize/req_opts/lease --
 * fields that live in dhcp-client-internal.h, which this milestone does
 * not own (client agent). The lease object cannot depend on the client
 * object's layout without a circular ownership problem, so the boundary
 * here is: dhcp_lease_new_from_message() below takes a small
 * DhcpLeaseParseParams (the two client fields it actually needs) instead
 * of the client itself, and message-type-dependent state validation
 * (client_parse_offer()/_ack()/_nak()/_bootreply() and the dispatch in
 * dhcp_client_parse_message()) becomes the client agent's own code,
 * calling dhcp_message_parse() and dhcp_lease_new_from_message() directly.
 * See the final report for this call spelled out as API guidance.
 */

#pragma once

/* Self-sufficient regardless of what a consumer includes first (a real
 * cross-agent bug: netd-resolv.c included dhcp-lease-internal.h without
 * netd-compat.h first, and this header needs its bool/usec_t/macros) --
 * safe to include redundantly, netd-compat.h has its own #pragma once. */
#include "netd-compat.h"


#include "dhcp-message.h"

typedef enum DhcpLeaseServerType {
        DHCP_LEASE_DNS,
        DHCP_LEASE_NTP,
        DHCP_LEASE_SIP,
        _DHCP_LEASE_SERVER_TYPE_MAX,
} DhcpLeaseServerType;

typedef struct DhcpLeaseServerData {
        struct in_addr *addr;
        size_t size;
} DhcpLeaseServerData;

typedef struct DhcpLeaseParseParams {
        bool bootp; /* siaddr/server-identifier and lifetime handling differ under plain BOOTP */
        usec_t fallback_lease_lifetime; /* 0 disables the fallback: a missing/zero lease time is then -EBADMSG */
} DhcpLeaseParseParams;

typedef struct DhcpLease {
        unsigned n_ref;

        DhcpMessage *message;

        /* each 0/USEC_INFINITY if unset */
        usec_t t1;
        usec_t t2;
        usec_t lifetime;
        usec_t timestamp_monotonic; /* CLOCK_MONOTONIC at acquisition -- see this file's header */

        be32_t address;
        be32_t server_address;
        be32_t subnet_mask;
        be32_t broadcast;

        struct in_addr *router;
        size_t router_size;

        DhcpLeaseServerData servers[_DHCP_LEASE_SERVER_TYPE_MAX];

        DhcpRoute *static_routes;
        size_t n_static_routes;
        DhcpRoute *classless_routes;
        size_t n_classless_routes;

        uint16_t mtu; /* 0 if unset */

        char *domainname;
        char *hostname;
        char *captive_portal;

        char *timezone;
} DhcpLease;

DhcpLease *dhcp_lease_ref(DhcpLease *p);
DhcpLease *dhcp_lease_unref(DhcpLease *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(DhcpLease *, dhcp_lease_unref);

int dhcp_lease_new_from_message(const DhcpLeaseParseParams *params, DhcpMessage *message, DhcpLease **ret);

int dhcp_lease_get_timestamp(DhcpLease *lease, usec_t *ret);
int dhcp_lease_get_address(DhcpLease *lease, struct in_addr *ret);
int dhcp_lease_get_broadcast(DhcpLease *lease, struct in_addr *ret);
int dhcp_lease_get_lifetime(DhcpLease *lease, usec_t *ret);
int dhcp_lease_get_t1(DhcpLease *lease, usec_t *ret);
int dhcp_lease_get_t2(DhcpLease *lease, usec_t *ret);
/* Deadline = timestamp_monotonic + duration, saturated (util.h's usec_add()). */
int dhcp_lease_get_lifetime_timestamp(DhcpLease *lease, usec_t *ret);
int dhcp_lease_get_t1_timestamp(DhcpLease *lease, usec_t *ret);
int dhcp_lease_get_t2_timestamp(DhcpLease *lease, usec_t *ret);
int dhcp_lease_get_mtu(DhcpLease *lease, uint16_t *ret);
int dhcp_lease_get_servers(DhcpLease *lease, DhcpLeaseServerType what, const struct in_addr **ret);
int dhcp_lease_get_dns(DhcpLease *lease, const struct in_addr **ret);
int dhcp_lease_get_ntp(DhcpLease *lease, const struct in_addr **ret);
int dhcp_lease_get_sip(DhcpLease *lease, const struct in_addr **ret);
int dhcp_lease_get_domainname(DhcpLease *lease, const char **ret);
int dhcp_lease_get_hostname(DhcpLease *lease, const char **ret);
int dhcp_lease_get_captive_portal(DhcpLease *lease, const char **ret);
int dhcp_lease_get_router(DhcpLease *lease, const struct in_addr **ret);
int dhcp_lease_get_netmask(DhcpLease *lease, struct in_addr *ret);
int dhcp_lease_get_prefix(DhcpLease *lease, struct in_addr *ret_prefix, uint8_t *ret_prefixlen);
int dhcp_lease_get_server_identifier(DhcpLease *lease, struct in_addr *ret);
int dhcp_lease_get_static_routes(DhcpLease *lease, DhcpRoute **ret, size_t *ret_n);
int dhcp_lease_get_classless_routes(DhcpLease *lease, DhcpRoute **ret, size_t *ret_n);
int dhcp_lease_get_timezone(DhcpLease *lease, const char **ret);
