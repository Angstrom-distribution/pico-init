/* SPDX-FileCopyrightText: 2013 Intel Corporation */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/dhcp-lease-internal.h.
 *
 * Trimmed relative to upstream:
 *  - No search-domain list (option 119) and no DNR resolver list (option 162).
 *  - No 6RD fields (need IPv6 masking; netd carries no IPv6).
 *  - No sd-json serialization state: leases live in memory, and netd-link.c
 *    writes its own text format to /run/netd/leases/<ifindex>.
 *  - triple_timestamp (CLOCK_REALTIME + CLOCK_MONOTONIC + CLOCK_BOOTTIME)
 *    becomes a single CLOCK_MONOTONIC usec_t: netd's timer queue
 *    (src/timer.c) is monotonic-only, and a wall-clock step (e.g. from the
 *    DHCP-driven SNTP update) must not move a lease's expiry.
 *  - No SD_DHCP_OPTION_IPV6_ONLY_PREFERRED handling: netd does not request
 *    option 108.
 *
 * API boundary: upstream's dhcp_lease_new_from_message() and
 * dhcp_client_parse_message() take the sd_dhcp_client and read many of its
 * fields. Here dhcp_lease_new_from_message() takes a small
 * DhcpLeaseParseParams (the two client fields it needs) so the lease does not
 * depend on the client's layout; message-type dispatch and state validation
 * live in dhcp-client.c, which calls dhcp_message_parse() and
 * dhcp_lease_new_from_message() directly.
 */

#pragma once

/* Self-sufficient: needs bool/usec_t/macros from netd-compat.h. */
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
