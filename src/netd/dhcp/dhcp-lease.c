/* SPDX-FileCopyrightText: 2013 Intel Corporation */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from src/libsystemd-network/sd-dhcp-lease.c (831 lines): lease
 * construction from a DHCPACK/BOOTREPLY, and the accessors for every option
 * netd uses -- including option 42 (NTP servers) and option 101 (TZDB
 * timezone name), the reason netd exists at all (plan §2.6).
 *
 * Quarry point and history review: see dhcp-lease-internal.h's header --
 * same window, same one (not-carried-here) backport, same API-boundary
 * redesign this file implements (DhcpLeaseParseParams instead of a client
 * object).
 *
 * Note on option 100 vs 101 (plan §2.6 point 1): upstream defines
 * SD_DHCP_OPTION_POSIX_TIMEZONE = 100 but has never parsed it anywhere;
 * only 101 is implemented here, matching upstream's actual behaviour
 * rather than its unused constant.
 *
 * Assertion policy: dhcp_lease_new_from_message() below reads option data
 * that already passed dhcp-message.c's own get_option_*() validation (which
 * itself validates against tlv-util.c's wire bounds), so what remains here
 * is protocol-level cross-checks (T1 < T2 < lifetime, a mandatory yiaddr)
 * on values a malicious server fully controls -- every one of those is a
 * real -EBADMSG/log-and-fall-back path, not an assert, matching upstream's
 * own choice (upstream did not assert on these either; the T1 < T2 <
 * lifetime asserts that follow are on values this function *just
 * recomputed* into a known-valid range two lines above, i.e. an internal
 * invariant on netd's own arithmetic, not on server-supplied bytes).
 */

#include "netd-compat.h"

#include "dhcp-lease-internal.h"

static int in4_addr_default_subnet_mask(const struct in_addr *addr, struct in_addr *ret) {
        unsigned char prefixlen;
        int r;

        r = in4_addr_default_prefixlen(addr, &prefixlen);
        if (r < 0)
                return r;

        return in4_addr_prefixlen_to_netmask(ret, prefixlen);
}

static DhcpLease *dhcp_lease_free(DhcpLease *lease) {
        if (!lease)
                return NULL;

        dhcp_message_unref(lease->message);

        free(lease->router);
        free(lease->timezone);
        free(lease->hostname);
        free(lease->domainname);
        free(lease->captive_portal);

        for (DhcpLeaseServerType i = 0; i < _DHCP_LEASE_SERVER_TYPE_MAX; i++)
                free(lease->servers[i].addr);

        free(lease->static_routes);
        free(lease->classless_routes);
        return mfree(lease);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DhcpLease, dhcp_lease, dhcp_lease_free);

static int dhcp_lease_new(DhcpLease **ret) {
        DhcpLease *lease;

        assert(ret);

        lease = new0(DhcpLease, 1);
        if (!lease)
                return -ENOMEM;

        lease->n_ref = 1;

        *ret = lease;
        return 0;
}

int dhcp_lease_new_from_message(const DhcpLeaseParseParams *params, DhcpMessage *message, DhcpLease **ret) {
        int r;

        assert(params);
        assert(message);
        assert(ret);

        _cleanup_(dhcp_lease_unrefp) DhcpLease *lease = NULL;
        r = dhcp_lease_new(&lease);
        if (r < 0)
                return r;

        /* acquired address: mandatory, and fully server-controlled -- a real
         * validation error, not an assert. */
        netd_validate(message->header.yiaddr != 0, -EBADMSG);
        lease->address = message->header.yiaddr;

        /* subnet mask: mandatory, falling back to the classful default. */
        if (dhcp_message_get_option_be32(message, SD_DHCP_OPTION_SUBNET_MASK, &lease->subnet_mask) < 0) {
                struct in_addr mask;
                r = in4_addr_default_subnet_mask(&(struct in_addr){ .s_addr = message->header.yiaddr }, &mask);
                if (r < 0)
                        return r;
                lease->subnet_mask = mask.s_addr;
        }

        /* DHCP server address: mandatory. */
        r = dhcp_message_get_option_be32(message, SD_DHCP_OPTION_SERVER_IDENTIFIER, &lease->server_address);
        if (r < 0) {
                if (!params->bootp)
                        return log_warning_errno(
                                        r,
                                        "Failed to read %s option: %s",
                                        dhcp_option_code_to_string(SD_DHCP_OPTION_SERVER_IDENTIFIER),
                                        strerror(-r));

                /* BOOTP typically has no Server Identifier option; use siaddr. */
                lease->server_address = message->header.siaddr;
        }

        /* lifetime: mandatory (BOOTP has none -> infinite). */
        if (params->bootp)
                lease->lifetime = USEC_INFINITY;
        else {
                r = dhcp_message_get_option_sec(
                                message, SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME, true, &lease->lifetime);
                if (r < 0 || lease->lifetime == 0) {
                        if (params->fallback_lease_lifetime == 0) {
                                if (r < 0)
                                        return log_warning_errno(
                                                        r,
                                                        "Failed to read %s option: %s",
                                                        dhcp_option_code_to_string(
                                                                        SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME),
                                                        strerror(-r));

                                return log_warning_errno(
                                                -EBADMSG,
                                                "The %s option is set to 0 seconds.",
                                                dhcp_option_code_to_string(
                                                                SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME));
                        }

                        lease->lifetime = params->fallback_lease_lifetime;
                }

                /* Too-short a lifetime makes the connection unstable; bump to
                 * 30s, matching upstream's own floor. */
                if (lease->lifetime <= 30 * USEC_PER_SEC)
                        lease->lifetime = 30 * USEC_PER_SEC;

                if (lease->lifetime != USEC_INFINITY) {
                        r = dhcp_message_get_option_sec(
                                        message, SD_DHCP_OPTION_REBINDING_TIME, true, &lease->t2);
                        if (r < 0 && r != -ENODATA)
                                log_debug_errno(r,
                                                "Failed to read %s option, ignoring: %s",
                                                dhcp_option_code_to_string(SD_DHCP_OPTION_REBINDING_TIME),
                                                strerror(-r));

                        /* RFC 2131 4.4.5: T2 defaults to 0.875 * lifetime. */
                        if (lease->t2 == 0 || lease->t2 >= lease->lifetime)
                                lease->t2 = lease->lifetime * 7 / 8;

                        r = dhcp_message_get_option_sec(message, SD_DHCP_OPTION_RENEWAL_TIME, true, &lease->t1);
                        if (r < 0 && r != -ENODATA)
                                log_debug_errno(r,
                                                "Failed to read %s option, ignoring: %s",
                                                dhcp_option_code_to_string(SD_DHCP_OPTION_RENEWAL_TIME),
                                                strerror(-r));

                        /* RFC 2131 4.4.5: T1 defaults to 0.5 * lifetime. */
                        if (lease->t1 == 0 || lease->t1 >= lease->t2)
                                lease->t1 = lease->lifetime / 2;

                        if (lease->t1 >= lease->t2)
                                lease->t2 = lease->lifetime * 7 / 8;

                        /* Internal invariant: the arithmetic just above (not the
                         * server) is what guarantees this ordering. */
                        assert(lease->t1 > 0);
                        assert(lease->t1 < lease->t2);
                        assert(lease->t2 < lease->lifetime);
                }
        }

        r = dhcp_message_get_option_be32(message, SD_DHCP_OPTION_BROADCAST, &lease->broadcast);
        if (r < 0 && r != -ENODATA)
                log_debug_errno(r,
                                "Failed to parse %s option, ignoring: %s",
                                dhcp_option_code_to_string(SD_DHCP_OPTION_BROADCAST),
                                strerror(-r));

        r = dhcp_message_get_option_addresses(
                        message, SD_DHCP_OPTION_ROUTER, &lease->router_size, &lease->router);
        if (r < 0 && r != -ENODATA)
                log_debug_errno(r,
                                "Failed to parse %s option, ignoring: %s",
                                dhcp_option_code_to_string(SD_DHCP_OPTION_ROUTER),
                                strerror(-r));

        r = dhcp_message_get_option_addresses(
                        message,
                        SD_DHCP_OPTION_DOMAIN_NAME_SERVER,
                        &lease->servers[DHCP_LEASE_DNS].size,
                        &lease->servers[DHCP_LEASE_DNS].addr);
        if (r < 0 && r != -ENODATA)
                log_debug_errno(r,
                                "Failed to parse %s option, ignoring: %s",
                                dhcp_option_code_to_string(SD_DHCP_OPTION_DOMAIN_NAME_SERVER),
                                strerror(-r));

        r = dhcp_message_get_option_addresses(
                        message,
                        SD_DHCP_OPTION_NTP_SERVER,
                        &lease->servers[DHCP_LEASE_NTP].size,
                        &lease->servers[DHCP_LEASE_NTP].addr);
        if (r < 0 && r != -ENODATA)
                log_debug_errno(r,
                                "Failed to parse %s option, ignoring: %s",
                                dhcp_option_code_to_string(SD_DHCP_OPTION_NTP_SERVER),
                                strerror(-r));

        r = dhcp_message_get_option_addresses(
                        message,
                        SD_DHCP_OPTION_SIP_SERVER,
                        &lease->servers[DHCP_LEASE_SIP].size,
                        &lease->servers[DHCP_LEASE_SIP].addr);
        if (r < 0 && r != -ENODATA)
                log_debug_errno(r,
                                "Failed to parse %s option, ignoring: %s",
                                dhcp_option_code_to_string(SD_DHCP_OPTION_SIP_SERVER),
                                strerror(-r));

        r = dhcp_message_get_option_routes(
                        message, SD_DHCP_OPTION_STATIC_ROUTE, &lease->n_static_routes, &lease->static_routes);
        if (r < 0 && r != -ENODATA)
                log_debug_errno(r,
                                "Failed to parse %s option, ignoring: %s",
                                dhcp_option_code_to_string(SD_DHCP_OPTION_STATIC_ROUTE),
                                strerror(-r));

        r = dhcp_message_get_option_routes(
                        message,
                        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
                        &lease->n_classless_routes,
                        &lease->classless_routes);
        if (r < 0) {
                if (r != -ENODATA)
                        log_debug_errno(r,
                                        "Failed to parse %s option, ignoring: %s",
                                        dhcp_option_code_to_string(SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE),
                                        strerror(-r));

                r = dhcp_message_get_option_routes(
                                message,
                                SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE,
                                &lease->n_classless_routes,
                                &lease->classless_routes);
                if (r < 0 && r != -ENODATA)
                        log_debug_errno(r,
                                        "Failed to parse %s option, ignoring: %s",
                                        dhcp_option_code_to_string(
                                                        SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE),
                                        strerror(-r));
        }

        r = dhcp_message_get_option_dns_name(message, SD_DHCP_OPTION_DOMAIN_NAME, &lease->domainname);
        if (r < 0 && r != -ENODATA)
                log_debug_errno(r,
                                "Failed to parse %s option, ignoring: %s",
                                dhcp_option_code_to_string(SD_DHCP_OPTION_DOMAIN_NAME),
                                strerror(-r));

        r = dhcp_message_get_option_hostname(message, &lease->hostname);
        if (r < 0 && r != -ENODATA)
                log_debug_errno(r,
                                "Failed to parse %s option, ignoring: %s",
                                dhcp_option_code_to_string(SD_DHCP_OPTION_HOST_NAME),
                                strerror(-r));

        _cleanup_free_ char *captive_portal = NULL;
        r = dhcp_message_get_option_string(message, SD_DHCP_OPTION_DHCP_CAPTIVE_PORTAL, &captive_portal);
        if (r >= 0)
                lease->captive_portal = TAKE_PTR(captive_portal);
        else if (r != -ENODATA)
                log_debug_errno(r,
                                "Failed to parse %s option, ignoring: %s",
                                dhcp_option_code_to_string(SD_DHCP_OPTION_DHCP_CAPTIVE_PORTAL),
                                strerror(-r));

        _cleanup_free_ char *tz = NULL;
        r = dhcp_message_get_option_string(message, SD_DHCP_OPTION_TZDB_TIMEZONE, &tz);
        if (r >= 0)
                lease->timezone = TAKE_PTR(tz);
        else if (r != -ENODATA)
                log_debug_errno(r,
                                "Failed to parse %s option, ignoring: %s",
                                dhcp_option_code_to_string(SD_DHCP_OPTION_TZDB_TIMEZONE),
                                strerror(-r));

        uint16_t mtu;
        r = dhcp_message_get_option_u16(message, SD_DHCP_OPTION_MTU_INTERFACE, &mtu);
        if (r >= 0) {
                /* RFC 791/1122: 576 bytes is the minimum a host must reassemble;
                 * below that is not usable for real IP traffic. */
                if (mtu >= 576)
                        lease->mtu = mtu;
        } else if (r != -ENODATA)
                log_debug_errno(r,
                                "Failed to parse %s option, ignoring: %s",
                                dhcp_option_code_to_string(SD_DHCP_OPTION_MTU_INTERFACE),
                                strerror(-r));

        lease->timestamp_monotonic = now_monotonic();
        lease->message = dhcp_message_ref(message);
        *ret = TAKE_PTR(lease);
        return 0;
}

int dhcp_lease_get_timestamp(DhcpLease *lease, usec_t *ret) {
        assert_return(lease, -EINVAL);

        if (lease->timestamp_monotonic == 0)
                return -ENODATA;

        if (ret)
                *ret = lease->timestamp_monotonic;
        return 0;
}

int dhcp_lease_get_address(DhcpLease *lease, struct in_addr *ret) {
        assert_return(lease, -EINVAL);

        if (lease->address == 0)
                return -ENODATA;

        if (ret)
                ret->s_addr = lease->address;
        return 0;
}

int dhcp_lease_get_broadcast(DhcpLease *lease, struct in_addr *ret) {
        assert_return(lease, -EINVAL);

        if (lease->broadcast == 0)
                return -ENODATA;

        if (ret)
                ret->s_addr = lease->broadcast;
        return 0;
}

int dhcp_lease_get_lifetime(DhcpLease *lease, usec_t *ret) {
        assert_return(lease, -EINVAL);

        if (lease->lifetime == 0)
                return -ENODATA;

        if (ret)
                *ret = lease->lifetime;
        return 0;
}

int dhcp_lease_get_t1(DhcpLease *lease, usec_t *ret) {
        assert_return(lease, -EINVAL);

        if (lease->t1 == 0)
                return -ENODATA;

        if (ret)
                *ret = lease->t1;
        return 0;
}

int dhcp_lease_get_t2(DhcpLease *lease, usec_t *ret) {
        assert_return(lease, -EINVAL);

        if (lease->t2 == 0)
                return -ENODATA;

        if (ret)
                *ret = lease->t2;
        return 0;
}

static int lease_get_deadline(DhcpLease *lease, usec_t duration, usec_t *ret) {
        usec_t timestamp;
        int r;

        r = dhcp_lease_get_timestamp(lease, &timestamp);
        if (r < 0)
                return r;

        if (ret)
                *ret = usec_add(timestamp, duration);
        return 0;
}

int dhcp_lease_get_lifetime_timestamp(DhcpLease *lease, usec_t *ret) {
        usec_t t;
        int r = dhcp_lease_get_lifetime(lease, &t);
        return r < 0 ? r : lease_get_deadline(lease, t, ret);
}

int dhcp_lease_get_t1_timestamp(DhcpLease *lease, usec_t *ret) {
        usec_t t;
        int r = dhcp_lease_get_t1(lease, &t);
        return r < 0 ? r : lease_get_deadline(lease, t, ret);
}

int dhcp_lease_get_t2_timestamp(DhcpLease *lease, usec_t *ret) {
        usec_t t;
        int r = dhcp_lease_get_t2(lease, &t);
        return r < 0 ? r : lease_get_deadline(lease, t, ret);
}

int dhcp_lease_get_mtu(DhcpLease *lease, uint16_t *ret) {
        assert_return(lease, -EINVAL);

        if (lease->mtu == 0)
                return -ENODATA;

        if (ret)
                *ret = lease->mtu;
        return 0;
}

int dhcp_lease_get_servers(DhcpLease *lease, DhcpLeaseServerType what, const struct in_addr **ret) {
        assert_return(lease, -EINVAL);
        assert_return(what < _DHCP_LEASE_SERVER_TYPE_MAX, -EINVAL);

        if (lease->servers[what].size == 0)
                return -ENODATA;

        if (ret)
                *ret = lease->servers[what].addr;
        return (int) lease->servers[what].size;
}

int dhcp_lease_get_dns(DhcpLease *lease, const struct in_addr **ret) {
        return dhcp_lease_get_servers(lease, DHCP_LEASE_DNS, ret);
}
int dhcp_lease_get_ntp(DhcpLease *lease, const struct in_addr **ret) {
        return dhcp_lease_get_servers(lease, DHCP_LEASE_NTP, ret);
}
int dhcp_lease_get_sip(DhcpLease *lease, const struct in_addr **ret) {
        return dhcp_lease_get_servers(lease, DHCP_LEASE_SIP, ret);
}

int dhcp_lease_get_domainname(DhcpLease *lease, const char **ret) {
        assert_return(lease, -EINVAL);

        if (!lease->domainname)
                return -ENODATA;

        if (ret)
                *ret = lease->domainname;
        return 0;
}

int dhcp_lease_get_hostname(DhcpLease *lease, const char **ret) {
        assert_return(lease, -EINVAL);

        if (!lease->hostname)
                return -ENODATA;

        if (ret)
                *ret = lease->hostname;
        return 0;
}

int dhcp_lease_get_captive_portal(DhcpLease *lease, const char **ret) {
        assert_return(lease, -EINVAL);

        if (!lease->captive_portal)
                return -ENODATA;

        if (ret)
                *ret = lease->captive_portal;
        return 0;
}

int dhcp_lease_get_router(DhcpLease *lease, const struct in_addr **ret) {
        assert_return(lease, -EINVAL);

        if (lease->router_size == 0)
                return -ENODATA;

        if (ret)
                *ret = lease->router;
        return (int) lease->router_size;
}

int dhcp_lease_get_netmask(DhcpLease *lease, struct in_addr *ret) {
        assert_return(lease, -EINVAL);

        if (lease->subnet_mask == 0)
                return -ENODATA;

        if (ret)
                ret->s_addr = lease->subnet_mask;
        return 0;
}

int dhcp_lease_get_prefix(DhcpLease *lease, struct in_addr *ret_prefix, uint8_t *ret_prefixlen) {
        struct in_addr address, netmask;
        unsigned char prefixlen;
        int r;

        r = dhcp_lease_get_address(lease, &address);
        if (r < 0)
                return r;

        r = dhcp_lease_get_netmask(lease, &netmask);
        if (r < 0)
                return r;

        r = in4_addr_netmask_to_prefixlen(&netmask, &prefixlen);
        if (r < 0)
                return r;

        r = in4_addr_mask(&address, prefixlen);
        if (r < 0)
                return r;

        if (ret_prefix)
                *ret_prefix = address;
        if (ret_prefixlen)
                *ret_prefixlen = prefixlen;
        return 0;
}

int dhcp_lease_get_server_identifier(DhcpLease *lease, struct in_addr *ret) {
        assert_return(lease, -EINVAL);

        if (lease->server_address == 0)
                return -ENODATA;

        if (ret)
                ret->s_addr = lease->server_address;
        return 0;
}

static int dhcp_lease_get_routes(DhcpRoute *routes, size_t n_routes, DhcpRoute **ret, size_t *ret_n) {
        if (n_routes == 0)
                return -ENODATA;

        if (ret)
                *ret = routes;
        if (ret_n)
                *ret_n = n_routes;
        return (int) n_routes;
}

int dhcp_lease_get_static_routes(DhcpLease *lease, DhcpRoute **ret, size_t *ret_n) {
        assert_return(lease, -EINVAL);
        return dhcp_lease_get_routes(lease->static_routes, lease->n_static_routes, ret, ret_n);
}

int dhcp_lease_get_classless_routes(DhcpLease *lease, DhcpRoute **ret, size_t *ret_n) {
        assert_return(lease, -EINVAL);
        return dhcp_lease_get_routes(lease->classless_routes, lease->n_classless_routes, ret, ret_n);
}

int dhcp_lease_get_timezone(DhcpLease *lease, const char **ret) {
        assert_return(lease, -EINVAL);

        if (!lease->timezone)
                return -ENODATA;

        if (ret)
                *ret = lease->timezone;
        return 0;
}
