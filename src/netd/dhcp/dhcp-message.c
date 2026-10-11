/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/dhcp-message.c. See
 * dhcp-message.h for the cut list.
 *
 * Assertion policy (netd-compat.h): every assert() kept from upstream guards
 * an internal invariant (a non-NULL out-param, an enum value the callers
 * dispatched on, a post-condition on a loop the same function just ran, e.g.
 * `assert(count == 2 * n_routes)`), never a bound taken off the wire. Wire
 * bounds (tag, length, remaining-buffer) are checked one layer down in
 * tlv-util.c's tlv_parse() and return -EBADMSG. The header-length and hlen
 * checks in dhcp_message_verify_header() are plain `return -EBADMSG`, as
 * upstream.
 */

#include "netd-compat.h"

#include "dhcp-client-id-internal.h"
#include "dhcp-message.h"
#include "dns-name.h"

#define FLAGS_SET(flags, flag) (((flags) & (flag)) == (flag))

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

/* UDP-over-IPv4 payload ceiling (65535 - 8-byte UDP header); a DHCP message
 * larger than this could not be sent as one UDP datagram regardless of what
 * TLV parsing would otherwise accept. */
#define DHCP_UDP_PAYLOAD_MAX_SIZE 65527U

/* --- time <-> wire seconds (upstream's network-common.c usec_to_be32_sec()/
 * be32_sec_to_usec()). UINT32_MAX maps to/from USEC_INFINITY. --- */

static be32_t usec_to_be32_sec(usec_t t) {
        if (t == USEC_INFINITY)
                return htobe32(UINT32_MAX);
        if (t >= ((usec_t) (UINT32_MAX - 1)) * USEC_PER_SEC)
                return htobe32(UINT32_MAX - 1);

        return htobe32((uint32_t) ((t + USEC_PER_SEC - 1) / USEC_PER_SEC));
}

static usec_t be32_sec_to_usec(be32_t t, bool max_as_infinity) {
        uint32_t s = be32toh(t);

        if (s == UINT32_MAX && max_as_infinity)
                return USEC_INFINITY;

        return (usec_t) s * USEC_PER_SEC;
}

/* --- string safety (upstream's string_is_safe(), trimmed to: no raw control
 * bytes, so wire-derived text cannot inject escapes or newlines into logs or
 * config files). --- */

static bool string_is_safe(const char *s) {
        if (!s)
                return false;

        for (const unsigned char *p = (const unsigned char *) s; *p; p++)
                if (*p < 0x20 || *p == 0x7f)
                        return false;

        return true;
}

/* is_localhost() (src/basic/hostname-util.c), trimmed to the RFC 6761
 * cases that matter for rejecting a DHCP-supplied domain/hostname. */
static bool is_localhost(const char *name) {
        size_t n;

        if (!name)
                return false;

        n = strlen(name);
        if (n > 0 && name[n - 1] == '.')
                n--;

        return (n == 9 && strncasecmp(name, "localhost", 9) == 0) ||
                        (n >= 10 && strncasecmp(name + n - 10, ".localhost", 10) == 0);
}

static int normalize_dns_name(const char *name, char **ret) {
        _cleanup_free_ char *normalized = NULL;
        int r;

        assert(name);

        r = dns_name_normalize(name, &normalized);
        if (r < 0)
                return r;

        if (is_localhost(normalized))
                return -EINVAL;
        if (dns_name_is_root(normalized))
                return -EINVAL;

        if (ret)
                *ret = TAKE_PTR(normalized);
        return 0;
}

/* --- object lifetime --- */

static DhcpMessage *dhcp_message_free(DhcpMessage *message) {
        if (!message)
                return NULL;

        tlv_done(&message->options);
        return mfree(message);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DhcpMessage, dhcp_message, dhcp_message_free);

int dhcp_message_new(DhcpMessage **ret) {
        assert(ret);

        DhcpMessage *message = new0(DhcpMessage, 1);
        if (!message)
                return -ENOMEM;

        message->n_ref = 1;
        message->options = TLV_INIT(TLV_DHCP4);

        *ret = TAKE_PTR(message);
        return 0;
}

int dhcp_message_init_header(
                DhcpMessage *message,
                uint8_t op,
                uint32_t xid,
                uint16_t arp_type,
                const struct hw_addr_data *hw_addr) {

        assert(message);
        assert(IN_SET(op, BOOTREQUEST, BOOTREPLY));

        if (hw_addr && hw_addr->length > sizeof(message->header.chaddr))
                return -EINVAL;

        message->header = (DHCPMessageHeader){
                .op = op,
                .htype = arp_type <= UINT8_MAX ? (uint8_t) arp_type : 0,
                .hlen = hw_addr ? (uint8_t) hw_addr->length : 0,
                .xid = htobe32(xid),
                .magic = htobe32(DHCP_MAGIC_COOKIE),
        };

        if (hw_addr)
                memcpy(message->header.chaddr, hw_addr->bytes, hw_addr->length);
        return 0;
}

void dhcp_message_set_broadcast_flag(DhcpMessage *message, bool b) {
        assert(message);

        if (b)
                message->header.flags |= htobe16(0x8000);
        else
                message->header.flags &= (be16_t) ~htobe16(0x8000);
}

bool dhcp_message_has_broadcast_flag(DhcpMessage *message) {
        assert(message);

        return (message->header.flags & htobe16(0x8000)) != 0;
}

int dhcp_message_get_hw_addr(DhcpMessage *message, struct hw_addr_data *ret) {
        assert(message);
        assert(ret);

        if (message->header.hlen > sizeof(message->header.chaddr))
                return -EBADMSG;

        ret->length = message->header.hlen;
        memcpy(ret->bytes, message->header.chaddr, message->header.hlen);
        return 0;
}

/* --- option list: generic --- */

bool dhcp_message_has_option(DhcpMessage *message, uint8_t code) {
        assert(message);
        return tlv_contains(&message->options, code);
}

void dhcp_message_remove_option(DhcpMessage *message, uint8_t code) {
        assert(message);
        tlv_remove(&message->options, code);
}

int dhcp_message_append_option(DhcpMessage *message, uint8_t code, size_t length, const void *data) {
        assert(message);
        return tlv_append(&message->options, code, length, data);
}

int dhcp_message_append_option_flag(DhcpMessage *message, uint8_t code) {
        if (dhcp_message_has_option(message, code))
                return -EEXIST;

        return dhcp_message_append_option(message, code, 0, NULL);
}

int dhcp_message_append_option_u8(DhcpMessage *message, uint8_t code, uint8_t data) {
        if (dhcp_message_has_option(message, code))
                return -EEXIST;

        return dhcp_message_append_option(message, code, sizeof(uint8_t), &data);
}

int dhcp_message_append_option_u16(DhcpMessage *message, uint8_t code, uint16_t data) {
        be16_t b;

        if (dhcp_message_has_option(message, code))
                return -EEXIST;

        b = htobe16(data);
        return dhcp_message_append_option(message, code, sizeof(be16_t), &b);
}

int dhcp_message_append_option_be32(DhcpMessage *message, uint8_t code, be32_t data) {
        if (dhcp_message_has_option(message, code))
                return -EEXIST;

        return dhcp_message_append_option(message, code, sizeof(be32_t), &data);
}

int dhcp_message_append_option_sec(DhcpMessage *message, uint8_t code, usec_t usec) {
        return dhcp_message_append_option_be32(message, code, usec_to_be32_sec(usec));
}

int dhcp_message_append_option_address(DhcpMessage *message, uint8_t code, const struct in_addr *addr) {
        assert(addr);
        return dhcp_message_append_option_be32(message, code, addr->s_addr);
}

int dhcp_message_append_option_addresses(
                DhcpMessage *message, uint8_t code, size_t n_addr, const struct in_addr *addr) {

        assert(n_addr == 0 || addr);

        if (n_addr == 0)
                return 0;

        if (code == SD_DHCP_OPTION_SIP_SERVER) {
                if (dhcp_message_has_option(message, SD_DHCP_OPTION_SIP_SERVER))
                        return -EEXIST;

                size_t len = 1 + sizeof(struct in_addr) * n_addr;
                _cleanup_free_ uint8_t *buf = new (uint8_t, len);
                if (!buf)
                        return -ENOMEM;

                buf[0] = 1; /* 'enc' field, 0: domains, 1: addresses */
                memcpy(buf + 1, addr, sizeof(struct in_addr) * n_addr);

                return dhcp_message_append_option(message, code, len, buf);
        }

        return dhcp_message_append_option(message, code, sizeof(struct in_addr) * n_addr, addr);
}

int dhcp_message_append_option_string(DhcpMessage *message, uint8_t code, const char *data) {
        if (isempty(data))
                return 0;

        if (!string_is_safe(data))
                return -EINVAL;

        if (dhcp_message_has_option(message, code))
                return -EEXIST;

        return dhcp_message_append_option(message, code, strlen(data), data);
}

static int dhcp_message_append_option_static_routes(
                DhcpMessage *message, size_t n_routes, const DhcpRoute *routes) {
        int r;

        assert(routes || n_routes == 0);

        if (n_routes == 0)
                return 0;

        _cleanup_free_ struct in_addr *buf = new (struct in_addr, 2 * n_routes);
        if (!buf)
                return -ENOMEM;

        size_t count = 0;
        FOREACH_ARRAY(route, routes, n_routes) {
                unsigned char prefixlen;

                r = in4_addr_default_prefixlen(&route->dst_addr, &prefixlen);
                if (r < 0)
                        return r;
                if (prefixlen != route->dst_prefixlen)
                        return -EINVAL;

                struct in_addr dst = route->dst_addr;
                (void) in4_addr_mask(&dst, prefixlen);

                buf[count++] = dst;
                buf[count++] = route->gw_addr;
        }

        /* Internal invariant: the loop above appends exactly two entries per
         * route it did not already reject with a `return`. */
        assert(count == 2 * n_routes);

        return dhcp_message_append_option_addresses(message, SD_DHCP_OPTION_STATIC_ROUTE, 2 * n_routes, buf);
}

static int dhcp_message_append_option_classless_static_routes(
                DhcpMessage *message, uint8_t code, size_t n_routes, const DhcpRoute *routes) {

        assert(routes || n_routes == 0);
        assert(IN_SET(code,
                      SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
                      SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE));

        if (n_routes == 0)
                return 0;

        _cleanup_free_ uint8_t *buf = new (uint8_t, (1 + 2 * sizeof(struct in_addr)) * n_routes);
        if (!buf)
                return -ENOMEM;

        uint8_t *p = buf;
        FOREACH_ARRAY(route, routes, n_routes) {
                if (route->dst_prefixlen > sizeof(struct in_addr) * 8)
                        return -EINVAL;

                *p++ = route->dst_prefixlen;
                struct in_addr dst = route->dst_addr;
                (void) in4_addr_mask(&dst, route->dst_prefixlen);
                memcpy(p, &dst, DIV_ROUND_UP(route->dst_prefixlen, 8));
                p += DIV_ROUND_UP(route->dst_prefixlen, 8);
                memcpy(p, &route->gw_addr, sizeof(struct in_addr));
                p += sizeof(struct in_addr);
        }

        return dhcp_message_append_option(message, code, (size_t) (p - buf), buf);
}

int dhcp_message_append_option_routes(
                DhcpMessage *message, uint8_t code, size_t n_routes, const DhcpRoute *routes) {
        switch (code) {
        case SD_DHCP_OPTION_STATIC_ROUTE:
                return dhcp_message_append_option_static_routes(message, n_routes, routes);
        case SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE:
        case SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE:
                return dhcp_message_append_option_classless_static_routes(message, code, n_routes, routes);
        default:
                return -EINVAL;
        }
}

int dhcp_message_append_option_client_id(DhcpMessage *message, const DhcpClientId *id) {
        assert(id);

        if (!dhcp_client_id_is_set(id))
                return -EINVAL;

        if (dhcp_message_has_option(message, SD_DHCP_OPTION_CLIENT_IDENTIFIER))
                return -EEXIST;

        return dhcp_message_append_option(message, SD_DHCP_OPTION_CLIENT_IDENTIFIER, id->size, id->raw);
}

int dhcp_message_append_option_parameter_request_list(DhcpMessage *message, const NetdU8Set *prl) {
        size_t len;

        assert(prl);

        len = netd_u8set_size(prl);
        if (len == 0)
                return 0;

        _cleanup_free_ uint8_t *buf = new (uint8_t, len);
        if (!buf)
                return -ENOMEM;

        /* FOREACH_U8SET iterates in ascending option order, so the list is
         * deterministic (upstream's Set is hash-ordered). */
        size_t i = 0;
        FOREACH_U8SET(v, prl)
        buf[i++] = v;
        assert(i == len);

        return dhcp_message_append_option(message, SD_DHCP_OPTION_PARAMETER_REQUEST_LIST, len, buf);
}

int dhcp_message_append_option_hostname(DhcpMessage *message, const char *hostname) {
        if (isempty(hostname))
                return 0;

        if (dhcp_message_has_option(message, SD_DHCP_OPTION_HOST_NAME))
                return -EEXIST;

        if (!dns_name_is_single_label(hostname))
                /* Upstream falls back to encoding this as FQDN (option 81),
                 * which is cut here (dhcp-message.h's header). */
                return -EOPNOTSUPP;

        return dhcp_message_append_option_string(message, SD_DHCP_OPTION_HOST_NAME, hostname);
}

/* --- option list: generic get --- */

int dhcp_message_get_option(DhcpMessage *message, uint8_t code, size_t length, void *ret) {
        int r;
        struct iovec iov;

        assert(message);

        r = tlv_get_full(&message->options, code, length, ret ? &iov : NULL);
        if (r < 0)
                return r;

        if (ret && iov.iov_len > 0)
                memcpy(ret, iov.iov_base, iov.iov_len);
        return 0;
}

int dhcp_message_get_option_alloc(DhcpMessage *message, uint8_t code, struct iovec *ret) {
        assert(message);
        return tlv_get_alloc(&message->options, code, ret);
}

int dhcp_message_get_option_flag(DhcpMessage *message, uint8_t code) {
        return dhcp_message_get_option(message, code, 0, NULL);
}

int dhcp_message_get_option_u8(DhcpMessage *message, uint8_t code, uint8_t *ret) {
        return dhcp_message_get_option(message, code, sizeof(uint8_t), ret);
}

int dhcp_message_get_option_u16(DhcpMessage *message, uint8_t code, uint16_t *ret) {
        be16_t b;
        int r;

        r = dhcp_message_get_option(message, code, sizeof(be16_t), ret ? &b : NULL);
        if (r < 0)
                return r;

        if (ret)
                *ret = be16toh(b);
        return 0;
}

int dhcp_message_get_option_be32(DhcpMessage *message, uint8_t code, be32_t *ret) {
        return dhcp_message_get_option(message, code, sizeof(be32_t), ret);
}

int dhcp_message_get_option_sec(DhcpMessage *message, uint8_t code, bool max_as_infinity, usec_t *ret) {
        be32_t t;
        int r;

        r = dhcp_message_get_option_be32(message, code, &t);
        if (r < 0)
                return r;

        if (ret)
                *ret = be32_sec_to_usec(t, max_as_infinity);
        return 0;
}

int dhcp_message_get_option_address(DhcpMessage *message, uint8_t code, struct in_addr *ret) {
        return dhcp_message_get_option_be32(message, code, ret ? &ret->s_addr : NULL);
}

int dhcp_message_get_option_addresses(
                DhcpMessage *message, uint8_t code, size_t *ret_n_addr, struct in_addr **ret_addr) {

        int r;

        assert(ret_n_addr || !ret_addr);

        _cleanup_free_ void *base = NULL;
        struct iovec iov;
        r = dhcp_message_get_option_alloc(message, code, &iov);
        if (r < 0)
                return r;
        base = iov.iov_base;

        if (code == SD_DHCP_OPTION_SIP_SERVER) {
                if (iov.iov_len == 0)
                        return -EBADMSG;
                if (*(uint8_t *) iov.iov_base != 1) /* 'enc' field, 0: domains, 1: addresses */
                        return -ENODATA;

                iov.iov_base = (uint8_t *) iov.iov_base + 1;
                iov.iov_len -= 1;
        }

        /* Externally-supplied length: a real validation error, not an assert. */
        netd_validate(iov.iov_len % sizeof(struct in_addr) == 0, -EBADMSG);

        size_t n = iov.iov_len / sizeof(struct in_addr);
        if (n == 0)
                return -ENODATA;

        if (ret_addr) {
                struct in_addr *addr = newdup(struct in_addr, iov.iov_base, n);
                if (!addr)
                        return -ENOMEM;
                *ret_addr = addr;
        }
        if (ret_n_addr)
                *ret_n_addr = n;
        return 0;
}

int dhcp_message_get_option_string(DhcpMessage *message, uint8_t code, char **ret) {
        int r;

        struct iovec iov = { 0 };
        r = dhcp_message_get_option_alloc(message, code, &iov);
        if (r < 0)
                return r;
        _cleanup_free_ void *base = iov.iov_base;

        if (iov.iov_len == 0)
                return -ENODATA;

        /* Allow NUL at the end (tlv_get_alloc() always appends one), but
         * refuse an intermediate one -- externally-supplied data. */
        netd_validate(!memchr(iov.iov_base, 0, iov.iov_len - 1), -EBADMSG);

        if (isempty(iov.iov_base))
                return -ENODATA;

        netd_validate(string_is_safe(iov.iov_base), -EBADMSG);

        if (ret)
                *ret = TAKE_PTR(base);
        return 0;
}

static int dhcp_message_get_option_static_routes(
                DhcpMessage *message, size_t *ret_n_routes, DhcpRoute **ret_routes) {
        int r;

        size_t n;
        _cleanup_free_ struct in_addr *addrs = NULL;
        r = dhcp_message_get_option_addresses(message, SD_DHCP_OPTION_STATIC_ROUTE, &n, &addrs);
        if (r < 0)
                return r;

        netd_validate(n % 2 == 0, -EBADMSG);

        _cleanup_free_ DhcpRoute *routes = NULL;
        size_t routes_allocated = 0, n_routes = 0;

        for (size_t i = 0; i < n; i += 2) {
                struct in_addr dst = addrs[i];
                unsigned char prefixlen;

                if (in4_addr_default_prefixlen(&dst, &prefixlen) < 0)
                        continue;

                (void) in4_addr_mask(&dst, prefixlen);

                /* RFC 2132 5.8: 0.0.0.0 is an illegal static-route destination. */
                if (in4_addr_is_null(&dst))
                        continue;

                if (!ret_routes) {
                        n_routes++;
                        continue;
                }

                if (!GREEDY_REALLOC(routes, n_routes + 1))
                        return -ENOMEM;

                routes[n_routes++] = (DhcpRoute){
                        .dst_addr = dst,
                        .gw_addr = addrs[i + 1],
                        .dst_prefixlen = prefixlen,
                };
        }

        if (n_routes == 0)
                return -ENODATA;

        if (ret_routes)
                *ret_routes = TAKE_PTR(routes);
        if (ret_n_routes)
                *ret_n_routes = n_routes;
        return 0;
}

static int dhcp_message_get_option_classless_static_routes(
                DhcpMessage *message, uint8_t code, size_t *ret_n_routes, DhcpRoute **ret_routes) {

        int r;

        assert(IN_SET(code,
                      SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
                      SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE));

        struct iovec iov = { 0 };
        r = dhcp_message_get_option_alloc(message, code, &iov);
        if (r < 0)
                return r;
        _cleanup_free_ void *base = iov.iov_base;

        _cleanup_free_ DhcpRoute *routes = NULL;
        size_t routes_allocated = 0, n_routes = 0;

        const uint8_t *p = iov.iov_base;
        size_t left = iov.iov_len;

        while (left > 0) {
                uint8_t prefixlen = *p++;
                left--;

                netd_validate(prefixlen <= 32, -EBADMSG);

                size_t n = DIV_ROUND_UP(prefixlen, 8);
                netd_validate(n <= left, -EBADMSG);

                struct in_addr dst = { 0 };
                memcpy(&dst, p, n);
                (void) in4_addr_mask(&dst, prefixlen);
                p += n;
                left -= n;

                netd_validate(left >= sizeof(struct in_addr), -EBADMSG);

                struct in_addr gw;
                memcpy(&gw, p, sizeof(struct in_addr));
                p += sizeof(struct in_addr);
                left -= sizeof(struct in_addr);

                if (!ret_routes) {
                        n_routes++;
                        continue;
                }

                if (!GREEDY_REALLOC(routes, n_routes + 1))
                        return -ENOMEM;

                routes[n_routes++] = (DhcpRoute){
                        .dst_addr = dst,
                        .gw_addr = gw,
                        .dst_prefixlen = prefixlen,
                };
        }

        if (n_routes == 0)
                return -ENODATA;

        if (ret_routes)
                *ret_routes = TAKE_PTR(routes);
        if (ret_n_routes)
                *ret_n_routes = n_routes;
        return 0;
}

int dhcp_message_get_option_routes(
                DhcpMessage *message, uint8_t code, size_t *ret_n_routes, DhcpRoute **ret_routes) {

        switch (code) {
        case SD_DHCP_OPTION_STATIC_ROUTE:
                return dhcp_message_get_option_static_routes(message, ret_n_routes, ret_routes);
        case SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE:
        case SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE:
                return dhcp_message_get_option_classless_static_routes(message, code, ret_n_routes, ret_routes);
        default:
                return -EINVAL;
        }
}

int dhcp_message_get_option_client_id(DhcpMessage *message, DhcpClientId *ret) {
        int r;

        assert(ret);

        struct iovec iov = { 0 };
        r = dhcp_message_get_option_alloc(message, SD_DHCP_OPTION_CLIENT_IDENTIFIER, &iov);
        if (r < 0)
                return r;
        _cleanup_free_ void *base = iov.iov_base;

        return dhcp_client_id_set_raw(ret, iov.iov_base, iov.iov_len);
}

int dhcp_message_get_option_parameter_request_list(DhcpMessage *message, NetdU8Set *ret) {
        int r;

        assert(ret);

        struct iovec iov = { 0 };
        r = dhcp_message_get_option_alloc(message, SD_DHCP_OPTION_PARAMETER_REQUEST_LIST, &iov);
        if (r < 0)
                return r;
        _cleanup_free_ void *base = iov.iov_base;

        if (iov.iov_len == 0)
                return -ENODATA;

        netd_u8set_clear(ret);
        FOREACH_ARRAY(b, (uint8_t *) iov.iov_base, iov.iov_len)
        (void) netd_u8set_put(ret, *b);

        return 0;
}

int dhcp_message_get_option_dns_name(DhcpMessage *message, uint8_t code, char **ret) {
        int r;

        _cleanup_free_ char *name = NULL;
        r = dhcp_message_get_option_string(message, code, &name);
        if (r < 0)
                return r;

        return normalize_dns_name(name, ret);
}

int dhcp_message_get_option_hostname(DhcpMessage *message, char **ret) {
        /* FQDN option is cut (dhcp-message.h's header); Host Name is the
         * only source left. */
        return dhcp_message_get_option_dns_name(message, SD_DHCP_OPTION_HOST_NAME, ret);
}

/* --- parse / build --- */

static int dhcp_message_verify_header(
                const struct iovec *iov,
                uint8_t op,
                const uint32_t *xid,
                uint16_t arp_type,
                const struct hw_addr_data *hw_addr) {

        assert(iov);
        assert(IN_SET(op, 0, BOOTREQUEST, BOOTREPLY));

        if (!iov->iov_base || iov->iov_len < sizeof(DHCPMessageHeader))
                return -EBADMSG;

        if (iov->iov_len > DHCP_UDP_PAYLOAD_MAX_SIZE)
                return -EBADMSG;

        const DHCPMessageHeader *header = iov->iov_base;

        if (!IN_SET(header->op, BOOTREQUEST, BOOTREPLY))
                return -EBADMSG;
        if (op != 0 && header->op != op)
                return -EBADMSG;

        if (xid && be32toh(header->xid) != *xid)
                return -EBADMSG;

        if (arp_type <= UINT8_MAX && header->htype != arp_type)
                return -EBADMSG;

        if (header->hlen > sizeof(header->chaddr))
                return -EBADMSG;

        if (hw_addr) {
                if (hw_addr->length != header->hlen)
                        return -EBADMSG;
                if (hw_addr->length > 0 && memcmp(header->chaddr, hw_addr->bytes, hw_addr->length) != 0)
                        return -EBADMSG;
        }

        return 0;
}

int dhcp_message_parse(
                const struct iovec *iov,
                uint8_t op,
                const uint32_t *xid,
                uint16_t arp_type,
                const struct hw_addr_data *hw_addr,
                DhcpMessage **ret) {

        int r;

        assert(iov);
        assert(ret);

        r = dhcp_message_verify_header(iov, op, xid, arp_type, hw_addr);
        if (r < 0)
                return r;

        _cleanup_(dhcp_message_unrefp) DhcpMessage *message = NULL;
        r = dhcp_message_new(&message);
        if (r < 0)
                return r;

        memcpy(&message->header, iov->iov_base, sizeof(DHCPMessageHeader));

        if (be32toh(message->header.magic) != DHCP_MAGIC_COOKIE) {
                /* BOOTP, no options. */
                *ret = TAKE_PTR(message);
                return 0;
        }

        struct iovec opts = {
                .iov_base = (uint8_t *) iov->iov_base + sizeof(DHCPMessageHeader),
                .iov_len = iov->iov_len - sizeof(DHCPMessageHeader),
        };
        r = tlv_parse(&message->options, &opts);
        if (r < 0)
                return r;

        /* Option 52 (Overload): the sname/file header fields may carry more
         * options. */
        uint8_t overload = DHCP_OVERLOAD_NONE;
        (void) dhcp_message_get_option_u8(message, SD_DHCP_OPTION_OVERLOAD, &overload);

        if (FLAGS_SET(overload, DHCP_OVERLOAD_FILE)) {
                struct iovec file_iov = {
                        .iov_base = message->header.file,
                        .iov_len = sizeof(message->header.file),
                };
                r = tlv_parse(&message->options, &file_iov);
                if (r < 0)
                        return r;

                memset(message->header.file, 0, sizeof(message->header.file));
        }

        if (FLAGS_SET(overload, DHCP_OVERLOAD_SNAME)) {
                struct iovec sname_iov = {
                        .iov_base = message->header.sname,
                        .iov_len = sizeof(message->header.sname),
                };
                r = tlv_parse(&message->options, &sname_iov);
                if (r < 0)
                        return r;

                memset(message->header.sname, 0, sizeof(message->header.sname));
        }

        *ret = TAKE_PTR(message);
        return 0;
}

size_t dhcp_message_payload_size(DhcpMessage *message) {
        size_t sz;

        assert(message);

        sz = sizeof(DHCPMessageHeader) + tlv_size(&message->options);
        return sz > BOOTP_MESSAGE_SIZE ? sz : BOOTP_MESSAGE_SIZE;
}

int dhcp_message_build(DhcpMessage *message, struct iovec *ret) {
        int r;

        assert(message);
        assert(ret);

        size_t size = sizeof(DHCPMessageHeader) + tlv_size(&message->options);
        if (size > DHCP_UDP_PAYLOAD_MAX_SIZE)
                return -E2BIG;

        struct iovec options;
        r = tlv_build(&message->options, &options);
        if (r < 0)
                return r;

        /* Message must be at least BOOTP_MESSAGE_SIZE bytes for compatibility
         * with other implementations and network appliances. */
        size_t padding_size = size < BOOTP_MESSAGE_SIZE ? BOOTP_MESSAGE_SIZE - size : 0;

        uint8_t *buf = new (uint8_t, sizeof(DHCPMessageHeader) + options.iov_len + padding_size);
        if (!buf) {
                free(options.iov_base);
                return -ENOMEM;
        }

        memcpy(buf, &message->header, sizeof(DHCPMessageHeader));
        memcpy(buf + sizeof(DHCPMessageHeader), options.iov_base, options.iov_len);
        if (padding_size > 0)
                memset(buf + sizeof(DHCPMessageHeader) + options.iov_len, 0, padding_size);

        free(options.iov_base);

        *ret = (struct iovec){ .iov_base = buf,
                               .iov_len = sizeof(DHCPMessageHeader) + options.iov_len + padding_size };
        return 0;
}
