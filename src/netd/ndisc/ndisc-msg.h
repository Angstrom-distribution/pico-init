/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * IPv6 neighbour discovery messages (RFC 4861): the router advertisement a
 * host receives and the router solicitation it sends, and the lifetime rules
 * SLAAC applies to what an advertisement carries (RFC 4862).
 *
 * Pure code: no I/O, no allocation, no clock. Every byte of an advertisement
 * comes from the network, so every length is checked against the buffer
 * before it is read, and every option walk advances by at least eight bytes,
 * so a hostile packet costs at most one pass over its own length.
 *
 * Read with systemd's libsystemd-network/ndisc-option.c and sd-ndisc-router.c
 * as the reference for which malformed input is fatal to the whole
 * advertisement (a zero-length option, an option running past the end) and
 * which only to the one option (a typed option of the wrong size).
 */

#pragma once

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../util.h"

#define NDISC_RA_TYPE 134
#define NDISC_RS_TYPE 133
#define NDISC_RA_HEADER_LEN 16 /* ICMPv6 header and the RA fixed part */
#define NDISC_RS_HEADER_LEN 8

#define NDISC_OPT_SLLAO 1
#define NDISC_OPT_TLLAO 2
#define NDISC_OPT_PREFIX 3
#define NDISC_OPT_MTU 5
#define NDISC_OPT_ROUTE 24
#define NDISC_OPT_RDNSS 25
#define NDISC_OPT_DNSSL 31

/* 0xffffffff in a lifetime field: no expiry. */
#define NDISC_LIFETIME_INFINITE UINT32_MAX

/* RFC 4191 router preference, ordered as RouteMetric=high:medium:low lists
 * the metrics, so it indexes that triple. */
typedef enum NdiscPref {
        NDISC_PREF_HIGH,
        NDISC_PREF_MEDIUM,
        NDISC_PREF_LOW,
        _NDISC_PREF_MAX,
} NdiscPref;

typedef struct NdiscRaHeader {
        uint8_t hop_limit;
        bool managed; /* M: addresses from DHCPv6 */
        bool other;   /* O: other configuration from DHCPv6 */
        NdiscPref pref;
        uint16_t router_lifetime; /* seconds; 0 is "not a default router" */
        uint32_t reachable_ms;
        uint32_t retrans_ms;
} NdiscRaHeader;

/* One option as it sits in the packet: `data` points at its type byte and
 * `len` is its whole length in bytes, a non-zero multiple of 8. */
typedef struct NdiscOpt {
        uint8_t type;
        const uint8_t *data;
        size_t len;
} NdiscOpt;

typedef struct NdiscOptIter {
        const uint8_t *buf;
        size_t len;
        size_t off;
} NdiscOptIter;

/* A prefix information option. `autonomous` is already false when the prefix
 * length is not 64, which SLAAC needs; `prefix` is masked to its length. */
typedef struct NdiscPrefixInfo {
        struct in6_addr prefix;
        uint8_t prefixlen;
        bool onlink;
        bool autonomous;
        uint32_t valid_sec;
        uint32_t preferred_sec;
} NdiscPrefixInfo;

/* The longest name a DNSSL option can carry, as text, with its NUL. */
#define NDISC_DNSSL_NAME_MAX 254

/*
 * The fixed part of a router advertisement: at least NDISC_RA_HEADER_LEN
 * bytes, type 134, code 0. Preference 10 (reserved) reads as medium, as
 * RFC 4191 2.2 says. 0 or -EBADMSG.
 */
int ndisc_ra_parse_header(const uint8_t *buf, size_t len, NdiscRaHeader *ret);

/*
 * Walks the options of a router advertisement whose header has been checked.
 * ndisc_opt_iter_next() returns 1 with `ret` set, 0 at the end, or -EBADMSG
 * for an option of length zero or one running past the buffer: RFC 4861
 * 6.1.2 then has the whole advertisement dropped, so callers check with
 * ndisc_ra_check_options() before acting on any option.
 */
void ndisc_opt_iter_init(NdiscOptIter *it, const uint8_t *buf, size_t len);
int ndisc_opt_iter_next(NdiscOptIter *it, NdiscOpt *ret);

/* 0 when every option is well framed, or -EBADMSG. */
int ndisc_ra_check_options(const uint8_t *buf, size_t len);

/*
 * Typed decoders. Each returns 0, or -EBADMSG when the option is malformed;
 * the caller then skips that option and keeps the rest of the advertisement.
 *
 * Prefix: exactly 32 bytes, a prefix length of at most 128.
 * MTU: exactly 8 bytes.
 * RDNSS: at least 24 bytes and 8 plus a multiple of 16; *ret_n is the number
 *   of addresses, read with ndisc_opt_rdnss_addr().
 * DNSSL: at least 16 bytes, every name well formed (see ndisc_opt_dnssl_next()).
 */
int ndisc_opt_prefix(const NdiscOpt *opt, NdiscPrefixInfo *ret);
int ndisc_opt_mtu(const NdiscOpt *opt, uint32_t *ret);
int ndisc_opt_rdnss(const NdiscOpt *opt, uint32_t *ret_lifetime, size_t *ret_n);
void ndisc_opt_rdnss_addr(const NdiscOpt *opt, size_t i, struct in6_addr *ret);
int ndisc_opt_dnssl(const NdiscOpt *opt, uint32_t *ret_lifetime);

/*
 * The next domain of a DNSSL option checked by ndisc_opt_dnssl(), as dotted
 * text without a trailing dot. `*pos` starts at 0. Returns 1 with `name`
 * set, 0 at the end, -EBADMSG for a malformed name. Labels hold letters,
 * digits, '-' and '_' only, at most 63 bytes each, uncompressed: a name
 * written into resolv.conf must not be able to carry a space or a newline.
 * The root and "localhost" are skipped, as networkd skips them.
 */
int ndisc_opt_dnssl_next(const NdiscOpt *opt, size_t *pos, char name[NDISC_DNSSL_NAME_MAX]);

/*
 * A router solicitation into `buf` (at least 16 bytes): type 133, with a
 * source link-layer address option when `hw` is a 6 byte address. The kernel
 * fills the checksum of a raw ICMPv6 socket. Returns the length.
 */
size_t ndisc_rs_build(uint8_t *buf, const uint8_t *hw, size_t hw_len);

/* The deadline of a lifetime received at `now`: USEC_INFINITY for
 * NDISC_LIFETIME_INFINITE, saturating rather than wrapping otherwise. */
usec_t ndisc_lifetime_deadline(usec_t now, uint32_t sec);

/* Seconds left until `deadline`, rounded up, as the kernel takes a lifetime:
 * NDISC_LIFETIME_INFINITE for USEC_INFINITY, never more than that minus one
 * otherwise, 0 once it has passed. */
uint32_t ndisc_lifetime_remaining(usec_t now, usec_t deadline);

/*
 * The valid lifetime of a SLAAC address after a prefix option, RFC 4862
 * 5.5.3 e: an advertised lifetime above two hours, or beyond what is left,
 * is taken; otherwise what is left stays when it is two hours or less, and is
 * cut to two hours when it is more. `current` is the address's present
 * deadline, 0 when it has none yet, in which case the advertised one is
 * taken. A lifetime of zero thus cannot end an address at once.
 */
usec_t ndisc_slaac_valid_until(usec_t now, uint32_t advertised_sec, usec_t current);
