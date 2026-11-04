/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Interface identifiers for SLAAC addresses, as systemd-networkd makes them
 * (networkd-address-generation.c): modified EUI-64 from a 6 byte hardware
 * address (RFC 4291 2.5.1), the low 64 bits of a static token, and the
 * RFC 7217 stable identifier
 *
 *   RID = siphash24(key = secret, prefix[0..8] || ifname || hw_addr || dad_counter)
 *
 * whose secret is the machine's application-specific ID for networkd's
 * NDISC application ID, HMAC-SHA256 keyed by the machine ID as
 * sd_id128_get_machine_app_specific() makes it. A board moved from networkd
 * therefore keeps its SLAAC addresses. networkd also hashes the Wi-Fi SSID
 * when the link has one; netd does not follow SSIDs, so an explicit
 * prefixstable token on a wireless link differs from networkd's.
 *
 * Pure code: no I/O and no allocation.
 */

#pragma once

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* RFC 7217 5: how many identifiers to try before giving up on a prefix. */
#define NDISC_IID_STABLE_RETRIES 3

/* The secret for ndisc_iid_stable() from the 16 bytes of the machine ID. */
void ndisc_stable_secret(const uint8_t machine_id[16], uint8_t secret[16]);

/* prefix[0..8] and the modified EUI-64 of `hw`. 0, or -EINVAL unless `hw_len` is 6. */
int ndisc_iid_eui64(const struct in6_addr *prefix, const uint8_t *hw, size_t hw_len, struct in6_addr *ret);

/* prefix[0..8] and token[8..16]. */
void ndisc_iid_static(const struct in6_addr *prefix, const struct in6_addr *token, struct in6_addr *ret);

/*
 * The RFC 7217 address for one `dad_counter`. 0, or -EADDRNOTAVAIL when the
 * identifier falls in a range RFC 4291 and the IANA registry reserve
 * (subnet-router anycast, the reserved interface identifiers, the reserved
 * subnet anycast addresses); the caller then tries the next counter.
 */
int ndisc_iid_stable(
                const uint8_t secret[16],
                const struct in6_addr *prefix,
                const char *ifname,
                const uint8_t *hw,
                size_t hw_len,
                uint8_t dad_counter,
                struct in6_addr *ret);

/*
 * The first usable RFC 7217 address with a counter from `from` up to
 * NDISC_IID_STABLE_RETRIES - 1, with *ret_counter set to the counter used.
 * -EADDRINUSE when none is left.
 */
int ndisc_iid_stable_from(
                const uint8_t secret[16],
                const struct in6_addr *prefix,
                const char *ifname,
                const uint8_t *hw,
                size_t hw_len,
                uint8_t from,
                uint8_t *ret_counter,
                struct in6_addr *ret);
