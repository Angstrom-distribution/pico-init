/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* See ndisc-iid.h. */

#include "ndisc-iid.h"

#include <endian.h>
#include <errno.h>
#include <string.h>

#include "../../compat/libsystemd/hmac-sha256.h"
#include "dhcp/siphash24.h"

/* networkd-address-generation.c's NDISC_APP_ID. */
static const uint8_t ndisc_app_id[16] = {
        0x13, 0xac, 0x81, 0xa7, 0xd5, 0x3f, 0x49, 0x78, 0x92, 0x79, 0x5d, 0x0c, 0x29, 0x3a, 0xbc, 0x7e,
};

void ndisc_stable_secret(const uint8_t machine_id[16], uint8_t secret[16]) {
        uint8_t digest[SHA256_DIGEST_SIZE];

        hmac_sha256(machine_id, 16, ndisc_app_id, sizeof(ndisc_app_id), digest);
        memcpy(secret, digest, 16);

        /* sd_id128_get_app_specific() returns a version 4 UUID. */
        secret[6] = (uint8_t) ((secret[6] & 0x0f) | 0x40);
        secret[8] = (uint8_t) ((secret[8] & 0x3f) | 0x80);
}

int ndisc_iid_eui64(const struct in6_addr *prefix, const uint8_t *hw, size_t hw_len, struct in6_addr *ret) {
        if (!hw || hw_len != 6)
                return -EINVAL;

        memcpy(ret->s6_addr, prefix->s6_addr, 8);
        ret->s6_addr[8] = hw[0] ^ 0x02;
        ret->s6_addr[9] = hw[1];
        ret->s6_addr[10] = hw[2];
        ret->s6_addr[11] = 0xff;
        ret->s6_addr[12] = 0xfe;
        ret->s6_addr[13] = hw[3];
        ret->s6_addr[14] = hw[4];
        ret->s6_addr[15] = hw[5];
        return 0;
}

void ndisc_iid_static(const struct in6_addr *prefix, const struct in6_addr *token, struct in6_addr *ret) {
        memcpy(ret->s6_addr, prefix->s6_addr, 8);
        memcpy(ret->s6_addr + 8, token->s6_addr + 8, 8);
}

/* True when the first `bits` bits of `a` are those of `range`. */
static bool covers(const uint8_t *range, unsigned bits, const struct in6_addr *a) {
        unsigned full = bits / 8, rest = bits % 8;

        if (memcmp(range, a->s6_addr, full) != 0)
                return false;

        return rest == 0 || ((range[full] ^ a->s6_addr[full]) & (uint8_t) (0xff00u >> rest)) == 0;
}

/* networkd's stable_private_address_is_valid(), over the whole address as it
 * is written there. */
static bool stable_address_usable(const struct in6_addr *a) {
        static const uint8_t subnet_router_anycast[16] = { 0 };
        static const uint8_t reserved_iids[16] = { 0x02, 0x00, 0x5e, 0xff, 0xfe };
        static const uint8_t reserved_subnet_anycast[16] = { 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80 };

        return !covers(subnet_router_anycast, 64, a) && !covers(reserved_iids, 40, a) &&
                        !covers(reserved_subnet_anycast, 57, a);
}

int ndisc_iid_stable(
                const uint8_t secret[16],
                const struct in6_addr *prefix,
                const char *ifname,
                const uint8_t *hw,
                size_t hw_len,
                uint8_t dad_counter,
                struct in6_addr *ret) {
        struct siphash state;
        uint64_t rid;

        siphash24_init(&state, secret);
        siphash24_compress(prefix->s6_addr, 8, &state);
        siphash24_compress(ifname, strlen(ifname), &state);
        if (hw && hw_len > 0)
                siphash24_compress(hw, hw_len, &state);
        siphash24_compress(&dad_counter, 1, &state);

        rid = htole64(siphash24_finalize(&state));

        memcpy(ret->s6_addr, prefix->s6_addr, 8);
        memcpy(ret->s6_addr + 8, &rid, 8);

        return stable_address_usable(ret) ? 0 : -EADDRNOTAVAIL;
}

int ndisc_iid_stable_from(
                const uint8_t secret[16],
                const struct in6_addr *prefix,
                const char *ifname,
                const uint8_t *hw,
                size_t hw_len,
                uint8_t from,
                uint8_t *ret_counter,
                struct in6_addr *ret) {
        for (unsigned c = from; c < NDISC_IID_STABLE_RETRIES; c++)
                if (ndisc_iid_stable(secret, prefix, ifname, hw, hw_len, (uint8_t) c, ret) == 0) {
                        *ret_counter = (uint8_t) c;
                        return 0;
                }

        return -EADDRINUSE;
}
