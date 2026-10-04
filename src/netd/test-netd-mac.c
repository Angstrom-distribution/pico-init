/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * GOAL B: persistent MAC derivation for a random-hardware-address link
 * (netd-link.c's link_apply_persistent_mac(), via the exposed pure helper
 * netd_persistent_mac_derive() -- see netd-link.h's own comment on why that
 * split exists).
 *
 * The four fixed (machine_id, ifname) -> mac vectors below were computed
 * independently with a from-scratch Python SipHash-2-4 implementation
 * (RFC-faithful, cross-checked against the three published reference
 * vectors for key 000102...0f and inputs of length 0/1/2 before trusting it
 * for these), not derived from or copied out of netd-link.c itself -- a
 * mirrored bug in both the reference and the implementation would
 * otherwise pass this test silently. Algorithm under test:
 *
 *   v = machine_id (16 bytes) || ifname (strlen bytes, no NUL)
 *   mac = low 6 bytes of htole64(siphash24(v, PERSISTENT_MAC_HASH_KEY))
 *   mac[0] &= 0xfe (clear multicast); mac[0] |= 0x02 (set local-admin)
 *
 * matching systemd's net_get_unique_predictable_data_from_name() +
 * net_verify_hardware_address() (netif-util.c), with PERSISTENT_MAC_HASH_KEY
 * = that file's own HASH_KEY (netd-link.c cites it by name).
 *
 * What this file does NOT cover: the exemption gating in
 * link_apply_persistent_mac() itself (loopback, already-up, addr_assign_type
 * PERM/SET/STOLEN, missing machine-id) -- each needs a live Link with a real
 * ifindex/flags/arp_type, the way test-netd-rtnl.c's netns/veth fixtures
 * give test-netd-rtnl.c one. Left as a follow-up rather than built here.
 */

#include <string.h>

#include "../test-util.h"
#include "netd-link.h"

static void format_mac(const uint8_t mac[NETD_HW_ADDR_MAX], char *out, size_t bufsize) {
        snprintf(out, bufsize, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

typedef struct Vector {
        const char *machine_id_hex; /* 32 hex chars, no dashes */
        const char *ifname;
        const char *expected_mac;
} Vector;

static const Vector vectors[] = {
        { "0123456789abcdef0123456789abcdef",  "usb0", "be:ac:c6:0e:54:77" },
        { "0123456789abcdef0123456789abcdef",  "eth1", "c2:31:8e:a4:e8:98" },
        { "fedcba9876543210fedcba9876543210",  "usb0", "9a:2e:7d:bb:ca:09" },
        { "00000000000000000000000000000000", "wlan0", "7e:13:d6:f3:c4:00" },
};

static void hex_to_id128(const char *hex, uint8_t out[16]) {
        for (size_t i = 0; i < 16; i++) {
                unsigned v;

                ASSERT_TRUE(sscanf(hex + i * 2, "%2x", &v) == 1);
                out[i] = (uint8_t) v;
        }
}

/* Every vector matches the independently-computed expected MAC exactly. */
static void test_fixed_vectors(void) {
        for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
                uint8_t mid[16], mac[NETD_HW_ADDR_MAX];
                char got[32];

                hex_to_id128(vectors[i].machine_id_hex, mid);
                netd_persistent_mac_derive(mid, vectors[i].ifname, mac);
                format_mac(mac, got, sizeof got);

                ASSERT_STREQ(got, vectors[i].expected_mac);
        }
}

/* net_verify_hardware_address()'s own unconditional fixup (netif-util.c):
 * every generated MAC has the multicast bit clear and the local-admin bit
 * set -- true for every vector, and for vectors[0]/vectors[2] specifically
 * because the RAW (pre-fixup) low byte has the opposite of one of those
 * bits (0xbc and 0x9b respectively, confirmed against the same reference
 * implementation that produced the expected vectors above), so this is
 * checking the fixup actually ran, not a tautology the raw bytes already
 * satisfied. */
static void test_bit_fixup(void) {
        for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
                uint8_t mid[16], mac[NETD_HW_ADDR_MAX];

                hex_to_id128(vectors[i].machine_id_hex, mid);
                netd_persistent_mac_derive(mid, vectors[i].ifname, mac);

                ASSERT_EQ_INT(mac[0] & 0x01, 0);    /* multicast bit clear */
                ASSERT_EQ_INT(mac[0] & 0x02, 0x02); /* local-admin bit set */
        }
}

/* Same (machine_id, ifname) in twice, byte-for-byte identical mac out --
 * no hidden randomness, no state carried between calls. */
static void test_deterministic(void) {
        uint8_t mid[16], mac_a[NETD_HW_ADDR_MAX], mac_b[NETD_HW_ADDR_MAX];

        hex_to_id128(vectors[0].machine_id_hex, mid);
        netd_persistent_mac_derive(mid, vectors[0].ifname, mac_a);
        netd_persistent_mac_derive(mid, vectors[0].ifname, mac_b);

        ASSERT_TRUE(memcmp(mac_a, mac_b, sizeof mac_a) == 0);
}

/* A different ifname under the same machine id, and a different machine id
 * under the same ifname, each produce a different MAC -- vectors[0] vs [1]
 * (name differs), vectors[0] vs [2] (id differs). Not a cryptographic
 * proof of no collisions in general, just that this function is not
 * silently collapsing onto one constant output. */
static void test_distinguishes_inputs(void) {
        char a[32], b[32], c[32];
        uint8_t mid[16], mac[NETD_HW_ADDR_MAX];

        hex_to_id128(vectors[0].machine_id_hex, mid);
        netd_persistent_mac_derive(mid, vectors[0].ifname, mac);
        format_mac(mac, a, sizeof a);

        netd_persistent_mac_derive(mid, vectors[1].ifname, mac);
        format_mac(mac, b, sizeof b);

        hex_to_id128(vectors[2].machine_id_hex, mid);
        netd_persistent_mac_derive(mid, vectors[0].ifname, mac);
        format_mac(mac, c, sizeof c);

        ASSERT_TRUE(strcmp(a, b) != 0);
        ASSERT_TRUE(strcmp(a, c) != 0);
}

int main(void) {
        test_fixed_vectors();
        test_bit_fixup();
        test_deterministic();
        test_distinguishes_inputs();
        return 0;
}
