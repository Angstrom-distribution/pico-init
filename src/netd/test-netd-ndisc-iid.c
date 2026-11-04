/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * SLAAC interface identifiers against fixed vectors. The RFC 7217 vectors
 * were computed with a separate Python implementation of the algorithm in
 * systemd's networkd-address-generation.c (hmac/hashlib from the Python
 * standard library and a SipHash-2-4 checked against the reference vector of
 * the SipHash paper), not with a running networkd.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../test-util.h"
#include "ndisc/ndisc-iid.h"

static const uint8_t machine_id[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

static struct in6_addr addr(const char *s) {
        struct in6_addr a;

        ASSERT_EQ_INT(inet_pton(AF_INET6, s, &a), 1);
        return a;
}

static void assert_addr(const struct in6_addr *a, const char *want) {
        char buf[INET6_ADDRSTRLEN];

        ASSERT_TRUE(inet_ntop(AF_INET6, a, buf, sizeof(buf)) != NULL);
        ASSERT_STREQ(buf, want);
}

static void test_secret(void) {
        static const uint8_t want[16] = {
                0x0a, 0x1e, 0x63, 0x0d, 0x41, 0x88, 0x48, 0x72,
                0x9d, 0xfe, 0x50, 0x6f, 0x29, 0x17, 0x86, 0xf4,
        };
        uint8_t secret[16];

        ndisc_stable_secret(machine_id, secret);
        ASSERT_TRUE(memcmp(secret, want, 16) == 0);
}

static void test_stable_vectors(void) {
        static const struct {
                const char *ifname;
                bool hw;
                const char *want[NDISC_IID_STABLE_RETRIES];
        } cases[] = {
                { "eth0",
                 true, { "2001:db8:1:0:edd8:a203:4fdd:d76b",
 "2001:db8:1:0:40e8:e7ce:2cce:f758",
 "2001:db8:1:0:186b:8664:4eef:871a" } },
                { "usb0",
                 false, { "2001:db8:1:0:b920:a2c3:a01e:a00",
 "2001:db8:1:0:c3cf:ad44:e01d:eef5",
 "2001:db8:1:0:19ca:917f:3f6c:a391" } },
        };
        static const uint8_t hw[6] = { 0x02, 0, 0, 0, 0, 0x01 };
        struct in6_addr prefix = addr("2001:db8:1::"), a;
        uint8_t secret[16], used;

        ndisc_stable_secret(machine_id, secret);

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
                for (uint8_t c = 0; c < NDISC_IID_STABLE_RETRIES; c++) {
                        ASSERT_EQ_INT(ndisc_iid_stable(
                                                      secret,
                                                      &prefix,
                                                      cases[i].ifname,
                                                      cases[i].hw ? hw : NULL,
                                                      cases[i].hw ? 6 : 0,
                                                      c,
                                                      &a),
                                      0);
                        assert_addr(&a, cases[i].want[c]);
                }

        ASSERT_EQ_INT(ndisc_iid_stable_from(secret, &prefix, "eth0", hw, 6, 1, &used, &a), 0);
        ASSERT_EQ_INT(used, 1);
        assert_addr(&a, "2001:db8:1:0:40e8:e7ce:2cce:f758");
        ASSERT_EQ_INT(ndisc_iid_stable_from(secret, &prefix, "eth0", hw, 6, 3, &used, &a), -EADDRINUSE);
}

/* networkd checks the generated address against the reserved ranges as a
 * whole address, so a prefix inside one of them never yields an identifier. */
static void test_stable_reserved(void) {
        struct in6_addr a, zero = addr("::"), anycast = addr("fdff:ffff:ffff:ff80::");
        uint8_t secret[16], used;

        ndisc_stable_secret(machine_id, secret);
        ASSERT_EQ_INT(ndisc_iid_stable(secret, &zero, "eth0", NULL, 0, 0, &a), -EADDRNOTAVAIL);
        ASSERT_EQ_INT(ndisc_iid_stable_from(secret, &anycast, "eth0", NULL, 0, 0, &used, &a), -EADDRINUSE);
}

static void test_eui64_and_static(void) {
        static const uint8_t hw[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
        struct in6_addr prefix = addr("2001:db8:1::"), token = addr("::1:2:3:4"), a;

        ASSERT_EQ_INT(ndisc_iid_eui64(&prefix, hw, 6, &a), 0);
        assert_addr(&a, "2001:db8:1:0:211:22ff:fe33:4455");
        ASSERT_EQ_INT(ndisc_iid_eui64(&prefix, hw, 0, &a), -EINVAL);
        ASSERT_EQ_INT(ndisc_iid_eui64(&prefix, NULL, 6, &a), -EINVAL);

        token = addr("ffff::1:2:3:4");
        ndisc_iid_static(&prefix, &token, &a);
        assert_addr(&a, "2001:db8:1:0:1:2:3:4");
}

int main(void) {
        test_secret();
        test_stable_vectors();
        test_stable_reserved();
        test_eui64_and_static();

        printf("test-netd-ndisc-iid: all checks passed\n");
        return 0;
}
