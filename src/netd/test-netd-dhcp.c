/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * N2/N3's acceptance test: the DHCPv4 client and server.
 *
 * Registered up front, placeholder body. What lands here (plan §2.8): a veth
 * pair inside a network namespace with netd's own client on one end and
 * netd's own server on the other, driven through DISCOVER/OFFER/REQUEST/ACK,
 * renewal at T1, and the mode-switch reconfigure the usb0 fallback scenario
 * needs -- plus golden-byte codec tests against packet dumps captured from
 * upstream. The golden bytes are not optional: a client and a server written
 * from the same misreading of RFC 2131 agree with each other perfectly.
 *
 * What it already exercises is the shim layer the whole lift rests on. Those
 * macros are hand-written replacements for GNU statement expressions
 * -Wpedantic rejects, so they are new code, not carried code, and they are
 * the substrate every lifted file will run on.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "dhcp/siphash24.h"
#include "dhcp/unaligned.h"
#include "netd-compat.h"

/*
 * The parameter request list. Upstream builds it with a Set of UINT8_TO_PTR
 * keys; netd uses a 256-bit bitmap, which is smaller, allocation-free, and
 * iterates in ascending option order -- the property the golden-byte tests
 * above will depend on.
 */
static void test_u8set(void) {
        NetdU8Set s;
        unsigned seen = 0;
        uint8_t last = 0;

        netd_u8set_clear(&s);
        ASSERT_EQ_INT(netd_u8set_size(&s), 0);
        ASSERT_TRUE(!netd_u8set_contains(&s, 42));

        ASSERT_EQ_INT(netd_u8set_put(&s, 42), 1);
        ASSERT_EQ_INT(netd_u8set_put(&s, 42), 0); /* already there */
        ASSERT_EQ_INT(netd_u8set_put(&s, 1), 1);
        ASSERT_EQ_INT(netd_u8set_put(&s, 255), 1);
        ASSERT_EQ_INT(netd_u8set_put(&s, 0), 1);
        ASSERT_EQ_INT(netd_u8set_size(&s), 4);

        ASSERT_TRUE(netd_u8set_contains(&s, 0));
        ASSERT_TRUE(netd_u8set_contains(&s, 255));
        ASSERT_TRUE(!netd_u8set_contains(&s, 254));

        /* Ascending, each member exactly once. */
        FOREACH_U8SET(v, &s) {
                if (seen > 0)
                        ASSERT_TRUE(v > last);
                last = v;
                seen++;
        }
        ASSERT_EQ_INT(seen, 4);
        ASSERT_EQ_INT(last, 255);

        ASSERT_EQ_INT(netd_u8set_remove(&s, 42), 1);
        ASSERT_EQ_INT(netd_u8set_remove(&s, 42), 0);
        ASSERT_EQ_INT(netd_u8set_size(&s), 3);
}

/* The standard-C stand-ins for upstream's statement-expression macros. */
static void test_ownership_macros(void) {
        char *p = strdup("lease");
        char *q;
        int fd = 7;
        int fd2;

        ASSERT_TRUE(p != NULL);
        q = TAKE_PTR(p);
        ASSERT_TRUE(p == NULL);
        ASSERT_STREQ(q, "lease");
        free(q);

        fd2 = TAKE_FD(fd);
        ASSERT_EQ_INT(fd2, 7);
        ASSERT_EQ_INT(fd, -1);

        ASSERT_TRUE(IN_SET(5, 1, 3, 5));
        ASSERT_TRUE(!IN_SET(4, 1, 3, 5));
}

/*
 * Unaligned access. This is the one that actually matters on the target: on
 * ARMv5TE a misaligned 32-bit load does not fault, it rotates the loaded
 * word, so a DHCP option value read through a plain uint32_t* comes back as
 * plausible garbage. Read at every offset, not just the aligned one.
 */
static void test_unaligned(void) {
        uint8_t buf[16];

        for (size_t off = 0; off < 8; off++) {
                memset(buf, 0, sizeof(buf));
                unaligned_write_be32(buf + off, 0xdeadbeefU);

                ASSERT_EQ_INT(buf[off], 0xde);
                ASSERT_EQ_INT(buf[off + 3], 0xef);
                ASSERT_EQ_INT(unaligned_read_be32(buf + off), 0xdeadbeefU);

                unaligned_write_be16(buf + off, 0x0102);
                ASSERT_EQ_INT(unaligned_read_be16(buf + off), 0x0102);
        }
}

/*
 * SipHash-2-4 against the reference vectors from the original paper, with the
 * canonical key 00..0f. Carried code gets checked against upstream's answer,
 * not against itself.
 */
static void test_siphash24(void) {
        static const uint8_t k[16] = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        };
        static const uint8_t in1[1] = { 0x00 };
        static const uint8_t in8[8] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

        ASSERT_TRUE(siphash24("", 0, k) == UINT64_C(0x726fdb47dd0e0e31));
        ASSERT_TRUE(siphash24(in1, sizeof(in1), k) == UINT64_C(0x74f839c593dc67fd));
        ASSERT_TRUE(siphash24(in8, sizeof(in8), k) == UINT64_C(0x93f5f5799a932462));
}

int main(void) {
        test_u8set();
        test_ownership_macros();
        test_unaligned();
        test_siphash24();

        printf("test-netd-dhcp: ok\n");
        return EXIT_SUCCESS;
}
