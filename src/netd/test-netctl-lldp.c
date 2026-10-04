/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * `networkctl lldp` row parsing: the escaping round trip, ID formatting,
 * capability letters, and that nothing a neighbour sends can reach the
 * terminal as a control character.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "netctl-lldp.h"

static void test_unescape(void) {
        uint8_t out[8];

        ASSERT_EQ_INT(netctl_lldp_unescape(out, sizeof(out), "ab%20c%00", 9), 5);
        ASSERT_TRUE(memcmp(out, "ab c\0", 5) == 0);
        ASSERT_TRUE(netctl_lldp_unescape(out, sizeof(out), "%2", 2) == (size_t) -1);  /* truncated escape */
        ASSERT_TRUE(netctl_lldp_unescape(out, sizeof(out), "%zz", 3) == (size_t) -1); /* not hex */
        ASSERT_TRUE(netctl_lldp_unescape(out, 3, "abcd", 4) == (size_t) -1);          /* does not fit */
        ASSERT_EQ_INT(netctl_lldp_unescape(out, sizeof(out), "", 0), 0);
}

static void test_format_id(void) {
        char out[NETCTL_LLDP_ID_MAX];

        netctl_lldp_format_id(out, sizeof(out), 0, 4, (const uint8_t *) "\x00\x11\x22\xaa\xbb\xcc", 6);
        ASSERT_STREQ(out, "00:11:22:aa:bb:cc");
        netctl_lldp_format_id(out, sizeof(out), 1, 3, (const uint8_t *) "\x00\x11\x22\xaa\xbb\xcc", 6);
        ASSERT_STREQ(out, "00:11:22:aa:bb:cc");
        netctl_lldp_format_id(out, sizeof(out), 0, 5, (const uint8_t *) "\x01\xc0\xa8\x07\x02", 5);
        ASSERT_STREQ(out, "192.168.7.2");
        netctl_lldp_format_id(out, sizeof(out), 1, 5, (const uint8_t *) "Gi0/1", 5);
        ASSERT_STREQ(out, "Gi0/1");
        netctl_lldp_format_id(out, sizeof(out), 0, 7, (const uint8_t *) "\x01\x02\xff", 3);
        ASSERT_STREQ(out, "0102ff");
        /* A MAC subtype with the wrong length is shown as what it is, not as a MAC. */
        netctl_lldp_format_id(out, sizeof(out), 0, 4, (const uint8_t *) "ab", 2);
        ASSERT_STREQ(out, "ab");
        /* Long values are cut to the buffer. */
        {
                uint8_t big[255];
                char small[10];

                memset(big, 0xab, sizeof(big));
                netctl_lldp_format_id(small, sizeof(small), 0, 7, big, sizeof(big));
                ASSERT_TRUE(strlen(small) < sizeof(small));
        }
}

static void test_caps(void) {
        char caps[NETCTL_LLDP_CAPS_LEN];

        netctl_lldp_format_caps(caps, 0);
        ASSERT_STREQ(caps, "...........");
        netctl_lldp_format_caps(caps, (1u << 2) | (1u << 4) | (1u << 7));
        ASSERT_STREQ(caps, "..b.r..a...");
        netctl_lldp_format_caps(caps, 0xffff);
        ASSERT_STREQ(caps, "opbwrtdacsm");
}

static void test_row(void) {
        NetctlLldpRow row;

        ASSERT_TRUE(netctl_lldp_parse_row(
                        "N expires=1234 src=02:00:00:00:0a:01 scope=nearest-bridge chassis=4:%00%11%22%aa%bb%cc port=5:Gi0/1 "
                        "descr=uplink%20to%20core name=sw-1 caps=0014 enabled=0014 vlan=7",
                        "usb0",
                        &row));
        ASSERT_STREQ(row.link, "usb0");
        ASSERT_STREQ(row.chassis, "00:11:22:aa:bb:cc");
        ASSERT_STREQ(row.port, "Gi0/1");
        ASSERT_STREQ(row.descr, "uplink to core");
        ASSERT_STREQ(row.name, "sw-1");
        ASSERT_STREQ(row.caps, "..b.r......");
        ASSERT_TRUE(row.expires == 1234);

        /* Optional fields absent. */
        ASSERT_TRUE(netctl_lldp_parse_row("N chassis=7:abc port=7:1", "x", &row));
        ASSERT_STREQ(row.name, "");
        ASSERT_STREQ(row.caps, "...........");

        /* A neighbour's escape sequence, newline and 8-bit bytes never reach the output raw. */
        ASSERT_TRUE(netctl_lldp_parse_row("N chassis=7:a port=7:b name=%1b[31mred%0a%ff", "x", &row));
        ASSERT_STREQ(row.name, "?[31mred??");

        /* Not rows. */
        ASSERT_TRUE(!netctl_lldp_parse_row("IFNAME=usb0", "x", &row));
        ASSERT_TRUE(!netctl_lldp_parse_row("N port=7:b", "x", &row));             /* no chassis */
        ASSERT_TRUE(!netctl_lldp_parse_row("N chassis=7:a", "x", &row));          /* no port */
        ASSERT_TRUE(!netctl_lldp_parse_row("N chassis=abc port=7:b", "x", &row)); /* no subtype */
        ASSERT_TRUE(!netctl_lldp_parse_row("N chassis=7:%zz port=7:b", "x", &row));
        ASSERT_TRUE(!netctl_lldp_parse_row("", "x", &row));
}

int main(void) {
        test_unescape();
        test_format_id();
        test_caps();
        test_row();
        printf("test-netctl-lldp: ok\n");
        return EXIT_SUCCESS;
}
