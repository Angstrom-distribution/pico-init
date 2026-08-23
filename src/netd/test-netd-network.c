/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * N0's acceptance test: the .network parser.
 *
 * Registered up front, placeholder body. What lands here when the parser does
 * (plan §2.5, §2.8): fixture trees containing verbatim copies of this
 * project's two real files -- usb0.network and usb0-server.network -- the
 * basename-shadowing rule across all three search-path directories, the
 * lexicographic ordering and first-match-wins semantics, [Match] Name= glob
 * matching, and the drop-in tolerance rule (an unknown section or directive
 * is a debug message, not a failure).
 *
 * What it can already assert is not nothing: the defaults. Every [DHCPv4]
 * default is a decision, and UseTimezone= is the one netd exists for.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "netd-network.h"

/* A .network that sets nothing must still come back with netd's defaults --
 * in particular UseTimezone=yes, which is where netd deliberately parts
 * company with networkd. */
static void test_defaults(void) {
        Network *nw = NULL;

        ASSERT_EQ_INT(network_new(&nw), 0);
        ASSERT_TRUE(nw != NULL);

        ASSERT_EQ_INT(nw->dhcp, NETWORK_DHCP_NO);
        ASSERT_TRUE(!nw->dhcp_server);
        ASSERT_EQ_INT(nw->n_addresses, 0);

        ASSERT_TRUE(nw->dhcp_use_dns);
        ASSERT_TRUE(nw->dhcp_use_ntp);
        ASSERT_TRUE(nw->dhcp_use_timezone);

        ASSERT_TRUE(network_free(nw) == NULL);
}

/* DHCP= is an address-family selector upstream, not a boolean, and netd
 * parses the whole set so a file written for networkd keeps its meaning. */
static void test_dhcp_spellings(void) {
        ASSERT_EQ_INT(network_dhcp_from_string("yes"), NETWORK_DHCP_YES);
        ASSERT_EQ_INT(network_dhcp_from_string("true"), NETWORK_DHCP_YES);
        ASSERT_EQ_INT(network_dhcp_from_string("1"), NETWORK_DHCP_YES);
        ASSERT_EQ_INT(network_dhcp_from_string("ipv4"), NETWORK_DHCP_IPV4);
        ASSERT_EQ_INT(network_dhcp_from_string("ipv6"), NETWORK_DHCP_IPV6);
        ASSERT_EQ_INT(network_dhcp_from_string("no"), NETWORK_DHCP_NO);
        ASSERT_EQ_INT(network_dhcp_from_string("off"), NETWORK_DHCP_NO);
        ASSERT_EQ_INT(network_dhcp_from_string("maybe"), _NETWORK_DHCP_INVALID);

        ASSERT_STREQ(network_dhcp_to_string(NETWORK_DHCP_IPV4), "ipv4");
}

/* Only YES and IPV4 arm the v4 client. An IPv6-only file parses and does
 * nothing, rather than being rejected (§2.9: all of IPv6 is out of scope). */
static void test_dhcp4_enabled(void) {
        Network *nw = NULL;

        ASSERT_EQ_INT(network_new(&nw), 0);

        nw->dhcp = NETWORK_DHCP_NO;
        ASSERT_TRUE(!network_dhcp4_enabled(nw));
        nw->dhcp = NETWORK_DHCP_IPV6;
        ASSERT_TRUE(!network_dhcp4_enabled(nw));
        nw->dhcp = NETWORK_DHCP_IPV4;
        ASSERT_TRUE(network_dhcp4_enabled(nw));
        nw->dhcp = NETWORK_DHCP_YES;
        ASSERT_TRUE(network_dhcp4_enabled(nw));

        ASSERT_TRUE(!network_dhcp4_enabled(NULL));

        network_free(nw);
}

int main(void) {
        test_defaults();
        test_dhcp_spellings();
        test_dhcp4_enabled();

        printf("test-netd-network: ok\n");
        return EXIT_SUCCESS;
}
