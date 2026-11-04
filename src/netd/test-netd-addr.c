/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netd-addr.c: literal parsing, masking, comparison and formatting for both
 * families. Pure functions; no kernel state is touched except the one stat()
 * behind netd_ipv6_supported(), whose result is not asserted.
 */

#include <errno.h>
#include <string.h>

#include "../test-util.h"
#include "netd-addr.h"

static void test_parse_v4(void) {
        NetdInAddr a;
        int f = 0;
        char buf[INET6_ADDRSTRLEN];

        ASSERT_EQ_INT(netd_addr_parse("192.168.7.2", &f, &a), 0);
        ASSERT_EQ_INT(f, AF_INET);
        ASSERT_STREQ(netd_addr_to_string(f, &a, buf), "192.168.7.2");
        ASSERT_EQ_INT(a.bytes[4], 0);
        ASSERT_EQ_INT(a.bytes[15], 0);

        ASSERT_EQ_INT(netd_addr_parse("", &f, &a), -EINVAL);
        ASSERT_EQ_INT(netd_addr_parse("192.168.7", &f, &a), -EINVAL);
        ASSERT_EQ_INT(netd_addr_parse("192.168.7.256", &f, &a), -EINVAL);
        ASSERT_EQ_INT(netd_addr_parse("192.168.7.2 ", &f, &a), -EINVAL);
        ASSERT_EQ_INT(netd_addr_parse("192.168.7.2x", &f, &a), -EINVAL);
        ASSERT_EQ_INT(netd_addr_parse("192.168.7.2:80", &f, &a), -EINVAL);
        ASSERT_EQ_INT(netd_addr_parse("example.org", &f, &a), -EINVAL);
        ASSERT_EQ_INT(netd_addr_parse(NULL, &f, &a), -EINVAL);
}

static void test_parse_v6(void) {
        NetdInAddr a;
        int f = 0;
        char buf[INET6_ADDRSTRLEN];

        ASSERT_EQ_INT(netd_addr_parse("fd00::1", &f, &a), 0);
        ASSERT_EQ_INT(f, AF_INET6);
        ASSERT_STREQ(netd_addr_to_string(f, &a, buf), "fd00::1");
        ASSERT_EQ_INT(a.bytes[0], 0xfd);
        ASSERT_EQ_INT(a.bytes[15], 1);

        ASSERT_EQ_INT(netd_addr_parse("2001:db8:0:0:0:0:0:2", &f, &a), 0);
        ASSERT_STREQ(netd_addr_to_string(f, &a, buf), "2001:db8::2");

        ASSERT_EQ_INT(netd_addr_parse("::ffff:10.0.0.1", &f, &a), 0);
        ASSERT_EQ_INT(f, AF_INET6);

        ASSERT_EQ_INT(netd_addr_parse("fe80::1%eth0", &f, &a), -EINVAL);
        ASSERT_EQ_INT(netd_addr_parse("fd00::1 ", &f, &a), -EINVAL);
        ASSERT_EQ_INT(netd_addr_parse("fd00::1g", &f, &a), -EINVAL);
        ASSERT_EQ_INT(netd_addr_parse("fd00:::1", &f, &a), -EINVAL);
        ASSERT_EQ_INT(netd_addr_parse("[fd00::1]", &f, &a), -EINVAL);
}

static void test_prefix_parse(void) {
        NetdInAddr a;
        int f = 0;
        unsigned char plen = 0;

        ASSERT_EQ_INT(netd_prefix_parse("10.1.2.3/24", &f, &a, &plen), 0);
        ASSERT_EQ_INT(f, AF_INET);
        ASSERT_EQ_INT(plen, 24);
        ASSERT_EQ_INT(a.bytes[3], 3);

        ASSERT_EQ_INT(netd_prefix_parse("10.1.2.3/0", &f, &a, &plen), 0);
        ASSERT_EQ_INT(plen, 0);
        ASSERT_EQ_INT(netd_prefix_parse("10.1.2.3/32", &f, &a, &plen), 0);
        ASSERT_EQ_INT(plen, 32);
        ASSERT_EQ_INT(netd_prefix_parse("10.1.2.3/33", &f, &a, &plen), -EINVAL);

        ASSERT_EQ_INT(netd_prefix_parse("fd00::1/64", &f, &a, &plen), 0);
        ASSERT_EQ_INT(f, AF_INET6);
        ASSERT_EQ_INT(plen, 64);
        ASSERT_EQ_INT(netd_prefix_parse("fd00::1/128", &f, &a, &plen), 0);
        ASSERT_EQ_INT(plen, 128);
        ASSERT_EQ_INT(netd_prefix_parse("fd00::1/129", &f, &a, &plen), -EINVAL);

        ASSERT_EQ_INT(netd_prefix_parse("10.1.2.3", &f, &a, &plen), -EINVAL);
        ASSERT_EQ_INT(netd_prefix_parse("fd00::1", &f, &a, &plen), -EINVAL);
        ASSERT_EQ_INT(netd_prefix_parse("10.1.2.3/", &f, &a, &plen), -EINVAL);
        ASSERT_EQ_INT(netd_prefix_parse("/24", &f, &a, &plen), -EINVAL);
        ASSERT_EQ_INT(netd_prefix_parse("10.1.2.3/2x", &f, &a, &plen), -EINVAL);
        ASSERT_EQ_INT(netd_prefix_parse("10.1.2.3/-1", &f, &a, &plen), -EINVAL);
        ASSERT_EQ_INT(netd_prefix_parse("10.1.2.3/ 24", &f, &a, &plen), -EINVAL);
        ASSERT_EQ_INT(netd_prefix_parse("10.1.2.3/1000", &f, &a, &plen), -EINVAL);
        ASSERT_EQ_INT(netd_prefix_parse("10.1.2.3/24/8", &f, &a, &plen), -EINVAL);
        ASSERT_EQ_INT(netd_prefix_parse("fe80::1%eth0/64", &f, &a, &plen), -EINVAL);
        ASSERT_EQ_INT(netd_prefix_parse("10.1.2.3/24 ", &f, &a, &plen), -EINVAL);
        ASSERT_EQ_INT(netd_prefix_parse(
                                      "this-is-a-name-that-is-far-too-long-to-be-an-address-literal/24",
                                      &f,
                                      &a,
                                      &plen),
                      -EINVAL);
}

static void test_mask(void) {
        NetdInAddr a;
        int f;
        char buf[INET6_ADDRSTRLEN];

        ASSERT_EQ_INT(netd_addr_parse("10.1.2.3", &f, &a), 0);
        netd_addr_mask(f, &a, 24);
        ASSERT_STREQ(netd_addr_to_string(f, &a, buf), "10.1.2.0");

        ASSERT_EQ_INT(netd_addr_parse("10.255.255.255", &f, &a), 0);
        netd_addr_mask(f, &a, 12);
        ASSERT_STREQ(netd_addr_to_string(f, &a, buf), "10.240.0.0");

        ASSERT_EQ_INT(netd_addr_parse("10.1.2.3", &f, &a), 0);
        netd_addr_mask(f, &a, 0);
        ASSERT_STREQ(netd_addr_to_string(f, &a, buf), "0.0.0.0");

        ASSERT_EQ_INT(netd_addr_parse("10.1.2.3", &f, &a), 0);
        netd_addr_mask(f, &a, 32);
        ASSERT_STREQ(netd_addr_to_string(f, &a, buf), "10.1.2.3");

        ASSERT_EQ_INT(netd_addr_parse("2001:db8:1:2:3:4:5:6", &f, &a), 0);
        netd_addr_mask(f, &a, 64);
        ASSERT_STREQ(netd_addr_to_string(f, &a, buf), "2001:db8:1:2::");

        ASSERT_EQ_INT(netd_addr_parse("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", &f, &a), 0);
        netd_addr_mask(f, &a, 35);
        ASSERT_STREQ(netd_addr_to_string(f, &a, buf), "2001:db8:e000::");

        ASSERT_EQ_INT(netd_addr_parse("2001:db8::1", &f, &a), 0);
        netd_addr_mask(f, &a, 128);
        ASSERT_STREQ(netd_addr_to_string(f, &a, buf), "2001:db8::1");
}

static void test_eq_and_predicates(void) {
        NetdInAddr a, b;
        int f;

        ASSERT_EQ_INT(netd_addr_parse("10.0.0.1", &f, &a), 0);
        ASSERT_EQ_INT(netd_addr_parse("10.0.0.1", &f, &b), 0);
        ASSERT_TRUE(netd_addr_eq(AF_INET, &a, &b));
        ASSERT_EQ_INT(netd_addr_parse("10.0.0.2", &f, &b), 0);
        ASSERT_TRUE(!netd_addr_eq(AF_INET, &a, &b));

        ASSERT_EQ_INT(netd_addr_parse("fd00::1", &f, &a), 0);
        ASSERT_EQ_INT(netd_addr_parse("fd00::1", &f, &b), 0);
        ASSERT_TRUE(netd_addr_eq(AF_INET6, &a, &b));
        ASSERT_EQ_INT(netd_addr_parse("fd00::2", &f, &b), 0);
        ASSERT_TRUE(!netd_addr_eq(AF_INET6, &a, &b));

        ASSERT_EQ_INT(netd_addr_parse("0.0.0.0", &f, &a), 0);
        ASSERT_TRUE(netd_addr_is_null(AF_INET, &a));
        ASSERT_EQ_INT(netd_addr_parse("::", &f, &a), 0);
        ASSERT_TRUE(netd_addr_is_null(AF_INET6, &a));
        ASSERT_EQ_INT(netd_addr_parse("::1", &f, &a), 0);
        ASSERT_TRUE(!netd_addr_is_null(AF_INET6, &a));
        ASSERT_TRUE(netd_addr_is_loopback(AF_INET6, &a));
        ASSERT_EQ_INT(netd_addr_parse("::2", &f, &a), 0);
        ASSERT_TRUE(!netd_addr_is_loopback(AF_INET6, &a));

        ASSERT_EQ_INT(netd_addr_parse("127.1.2.3", &f, &a), 0);
        ASSERT_TRUE(netd_addr_is_loopback(AF_INET, &a));
        ASSERT_EQ_INT(netd_addr_parse("128.0.0.1", &f, &a), 0);
        ASSERT_TRUE(!netd_addr_is_loopback(AF_INET, &a));

        ASSERT_EQ_INT(netd_addr_parse("169.254.3.4", &f, &a), 0);
        ASSERT_TRUE(netd_addr_is_link_local(AF_INET, &a));
        ASSERT_EQ_INT(netd_addr_parse("169.253.3.4", &f, &a), 0);
        ASSERT_TRUE(!netd_addr_is_link_local(AF_INET, &a));

        ASSERT_EQ_INT(netd_addr_parse("fe80::1", &f, &a), 0);
        ASSERT_TRUE(netd_addr_is_link_local(AF_INET6, &a));
        ASSERT_EQ_INT(netd_addr_parse("febf::1", &f, &a), 0);
        ASSERT_TRUE(netd_addr_is_link_local(AF_INET6, &a));
        ASSERT_EQ_INT(netd_addr_parse("fec0::1", &f, &a), 0);
        ASSERT_TRUE(!netd_addr_is_link_local(AF_INET6, &a));
}

static void test_to_string_unknown_family(void) {
        NetdInAddr a;
        char buf[INET6_ADDRSTRLEN];

        memset(&a, 0, sizeof(a));
        ASSERT_STREQ(netd_addr_to_string(AF_UNSPEC, &a, buf), "?");
}

int main(void) {
        test_parse_v4();
        test_parse_v6();
        test_prefix_parse();
        test_mask();
        test_eq_and_predicates();
        test_to_string_unknown_family();

        (void) netd_ipv6_supported();

        printf("test-netd-addr: all checks passed\n");
        return 0;
}
