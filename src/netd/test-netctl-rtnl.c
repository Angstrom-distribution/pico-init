/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Golden-byte tests for netctl_rtnl_decode_link() (netctl-rtnl.c): the
 * attribute decode netctl's own `status <iface>` relies on, fed hand-built
 * RTM_NEWLINK reply buffers rather than a real netlink socket, as
 * test-netd-codec.c does for the DHCP wire format.
 *
 * Fixtures are built with netd-rtnl-core.c's own nl_req_init()/nl_reserve()/
 * nl_add_attr() (this program links netd-rtnl-core.c and nothing else of
 * netd's) rather than literal byte arrays, so NLMSG_ALIGN/RTA_ALIGN padding
 * is right by construction.
 */

#include <errno.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <string.h>

#include "../test-util.h"
#include "netctl-rtnl.h"
#include "netd-rtnl-core.h"

/* Same fallback discipline as netctl-rtnl.c itself, for a kernel-headers
 * vintage that predates these. */
#ifndef IFLA_MIN_MTU
#        define IFLA_MIN_MTU 50
#endif
#ifndef IFLA_MAX_MTU
#        define IFLA_MAX_MTU 51
#endif
#ifndef IFLA_PROP_LIST
#        define IFLA_PROP_LIST 52
#endif
#ifndef IFLA_ALT_IFNAME
#        define IFLA_ALT_IFNAME 53
#endif
#ifndef IFLA_INET6_ADDR_GEN_MODE
#        define IFLA_INET6_ADDR_GEN_MODE 8
#endif

/* Appends one rtattr into a plain byte buffer, for building the nested
 * IFLA_AF_SPEC -> AF_INET6 -> IFLA_INET6_ADDR_GEN_MODE blob below --
 * nl_add_attr() itself only appends to a top-level struct nl_request, not
 * to an arbitrary nested payload, so this is the same append logic
 * reapplied one level down. */
static size_t append_rta(uint8_t *buf, size_t cap, size_t pos, uint16_t type, const void *data, size_t datalen) {
        struct rtattr *rta;
        size_t rtalen = RTA_LENGTH(datalen);
        size_t total = RTA_ALIGN(rtalen);

        ASSERT_TRUE(pos + total <= cap);

        rta = (struct rtattr *) (buf + pos);
        memset(rta, 0, total);
        rta->rta_type = type;
        rta->rta_len = (unsigned short) rtalen;
        if (datalen)
                memcpy(RTA_DATA(rta), data, datalen);

        return pos + total;
}

/* Base fixture: a bare ifinfomsg, no attributes yet -- every test below adds
 * to this. `req` is the caller's; this just does the RTM_NEWLINK/ifinfomsg
 * part every case needs. */
static void init_base(struct nl_request *req) {
        struct nlmsghdr *nlh;
        struct ifinfomsg *ifi;

        nlh = nl_req_init(req, RTM_NEWLINK, 0);
        ASSERT_TRUE(nlh != NULL);

        ifi = nl_reserve(req, sizeof(*ifi));
        ASSERT_TRUE(ifi != NULL);
        ifi->ifi_family = AF_UNSPEC;
        ifi->ifi_type = ARPHRD_ETHER;
        ifi->ifi_index = 7;
        ifi->ifi_flags = 0;
}

/* nl_finish_and_send() normally sets this right before sending; there is no
 * send here, just the length field the NLMSG_OK/RTA_OK walk needs. */
static void finish(struct nl_request *req) {
        req->hdr.nlmsg_len = (uint32_t) req->len;
}

static void test_qdisc_present_and_absent(void) {
        struct nl_request req;
        NetctlLinkInfo info;

        init_base(&req);
        ASSERT_TRUE(nl_add_attr(&req, IFLA_QDISC, "noqueue", strlen("noqueue")) == 0);
        finish(&req);

        ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
        ASSERT_TRUE(info.qdisc != NULL);
        ASSERT_STREQ(info.qdisc, "noqueue");
        netctl_link_info_free(&info);

        init_base(&req);
        finish(&req);

        ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
        ASSERT_TRUE(info.qdisc == NULL);
        netctl_link_info_free(&info);
}

static void test_mtu_combinations(void) {
        struct nl_request req;
        NetctlLinkInfo info;
        uint32_t mtu = 1500, min_mtu = 68, max_mtu = 9000;

        /* Neither min nor max. */
        init_base(&req);
        ASSERT_TRUE(nl_add_attr(&req, IFLA_MTU, &mtu, sizeof mtu) == 0);
        finish(&req);
        ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
        ASSERT_TRUE(info.has_mtu && info.mtu == mtu);
        ASSERT_TRUE(!info.has_min_mtu && !info.has_max_mtu);
        netctl_link_info_free(&info);

        /* Only max. */
        init_base(&req);
        ASSERT_TRUE(nl_add_attr(&req, IFLA_MTU, &mtu, sizeof mtu) == 0);
        ASSERT_TRUE(nl_add_attr(&req, IFLA_MAX_MTU, &max_mtu, sizeof max_mtu) == 0);
        finish(&req);
        ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
        ASSERT_TRUE(!info.has_min_mtu);
        ASSERT_TRUE(info.has_max_mtu && info.max_mtu == max_mtu);
        netctl_link_info_free(&info);

        /* Both. */
        init_base(&req);
        ASSERT_TRUE(nl_add_attr(&req, IFLA_MTU, &mtu, sizeof mtu) == 0);
        ASSERT_TRUE(nl_add_attr(&req, IFLA_MIN_MTU, &min_mtu, sizeof min_mtu) == 0);
        ASSERT_TRUE(nl_add_attr(&req, IFLA_MAX_MTU, &max_mtu, sizeof max_mtu) == 0);
        finish(&req);
        ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
        ASSERT_TRUE(info.has_min_mtu && info.min_mtu == min_mtu);
        ASSERT_TRUE(info.has_max_mtu && info.max_mtu == max_mtu);
        netctl_link_info_free(&info);
}

static size_t count_strv(char **v) {
        size_t n = 0;

        if (!v)
                return 0;
        while (v[n])
                n++;
        return n;
}

static void test_alt_names(void) {
        struct nl_request req;
        NetctlLinkInfo info;

        /* None: IFLA_PROP_LIST entirely absent, same as the real kernel
         * omits it for a link with no alternative names. */
        init_base(&req);
        finish(&req);
        ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
        ASSERT_EQ_INT(count_strv(info.alt_names), 0);
        netctl_link_info_free(&info);

        /* One. */
        {
                uint8_t prop[64];
                size_t n = 0;

                n = append_rta(prop, sizeof prop, n, IFLA_ALT_IFNAME, "altname0", strlen("altname0"));

                init_base(&req);
                ASSERT_TRUE(nl_add_attr(&req, IFLA_PROP_LIST, prop, n) == 0);
                finish(&req);
                ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
                ASSERT_EQ_INT(count_strv(info.alt_names), 1);
                ASSERT_STREQ(info.alt_names[0], "altname0");
                netctl_link_info_free(&info);
        }

        /* Three. */
        {
                uint8_t prop[128];
                size_t n = 0;

                n = append_rta(prop, sizeof prop, n, IFLA_ALT_IFNAME, "a0", strlen("a0"));
                n = append_rta(prop, sizeof prop, n, IFLA_ALT_IFNAME, "a1", strlen("a1"));
                n = append_rta(prop, sizeof prop, n, IFLA_ALT_IFNAME, "a2", strlen("a2"));

                init_base(&req);
                ASSERT_TRUE(nl_add_attr(&req, IFLA_PROP_LIST, prop, n) == 0);
                finish(&req);
                ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
                ASSERT_EQ_INT(count_strv(info.alt_names), 3);
                ASSERT_STREQ(info.alt_names[0], "a0");
                ASSERT_STREQ(info.alt_names[1], "a1");
                ASSERT_STREQ(info.alt_names[2], "a2");
                netctl_link_info_free(&info);
        }
}

static void test_addr_gen_mode(void) {
        struct nl_request req;
        NetctlLinkInfo info;

        /* Absent: no IFLA_AF_SPEC at all. */
        init_base(&req);
        finish(&req);
        ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
        ASSERT_TRUE(!info.has_addr_gen_mode);
        netctl_link_info_free(&info);

        /* Present: IFLA_AF_SPEC -> AF_INET6 -> IFLA_INET6_ADDR_GEN_MODE,
         * two levels of nesting -- exactly what rtattr_enter() is for,
         * called twice by decode_addr_gen_mode(). Mode 2 is
         * stable-privacy, chosen because it is neither 0 (a value a
         * zero-initialized `info` could produce by accident) nor
         * out-of-range. */
        {
                uint8_t inner[32], af_inet6[32];
                size_t inner_len = 0, af_inet6_len = 0;
                uint8_t mode = 2;

                inner_len = append_rta(
                                inner, sizeof inner, inner_len, IFLA_INET6_ADDR_GEN_MODE, &mode, sizeof mode);
                af_inet6_len = append_rta(af_inet6, sizeof af_inet6, af_inet6_len, AF_INET6, inner, inner_len);

                init_base(&req);
                ASSERT_TRUE(nl_add_attr(&req, IFLA_AF_SPEC, af_inet6, af_inet6_len) == 0);
                finish(&req);
                ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
                ASSERT_TRUE(info.has_addr_gen_mode);
                ASSERT_EQ_INT(info.addr_gen_mode, mode);
                netctl_link_info_free(&info);
        }
}

static void test_queue_counts(void) {
        struct nl_request req;
        NetctlLinkInfo info;
        uint32_t tx = 4, rx = 4, zero = 0;

        /* Present, nonzero. */
        init_base(&req);
        ASSERT_TRUE(nl_add_attr(&req, IFLA_NUM_TX_QUEUES, &tx, sizeof tx) == 0);
        ASSERT_TRUE(nl_add_attr(&req, IFLA_NUM_RX_QUEUES, &rx, sizeof rx) == 0);
        finish(&req);
        ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
        ASSERT_TRUE(info.has_queues);
        ASSERT_EQ_INT(info.tx_queues, tx);
        ASSERT_EQ_INT(info.rx_queues, rx);
        netctl_link_info_free(&info);

        /* Absent entirely. */
        init_base(&req);
        finish(&req);
        ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
        ASSERT_TRUE(!info.has_queues);
        netctl_link_info_free(&info);

        /* Present but zero, both -- upstream's own ">0" guard: no honest
         * row to print, same as absent. */
        init_base(&req);
        ASSERT_TRUE(nl_add_attr(&req, IFLA_NUM_TX_QUEUES, &zero, sizeof zero) == 0);
        ASSERT_TRUE(nl_add_attr(&req, IFLA_NUM_RX_QUEUES, &zero, sizeof zero) == 0);
        finish(&req);
        ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
        ASSERT_TRUE(!info.has_queues);
        netctl_link_info_free(&info);
}

/*
 * A truncated attribute -- nlmsg_len cut short enough that the final
 * attribute's own claimed length no longer fits in what RTA_OK() is told
 * remains -- must not crash, and must leave the row it was for omitted
 * (never garbage, never a partially-copied value). This is the bounds
 * discipline netd-rtnl.c's own file banner states as a hard rule, exercised
 * here against netctl-rtnl.c's decoder specifically.
 */
static void test_truncated_attribute_is_safe(void) {
        struct nl_request req;
        NetctlLinkInfo info;

        init_base(&req);
        ASSERT_TRUE(nl_add_attr(&req, IFLA_QDISC, "noqueue", strlen("noqueue")) == 0);
        finish(&req);

        /* Lop off the last 4 bytes of the message -- shorter than the
         * QDisc attribute's own claimed rta_len, so RTA_OK() stops before
         * reaching (or trusting) it. */
        req.hdr.nlmsg_len -= 4;

        ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
        ASSERT_TRUE(info.qdisc == NULL);
        netctl_link_info_free(&info);
}

/* ifi_type/ifi_flags come straight from the ifinfomsg header, not an
 * attribute -- free with every reply, checked once here rather than
 * repeated in every other test above. */
static void test_header_fields(void) {
        struct nl_request req;
        NetctlLinkInfo info;

        init_base(&req);
        finish(&req);

        ASSERT_EQ_INT(netctl_rtnl_decode_link(&req.hdr, &info), 0);
        ASSERT_EQ_INT(info.arp_type, ARPHRD_ETHER);
        netctl_link_info_free(&info);
}

static void test_invalid_arguments(void) {
        NetctlLinkInfo info;
        struct nlmsghdr nlh = { 0 };

        ASSERT_EQ_INT(netctl_rtnl_decode_link(NULL, &info), -EINVAL);
        ASSERT_EQ_INT(netctl_rtnl_decode_link(&nlh, NULL), -EINVAL);

        /* A message too short to even hold the ifinfomsg header. */
        nlh.nlmsg_len = sizeof(nlh);
        ASSERT_EQ_INT(netctl_rtnl_decode_link(&nlh, &info), -EBADMSG);
}

int main(void) {
        test_qdisc_present_and_absent();
        test_mtu_combinations();
        test_alt_names();
        test_addr_gen_mode();
        test_queue_counts();
        test_truncated_attribute_is_safe();
        test_header_fields();
        test_invalid_arguments();
        return 0;
}
