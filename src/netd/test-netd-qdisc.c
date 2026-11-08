/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Root qdisc support without a kernel: the RTM_NEWQDISC, RTM_DELQDISC and
 * RTM_GETQDISC messages against fixed bytes, the decoder for a kernel reply
 * and the qdisc sections of a .network file. test-netd-qdisc-link covers the
 * kernel side.
 */

#include <endian.h>
#include <errno.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "netd-network.h"
#include "netd-rtnl-core.h"
#include "netd-rtnl.h"

/* nlmsg_len, seq and pid are filled in when the message is sent. */
static void finish(struct nl_request *req) {
        req->hdr.nlmsg_len = (uint32_t) req->len;
}

static void test_message_numbers(void) {
        ASSERT_EQ_INT(RTM_NEWQDISC, 36);
        ASSERT_EQ_INT(RTM_DELQDISC, 37);
        ASSERT_EQ_INT(RTM_GETQDISC, 38);
        ASSERT_TRUE(TC_H_ROOT == 0xFFFFFFFFu);
}

#if __BYTE_ORDER == __LITTLE_ENDIAN

/* RTM_NEWQDISC, NLM_F_REQUEST|ACK|REPLACE|CREATE, ifindex 7, parent root,
 * TCA_KIND "fq_codel" and an empty TCA_OPTIONS. */
static const uint8_t replace_fq_codel[] = {
        0x38, 0x00, 0x00, 0x00, 0x24, 0x00, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x01, 0x00, 'f',  'q',
        '_',  'c',  'o',  'd',  'e',  'l',  0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
};

/* RTM_DELQDISC, NLM_F_REQUEST|ACK, ifindex 7, TCA_KIND "fq". */
static const uint8_t delete_fq[] = {
        0x2c, 0x00, 0x00, 0x00, 0x25, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x01, 0x00, 'f',  'q',  0x00, 0x00,
};

/* RTM_GETQDISC, NLM_F_REQUEST|ECHO|ACK, ifindex 7, parent root. */
static const uint8_t get_root[] = {
        0x24, 0x00, 0x00, 0x00, 0x26, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
};

/* What the kernel answers to the request above for a multi-queue link: TCA_KIND
 * "mq" followed by TCA_HW_OFFLOAD, which the decoder has to step over. */
static const uint8_t reply_mq[] = {
        0x34, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x42,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x01,
        0x00, 'm',  'q',  0x00, 0x00, 0x05, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static void check_bytes(struct nl_request *req, const uint8_t *want, size_t len) {
        finish(req);
        ASSERT_EQ_INT((int) req->len, (int) len);
        ASSERT_TRUE(memcmp(req->buf, want, len) == 0);
}

static void test_encoding(void) {
        struct nl_request req;

        ASSERT_EQ_INT(netd_rtnl_qdisc_build(&req, RTM_NEWQDISC, 7, "fq_codel"), 0);
        check_bytes(&req, replace_fq_codel, sizeof(replace_fq_codel));

        ASSERT_EQ_INT(netd_rtnl_qdisc_build(&req, RTM_DELQDISC, 7, "fq"), 0);
        check_bytes(&req, delete_fq, sizeof(delete_fq));

        ASSERT_EQ_INT(netd_rtnl_qdisc_build(&req, RTM_GETQDISC, 7, NULL), 0);
        check_bytes(&req, get_root, sizeof(get_root));
}

static void test_decode_reply(void) {
        union nl_recv_buf rb;
        char kind[IFNAMSIZ];
        uint32_t handle = 99;
        int ifindex = 0;

        memcpy(rb.buf, reply_mq, sizeof(reply_mq));
        ASSERT_EQ_INT(netd_rtnl_qdisc_parse(&rb.hdr, &ifindex, kind, sizeof(kind), &handle), 0);
        ASSERT_STREQ(kind, "mq");
        ASSERT_EQ_INT(ifindex, 7);
        ASSERT_EQ_INT(handle, 0);

        /* A qdisc made through RTM_NEWQDISC carries a handle (tc shows 800f:),
         * and the handle is optional for the caller. */
        memcpy(rb.buf, reply_mq, sizeof(reply_mq));
        ((struct tcmsg *) NLMSG_DATA(&rb.hdr))->tcm_handle = 0x800f0000u;
        ASSERT_EQ_INT(netd_rtnl_qdisc_parse(&rb.hdr, &ifindex, kind, sizeof(kind), &handle), 0);
        ASSERT_EQ_INT(handle, 0x800f0000u);
        ASSERT_EQ_INT(netd_rtnl_qdisc_parse(&rb.hdr, NULL, kind, sizeof(kind), NULL), 0);

        /* Another message type is not a qdisc. */
        memcpy(rb.buf, reply_mq, sizeof(reply_mq));
        rb.hdr.nlmsg_type = RTM_NEWLINK;
        ASSERT_EQ_INT(netd_rtnl_qdisc_parse(&rb.hdr, &ifindex, kind, sizeof(kind), &handle), -EBADMSG);

        /* A message cut off inside the tcmsg. */
        memcpy(rb.buf, reply_mq, sizeof(reply_mq));
        rb.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)) - 1;
        ASSERT_EQ_INT(netd_rtnl_qdisc_parse(&rb.hdr, &ifindex, kind, sizeof(kind), &handle), -EBADMSG);

        /* The attribute list stops before TCA_KIND. */
        memcpy(rb.buf, reply_mq, sizeof(reply_mq));
        rb.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
        ASSERT_EQ_INT(netd_rtnl_qdisc_parse(&rb.hdr, &ifindex, kind, sizeof(kind), &handle), -EBADMSG);

        /* A TCA_KIND that claims more than the message holds. */
        memcpy(rb.buf, reply_mq, sizeof(reply_mq));
        rb.buf[36] = 0x40;
        ASSERT_EQ_INT(netd_rtnl_qdisc_parse(&rb.hdr, &ifindex, kind, sizeof(kind), &handle), -EBADMSG);
}

#endif /* little endian */

static void test_build_refuses_bad_input(void) {
        struct nl_request req;
        char longkind[IFNAMSIZ + 1];

        memset(longkind, 'a', sizeof(longkind) - 1);
        longkind[sizeof(longkind) - 1] = '\0';

        ASSERT_EQ_INT(netd_rtnl_qdisc_build(&req, RTM_NEWQDISC, 0, "fq"), -EINVAL);
        ASSERT_EQ_INT(netd_rtnl_qdisc_build(&req, RTM_NEWQDISC, -3, "fq"), -EINVAL);
        ASSERT_EQ_INT(netd_rtnl_qdisc_build(&req, RTM_NEWQDISC, 7, NULL), -EINVAL);
        ASSERT_EQ_INT(netd_rtnl_qdisc_build(&req, RTM_NEWQDISC, 7, ""), -EINVAL);
        ASSERT_EQ_INT(netd_rtnl_qdisc_build(&req, RTM_NEWQDISC, 7, longkind), -EINVAL);
        ASSERT_EQ_INT(netd_rtnl_qdisc_build(&req, RTM_NEWLINK, 7, "fq"), -EINVAL);
        ASSERT_EQ_INT(netd_rtnl_qdisc_build(NULL, RTM_NEWQDISC, 7, "fq"), -EINVAL);

        /* The longest name the kernel takes, IFNAMSIZ - 1, is still built. */
        longkind[IFNAMSIZ - 1] = '\0';
        ASSERT_EQ_INT(netd_rtnl_qdisc_build(&req, RTM_NEWQDISC, 7, longkind), 0);
}

static void test_kind_names(void) {
        ASSERT_TRUE(network_qdisc_to_string(NETWORK_QDISC_NONE) == NULL);
        ASSERT_STREQ(network_qdisc_to_string(NETWORK_QDISC_FQ_CODEL), "fq_codel");
        ASSERT_STREQ(network_qdisc_to_string(NETWORK_QDISC_FQ), "fq");
        ASSERT_STREQ(network_qdisc_to_string(NETWORK_QDISC_CAKE), "cake");
        ASSERT_TRUE(network_qdisc_to_string(_NETWORK_QDISC_MAX) == NULL);
        ASSERT_TRUE(network_qdisc_to_string((NetworkQdisc) -1) == NULL);
}

/* --- .network sections --- */

static NetworkQdisc parse_qdisc(const char *tmp, const char *body) {
        char path[4096];
        Network *nw = NULL;
        NetworkQdisc q;

        ASSERT_EQ_INT(test_write_file(tmp, "q.network", body), 0);
        snprintf(path, sizeof(path), "%s/q.network", tmp);
        ASSERT_EQ_INT(network_parse_file(path, &nw), 0);
        q = nw->qdisc;
        network_free(nw);
        return q;
}

static void test_sections(void) {
        char *tmp = test_tmpdir_new();

        ASSERT_TRUE(tmp != NULL);

        ASSERT_EQ_INT(parse_qdisc(tmp, "[Match]\nName=eth0\n"), NETWORK_QDISC_NONE);

        /* Parent= defaults to root, but as in networkd a section with no key
         * installs nothing. */
        ASSERT_EQ_INT(parse_qdisc(tmp, "[FairQueueingControlledDelay]\nParent=root\n"),
                      NETWORK_QDISC_FQ_CODEL);
        ASSERT_EQ_INT(parse_qdisc(tmp, "[FairQueueing]\nHandle=1\n"), NETWORK_QDISC_FQ);
        ASSERT_EQ_INT(parse_qdisc(tmp, "[CAKE]\nParent=root\n"), NETWORK_QDISC_CAKE);
        ASSERT_EQ_INT(parse_qdisc(tmp, "[CAKE]\n"), NETWORK_QDISC_NONE);
        ASSERT_EQ_INT(parse_qdisc(tmp, "[FairQueueing]\n\n[CAKE]\nNAT=yes\n"), NETWORK_QDISC_CAKE);

        /* Parent= may follow other keys, and the section may follow others. */
        ASSERT_EQ_INT(parse_qdisc(tmp,
                                  "[Match]\nName=eth0\n\n[FairQueueing]\nPacketLimit=100\nParent=root\n\n[Network]\n"
                                  "DHCP=yes\n"),
                      NETWORK_QDISC_FQ);

        /* Parents netd does not install on drop the section. */
        ASSERT_EQ_INT(parse_qdisc(tmp, "[CAKE]\nParent=clsact\n"), NETWORK_QDISC_NONE);
        ASSERT_EQ_INT(parse_qdisc(tmp, "[CAKE]\nParent=ingress\n"), NETWORK_QDISC_NONE);
        ASSERT_EQ_INT(parse_qdisc(tmp, "[CAKE]\nParent=1:2\n"), NETWORK_QDISC_NONE);
        ASSERT_EQ_INT(parse_qdisc(tmp, "[CAKE]\nParent=ROOT\n"), NETWORK_QDISC_NONE);

        /* The last Parent= wins, as in networkd; an empty one is
         * invalid and drops the section. */
        ASSERT_EQ_INT(parse_qdisc(tmp, "[CAKE]\nParent=clsact\nParent=root\n"), NETWORK_QDISC_CAKE);
        ASSERT_EQ_INT(parse_qdisc(tmp, "[CAKE]\nParent=root\nParent=clsact\n"), NETWORK_QDISC_NONE);
        ASSERT_EQ_INT(parse_qdisc(tmp, "[CAKE]\nParent=\n"), NETWORK_QDISC_NONE);

        /* The first root section stays; the second is dropped. */
        ASSERT_EQ_INT(parse_qdisc(tmp, "[FairQueueing]\nPacketLimit=100\n\n[CAKE]\nNAT=yes\n"),
                      NETWORK_QDISC_FQ);
        ASSERT_EQ_INT(parse_qdisc(tmp, "[CAKE]\nParent=clsact\n\n[FairQueueing]\nPacketLimit=100\n"),
                      NETWORK_QDISC_FQ);
        ASSERT_EQ_INT(parse_qdisc(tmp, "[FairQueueing]\nPacketLimit=100\n\n[CAKE]\nParent=clsact\n"),
                      NETWORK_QDISC_FQ);

        /* [QDisc] holds clsact and ingress in networkd: nothing to install. */
        ASSERT_EQ_INT(parse_qdisc(tmp, "[QDisc]\nParent=root\n"), NETWORK_QDISC_NONE);

        /* A Parent= in any other section is not a qdisc parent. */
        ASSERT_EQ_INT(parse_qdisc(tmp, "[Network]\nParent=root\n"), NETWORK_QDISC_NONE);
        ASSERT_EQ_INT(parse_qdisc(tmp, "[CAKE]\nParent=root\n\n[Network]\nParent=clsact\n"),
                      NETWORK_QDISC_CAKE);

        /* Tuning keys are accepted and dropped. */
        ASSERT_EQ_INT(parse_qdisc(tmp, "[CAKE]\nBandwidth=10M\nHandle=1\nNAT=yes\n"), NETWORK_QDISC_CAKE);

        test_rm_rf(tmp);
        free(tmp);
}

int main(void) {
        test_message_numbers();
#if __BYTE_ORDER == __LITTLE_ENDIAN
        test_encoding();
        test_decode_reply();
#else
        fprintf(stderr, "test-netd-qdisc: the message fixtures are little endian, skipping them\n");
#endif
        test_build_refuses_bad_input();
        test_kind_names();
        test_sections();

        printf("test-netd-qdisc: all checks passed\n");
        return 0;
}
