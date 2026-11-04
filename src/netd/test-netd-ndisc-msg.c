/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The router advertisement parser and the router solicitation builder
 * against fixed bytes, the rejection rules for malformed options, a
 * truncation and mutation run over a full advertisement, and the lifetime
 * arithmetic of RFC 4862 5.5.3.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "ndisc/ndisc-msg.h"

/* An advertisement with every option netd reads: hop limit 64, M and O
 * clear, preference high, router lifetime 1800 s, reachable 0, retrans 0;
 * SLLAO 02:00:00:00:00:01; prefix 2001:db8:1::/64 L and A, valid 86400,
 * preferred 14400; MTU 1480; RDNSS lifetime 600 with 2001:db8::53 and
 * 2001:db8::54; DNSSL lifetime 600 with example.com and lab.example.org. */
static const uint8_t full_ra[] = {
        /* ICMPv6 header and RA fixed part */
        0x86,
        0x00,
        0x00,
        0x00,
        0x40,
        0x08,
        0x07,
        0x08,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        /* SLLAO */
        0x01,
        0x01,
        0x02,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        /* prefix information */
        0x03,
        0x04,
        0x40,
        0xc0,
        0x00,
        0x01,
        0x51,
        0x80,
        0x00,
        0x00,
        0x38,
        0x40,
        0x00,
        0x00,
        0x00,
        0x00,
        0x20,
        0x01,
        0x0d,
        0xb8,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        /* MTU */
        0x05,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x05,
        0xc8,
        /* RDNSS */
        0x19,
        0x05,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0x58,
        0x20,
        0x01,
        0x0d,
        0xb8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x53,
        0x20,
        0x01,
        0x0d,
        0xb8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x54,
        /* DNSSL: 8 header + 13 + 17 names + 2 padding = 40 bytes, length 5 */
        0x1f,
        0x05,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0x58,
        0x07,
        'e',
        'x',
        'a',
        'm',
        'p',
        'l',
        'e',
        0x03,
        'c',
        'o',
        'm',
        0x00,
        0x03,
        'l',
        'a',
        'b',
        0x07,
        'e',
        'x',
        'a',
        'm',
        'p',
        'l',
        'e',
        0x03,
        'o',
        'r',
        'g',
        0x00,
        0x00,
        0x00,
};

static void test_header(void) {
        NdiscRaHeader h;
        uint8_t ra[NDISC_RA_HEADER_LEN];

        ASSERT_EQ_INT(ndisc_ra_parse_header(full_ra, sizeof(full_ra), &h), 0);
        ASSERT_EQ_INT(h.hop_limit, 64);
        ASSERT_TRUE(!h.managed && !h.other);
        ASSERT_EQ_INT(h.pref, NDISC_PREF_HIGH);
        ASSERT_EQ_INT(h.router_lifetime, 1800);

        memcpy(ra, full_ra, sizeof(ra));
        ra[5] = 0xc0 | 0x18; /* M, O, preference 11 */
        ASSERT_EQ_INT(ndisc_ra_parse_header(ra, sizeof(ra), &h), 0);
        ASSERT_TRUE(h.managed && h.other);
        ASSERT_EQ_INT(h.pref, NDISC_PREF_LOW);

        ra[5] = 0x10; /* the reserved 10 */
        ASSERT_EQ_INT(ndisc_ra_parse_header(ra, sizeof(ra), &h), 0);
        ASSERT_EQ_INT(h.pref, NDISC_PREF_MEDIUM);

        ASSERT_EQ_INT(ndisc_ra_parse_header(ra, NDISC_RA_HEADER_LEN - 1, &h), -EBADMSG);
        ra[1] = 1;
        ASSERT_EQ_INT(ndisc_ra_parse_header(ra, sizeof(ra), &h), -EBADMSG);
        ra[1] = 0;
        ra[0] = NDISC_RS_TYPE;
        ASSERT_EQ_INT(ndisc_ra_parse_header(ra, sizeof(ra), &h), -EBADMSG);
}

static void test_full_decode(void) {
        static const uint8_t ns1[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 0x53 };
        static const uint8_t ns2[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 0x54 };
        static const uint8_t pfx[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01 };
        NdiscOptIter it;
        NdiscOpt opt;
        NdiscPrefixInfo pi;
        struct in6_addr a;
        char name[NDISC_DNSSL_NAME_MAX];
        uint32_t v;
        size_t n, pos = 0;
        int types[8], k = 0;

        ASSERT_EQ_INT(ndisc_ra_check_options(full_ra, sizeof(full_ra)), 0);

        ndisc_opt_iter_init(&it, full_ra, sizeof(full_ra));
        while (ndisc_opt_iter_next(&it, &opt) > 0 && k < 8) {
                types[k++] = opt.type;

                switch (opt.type) {
                case NDISC_OPT_PREFIX:
                        ASSERT_EQ_INT(ndisc_opt_prefix(&opt, &pi), 0);
                        ASSERT_EQ_INT(pi.prefixlen, 64);
                        ASSERT_TRUE(pi.onlink && pi.autonomous);
                        ASSERT_EQ_INT(pi.valid_sec, 86400);
                        ASSERT_EQ_INT(pi.preferred_sec, 14400);
                        ASSERT_TRUE(memcmp(pi.prefix.s6_addr, pfx, 16) == 0);
                        break;
                case NDISC_OPT_MTU:
                        ASSERT_EQ_INT(ndisc_opt_mtu(&opt, &v), 0);
                        ASSERT_EQ_INT(v, 1480);
                        break;
                case NDISC_OPT_RDNSS:
                        ASSERT_EQ_INT(ndisc_opt_rdnss(&opt, &v, &n), 0);
                        ASSERT_EQ_INT(v, 600);
                        ASSERT_EQ_INT(n, 2);
                        ndisc_opt_rdnss_addr(&opt, 0, &a);
                        ASSERT_TRUE(memcmp(a.s6_addr, ns1, 16) == 0);
                        ndisc_opt_rdnss_addr(&opt, 1, &a);
                        ASSERT_TRUE(memcmp(a.s6_addr, ns2, 16) == 0);
                        break;
                case NDISC_OPT_DNSSL:
                        ASSERT_EQ_INT(ndisc_opt_dnssl(&opt, &v), 0);
                        ASSERT_EQ_INT(v, 600);
                        ASSERT_EQ_INT(ndisc_opt_dnssl_next(&opt, &pos, name), 1);
                        ASSERT_STREQ(name, "example.com");
                        ASSERT_EQ_INT(ndisc_opt_dnssl_next(&opt, &pos, name), 1);
                        ASSERT_STREQ(name, "lab.example.org");
                        ASSERT_EQ_INT(ndisc_opt_dnssl_next(&opt, &pos, name), 0);
                        break;
                default:
                        break;
                }
        }

        ASSERT_EQ_INT(k, 5);
        ASSERT_EQ_INT(types[0], NDISC_OPT_SLLAO);
        ASSERT_EQ_INT(types[1], NDISC_OPT_PREFIX);
        ASSERT_EQ_INT(types[2], NDISC_OPT_MTU);
        ASSERT_EQ_INT(types[3], NDISC_OPT_RDNSS);
        ASSERT_EQ_INT(types[4], NDISC_OPT_DNSSL);
}

/* A header with one option of `len` bytes appended, the option's length
 * field set to `units`. */
static size_t ra_with_option(uint8_t *buf, const uint8_t *opt, size_t len, uint8_t units) {
        memcpy(buf, full_ra, NDISC_RA_HEADER_LEN);
        memcpy(buf + NDISC_RA_HEADER_LEN, opt, len);
        buf[NDISC_RA_HEADER_LEN + 1] = units;
        return NDISC_RA_HEADER_LEN + len;
}

/* RFC 4861 6.1.2: a zero-length option, or one past the end, costs the whole
 * advertisement. */
static void test_framing_rejects(void) {
        uint8_t buf[256];
        size_t len;

        len = ra_with_option(buf, full_ra + 16, 8, 0);
        ASSERT_EQ_INT(ndisc_ra_check_options(buf, len), -EBADMSG);

        len = ra_with_option(buf, full_ra + 16, 8, 2);
        ASSERT_EQ_INT(ndisc_ra_check_options(buf, len), -EBADMSG);

        /* One byte of option header, no length byte. */
        ASSERT_EQ_INT(ndisc_ra_check_options(full_ra, NDISC_RA_HEADER_LEN + 1), -EBADMSG);

        /* A zero-length option after good ones still rejects them all. */
        memcpy(buf, full_ra, sizeof(full_ra));
        buf[sizeof(full_ra)] = 0x01;
        buf[sizeof(full_ra) + 1] = 0;
        memset(buf + sizeof(full_ra) + 2, 0, 6);
        ASSERT_EQ_INT(ndisc_ra_check_options(buf, sizeof(full_ra) + 8), -EBADMSG);

        /* Header only: no options is fine. */
        ASSERT_EQ_INT(ndisc_ra_check_options(full_ra, NDISC_RA_HEADER_LEN), 0);
}

static int decode_single(const uint8_t *buf, size_t len, int (*decode)(const NdiscOpt *)) {
        NdiscOptIter it;
        NdiscOpt opt;

        ASSERT_EQ_INT(ndisc_ra_check_options(buf, len), 0);
        ndisc_opt_iter_init(&it, buf, len);
        ASSERT_EQ_INT(ndisc_opt_iter_next(&it, &opt), 1);
        return decode(&opt);
}

static int decode_prefix(const NdiscOpt *opt) {
        NdiscPrefixInfo pi;

        return ndisc_opt_prefix(opt, &pi);
}

static int decode_mtu(const NdiscOpt *opt) {
        uint32_t v;

        return ndisc_opt_mtu(opt, &v);
}

static int decode_rdnss(const NdiscOpt *opt) {
        uint32_t v;
        size_t n;

        return ndisc_opt_rdnss(opt, &v, &n);
}

static int decode_dnssl(const NdiscOpt *opt) {
        uint32_t v;

        return ndisc_opt_dnssl(opt, &v);
}

/* A typed option of the wrong shape is skipped on its own. */
static void test_typed_rejects(void) {
        uint8_t buf[256], opt[64];
        NdiscOptIter it;
        NdiscOpt o;
        NdiscPrefixInfo pi;
        size_t len;

        /* Prefix information of 24 and 40 bytes instead of 32. */
        memset(opt, 0, sizeof(opt));
        memcpy(opt, full_ra + 24, 32);
        len = ra_with_option(buf, opt, 24, 3);
        ASSERT_EQ_INT(decode_single(buf, len, decode_prefix), -EBADMSG);
        len = ra_with_option(buf, opt, 40, 5);
        ASSERT_EQ_INT(decode_single(buf, len, decode_prefix), -EBADMSG);

        /* A /56 is on-link but cannot be SLAAC; the prefix is masked. */
        memcpy(opt, full_ra + 24, 32);
        opt[2] = 56;
        opt[16 + 7] = 0xff;
        len = ra_with_option(buf, opt, 32, 4);
        ndisc_opt_iter_init(&it, buf, len);
        ASSERT_EQ_INT(ndisc_opt_iter_next(&it, &o), 1);
        ASSERT_EQ_INT(ndisc_opt_prefix(&o, &pi), 0);
        ASSERT_TRUE(pi.onlink && !pi.autonomous);
        ASSERT_EQ_INT(pi.prefix.s6_addr[7], 0);
        ASSERT_EQ_INT(pi.prefix.s6_addr[5], 1);

        opt[2] = 129;
        len = ra_with_option(buf, opt, 32, 4);
        ASSERT_EQ_INT(decode_single(buf, len, decode_prefix), -EBADMSG);

        /* MTU of 16 bytes. */
        memset(opt, 0, sizeof(opt));
        opt[0] = NDISC_OPT_MTU;
        len = ra_with_option(buf, opt, 16, 2);
        ASSERT_EQ_INT(decode_single(buf, len, decode_mtu), -EBADMSG);

        /* RDNSS of an even length, and without an address. */
        memset(opt, 0, sizeof(opt));
        opt[0] = NDISC_OPT_RDNSS;
        len = ra_with_option(buf, opt, 16, 2);
        ASSERT_EQ_INT(decode_single(buf, len, decode_rdnss), -EBADMSG);
        len = ra_with_option(buf, opt, 32, 4);
        ASSERT_EQ_INT(decode_single(buf, len, decode_rdnss), -EBADMSG);
        len = ra_with_option(buf, opt, 8, 1);
        ASSERT_EQ_INT(decode_single(buf, len, decode_rdnss), -EBADMSG);
        len = ra_with_option(buf, opt, 24, 3);
        ASSERT_EQ_INT(decode_single(buf, len, decode_rdnss), 0);

        /* DNSSL with no room for a name. */
        memset(opt, 0, sizeof(opt));
        opt[0] = NDISC_OPT_DNSSL;
        len = ra_with_option(buf, opt, 8, 1);
        ASSERT_EQ_INT(decode_single(buf, len, decode_dnssl), -EBADMSG);
        len = ra_with_option(buf, opt, 16, 2);
        ASSERT_EQ_INT(decode_single(buf, len, decode_dnssl), 0);
}

/* One DNSSL option holding `name` (wire format, `n` bytes) padded to 8. */
static int dnssl_verdict(const uint8_t *name, size_t n, char first[NDISC_DNSSL_NAME_MAX]) {
        uint8_t buf[512], opt[400];
        size_t len = 8 + n, pos = 0;
        NdiscOptIter it;
        NdiscOpt o;
        uint32_t v;
        int r;

        memset(opt, 0, sizeof(opt));
        opt[0] = NDISC_OPT_DNSSL;
        memcpy(opt + 8, name, n);
        len = (len + 7) / 8 * 8;
        if (len < 16)
                len = 16;
        len = ra_with_option(buf, opt, len, (uint8_t) (len / 8));

        ndisc_opt_iter_init(&it, buf, len);
        ASSERT_EQ_INT(ndisc_opt_iter_next(&it, &o), 1);
        r = ndisc_opt_dnssl(&o, &v);
        if (r < 0 || !first)
                return r;

        first[0] = '\0';
        return ndisc_opt_dnssl_next(&o, &pos, first);
}

static void test_dnssl_rejects(void) {
        uint8_t name[300];
        char first[NDISC_DNSSL_NAME_MAX];

        /* A 64-byte label. */
        memset(name, 'a', sizeof(name));
        name[0] = 64;
        name[65] = 0;
        ASSERT_EQ_INT(dnssl_verdict(name, 66, NULL), -EBADMSG);

        /* A 63-byte label is fine. */
        name[0] = 63;
        name[64] = 0;
        ASSERT_EQ_INT(dnssl_verdict(name, 65, first), 1);
        ASSERT_EQ_INT(strlen(first), 63);

        /* A compression pointer. */
        memcpy(name,
               "\x03"
               "lab"
               "\xc0\x0c",
               6);
        ASSERT_EQ_INT(dnssl_verdict(name, 6, NULL), -EBADMSG);

        /* A name that runs to the end of the option without its empty label:
         * eight bytes of name fill the option exactly. */
        memcpy(name,
               "\x07"
               "example",
               8);
        ASSERT_EQ_INT(dnssl_verdict(name, 8, NULL), -EBADMSG);

        /* A space or a newline would split a resolv.conf line. */
        memcpy(name,
               "\x03"
               "a b"
               "\x00",
               5);
        ASSERT_EQ_INT(dnssl_verdict(name, 5, NULL), -EBADMSG);
        memcpy(name,
               "\x03"
               "a\nb"
               "\x00",
               5);
        ASSERT_EQ_INT(dnssl_verdict(name, 5, NULL), -EBADMSG);

        /* localhost is skipped, the next name is returned. */
        memcpy(name,
               "\x09"
               "localhost"
               "\x00"
               "\x03"
               "lan"
               "\x00",
               16);
        ASSERT_EQ_INT(dnssl_verdict(name, 16, first), 1);
        ASSERT_STREQ(first, "lan");

        /* Only padding: no name. */
        memset(name, 0, 8);
        ASSERT_EQ_INT(dnssl_verdict(name, 8, first), 0);

        /* A name longer than 253 characters. */
        for (size_t i = 0; i < 5; i++) {
                name[i * 51] = 50;
                memset(name + i * 51 + 1, 'b', 50);
        }
        name[255] = 0;
        ASSERT_EQ_INT(dnssl_verdict(name, 256, NULL), -EBADMSG);
}

/* Everything a receiver would do with one advertisement. */
static void decode_everything(const uint8_t *buf, size_t len) {
        NdiscRaHeader h;
        NdiscOptIter it;
        NdiscOpt opt;
        int r;

        if (ndisc_ra_parse_header(buf, len, &h) < 0 || ndisc_ra_check_options(buf, len) < 0)
                return;

        ndisc_opt_iter_init(&it, buf, len);
        while ((r = ndisc_opt_iter_next(&it, &opt)) > 0) {
                NdiscPrefixInfo pi;
                struct in6_addr a;
                char name[NDISC_DNSSL_NAME_MAX];
                uint32_t v;
                size_t n, pos = 0;

                ASSERT_TRUE(opt.data >= buf && opt.data + opt.len <= buf + len);
                (void) ndisc_opt_prefix(&opt, &pi);
                (void) ndisc_opt_mtu(&opt, &v);
                if (ndisc_opt_rdnss(&opt, &v, &n) == 0) {
                        ASSERT_TRUE(8 + n * 16 <= opt.len);
                        for (size_t i = 0; i < n; i++)
                                ndisc_opt_rdnss_addr(&opt, i, &a);
                }
                if (ndisc_opt_dnssl(&opt, &v) == 0)
                        while (ndisc_opt_dnssl_next(&opt, &pos, name) > 0)
                                ASSERT_TRUE(strlen(name) < NDISC_DNSSL_NAME_MAX);
        }
        ASSERT_TRUE(r == 0 || r == -EBADMSG);
}

/* Every truncation and every single-byte mutation of the full advertisement,
 * each in a buffer of exactly its own length, so a read past the end is a
 * read past the allocation. */
static void test_truncation_and_mutation(void) {
        static const uint8_t values[] = { 0x00, 0x01, 0x02, 0x03, 0x3f, 0x40, 0x80, 0xc0, 0xff };
        uint8_t *buf;

        for (size_t len = 0; len <= sizeof(full_ra); len++) {
                buf = malloc(len ? len : 1);
                ASSERT_TRUE(buf != NULL);
                memcpy(buf, full_ra, len);
                decode_everything(buf, len);
                free(buf);
        }

        for (size_t i = 0; i < sizeof(full_ra); i++)
                for (size_t v = 0; v < sizeof(values); v++) {
                        buf = malloc(sizeof(full_ra));
                        ASSERT_TRUE(buf != NULL);
                        memcpy(buf, full_ra, sizeof(full_ra));
                        buf[i] = values[v];
                        decode_everything(buf, sizeof(full_ra));
                        free(buf);
                }
}

static void test_rs_build(void) {
        static const uint8_t hw[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
        static const uint8_t with[16] = { 0x85, 0,    0,    0,    0,    0,    0,    0,
                                          0x01, 0x01, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
        static const uint8_t without[8] = { 0x85, 0, 0, 0, 0, 0, 0, 0 };
        uint8_t buf[16];

        memset(buf, 0xaa, sizeof(buf));
        ASSERT_EQ_INT(ndisc_rs_build(buf, hw, 6), 16);
        ASSERT_TRUE(memcmp(buf, with, 16) == 0);

        memset(buf, 0xaa, sizeof(buf));
        ASSERT_EQ_INT(ndisc_rs_build(buf, NULL, 0), 8);
        ASSERT_TRUE(memcmp(buf, without, 8) == 0);
        ASSERT_EQ_INT(ndisc_rs_build(buf, hw, 4), 8);
}

static void test_lifetimes(void) {
        const usec_t now = 1000 * USEC_PER_SEC, hour = 3600 * USEC_PER_SEC;

        ASSERT_TRUE(ndisc_lifetime_deadline(now, NDISC_LIFETIME_INFINITE) == USEC_INFINITY);
        ASSERT_TRUE(ndisc_lifetime_deadline(now, 0) == now);
        ASSERT_TRUE(ndisc_lifetime_deadline(now, 0xfffffffe) == now + (usec_t) 0xfffffffe * USEC_PER_SEC);
        ASSERT_TRUE(ndisc_lifetime_deadline(USEC_INFINITY - 5, 10) == USEC_INFINITY);

        ASSERT_EQ_INT(ndisc_lifetime_remaining(now, USEC_INFINITY), NDISC_LIFETIME_INFINITE);
        ASSERT_EQ_INT(ndisc_lifetime_remaining(now, now), 0);
        ASSERT_EQ_INT(ndisc_lifetime_remaining(now, now - 1), 0);
        ASSERT_EQ_INT(ndisc_lifetime_remaining(now, now + 1), 1);
        ASSERT_EQ_INT(ndisc_lifetime_remaining(now, now + 10 * USEC_PER_SEC), 10);
        ASSERT_EQ_INT(ndisc_lifetime_remaining(0, USEC_INFINITY - 1), NDISC_LIFETIME_INFINITE - 1);

        /* RFC 4862 5.5.3 e, case by case. */
        ASSERT_TRUE(ndisc_slaac_valid_until(now, 600, 0) == now + 600 * USEC_PER_SEC);
        ASSERT_TRUE(ndisc_slaac_valid_until(now, 0, 0) == now);
        /* 1: above two hours, or beyond what is left: taken. */
        ASSERT_TRUE(ndisc_slaac_valid_until(now, 3 * 3600, now + 60 * USEC_PER_SEC) == now + 3 * hour);
        ASSERT_TRUE(ndisc_slaac_valid_until(now, 600, now + 60 * USEC_PER_SEC) == now + 600 * USEC_PER_SEC);
        /* 2: what is left is two hours or less: it stays, a zero included. */
        ASSERT_TRUE(ndisc_slaac_valid_until(now, 0, now + hour) == now + hour);
        ASSERT_TRUE(ndisc_slaac_valid_until(now, 60, now + 2 * hour) == now + 2 * hour);
        /* 3: otherwise two hours. */
        ASSERT_TRUE(ndisc_slaac_valid_until(now, 0, now + 5 * hour) == now + 2 * hour);
        ASSERT_TRUE(ndisc_slaac_valid_until(now, 60, USEC_INFINITY) == now + 2 * hour);
        ASSERT_TRUE(ndisc_slaac_valid_until(now, NDISC_LIFETIME_INFINITE, now + hour) == USEC_INFINITY);
}

int main(void) {
        test_header();
        test_full_decode();
        test_framing_rejects();
        test_typed_rejects();
        test_dnssl_rejects();
        test_truncation_and_mutation();
        test_rs_build();
        test_lifetimes();

        printf("test-netd-ndisc-msg: all checks passed\n");
        return 0;
}
