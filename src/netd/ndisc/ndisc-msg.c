/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* See ndisc-msg.h. */

#include "ndisc-msg.h"

#include <errno.h>
#include <string.h>
#include <strings.h>

#define USEC_PER_HOUR_L (3600ULL * USEC_PER_SEC)

/* Multi-byte fields are read byte by byte: an option can start at any
 * eight-byte offset of a receive buffer, and on ARMv5 a misaligned word load
 * rotates instead of faulting. */
static uint16_t be16_at(const uint8_t *p) {
        return (uint16_t) ((p[0] << 8) | p[1]);
}

static uint32_t be32_at(const uint8_t *p) {
        return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
}

static NdiscPref pref_from_bits(uint8_t bits) {
        switch (bits & 3) {
        case 1:
                return NDISC_PREF_HIGH;
        case 3:
                return NDISC_PREF_LOW;
        default:
                return NDISC_PREF_MEDIUM; /* 00, and the reserved 10 */
        }
}

int ndisc_ra_parse_header(const uint8_t *buf, size_t len, NdiscRaHeader *ret) {
        if (!buf || !ret || len < NDISC_RA_HEADER_LEN)
                return -EBADMSG;

        if (buf[0] != NDISC_RA_TYPE || buf[1] != 0)
                return -EBADMSG;

        memset(ret, 0, sizeof(*ret));
        ret->hop_limit = buf[4];
        ret->managed = buf[5] & 0x80;
        ret->other = buf[5] & 0x40;
        ret->pref = pref_from_bits((uint8_t) (buf[5] >> 3));
        ret->router_lifetime = be16_at(buf + 6);
        ret->reachable_ms = be32_at(buf + 8);
        ret->retrans_ms = be32_at(buf + 12);
        return 0;
}

void ndisc_opt_iter_init(NdiscOptIter *it, const uint8_t *buf, size_t len) {
        it->buf = buf;
        it->len = len;
        it->off = NDISC_RA_HEADER_LEN;
}

int ndisc_opt_iter_next(NdiscOptIter *it, NdiscOpt *ret) {
        size_t olen;

        if (it->off >= it->len)
                return 0;

        if (it->len - it->off < 2)
                return -EBADMSG;

        olen = (size_t) it->buf[it->off + 1] * 8;
        if (olen == 0 || olen > it->len - it->off)
                return -EBADMSG;

        ret->type = it->buf[it->off];
        ret->data = it->buf + it->off;
        ret->len = olen;
        it->off += olen;
        return 1;
}

int ndisc_ra_check_options(const uint8_t *buf, size_t len) {
        NdiscOptIter it;
        NdiscOpt opt;
        int r;

        ndisc_opt_iter_init(&it, buf, len);
        while ((r = ndisc_opt_iter_next(&it, &opt)) > 0)
                ;

        return r;
}

int ndisc_opt_prefix(const NdiscOpt *opt, NdiscPrefixInfo *ret) {
        const uint8_t *p = opt->data;
        unsigned plen;

        if (opt->type != NDISC_OPT_PREFIX || opt->len != 32)
                return -EBADMSG;

        plen = p[2];
        if (plen > 128)
                return -EBADMSG;

        memset(ret, 0, sizeof(*ret));
        ret->prefixlen = (uint8_t) plen;
        ret->onlink = p[3] & 0x80;
        ret->autonomous = (p[3] & 0x40) && plen == 64;
        ret->valid_sec = be32_at(p + 4);
        ret->preferred_sec = be32_at(p + 8);
        memcpy(ret->prefix.s6_addr, p + 16, 16);

        for (unsigned i = 0; i < 16; i++) {
                unsigned keep = plen > i * 8 ? plen - i * 8 : 0;

                if (keep < 8)
                        ret->prefix.s6_addr[i] &= (uint8_t) (0xff00u >> keep);
        }

        return 0;
}

int ndisc_opt_mtu(const NdiscOpt *opt, uint32_t *ret) {
        if (opt->type != NDISC_OPT_MTU || opt->len != 8)
                return -EBADMSG;

        *ret = be32_at(opt->data + 4);
        return 0;
}

int ndisc_opt_rdnss(const NdiscOpt *opt, uint32_t *ret_lifetime, size_t *ret_n) {
        if (opt->type != NDISC_OPT_RDNSS || opt->len < 24 || opt->len % 16 != 8)
                return -EBADMSG;

        *ret_lifetime = be32_at(opt->data + 4);
        *ret_n = (opt->len - 8) / 16;
        return 0;
}

void ndisc_opt_rdnss_addr(const NdiscOpt *opt, size_t i, struct in6_addr *ret) {
        memcpy(ret->s6_addr, opt->data + 8 + i * 16, 16);
}

static bool label_char_ok(uint8_t c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
                        c == '_';
}

/*
 * One name at *pos, as text, or -EBADMSG. Zero bytes before a name are the
 * padding RFC 8106 5.2 puts after the last one, and are skipped; 0 at the
 * end of the option.
 */
static int dnssl_name_at(const NdiscOpt *opt, size_t *pos, char name[NDISC_DNSSL_NAME_MAX]) {
        const uint8_t *p = opt->data;
        size_t i = *pos < 8 ? 8 : *pos, out = 0;

        while (i < opt->len && p[i] == 0)
                i++;
        if (i >= opt->len) {
                *pos = i;
                return 0;
        }

        for (;;) {
                size_t llen;

                if (i >= opt->len)
                        return -EBADMSG; /* no terminating empty label */

                llen = p[i++];
                if (llen == 0)
                        break;
                if (llen > 63 || llen > opt->len - i)
                        return -EBADMSG; /* a compression pointer, or past the option */
                if (out + (out > 0) + llen >= NDISC_DNSSL_NAME_MAX)
                        return -EBADMSG;

                if (out > 0)
                        name[out++] = '.';
                for (size_t k = 0; k < llen; k++) {
                        if (!label_char_ok(p[i + k]))
                                return -EBADMSG;
                        name[out++] = (char) p[i + k];
                }
                i += llen;
        }

        name[out] = '\0';
        *pos = i;
        return 1;
}

int ndisc_opt_dnssl(const NdiscOpt *opt, uint32_t *ret_lifetime) {
        char name[NDISC_DNSSL_NAME_MAX];
        size_t pos = 0;
        int r;

        if (opt->type != NDISC_OPT_DNSSL || opt->len < 16)
                return -EBADMSG;

        while ((r = dnssl_name_at(opt, &pos, name)) > 0)
                ;
        if (r < 0)
                return r;

        *ret_lifetime = be32_at(opt->data + 4);
        return 0;
}

int ndisc_opt_dnssl_next(const NdiscOpt *opt, size_t *pos, char name[NDISC_DNSSL_NAME_MAX]) {
        int r;

        do
                r = dnssl_name_at(opt, pos, name);
        while (r > 0 && strcasecmp(name, "localhost") == 0);

        return r;
}

size_t ndisc_rs_build(uint8_t *buf, const uint8_t *hw, size_t hw_len) {
        memset(buf, 0, NDISC_RS_HEADER_LEN);
        buf[0] = NDISC_RS_TYPE;

        if (!hw || hw_len != 6)
                return NDISC_RS_HEADER_LEN;

        buf[8] = NDISC_OPT_SLLAO;
        buf[9] = 1;
        memcpy(buf + 10, hw, 6);
        return NDISC_RS_HEADER_LEN + 8;
}

usec_t ndisc_lifetime_deadline(usec_t now, uint32_t sec) {
        if (sec == NDISC_LIFETIME_INFINITE)
                return USEC_INFINITY;

        return usec_add(now, (usec_t) sec * USEC_PER_SEC);
}

uint32_t ndisc_lifetime_remaining(usec_t now, usec_t deadline) {
        usec_t left;

        if (deadline == USEC_INFINITY)
                return NDISC_LIFETIME_INFINITE;
        if (deadline <= now)
                return 0;

        left = (deadline - now) / USEC_PER_SEC + ((deadline - now) % USEC_PER_SEC != 0);
        return left >= NDISC_LIFETIME_INFINITE ? NDISC_LIFETIME_INFINITE - 1 : (uint32_t) left;
}

usec_t ndisc_slaac_valid_until(usec_t now, uint32_t advertised_sec, usec_t current) {
        usec_t advertised = ndisc_lifetime_deadline(now, advertised_sec);
        usec_t two_hours = usec_add(now, 2 * USEC_PER_HOUR_L);

        if (current == 0)
                return advertised;

        if ((usec_t) advertised_sec * USEC_PER_SEC > 2 * USEC_PER_HOUR_L || advertised > current)
                return advertised;

        if (current <= two_hours)
                return current;

        return two_hours;
}
