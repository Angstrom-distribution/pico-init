/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* IPv4 and IPv6 address literals as one value. See netd-addr.h. */

#include "netd-addr.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>

int netd_addr_parse(const char *s, int *family, NetdInAddr *ret) {
        NetdInAddr a;
        int f;

        if (!s || !family || !ret)
                return -EINVAL;

        memset(&a, 0, sizeof(a));
        f = strchr(s, ':') ? AF_INET6 : AF_INET;

        /* inet_pton() takes no %scope, no whitespace and no trailing text. */
        if (inet_pton(f, s, &a) != 1)
                return -EINVAL;

        *family = f;
        *ret = a;
        return 0;
}

int netd_prefix_parse(const char *s, int *family, NetdInAddr *ret, unsigned char *plen) {
        char buf[INET6_ADDRSTRLEN + 8];
        const char *slash = s ? strchr(s, '/') : NULL;
        size_t alen;
        unsigned v = 0;
        int f, r;

        if (!slash || !family || !ret || !plen)
                return -EINVAL;

        alen = (size_t) (slash - s);
        if (alen == 0 || alen >= sizeof(buf))
                return -EINVAL;

        memcpy(buf, s, alen);
        buf[alen] = '\0';

        r = netd_addr_parse(buf, &f, ret);
        if (r < 0)
                return r;

        slash++;
        if (*slash == '\0' || strlen(slash) > 3)
                return -EINVAL;

        for (const char *c = slash; *c; c++) {
                if (*c < '0' || *c > '9')
                        return -EINVAL;
                v = v * 10 + (unsigned) (*c - '0');
        }

        if (v > (f == AF_INET ? 32u : 128u))
                return -EINVAL;

        *family = f;
        *plen = (unsigned char) v;
        return 0;
}

void netd_addr_mask(int family, NetdInAddr *a, unsigned char plen) {
        unsigned size = family == AF_INET6 ? 16 : 4;
        unsigned keep = plen;

        if (keep > size * 8)
                keep = size * 8;

        for (unsigned i = 0; i < size; i++) {
                if (keep >= 8)
                        keep -= 8;
                else if (keep > 0) {
                        a->bytes[i] &= (uint8_t) (0xff << (8 - keep));
                        keep = 0;
                } else
                        a->bytes[i] = 0;
        }
}

bool netd_addr_eq(int family, const NetdInAddr *a, const NetdInAddr *b) {
        return memcmp(a->bytes, b->bytes, family == AF_INET6 ? 16 : 4) == 0;
}

bool netd_addr_is_null(int family, const NetdInAddr *a) {
        for (unsigned i = 0; i < (family == AF_INET6 ? 16u : 4u); i++)
                if (a->bytes[i] != 0)
                        return false;

        return true;
}

bool netd_addr_is_link_local(int family, const NetdInAddr *a) {
        if (family == AF_INET6)
                return a->bytes[0] == 0xfe && (a->bytes[1] & 0xc0) == 0x80;

        return a->bytes[0] == 169 && a->bytes[1] == 254;
}

bool netd_addr_is_loopback(int family, const NetdInAddr *a) {
        if (family == AF_INET6) {
                static const uint8_t lo[16] = { [15] = 1 };

                return memcmp(a->bytes, lo, sizeof(lo)) == 0;
        }

        return a->bytes[0] == 127;
}

const char *netd_addr_to_string(int family, const NetdInAddr *a, char buf[INET6_ADDRSTRLEN]) {
        if ((family != AF_INET && family != AF_INET6) || !inet_ntop(family, a, buf, INET6_ADDRSTRLEN))
                return "?";

        return buf;
}

bool netd_ipv6_supported(void) {
        struct stat st;

        return stat("/proc/net/if_inet6", &st) == 0;
}
