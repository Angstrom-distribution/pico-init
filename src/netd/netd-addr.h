/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * An IPv4 or IPv6 address as one value, for the parts of netd that treat both
 * families alike: [Address] entries, the link's address table, netlink
 * requests. Literals only; netd has no resolver.
 *
 * Functions that take a family expect AF_INET or AF_INET6. An IPv4 address
 * occupies the first four bytes of `bytes` and the rest is zero, so two
 * values of one family compare with memcmp().
 */

#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

typedef union NetdInAddr {
        struct in_addr in;
        struct in6_addr in6;
        uint8_t bytes[16];
} NetdInAddr;

/* A literal: dotted quad, or an IPv6 form without a %scope. 0 with *family
 * and *ret set, or -EINVAL. */
int netd_addr_parse(const char *s, int *family, NetdInAddr *ret);

/* "address/length", the length required and bounded by the family: 32 or
 * 128. The address is not masked. 0 or -EINVAL. */
int netd_prefix_parse(const char *s, int *family, NetdInAddr *ret, unsigned char *plen);

/* Zero every bit beyond the first `plen`. */
void netd_addr_mask(int family, NetdInAddr *a, unsigned char plen);

bool netd_addr_eq(int family, const NetdInAddr *a, const NetdInAddr *b);
bool netd_addr_is_null(int family, const NetdInAddr *a);
bool netd_addr_is_link_local(int family, const NetdInAddr *a); /* 169.254/16, fe80::/10 */
bool netd_addr_is_loopback(int family, const NetdInAddr *a);   /* 127/8, ::1 */

/* Writes into `buf`, which must hold INET6_ADDRSTRLEN bytes; returns it, or
 * "?" when the family is neither. */
const char *netd_addr_to_string(int family, const NetdInAddr *a, char buf[INET6_ADDRSTRLEN]);

/* True when the running kernel has IPv6: /proc/net/if_inet6 exists, as
 * socket.c tests it. */
bool netd_ipv6_supported(void);
