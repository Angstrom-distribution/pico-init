/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported subset of src/shared/dns-domain.c (~200 of 1,376 lines): the
 * flat-string DNS name helpers dhcp-message.c's option 12/15 (Host Name,
 * Domain Name) path needs, and only those: dns_name_normalize(),
 * dns_name_is_root(), dns_name_is_single_label(), dns_name_is_valid(),
 * dns_name_is_valid_ldh(), dns_name_equal().
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. History review
 * (4925d9f07f..main, plan §2.2): no fix in the 26-commit lift-set window
 * touches dns-domain.c.
 *
 * Plan §2.1's claim that dropping options 81 and 162 removes dns-domain.c
 * entirely is wrong, and the history review recorded why (plan §2.2 prose):
 * options 12 and 15 still route through dhcp_message_get_option_dns_name(),
 * and §2.7 needs the domain for resolv.conf. What *does* remove the
 * expensive half is additionally dropping option 119 (Domain Search), the
 * only caller of the RFC 3397 compression-pointer decoder --
 * dhcp_message_get_option_domains() in upstream's dhcp-message.c -- which
 * is why that decoder is not carried here.
 *
 * dns_label_escape() is carried, but only as a static helper inside
 * dns_name_concat()'s normalize round-trip (unescape then re-escape); it is
 * not exported, because its only external caller upstream was the option
 * 119 decoder this file does not have.
 *
 * Hard constraint honoured: no idn-util.h/libidn2, utf8.h, hexdecoct.h or
 * hash-funcs.h. dns_name_hash_func()/dns_name_compare_func() (siphash- and
 * strcasecmp-based ordering for a Hashmap key) are cut with them -- netd
 * never puts a DNS name in a hash table.
 *
 * Lives under src/netd/dhcp/ rather than as a top-level netd-*.c because
 * everything under src/netd/dhcp/ is LGPL-2.1-or-later and everything named
 * netd-*.[ch] is netd's own GPL-2.0-or-later code. This file is derived
 * work, so it belongs on the LGPL side of that line.
 */

#pragma once

/* Self-sufficient regardless of what a consumer includes first (a real
 * cross-agent bug: netd-resolv.c included dhcp-lease-internal.h without
 * netd-compat.h first, and this header needs its bool/usec_t/macros) --
 * safe to include redundantly, netd-compat.h has its own #pragma once. */
#include "netd-compat.h"


#include <stdbool.h>

/* 1 when `name` is a syntactically valid DNS name, 0 when not, -errno on a
 * real failure (OOM). */
int dns_name_is_valid(const char *name);

/* LDH-only variant (RFC 5890 "Letters, Digits, Hyphens", no backslash
 * escapes) -- kept for API parity even though its only upstream caller was
 * DNR (cut, plan §2.1). */
int dns_name_is_valid_ldh(const char *name);

/* Unescape + re-escape `name` into canonical form; *ret is a new string.
 * dhcp-message.c's normalize_dns_name() relies on the escaping side effect. */
int dns_name_normalize(const char *name, char **ret);

bool dns_name_is_root(const char *name);
bool dns_name_is_single_label(const char *name);

/* Case-insensitive label-wise equality; -errno on a malformed name on
 * either side. */
int dns_name_equal(const char *x, const char *y);
