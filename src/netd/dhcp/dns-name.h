/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported subset of systemd v261.2 src/shared/dns-domain.c: the flat-string
 * DNS name helpers dhcp-message.c's option 12/15 (Host Name, Domain Name)
 * path needs: dns_name_normalize(), dns_name_is_root(),
 * dns_name_is_single_label(), dns_name_is_valid(), dns_name_is_valid_ldh(),
 * dns_name_equal().
 *
 * Not carried: the RFC 3397 compression-pointer decoder (its only caller is
 * the option 119 Domain Search path, which is cut) and
 * dns_name_hash_func()/dns_name_compare_func() (no DNS name is hashed).
 * dns_label_escape() is a static helper used by the normalize round-trip.
 * No libidn2, utf8.h, hexdecoct.h or hash-funcs.h dependency.
 *
 * Lives under src/netd/dhcp/ because that directory is LGPL-2.1-or-later and
 * netd-*.[ch] is GPL-2.0-or-later; this file is derived work.
 */

#pragma once

/* Self-sufficient: needs bool/usec_t/macros from netd-compat.h. */
#include "netd-compat.h"


#include <stdbool.h>

/* 1 when `name` is a syntactically valid DNS name, 0 when not, -errno on a
 * real failure (OOM). */
int dns_name_is_valid(const char *name);

/* LDH-only variant (RFC 5890 "Letters, Digits, Hyphens", no backslash
 * escapes). Kept for parity with upstream; its upstream caller (DNR) is cut. */
int dns_name_is_valid_ldh(const char *name);

/* Unescape + re-escape `name` into canonical form; *ret is a new string.
 * dhcp-message.c's normalize_dns_name() relies on the escaping side effect. */
int dns_name_normalize(const char *name, char **ret);

bool dns_name_is_root(const char *name);
bool dns_name_is_single_label(const char *name);

/* Case-insensitive label-wise equality; -errno on a malformed name on
 * either side. */
int dns_name_equal(const char *x, const char *y);
