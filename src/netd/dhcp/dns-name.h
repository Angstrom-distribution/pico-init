/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * QUARRY PLACEHOLDER -- src/shared/dns-domain.c (subset) (~200 of 1,376 lines).
 *
 * The flat-string DNS name helpers, and only those: dns_name_normalize(),
 * dns_name_is_root(), dns_name_is_single_label(), dns_name_is_valid(),
 * dns_name_is_valid_ldh(), dns_name_equal().
 *
 * Plan §2.1 claims dropping options 81 and 162 removes dns-domain.c
 * entirely. That is wrong, and the quarry-history review caught it:
 * options 12 (Host Name) and 15 (Domain Name) still route through
 * dhcp_message_get_option_dns_name(), and §2.7 needs the domain for
 * resolv.conf. What *does* remove the expensive half is additionally
 * dropping option 119 (Domain Search), which is the only caller of the
 * RFC 3397 compression-pointer decoder and dns_label_escape().
 *
 * Hard constraint on the lift: this must not pull in idn-util.h/libidn2,
 * utf8.h, hexdecoct.h or hash-funcs.h. If a helper needs one of those, it
 * is not in the subset.
 *
 * Lives here rather than as a top-level netd-*.c because everything under
 * src/netd/dhcp/ is LGPL-2.1-or-later and everything named netd-*.[ch] is
 * netd's own GPL-2.0-or-later code. This file is derived work, so it
 * belongs on the LGPL side of that line
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. Nothing has been lifted
 * yet; this file exists so meson, REUSE and the include graph are settled
 * before N2 starts, and so no later milestone has to edit
 * meson.build while another one is also editing it.
 *
 * When the lift happens, this comment is replaced by the real one, in exactly
 * the style src/unit-parse.c's header demonstrates: the history review from
 * 4925d9f07f forward on main, and one recorded keep-or-backport call per
 * upstream fix, each with its commit hash. That record is the deliverable,
 * not a formality -- it is the only thing that makes a lifted file
 * maintainable afterwards.
 */

#pragma once

/* 1 when `name` is a syntactically valid DNS name, 0 when not, -errno on a
 * failure to decide. The whole flat-string subset lands beside it. */
int dns_name_is_valid(const char *name);
