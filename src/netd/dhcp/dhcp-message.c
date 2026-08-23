/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * QUARRY PLACEHOLDER -- src/libsystemd-network/dhcp-message.c (1,794 lines).
 *
 * The DHCPv4 wire codec: option append, option parse, message
 * construction. Zero sd_event references -- a genuine near-verbatim port.
 *
 * Cut on the way in (plan §2.1): FQDN (option 81) and DNR (option 162),
 * 232 lines that between them drag in the whole 1,376-line dns-domain.c
 * wire-format codec and sd-dns-resolver.c. Domain Search (option 119) is
 * cut too, which is what removes the RFC 3397 compression-pointer decoder
 * and dns_label_escape() -- see dns-name.h. Options 12 and 15 stay, and
 * they still need the flat-string name helpers.
 *
 * Watch for: this file holds 93 assert() calls, many of them on parsed
 * packet bytes. Read the assertion policy at the top of netd-compat.h
 * before lifting a single one of them
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

#include "dhcp-message.h"
