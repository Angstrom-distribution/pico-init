/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * QUARRY PLACEHOLDER -- src/libsystemd-network/tlv-util.h (85 lines).
 *
 * The type-length-value option list that struct sd_dhcp_message embeds by
 * value. Missing from plan §2.2's quarry table, and not optional:
 * dhcp-message.h includes it and dhcp-message.c cannot compile without
 * it. No upstream copyright line.
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

/* The type-length-value option list struct DhcpMessage embeds by value. */
typedef struct DhcpTlv DhcpTlv;
