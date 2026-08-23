/* SPDX-FileCopyrightText: 2013 Intel Corporation */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * QUARRY PLACEHOLDER -- src/libsystemd-network/dhcp-server-internal.h + dhcp-server-lease-internal.h (94 + 40 lines).
 *
 * The DHCPv4 server object and its lease table. Carries a real 2013 Intel
 * copyright line.
 *
 * The lease table is the one structural rewrite: upstream keeps four
 * Hashmaps (by address, by client-id, static and dynamic). At embedded
 * pool scale -- a usb gadget serving one client -- that is a flat array,
 * which is smaller, allocation-free and easier to reason about than four
 * hashmaps that must be kept consistent with each other.
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. Nothing has been lifted
 * yet; this file exists so meson, REUSE and the include graph are settled
 * before N3 starts, and so no later milestone has to edit
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

/* netd's name for upstream's sd_dhcp_server. */
typedef struct DhcpServer DhcpServer;
