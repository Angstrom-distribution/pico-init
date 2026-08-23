/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * QUARRY PLACEHOLDER -- src/libsystemd-network/dhcp-client-send.c + dhcp-client-send.h (708 + 22 lines).
 *
 * Building and transmitting DISCOVER/REQUEST/DECLINE/RELEASE/INFORM,
 * including the raw AF_PACKET path used before an address exists.
 *
 * The parameter request list is built here. Upstream uses a Set of
 * UINT8_TO_PTR keys; netd uses the NetdU8Set bitmap from netd-compat.h,
 * which also makes the emitted list deterministic -- load-bearing for the
 * golden-byte codec tests of §2.8.
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

#include "dhcp-client-internal.h"
