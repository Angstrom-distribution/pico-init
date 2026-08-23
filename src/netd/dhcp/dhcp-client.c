/* SPDX-FileCopyrightText: 2013 Intel Corporation */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * QUARRY PLACEHOLDER -- src/libsystemd-network/sd-dhcp-client.c (1,445 lines).
 *
 * The DHCPv4 client state machine: INIT -> SELECTING -> REQUESTING ->
 * BOUND, with RENEWING/REBINDING off T1/T2 and expiry.
 *
 * The long pole of the whole netd effort, and a rewrite wearing a port's
 * clothes (plan §2.1). 28.3% of this file's function-body lines are
 * event/timer plumbing, and it is smeared across roughly 9 of its ~35
 * functions rather than confined to a bottom layer:
 * client_enter_requesting() ends by arming the resend timer, and
 * client_timeout_resend() -- 122 lines, the biggest function here --
 * interleaves backoff arithmetic, transmission and rescheduling.
 *
 * So: the protocol logic inside those functions is kept, their control
 * flow is re-derived against pico-init's timer queue, and each one is
 * reviewed against the RFC 2131 timing behaviour the original encodes.
 * That review is the expensive part of N2, not the typing.
 *
 * Carries a real 2013 Intel copyright line. No netlink dependency
 * whatsoever -- AF_PACKET before a lease, plain UDP after -- which is
 * what makes the DHCP lift and the sd-netlink decision independent
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
