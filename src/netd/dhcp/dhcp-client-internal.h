/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * QUARRY PLACEHOLDER -- src/libsystemd-network/dhcp-client-internal.h (44 lines).
 *
 * The DHCPv4 client object's layout.
 *
 * This is where the rewrite shows: upstream holds five sd_event_source
 * pointers (timeout_resend, timeout_t1, timeout_t2, timeout_expire,
 * receive_message). netd holds four PicoTimerEvent handles and one
 * netd_epoll_tag instead -- and timer.h's handle-lifetime contract is
 * exactly what those four need: the queue NULLs the owner's slot when an
 * event fires or is cancelled, so a stale handle cannot exist.
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. Nothing has been lifted
 * yet; this file exists so meson, REUSE and the include graph are settled
 * before N1 starts, and so no later milestone has to edit
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

/* netd's name for upstream's sd_dhcp_client. */
typedef struct DhcpClient DhcpClient;
