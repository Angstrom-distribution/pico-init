/* SPDX-FileCopyrightText: 2013 Intel Corporation */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * QUARRY PLACEHOLDER -- src/libsystemd-network/sd-dhcp-lease.c (831 lines).
 *
 * Lease construction from a DHCPACK and the accessors for every option
 * netd uses -- including option 42 (NTP servers) and option 101 (TZDB
 * timezone name), which are the reason netd exists at all.
 *
 * Note on option 100 vs 101: upstream defines
 * SD_DHCP_OPTION_POSIX_TIMEZONE = 100 but has never parsed it anywhere.
 * Only 101 is implemented, and netd matches that choice rather than
 * inventing support for a code no server sends.
 *
 * Dropped entirely: lease-file persistence. Upstream's is the single
 * biggest hidden dependency in the whole analysis -- it pulls in 10,346
 * lines of sd-json to write one file. netd's leases live in memory, and
 * the trivial /run/netd/leases/<ifindex> text file netd-link.c writes is
 * its own format
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

#include "dhcp-lease-internal.h"
