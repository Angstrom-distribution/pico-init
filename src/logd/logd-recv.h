/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Datagram receive, per-PID fragment handling, /dev/log parsing and ucred+cgroup attribution (plan §3.2/§3.3).
 *
 * Scaffolding: milestone J1 owns this file and lands the real body. It is
 * registered in the build now so that milestone adds code to a file that
 * already exists and is already compiled, rather than editing meson.build
 * while another milestone is also editing it.
 */

#pragma once

/*
 * Placeholder so this file declares something and its translation unit is not
 * empty under -Wpedantic. Milestone J1 replaces it with the real surface;
 * nothing calls it, and it returns -ENOSYS rather than succeeding so a stray
 * caller fails loudly instead of silently doing nothing.
 */
int logd_recv_not_implemented(void);
