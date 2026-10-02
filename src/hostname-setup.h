/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Applying /etc/hostname to the running kernel.
 *
 * Nothing else does this. The kernel boots with hostname "(none)" and never
 * reads /etc/hostname itself; systemd applies it once, early, from PID 1
 * (src/core/hostname-setup.c's hostname_setup()) -- every tool downstream
 * (the shell prompt, uname -n, gethostname(2)) just reflects whatever the
 * last sethostname(2) call set. Without this, an image can ship a real
 * /etc/hostname and still show "(none)" forever: confirmed live on h2200,
 * /etc/hostname containing "h2200" with the kernel hostname never leaving
 * its boot-time default.
 */

#pragma once

/*
 * Reads /etc/hostname and applies it via sethostname(2).
 *
 * Best-effort and silent on the common "nothing to do" cases: a missing or
 * empty /etc/hostname just leaves the kernel default alone, matching
 * systemd's own hostname_setup() behaviour -- a board with no configured
 * hostname is not a boot failure. Returns 0 on success (including the
 * nothing-to-do cases) or -errno on a real failure applying a hostname that
 * was actually read.
 */
int hostname_setup(void);
