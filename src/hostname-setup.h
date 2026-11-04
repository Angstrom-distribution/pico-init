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
 * /etc/hostname and still show "(none)" forever.
 */

#pragma once

#include <stddef.h>

/*
 * Reads the first line of path into buf (size bytes, at least 2), without
 * its line ending and trailing blanks. Returns the length, 0 when there is
 * nothing to apply (no such file, empty file or a blank line; buf may then
 * be unchanged), or -errno on a read failure.
 */
int hostname_read(const char *path, char *buf, size_t size);

/*
 * Reads /etc/hostname and applies it via sethostname(2).
 *
 * Best-effort: a missing or empty /etc/hostname just leaves the kernel
 * default alone, matching systemd's own hostname_setup() behaviour -- a
 * board with no configured hostname is not a boot failure. Returns 1 when
 * the call changed the hostname, 0 when there was nothing to change, or
 * -errno on a real failure.
 *
 * name must hold HOST_NAME_MAX + 1 bytes. It is set to the hostname that
 * was applied (return 1) or that could not be applied (sethostname(2)
 * failed), and to "" otherwise. Nothing is logged: this runs before
 * /dev/kmsg is the log sink, so the caller reports the result once it is.
 */
int hostname_setup(char *name);
