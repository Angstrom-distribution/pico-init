/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The API virtual filesystems PID 1 must mount before anything else can work.
 *
 * Nothing else does this. The kernel mounts the root filesystem and hands
 * control to /sbin/init, and that is all -- /proc, /sys, /run and the rest are
 * PID 1's responsibility, and every other process on the system assumes they
 * are already there. Without them: no /proc/self, so ps and every process tool
 * is blind; no /sys/fs/cgroup, so this project's entire supervision mechanism
 * silently degrades to running services unsupervised; no /run, so anything
 * expecting a writable runtime directory fails.
 *
 * That last one is not hypothetical here -- an image booted before this
 * existed reached a working login prompt with `mount` itself reporting
 * "no /proc/mounts", which is exactly how invisible this failure is from
 * inside PID 1: everything appears to start correctly.
 */

#pragma once

/*
 * Mount everything in the table, in order. Idempotent: a filesystem the kernel
 * or an initramfs already mounted is left alone rather than stacked on.
 *
 * Returns the number mounted, or -errno if one of the mounts this really
 * cannot run without failed. A failure on an optional mountpoint is logged and
 * skipped -- a missing /dev/shm should not stop a board from booting to a
 * console where someone can debug it.
 */
int mount_setup(void);
