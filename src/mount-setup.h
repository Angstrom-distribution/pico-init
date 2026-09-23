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

#include <stdbool.h>
#include <stdint.h>

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

/*
 * Whether `where` is one of the table's mount points, and if so its hardening
 * floor: the MOUNT_ATTR_NOSUID/NODEV/NOEXEC bits the table mounts it with.
 *
 * For the fstab pass, which reapplies an fstab line's options to these mounts
 * rather than mounting them a second time -- and must never drop the floor
 * while doing it, since a "defaults" line rebuilt into a remount would
 * otherwise clear exactly the flags the comment above the table says are not
 * decoration.
 */
bool mount_setup_api_floor(const char *where, uint64_t *ret_floor);

/*
 * The five /dev symlinks PID 1 owns: /dev/fd, /dev/stdin, /dev/stdout,
 * /dev/stderr and (when the kernel has one) /dev/core.
 *
 * Nobody else makes these either. devtmpfs creates device nodes, never
 * symlinks, and every device manager since udev ~176 is only a policy layer on
 * top of it -- so on a devtmpfs-only image these simply do not exist, and
 * `foo >/dev/stderr` and every /dev/fd/N shell idiom fail. Upstream systemd
 * has them in PID 1 for exactly this reason (src/shared/dev-setup.c), not in
 * udev.
 *
 * `prefix` is prepended to each link's own path for tests; NULL means none.
 * The link *targets* are never prefixed -- see mount-setup.c.
 *
 * Idempotent, and safe to call on a /dev that already has some of them.
 * Returns the number of the five now correctly in place, or -errno only on an
 * internal error (a path that will not fit). A symlink that cannot be created
 * is logged and skipped: none of these is worth refusing to boot over.
 */
int dev_setup(const char *prefix);

/*
 * Kernel tunables PID 1 sets once, after mount_setup() has given it a /proc.
 *
 * Currently one: net.unix.max_dgram_qlen. Its distro default is commonly 10,
 * which caps an AF_UNIX SOCK_DGRAM receive queue at eleven datagrams
 * regardless of SO_RCVBUF -- and that queue is what holds a service's output
 * across a logd restart, so eleven datagrams against a 4 KiB stdio flush unit
 * is only ~44 KiB of crash-survival window per service. Raised to 64.
 *
 * Best-effort and silent: a read-only /proc/sys must never stop a boot.
 */
void sysctl_setup(void);
