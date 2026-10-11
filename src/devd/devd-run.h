/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * RUN+=: starting a tool on match, without ever waiting for it.
 *
 * devd is a single-threaded epoll loop, and `usb_modeswitch` against a modem
 * that is mid-reset can take seconds -- long enough for the kernel's uevent
 * socket buffer to overrun and for devd to miss the events the tool's own work
 * produces. So a RUN+= child is forked, recorded and left alone; it is reaped
 * when SIGCHLD arrives on the signalfd the loop already watches.
 *
 * A fork/exec in a signalfd daemon must do two things, both handled in the
 * child:
 *
 *  - Restore the signal mask. pico_signal_new() blocks SIGCHLD, SIGTERM and the
 *    rest process-wide so they can be read from a descriptor instead, and
 *    execve(2) preserves the mask across the exec. A helper started from here
 *    would otherwise inherit a process that cannot be interrupted or terminated
 *    in the ordinary way -- and would pass that on to anything it starts.
 *  - Give it a stdin. A tool that reads from a closed or inherited descriptor
 *    on a hotplug path is a hang with no console attached to notice it.
 *
 * The environment a child gets is the device's own properties (devd-match.c
 * builds it), which is how `usb_modeswitch` learns which device it was called
 * about beyond the argument the rule passed it.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * Where a RUN+= program with a non-absolute path is looked up (udev's own
 * rule). usb-modeswitch's rules file calls its dispatcher
 * /usr/lib/udev/usb_modeswitch by the bare name.
 */
#define DEVD_RUN_HELPER_DIR "/usr/lib/udev"

/*
 * Caps. The concurrency one is a real policy and not just an array bound: a
 * card reader full of partitions could otherwise fork a helper per partition
 * faster than any of them finish, on a machine with 64MiB of RAM.
 */
#define DEVD_RUN_CHILDREN_MAX 16
#define DEVD_RUN_ARGV_MAX 16
#define DEVD_RUN_ARG_MAX 192
#define DEVD_RUN_NAME_MAX 96
#define DEVD_RUN_PATH_MAX 256

typedef struct DevdRunChild {
        pid_t pid;
        char name[DEVD_RUN_NAME_MAX]; /* argv[0]'s basename, for the exit line */
} DevdRunChild;

typedef struct DevdRun {
        DevdRunChild children[DEVD_RUN_CHILDREN_MAX];
        size_t n_children;

        char helper_dir[DEVD_RUN_PATH_MAX];

        unsigned n_started;
        unsigned n_reaped;
        unsigned n_failed; /* exited non-zero or on a signal */
} DevdRun;

/* Zero the table and point the helper directory at DEVD_RUN_HELPER_DIR. */
void devd_run_init(DevdRun *r);

/* Point it somewhere else -- what lets a test run a helper it wrote itself
 * rather than whatever the host has in /usr/lib/udev. 0 or -errno. */
int devd_run_set_helper_dir(DevdRun *r, const char *dir);

/*
 * Split a RUN+= value into argv the way udev does: whitespace-separated, with
 * single and double quotes grouping and then removed. `usb_modeswitch '/%k'` is
 * two arguments, and the quotes are not part of the second one.
 *
 * Returns the argument count, or -EINVAL on an unterminated quote or an
 * argument that does not fit.
 */
int devd_run_split(const char *cmd, char argv[][DEVD_RUN_ARG_MAX], size_t max);

/*
 * Start `cmd`, with `env` (NULL-terminated) as the child's whole environment.
 * Returns the pid, -EAGAIN when too many children are already running, or
 * -errno. Never waits, never blocks on the child.
 */
int devd_run_spawn(DevdRun *r, const char *cmd, char * const *env);

/*
 * Reap everything that has exited, logging any that failed. Returns the number
 * reaped. Called from the SIGCHLD path of the loop's signal dispatch -- and
 * safe to call at any other time, which is what lets a test drive it without a
 * signalfd.
 */
int devd_run_reap(DevdRun *r);

/* How many children are still running. */
size_t devd_run_pending(const DevdRun *r);
