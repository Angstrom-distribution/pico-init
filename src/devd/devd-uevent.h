/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The kernel uevent listener (plans/31, Part 2, milestone H1).
 *
 * Structurally this is netd-rtnl.c's nl_socket_open() with three deltas, and
 * the third one is the only interesting one:
 *
 *  1. NETLINK_KOBJECT_UEVENT rather than NETLINK_ROUTE.
 *  2. Multicast group 1 rather than RTNLGRP_LINK. Group 1 is the kernel's own
 *     broadcast group; group 2 is udev's rebroadcast, which carries a
 *     0xfeedcafe-magic header libudev's BPF filter demands and which nothing on
 *     a pico image ever writes to. devd listens to the kernel, not to a daemon
 *     that is not there.
 *  3. A sender check rtnetlink never needed. *Any* process can send to a
 *     netlink socket, and the messages arrive on this socket looking exactly
 *     like the kernel's. devd runs as root and reacts to what it reads by
 *     mounting filesystems and creating device symlinks, so without this check
 *     it is a root-privilege reaction engine driven by unprivileged, spoofable
 *     input. Both mdev and mdevd check it; so does this.
 *
 * The wire format is flat: "ACTION@DEVPATH" then NUL-separated KEY=VALUE pairs,
 * no TLV walk and no nesting, which is why the parser below is a loop over a
 * buffer rather than rtnetlink's attribute machinery.
 *
 * Overflow carries over from netd unchanged: on -ENOBUFS the stream has dropped
 * events and the only correct answer is a full resync -- here, redoing the
 * coldplug walk, which by construction regenerates everything the lost events
 * would have said.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Long enough for any real DEVPATH; the kernel's own uevent buffer is 2048. */
#define DEVD_DEVPATH_MAX 512
#define DEVD_NAME_MAX 64
#define DEVD_SUBSYSTEM_MAX 32
#define DEVD_DEVTYPE_MAX 32

/* One kernel uevent message. */
#define DEVD_UEVENT_BUF_MAX 4096

/*
 * How much of the message's KEY=VALUE tail is kept verbatim.
 *
 * H1 needed six named fields and nothing else. The rule engine needs the rest:
 * ENV{} matches against whatever the kernel sent, and a RUN+= child is given
 * the same properties in its environment -- which is how `usb_modeswitch`
 * learns what it was called about. Keeping the tail as the wire's own
 * NUL-separated blob rather than re-parsing it into a table here leaves the
 * table's shape to devd-match.c, which is the file that has to bound it.
 */
#define DEVD_UEVENT_PROPS_MAX 2048

/*
 * Only the actions devd distinguishes. Everything else the kernel can send
 * (change, move, bind, unbind, online, offline) collapses to _OTHER: none of
 * them create or destroy a block device, and treating an unknown future action
 * as "act on it" is the wrong default for code that mounts things.
 */
typedef enum DevdAction {
        DEVD_ACTION_ADD,
        DEVD_ACTION_REMOVE,
        DEVD_ACTION_OTHER,
        _DEVD_ACTION_MAX,
} DevdAction;

typedef struct DevdUevent {
        DevdAction action;

        char devpath[DEVD_DEVPATH_MAX];     /* DEVPATH, kernel-relative: /devices/... */
        char subsystem[DEVD_SUBSYSTEM_MAX]; /* SUBSYSTEM= */
        char devname[DEVD_NAME_MAX];        /* DEVNAME=, e.g. "sda1"; "" when absent */
        char devtype[DEVD_DEVTYPE_MAX];     /* DEVTYPE=, "disk" or "partition" for block */

        unsigned major, minor;
        bool have_devno;

        unsigned partn; /* PARTN=, 0 when absent */

        /* The message's property tail, NUL-separated exactly as received and
         * truncated at the last whole pair that fits. */
        char props[DEVD_UEVENT_PROPS_MAX];
        size_t props_len;
} DevdUevent;

/*
 * Parse one received message. Returns 0, or -EINVAL when the buffer is not a
 * kernel uevent at all -- including the libudev-format messages group 2 carries,
 * which are rejected by their own "libudev\0" magic rather than misparsed.
 *
 * `n` is the received length, and no read here goes past it: a uevent is
 * NUL-separated by convention, not by guarantee, and a message whose last field
 * is unterminated is a malformed message rather than a licence to run off the
 * end of the buffer.
 */
int devd_uevent_parse(const char *buf, size_t n, DevdUevent *ret);

/*
 * Is this message really from the kernel? `nl_pid` and `nl_groups` come from
 * the sockaddr_nl recvmsg() filled in.
 *
 * Both halves are load-bearing. nl_pid == 0 means the sender is the kernel
 * rather than a process, and nl_groups != 0 means the message arrived by
 * multicast rather than as a unicast send aimed straight at this socket -- a
 * peer can spoof neither, but a peer that could spoof one would still be caught
 * by the other. Split out from the socket code so it can be tested without a
 * privileged sender to test against.
 */
bool devd_uevent_sender_is_kernel(uint32_t nl_pid, uint32_t nl_groups);

/* The action name, for logs. */
const char *devd_action_to_string(DevdAction a);

/*
 * Open the group-1 uevent socket. Returns the fd or -errno.
 *
 * Subscription happens here, before any caller walks sysfs -- netd's own
 * stated ordering (netd.h: "subscribe before enumerating"), for the same reason
 * and with the same consequence if it is got backwards: a device appearing
 * between the walk and the subscription would be missed by both paths forever,
 * and devd has no After=eudev.service to hide behind either.
 */
int devd_uevent_open(void);

/*
 * Read one message into `ret`. Returns 1 on a parsed message, 0 for one
 * dropped before parsing (a spoofed sender, an unparseable buffer -- both
 * logged, neither an error), -EAGAIN when the socket is drained, or -errno.
 * -ENOBUFS specifically means the kernel dropped events: resync, do not retry.
 */
int devd_uevent_recv(int fd, DevdUevent *ret);
