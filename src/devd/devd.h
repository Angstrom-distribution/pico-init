/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * devd: angstrom-pico's device hotplug daemon (plans/31, Part 2, milestone H1).
 *
 * These images run devtmpfs-only, with no udev and no replacement -- eudev was
 * removed this same cycle for a measured 18.1 MiB. devtmpfs creates and removes
 * every device node itself, hotplug included, so nodes are free. What devtmpfs
 * does not do is *react*, and this milestone is exactly two reactions:
 *
 *  - removable media appears -> read its GPT, mount its data partitions under
 *    /media/<partlabel>; disappears -> unmount and clean up.
 *  - any block device appears or disappears -> maintain the whole
 *    /dev/disk/by-{partuuid,partlabel,uuid,label,id} symlink surface.
 *
 * devd is a separate supervised daemon, not code inside PID 1 -- an owner
 * decision recorded in the plan, with two consequences worth stating here. It
 * costs a unit restart rather than the machine when it wedges, and after that
 * restart the coldplug walk is by construction a full recovery: every event
 * that was missed while devd was down is re-derived from what /sys says now.
 * PID 1's risk delta from this entire daemon is zero lines.
 *
 * It talks to PID 1 not at all. Both reactions are things a root process does
 * directly -- mount(2), symlink(2) -- so the IPC question the daemon shape
 * raises has the cheapest possible answer for this milestone. The control
 * socket seam exists (src/manager-ctrl.h) for the day something wants unit-
 * shaped visibility into a device; nothing here needs it.
 *
 * What is deliberately NOT here: the udev-rules engine (H2, the next
 * milestone), MBR/FAT probing (v1 is GPT-prepared media only), by-path links,
 * and DPS swap activation -- which stays in PID 1's boot-time dps_scan()
 * precisely because it is scoped to the boot disk, and moving it here would
 * only make swap arrive later for no gain.
 *
 * Implemented across devd.c (main), devd-loop.c (the object lifecycle, the
 * epoll loop, startup, coldplug and the reactions), devd-uevent.c (the netlink
 * listener and its parser), devd-block.c (the debounce state machine),
 * devd-probe.c (the ext superblock and by-id sysfs reads), devd-symlink.c (the
 * by-* families) and devd-media.c (the mount policy).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "../signal.h"
#include "../timer.h"
#include "../util.h"
#include "devd-block.h"
#include "devd-loop.h"

typedef struct Devd Devd;

/*
 * The three roots, fields rather than compile-time constants at the use site
 * for the reason netd's paths are settable: a test that created symlinks under
 * the host's real /dev, or mounted something on the machine running it, is a
 * test nobody can run twice.
 */
#define DEVD_SYS_ROOT "/sys"
#define DEVD_DEV_ROOT "/dev"
#define DEVD_MEDIA_ROOT "/media"

/* One mount devd made. Enough of them for every slot on any pico board, and a
 * short path buffer because every one of them is <media_root>/<one component>
 * by construction -- not a general path. */
#define DEVD_MAX_MOUNTS 32
#define DEVD_MOUNT_PATH_MAX 160

typedef struct DevdMount {
        char devname[DEVD_NAME_MAX];
        char dir[DEVD_MOUNT_PATH_MAX];
} DevdMount;

typedef enum DevdObjective {
        DEVD_RUNNING,
        DEVD_EXIT,
        _DEVD_OBJECTIVE_MAX,
} DevdObjective;

struct Devd {
        /* --- event plumbing (devd-loop.c) --- */
        int epoll_fd;
        PicoSignal *signal;
        PicoTimer *timer;

        struct devd_epoll_tag signal_tag;
        struct devd_epoll_tag timer_tag;
        struct devd_epoll_tag uevent_tag;

        /* --- the kernel interface (devd-uevent.c) --- */
        int uevent_fd;

        /* --- what has been seen (devd-block.c) --- */
        DevdBlock block;

        /*
         * One timer for the nearest open settle window, not one per disk. The
         * handle slot is owned here because pico_timer_add() writes through it
         * and clears it when the event fires -- see timer.h's HANDLE LIFETIME
         * note; a local would dangle.
         */
        PicoTimerEvent *settle_event;
        usec_t settle_at;

        /* --- what has been done --- */
        DevdMount mounts[DEVD_MAX_MOUNTS];
        size_t n_mounts;

        /*
         * The whole-disk device the root filesystem is on, or "" when the root
         * is not on a block device at all. Nothing on it is ever mounted under
         * /media: PID 1 already owns that disk, and a second mount of the root
         * partition is the exact surprise the DPS root-disk cross-check exists
         * to prevent (devd-media.h).
         */
        char boot_disk[DEVD_NAME_MAX];

        /* --- paths, all owned and all settable --- */
        char *sys_root;
        char *dev_root;
        char *media_root;

        DevdObjective objective;
};

/* Allocate, open the signalfd and timerfd, set up epoll. 0 or -errno. */
int devd_new(Devd **ret);

Devd *devd_free(Devd *d);

int devd_set_sys_root(Devd *d, const char *path);
int devd_set_dev_root(Devd *d, const char *path);
int devd_set_media_root(Devd *d, const char *path);

/*
 * Subscribe first, then walk. The ordering is netd's own stated convention
 * (netd.h) and is load-bearing for the same reason: a card inserted between the
 * walk and the subscription would be missed by both paths forever, and devd has
 * no device manager underneath it to fall back on. 0 or -errno.
 */
int devd_startup(Devd *d);
