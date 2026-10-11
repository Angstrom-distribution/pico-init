/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * devd: the device hotplug daemon.
 *
 * Images run devtmpfs-only, with no udev. devtmpfs creates and removes device
 * nodes itself, hotplug included; what it does not do is react. devd reacts:
 *
 *  - removable media appears -> read its GPT, mount its data partitions under
 *    /media/<partlabel>; disappears -> unmount and clean up.
 *  - any block device appears or disappears -> maintain the
 *    /dev/disk/by-{partuuid,partlabel,uuid,label,id} symlinks.
 *  - any device appears or disappears -> run the udev rules files found in
 *    /usr/lib/udev/rules.d and friends: node permissions, alias symlinks and
 *    starting a tool. Rule files are consumed unmodified; devd-rules.h
 *    describes the supported subset, and the rule that a partly understood
 *    rule is skipped whole, never clause by clause.
 *  - an input device appears -> classify it the way upstream's input_id
 *    builtin does (ID_INPUT, ID_INPUT_TOUCHSCREEN, ...) before the rules run,
 *    and record the answer in /run/udev/data where the compat libsystemd's
 *    sd_device reads it back; disappears -> retire that entry. Xorg's
 *    config/udev finds no input devices without it; see devd-input-id.h.
 *  - a device with a MODALIAS appears -> load its module; see devd-modalias.h.
 *
 * devd is a separate supervised daemon, not code inside PID 1: a wedged devd
 * costs a unit restart rather than the machine, and the coldplug walk after a
 * restart re-derives every missed event from what /sys says now. It does not
 * talk to PID 1 at all; mount(2) and symlink(2) are done directly.
 *
 * Not handled: MBR/FAT probing (only GPT-prepared media), by-path links, and
 * DPS swap activation, which stays in PID 1's boot-time dps_scan() because it
 * is scoped to the boot disk.
 *
 * Implemented across devd.c (main), devd-loop.c (the object lifecycle, the
 * epoll loop, startup, coldplug and the reactions), devd-uevent.c (the netlink
 * listener and its parser), devd-block.c (the debounce state machine),
 * devd-probe.c (the by-id sysfs reads), devd-symlink.c (the by-* families and
 * the links rules name), devd-media.c (the mount policy), devd-rules.c (the
 * rules parser), devd-match.c (what a rule means), devd-run.c (the RUN+=
 * child), devd-modalias.c (module autoloading), devd-input-id.c (input
 * classification) and devd-udev-db.c (the udev database entry that
 * classification is published through).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "../signal.h"
#include "../timer.h"
#include "../util.h"
#include "devd-block.h"
#include "devd-loop.h"
#include "devd-match.h"
#include "devd-rules.h"
#include "devd-run.h"
#include "devd-udev-db.h"

typedef struct Devd Devd;

/*
 * The roots are struct fields rather than constants at the use site so tests
 * can point them at a fixture instead of the host's real /dev, /media and
 * /run/udev/data. udev_db_root defaults to DEVD_UDEV_DB_ROOT (devd-udev-db.h).
 */
#define DEVD_SYS_ROOT "/sys"
#define DEVD_DEV_ROOT "/dev"
#define DEVD_MEDIA_ROOT "/media"

/* One mount devd made. The path is always <media_root>/<one component>, hence
 * the short buffer. */
#define DEVD_MAX_MOUNTS 32
#define DEVD_MOUNT_PATH_MAX 160

typedef struct DevdMount {
        char devname[DEVD_NAME_MAX];
        char dir[DEVD_MOUNT_PATH_MAX];
} DevdMount;

/*
 * Where the coldplug walk looks, relative to sys_root. /sys/class/block is the
 * block core's own; /sys/bus/usb/devices is for the rule engine, because a
 * device already attached at boot needs its mode switch as much as one plugged
 * in later. Not a replay of every subsystem's uevent file.
 */
#define DEVD_COLDPLUG_BLOCK "class/block"
#define DEVD_COLDPLUG_USB "bus/usb/devices"

/*
 * Every input device already present, for classification. Walked whether or
 * not any rules are loaded: on h2200 every input device that exists at boot
 * is a devicetree platform device whose ADD uevent fired before devd's socket
 * was open, so this walk is the only path that ever classifies them.
 */
#define DEVD_COLDPLUG_INPUT "class/input"

/*
 * One symlink a SYMLINK+= rule made, remembered so it can be removed when the
 * device goes. Bounded like every other table here; over the bound the link is
 * still created and not tracked, which is what coldplug's dangling sweep
 * is the backstop for.
 */
#define DEVD_MAX_RULE_LINKS 32

typedef struct DevdRuleLink {
        char devname[DEVD_NAME_MAX];
        char path[DEVD_RULE_LINK_MAX];
} DevdRuleLink;

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

        /* --- the rule engine (devd-rules.c, devd-match.c, devd-run.c) --- */
        DevdRuleSet *rules;
        DevdRun run;

        /*
         * One reusable device context rather than one per event. It is about
         * eleven kilobytes -- the property table dominates -- which is a large
         * stack frame to build and tear down on every uevent of a coldplug
         * burst, and there is never more than one event in flight.
         */
        DevdRuleDevice *rule_device;

        /* --- what has been done --- */
        DevdMount mounts[DEVD_MAX_MOUNTS];
        size_t n_mounts;

        DevdRuleLink rule_links[DEVD_MAX_RULE_LINKS];
        size_t n_rule_links;

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
        char *udev_db_root;

        DevdObjective objective;
};

/* Allocate, open the signalfd and timerfd, set up epoll. 0 or -errno. */
int devd_new(Devd **ret);

Devd *devd_free(Devd *d);

int devd_set_sys_root(Devd *d, const char *path);
int devd_set_dev_root(Devd *d, const char *path);
int devd_set_media_root(Devd *d, const char *path);
int devd_set_udev_db_root(Devd *d, const char *path);

/*
 * Subscribe first, then walk. The ordering is netd's own stated convention
 * (netd.h) and matters for the same reason: a card inserted between the
 * walk and the subscription would be missed by both paths forever, and devd has
 * no device manager underneath it to fall back on. 0 or -errno.
 */
int devd_startup(Devd *d);
