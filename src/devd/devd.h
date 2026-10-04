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
 * H2 adds the third reaction, and it is the one devd does not decide itself:
 *
 *  - any device at all appears or disappears -> run the udev rules files
 *    /usr/lib/udev/rules.d and friends really contain, and do what they say --
 *    node permissions, alias symlinks, and starting a tool.
 *
 * That milestone exists because a consumer was already on the image and inert:
 * usb-modeswitch's 421-rule file, its dispatcher wrapper and its binary all
 * ship, and nothing has been firing them since eudev was removed. devd consumes
 * that file unmodified rather than a translated copy -- see devd-rules.h for
 * the subset, and for the one semantic (skip a rule whole, never clause by
 * clause) that keeps a partly-understood file from matching more than its
 * author meant.
 *
 * And a fourth, which is upstream udevd's own rather than a rules file's:
 *
 *  - an input device appears -> classify it the way upstream's input_id
 *    builtin does (ID_INPUT, ID_INPUT_TOUCHSCREEN, ...), before the rules run
 *    so they can match on it, and record the answer in /run/udev/data where
 *    the compat libsystemd's sd_device reads it back; disappears -> retire
 *    that entry. Xorg's config/udev finds no input devices at all without it
 *    -- see devd-input-id.h.
 *
 * What is deliberately NOT here: MBR/FAT probing (v1 is GPT-prepared media
 * only), by-path links, and DPS swap activation -- which stays in PID 1's
 * boot-time dps_scan() precisely because it is scoped to the boot disk, and
 * moving it here would only make swap arrive later for no gain.
 *
 * Implemented across devd.c (main), devd-loop.c (the object lifecycle, the
 * epoll loop, startup, coldplug and the reactions), devd-uevent.c (the netlink
 * listener and its parser), devd-block.c (the debounce state machine),
 * devd-probe.c (the ext superblock and by-id sysfs reads), devd-symlink.c (the
 * by-* families and the links rules name), devd-media.c (the mount policy),
 * devd-rules.c (the rules parser), devd-match.c (what a rule means),
 * devd-run.c (the RUN+= child), devd-modalias.c (module autoloading),
 * devd-input-id.c (input classification) and devd-udev-db.c (the udev
 * database entry that classification is published through).
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
 * The roots, fields rather than compile-time constants at the use site for the
 * reason netd's paths are settable: a test that created symlinks under the
 * host's real /dev, or mounted something on the machine running it, is a test
 * nobody can run twice. The fourth, udev_db_root, defaults to
 * DEVD_UDEV_DB_ROOT (devd-udev-db.h) and is settable for the same reason -- a
 * test that wrote into the host's real /run/udev/data would be feeding the
 * host's own udev consumers.
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

/*
 * Where the coldplug walk looks, relative to sys_root. /sys/class/block is the
 * block core's own; /sys/bus/usb/devices is what the rule engine needs, because
 * a modem or a HID-proxy dongle already attached at boot needs its mode switch
 * as much as one plugged in later does. Deliberately still far short of the
 * every-subsystem uevent-file replay a full device manager does.
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
 * still created and simply not tracked, which is what coldplug's dangling sweep
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
 * (netd.h) and is load-bearing for the same reason: a card inserted between the
 * walk and the subscription would be missed by both paths forever, and devd has
 * no device manager underneath it to fall back on. 0 or -errno.
 */
int devd_startup(Devd *d);
