/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The disk/partition debounce state machine (plans/31, Part 2, H1).
 *
 * The problem it exists for: inserting one card produces a burst of separate
 * uevents -- an `add` for the disk, then one `add` per partition -- with no
 * settle barrier between them and no message anywhere saying "that was all of
 * them". Reacting per event means reading the partition table at the disk's own
 * add, when the kernel has not created the partitions yet, and then reading it
 * again for every partition after that. So devd does not react per event: a
 * disk's arrival opens a short window, every partition of that disk that lands
 * inside the window extends it, and the reaction runs once when the window
 * closes -- one gpt_scan_all() for the whole card.
 *
 * The window has an absolute ceiling as well as a sliding deadline. A device
 * emitting a steady dribble of partition events would otherwise push the
 * deadline forever and the reaction would never run at all; the ceiling turns
 * that into "react on what has arrived so far", which is what the late path
 * below is for anyway.
 *
 * A partition that arrives after its disk has already settled -- a card
 * repartitioned in place, or an event the coldplug walk raced -- is not an
 * error and does not reopen the window: it is acted on immediately, on its own.
 *
 * This file deliberately knows nothing about GPT, mounting or symlinks. It
 * takes parsed uevents and a clock and returns what happened, which is what
 * makes the settle behaviour testable without a block device: test-devd-block.c
 * drives it with synthetic bursts and a fake clock. The reactions live in
 * devd-loop.c, which is where the timer and the real /dev are.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "../util.h"
#include "devd-uevent.h"

/*
 * Caps, not growth. A pico board has one boot disk and a slot or two, and the
 * input driving these arrays is "whatever someone plugged in" -- a bound that
 * this file sets is worth more here than one an external device sets. Going
 * over either is logged and the event dropped, never a reallocation.
 *
 * The numbers are what a real Linux block-device set needs once the virtual
 * devices below are excluded, with room to spare; 16 partitions on a removable
 * card is already well past anything this serves.
 */
#define DEVD_MAX_DISKS 32
#define DEVD_MAX_PARTS 16

/*
 * Kernel-synthesised block devices, which devd deliberately does not track.
 *
 * Not a name heuristic -- it is where the kernel puts a device that has no
 * physical parent: ramdisks, loop devices, device-mapper. None of them is
 * removable, none of them hotplugs, and none of them has a bus identity to
 * build a by-id link out of. Excluding them is not a tidiness preference
 * either: CONFIG_BLK_DEV_RAM alone puts sixteen ram* devices on every system
 * before anything is plugged in, which measured out at more than the whole disk
 * table on a first run of the real daemon.
 *
 * The named cost: a loop device carrying a GPT gets no by-* links here, where
 * upstream udev would name its partitions. v1 is prepared removable media.
 */
#define DEVD_VIRTUAL_PREFIX "/devices/virtual/"

/*
 * MTD flash, which devd tracks but never probes.
 *
 * Reading a GPT off NAND costs orders of magnitude more than off a real block
 * device, and there is never one there to find -- raw flash carries JFFS2/UBI,
 * not a partition table. The match is the MTD class directory the kernel puts
 * between the flash device and its block device
 * (/devices/platform/<flash>/mtd/mtd0/block/mtdblock0), not the node name.
 *
 * Excluded from the probe only, not from the disk table: h2200 boots from NAND,
 * so mtdblock0 has to stay visible here.
 */
#define DEVD_MTD_INFIX "/mtd/"

/* How long the window stays open after the last event of a burst, and how far
 * past the first event it may ever run. */
#define DEVD_SETTLE_USEC (250 * USEC_PER_MSEC)
#define DEVD_SETTLE_CEILING_USEC (2 * USEC_PER_SEC)

typedef enum DevdBlockOutcome {
        DEVD_BLOCK_IGNORED,      /* nothing devd tracks */
        DEVD_BLOCK_DISK_PENDING, /* a disk appeared; the window is open */
        DEVD_BLOCK_PART_PENDING, /* a partition joined an open window */
        DEVD_BLOCK_PART_LATE,    /* a partition of an already-settled disk: act now */
        DEVD_BLOCK_PART_GONE,    /* a partition went away */
        DEVD_BLOCK_DISK_GONE,    /* a whole disk went away */
        _DEVD_BLOCK_OUTCOME_MAX,
} DevdBlockOutcome;

typedef struct DevdDisk {
        char name[DEVD_NAME_MAX];
        char parts[DEVD_MAX_PARTS][DEVD_NAME_MAX];
        size_t n_parts;

        bool settling;   /* the window is open */
        bool settled;    /* the reaction has run at least once */
        bool no_probe;   /* MTD flash: tracked, never read from */
        usec_t deadline; /* when the window closes; extended by each event */
        usec_t ceiling;  /* the latest that deadline may ever be pushed to */
} DevdDisk;

typedef struct DevdBlock {
        DevdDisk disks[DEVD_MAX_DISKS];
        size_t n_disks;

        usec_t settle_usec;  /* DEVD_SETTLE_USEC unless a test says otherwise */
        usec_t ceiling_usec; /* DEVD_SETTLE_CEILING_USEC likewise */

        /* Where the names returned by devd_block_event() live. Owned by the
         * DevdBlock so a remove can report a partition it has just forgotten,
         * and valid only until the next call -- callers act immediately. */
        char scratch_disk[DEVD_NAME_MAX];
        char scratch_part[DEVD_NAME_MAX];
} DevdBlock;

/* Zero the state and set the two windows. Pass 0 for either to take the
 * default; a test passes something small so it does not sleep. */
void devd_block_init(DevdBlock *b, usec_t settle_usec, usec_t ceiling_usec);

/*
 * Feed one parsed uevent, with the caller's clock.
 *
 * *ret gets what happened; *ret_disk and *ret_part (either may be NULL) point
 * at the names it concerns, valid until the next call. Returns 0, or -errno for
 * a malformed event -- which is not the same as DEVD_BLOCK_IGNORED: ignored
 * means "understood, not ours".
 */
int devd_block_event(
                DevdBlock *b,
                const DevdUevent *u,
                usec_t now,
                DevdBlockOutcome *ret,
                const char **ret_disk,
                const char **ret_part);

/*
 * The earliest open window's deadline, or USEC_INFINITY when none is open.
 * devd-loop.c arms one timer on this rather than one timer per disk.
 */
usec_t devd_block_next_settle(const DevdBlock *b);

/*
 * The name of one disk whose window has closed, marking it settled, or NULL
 * when none has. Called in a loop until it returns NULL -- a single burst can
 * close two windows at once, and the caller reacts to each.
 */
const char *devd_block_take_settled(DevdBlock *b, usec_t now);

/*
 * The partitions currently recorded under `disk`, in arrival order. *ret points
 * into the DevdBlock and is valid until the next call that changes it. Returns
 * the count, or 0 for an unknown disk.
 */
size_t devd_block_partitions(const DevdBlock *b, const char *disk, const char (**ret)[DEVD_NAME_MAX]);

/* Whether `disk` is a class devd records but does not read from -- see
 * DEVD_MTD_INFIX. False for a disk it is not tracking. */
bool devd_block_probe_excluded(const DevdBlock *b, const char *disk);

/* Drop `disk` and everything recorded under it. Called once a DISK_GONE has
 * been acted on -- after its partitions have been read, not before. */
void devd_block_forget(DevdBlock *b, const char *disk);

/*
 * Split a block uevent's DEVPATH into the disk and partition names the kernel's
 * own topology implies: the partition is the last component, its disk the one
 * above it. Exposed because the coldplug walk needs the same split, and derived
 * from the path rather than from the node name on purpose -- "vda1" and
 * "mmcblk0p1" are the same relationship under two naming rules, and only sysfs
 * knows which is which. Returns 0 or -EINVAL.
 */
int devd_block_names(const DevdUevent *u, char *disk, size_t disk_size, char *part, size_t part_size);

const char *devd_block_outcome_to_string(DevdBlockOutcome o);
