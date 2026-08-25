/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The debounce state machine, driven with synthetic bursts and a fake clock.
 *
 * This is the part of devd that would otherwise only be testable by plugging a
 * card in, and it is the part most likely to be subtly wrong: the kernel emits
 * a disk `add` and one `add` per partition with no settle barrier and no
 * message saying "that was all of them", so the correctness question is
 * entirely about *when* the reaction runs relative to a burst that has no
 * defined end.
 *
 * Passing the clock in rather than reading it is what makes that testable at
 * all -- every case below is a burst laid out on an invented timeline, and no
 * test here sleeps.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../test-util.h"
#include "devd-block.h"

/* A short window and a short ceiling, so the timeline below reads in
 * milliseconds instead of fractions of the real defaults. */
#define T_SETTLE (100 * USEC_PER_MSEC)
#define T_CEILING (500 * USEC_PER_MSEC)

/* .../block/sda and .../block/sda/sda1 -- the real sysfs shape, because the
 * disk name is derived from the parent directory rather than from the node
 * name. */
#define DISK_PATH "/devices/platform/scsi/host0/target0:0:0/0:0:0:0/block/sda"

static DevdUevent ev(DevdAction action, const char *devpath, const char *devname, const char *devtype) {
        DevdUevent u;

        memset(&u, 0, sizeof(u));
        u.action = action;
        snprintf(u.devpath, sizeof(u.devpath), "%s", devpath);
        snprintf(u.devname, sizeof(u.devname), "%s", devname);
        snprintf(u.devtype, sizeof(u.devtype), "%s", devtype);
        snprintf(u.subsystem, sizeof(u.subsystem), "block");

        return u;
}

static DevdBlockOutcome feed(DevdBlock *b, DevdUevent u, usec_t now) {
        DevdBlockOutcome o;

        ASSERT_EQ_INT(devd_block_event(b, &u, now, &o, NULL, NULL), 0);
        return o;
}

/*
 * The names come out of the sysfs topology, not out of the node name: "sda1"
 * and "mmcblk0p1" are the same relationship spelled two ways, and only the
 * parent directory says which disk either belongs to.
 */
static void test_names(void) {
        char disk[DEVD_NAME_MAX], part[DEVD_NAME_MAX];
        DevdUevent u;

        u = ev(DEVD_ACTION_ADD, DISK_PATH "/sda1", "sda1", "partition");
        ASSERT_EQ_INT(devd_block_names(&u, disk, sizeof(disk), part, sizeof(part)), 0);
        ASSERT_STREQ(disk, "sda");
        ASSERT_STREQ(part, "sda1");

        u = ev(DEVD_ACTION_ADD, DISK_PATH, "sda", "disk");
        ASSERT_EQ_INT(devd_block_names(&u, disk, sizeof(disk), part, sizeof(part)), 0);
        ASSERT_STREQ(disk, "sda");
        ASSERT_STREQ(part, "");

        /* An MMC partition, where the node name would have suggested a disk
         * called "mmcblk0p" if it had been derived by stripping digits. */
        u = ev(DEVD_ACTION_ADD,
               "/devices/soc/mmc_host/mmc0/mmc0:0001/block/mmcblk0/mmcblk0p1",
               "mmcblk0p1",
               "partition");
        ASSERT_EQ_INT(devd_block_names(&u, disk, sizeof(disk), part, sizeof(part)), 0);
        ASSERT_STREQ(disk, "mmcblk0");
        ASSERT_STREQ(part, "mmcblk0p1");

        /* A devpath with no components left to take a parent from. */
        u = ev(DEVD_ACTION_ADD, "/sda1", "sda1", "partition");
        ASSERT_EQ_INT(devd_block_names(&u, disk, sizeof(disk), part, sizeof(part)), -EINVAL);
}

static void test_ignores(void) {
        DevdBlock b;

        devd_block_init(&b, T_SETTLE, T_CEILING);

        /* Not the block subsystem. */
        {
                DevdUevent u = ev(DEVD_ACTION_ADD, "/devices/usb1/1-1", "", "usb_device");

                snprintf(u.subsystem, sizeof(u.subsystem), "usb");
                ASSERT_EQ_INT(feed(&b, u, 0), DEVD_BLOCK_IGNORED);
        }

        /* Block, but neither a disk nor a partition -- a loop control node or
         * a device-mapper table would land here. */
        ASSERT_EQ_INT(feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH, "sda", ""), 0), DEVD_BLOCK_IGNORED);

        /* An action that is neither add nor remove. */
        ASSERT_EQ_INT(feed(&b, ev(DEVD_ACTION_OTHER, DISK_PATH, "sda", "disk"), 0), DEVD_BLOCK_IGNORED);

        /* A kernel-synthesised device. Found by running the real daemon: a
         * stock kernel puts sixteen ram* and eight loop* devices here before
         * anything is plugged in, which filled the disk table by itself. */
        ASSERT_EQ_INT(feed(&b, ev(DEVD_ACTION_ADD, "/devices/virtual/block/ram0", "ram0", "disk"), 0),
                      DEVD_BLOCK_IGNORED);
        ASSERT_EQ_INT(feed(&b, ev(DEVD_ACTION_ADD, "/devices/virtual/block/loop0", "loop0", "disk"), 0),
                      DEVD_BLOCK_IGNORED);

        ASSERT_TRUE(devd_block_next_settle(&b) == USEC_INFINITY);
}

/*
 * The case the whole file exists for: a card's disk and its two partitions
 * arrive as three separate events, and exactly one reaction runs, after all
 * three, with both partitions already recorded.
 */
static void test_burst_settles_once(void) {
        const char(*parts)[DEVD_NAME_MAX] = NULL;
        DevdBlock b;

        devd_block_init(&b, T_SETTLE, T_CEILING);

        ASSERT_EQ_INT(feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH, "sda", "disk"), 1000), DEVD_BLOCK_DISK_PENDING);
        ASSERT_TRUE(devd_block_next_settle(&b) == 1000 + T_SETTLE);

        /* Ten milliseconds later, the first partition -- inside the window,
         * which slides rather than being consumed. */
        ASSERT_EQ_INT(feed(&b,
                           ev(DEVD_ACTION_ADD, DISK_PATH "/sda1", "sda1", "partition"),
                           1000 + 10 * USEC_PER_MSEC),
                      DEVD_BLOCK_PART_PENDING);
        ASSERT_TRUE(devd_block_next_settle(&b) == 1000 + 10 * USEC_PER_MSEC + T_SETTLE);

        ASSERT_EQ_INT(feed(&b,
                           ev(DEVD_ACTION_ADD, DISK_PATH "/sda2", "sda2", "partition"),
                           1000 + 20 * USEC_PER_MSEC),
                      DEVD_BLOCK_PART_PENDING);

        /* Still inside the window: nothing has settled yet. */
        ASSERT_TRUE(devd_block_take_settled(&b, 1000 + 30 * USEC_PER_MSEC) == NULL);

        /* Past it: exactly one disk settles, and only once. */
        ASSERT_STREQ(devd_block_take_settled(&b, 1000 + 200 * USEC_PER_MSEC), "sda");
        ASSERT_TRUE(devd_block_take_settled(&b, 1000 + 200 * USEC_PER_MSEC) == NULL);
        ASSERT_TRUE(devd_block_next_settle(&b) == USEC_INFINITY);

        ASSERT_EQ_INT(devd_block_partitions(&b, "sda", &parts), 2);
        ASSERT_STREQ(parts[0], "sda1");
        ASSERT_STREQ(parts[1], "sda2");
}

/*
 * A device dribbling partition events forever must not push the deadline
 * forever: past the ceiling the window closes anyway, and what arrives after
 * that takes the late path.
 */
static void test_ceiling(void) {
        DevdBlock b;
        usec_t t;

        devd_block_init(&b, T_SETTLE, T_CEILING);

        ASSERT_EQ_INT(feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH, "sda", "disk"), 0), DEVD_BLOCK_DISK_PENDING);

        /* One event every 50ms for a second: each one alone would push the
         * deadline out by 100ms. */
        for (t = 50 * USEC_PER_MSEC; t <= USEC_PER_SEC; t += 50 * USEC_PER_MSEC) {
                char name[DEVD_NAME_MAX], path[DEVD_DEVPATH_MAX];

                snprintf(name, sizeof(name), "sda%u", (unsigned) (t / (50 * USEC_PER_MSEC)));
                snprintf(path, sizeof(path), "%s/%s", DISK_PATH, name);

                (void) feed(&b, ev(DEVD_ACTION_ADD, path, name, "partition"), t);
        }

        /* The deadline never went past the ceiling, so the window closed at it
         * rather than never. */
        ASSERT_TRUE(devd_block_next_settle(&b) <= T_CEILING);
        ASSERT_STREQ(devd_block_take_settled(&b, T_CEILING), "sda");
}

/* A partition arriving after its disk has settled is acted on alone, and does
 * not reopen a window for the disk. */
static void test_late_partition(void) {
        DevdBlock b;

        devd_block_init(&b, T_SETTLE, T_CEILING);

        (void) feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH, "sda", "disk"), 0);
        ASSERT_STREQ(devd_block_take_settled(&b, T_SETTLE), "sda");

        ASSERT_EQ_INT(feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH "/sda1", "sda1", "partition"), 10 * USEC_PER_SEC),
                      DEVD_BLOCK_PART_LATE);
        ASSERT_TRUE(devd_block_next_settle(&b) == USEC_INFINITY);
}

/* A partition seen before its own disk still ends up attached to it -- the
 * coldplug walk reads /sys/class/block in directory order, which is not
 * disk-before-partition order. */
static void test_partition_before_disk(void) {
        const char(*parts)[DEVD_NAME_MAX] = NULL;
        DevdBlock b;

        devd_block_init(&b, T_SETTLE, T_CEILING);

        ASSERT_EQ_INT(feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH "/sda1", "sda1", "partition"), 0),
                      DEVD_BLOCK_PART_PENDING);
        ASSERT_EQ_INT(feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH, "sda", "disk"), 0), DEVD_BLOCK_DISK_PENDING);

        ASSERT_STREQ(devd_block_take_settled(&b, T_SETTLE), "sda");
        ASSERT_EQ_INT(devd_block_partitions(&b, "sda", &parts), 1);
        ASSERT_STREQ(parts[0], "sda1");
}

/* Removal: a partition leaves its disk's list; a disk keeps its list until the
 * caller has had a chance to clean each partition up. */
static void test_removal(void) {
        const char(*parts)[DEVD_NAME_MAX] = NULL;
        const char *disk = NULL, *part = NULL;
        DevdBlockOutcome o;
        DevdUevent u;
        DevdBlock b;

        devd_block_init(&b, T_SETTLE, T_CEILING);

        (void) feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH, "sda", "disk"), 0);
        (void) feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH "/sda1", "sda1", "partition"), 0);
        (void) feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH "/sda2", "sda2", "partition"), 0);
        ASSERT_STREQ(devd_block_take_settled(&b, T_SETTLE), "sda");

        u = ev(DEVD_ACTION_REMOVE, DISK_PATH "/sda1", "sda1", "partition");
        ASSERT_EQ_INT(devd_block_event(&b, &u, 0, &o, &disk, &part), 0);
        ASSERT_EQ_INT(o, DEVD_BLOCK_PART_GONE);
        ASSERT_STREQ(disk, "sda");

        /* The name is still readable even though the partition has just been
         * forgotten -- the caller needs it to undo the mount. */
        ASSERT_STREQ(part, "sda1");
        ASSERT_EQ_INT(devd_block_partitions(&b, "sda", &parts), 1);
        ASSERT_STREQ(parts[0], "sda2");

        u = ev(DEVD_ACTION_REMOVE, DISK_PATH, "sda", "disk");
        ASSERT_EQ_INT(devd_block_event(&b, &u, 0, &o, &disk, &part), 0);
        ASSERT_EQ_INT(o, DEVD_BLOCK_DISK_GONE);

        /* Still there: the surviving partition has not been cleaned up yet,
         * and forgetting the disk first would lose the only list of what to
         * clean. */
        ASSERT_EQ_INT(devd_block_partitions(&b, "sda", &parts), 1);

        devd_block_forget(&b, "sda");
        ASSERT_EQ_INT(devd_block_partitions(&b, "sda", &parts), 0);

        /* A remove for something never seen is not an error and not a
         * reaction. */
        u = ev(DEVD_ACTION_REMOVE, DISK_PATH "/sda9", "sda9", "partition");
        ASSERT_EQ_INT(devd_block_event(&b, &u, 0, &o, NULL, NULL), 0);
        ASSERT_EQ_INT(o, DEVD_BLOCK_IGNORED);
}

/* A card swapped in the same slot: the disk re-announces itself, and the
 * partitions that follow belong to the new card, so the window reopens. */
static void test_reinsert_reopens(void) {
        DevdBlock b;

        devd_block_init(&b, T_SETTLE, T_CEILING);

        (void) feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH, "sda", "disk"), 0);
        ASSERT_STREQ(devd_block_take_settled(&b, T_SETTLE), "sda");

        ASSERT_EQ_INT(feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH, "sda", "disk"), 10 * USEC_PER_SEC),
                      DEVD_BLOCK_DISK_PENDING);
        ASSERT_EQ_INT(feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH "/sda1", "sda1", "partition"), 10 * USEC_PER_SEC),
                      DEVD_BLOCK_PART_PENDING);
        ASSERT_STREQ(devd_block_take_settled(&b, 10 * USEC_PER_SEC + T_SETTLE), "sda");
}

/* Two cards in two slots settle independently, and one epoll wakeup can close
 * both windows -- which is why the caller loops on take_settled(). */
static void test_two_disks(void) {
        DevdBlock b;
        const char *first, *second;

        devd_block_init(&b, T_SETTLE, T_CEILING);

        (void) feed(&b, ev(DEVD_ACTION_ADD, DISK_PATH, "sda", "disk"), 0);
        (void) feed(&b,
                    ev(DEVD_ACTION_ADD, "/devices/soc/mmc_host/mmc0/mmc0:0001/block/mmcblk0", "mmcblk0", "disk"),
                    0);

        first = devd_block_take_settled(&b, T_SETTLE);
        ASSERT_TRUE(first != NULL);

        second = devd_block_take_settled(&b, T_SETTLE);
        ASSERT_TRUE(second != NULL);
        ASSERT_TRUE(strcmp(first, second) != 0);

        ASSERT_TRUE(devd_block_take_settled(&b, T_SETTLE) == NULL);
}

/* The bounds are this file's, not the plugged-in device's: going over either
 * one drops the event rather than growing an array. */
static void test_bounds(void) {
        const char(*parts)[DEVD_NAME_MAX] = NULL;
        DevdBlock b;

        devd_block_init(&b, T_SETTLE, T_CEILING);

        for (unsigned i = 0; i < DEVD_MAX_DISKS + 4; i++) {
                char name[DEVD_NAME_MAX], path[DEVD_DEVPATH_MAX];

                snprintf(name, sizeof(name), "sd%u", i);
                snprintf(path, sizeof(path), "/devices/scsi/block/%s", name);
                (void) feed(&b, ev(DEVD_ACTION_ADD, path, name, "disk"), 0);
        }

        for (unsigned i = 0; i < DEVD_MAX_PARTS + 4; i++) {
                char name[DEVD_NAME_MAX], path[DEVD_DEVPATH_MAX];

                snprintf(name, sizeof(name), "sd0p%u", i + 1);
                snprintf(path, sizeof(path), "/devices/scsi/block/sd0/%s", name);
                (void) feed(&b, ev(DEVD_ACTION_ADD, path, name, "partition"), 0);
        }

        ASSERT_EQ_INT(devd_block_partitions(&b, "sd0", &parts), DEVD_MAX_PARTS);
}

int main(void) {
        test_names();
        test_ignores();
        test_burst_settles_once();
        test_ceiling();
        test_late_partition();
        test_partition_before_disk();
        test_removal();
        test_reinsert_reopens();
        test_two_disks();
        test_bounds();

        printf("test-devd-block: all checks passed\n");
        return 0;
}
