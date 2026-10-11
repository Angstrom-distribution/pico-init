/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The debounce state machine. devd-block.h has the why; this is bookkeeping
 * over two fixed arrays and a clock the caller supplies.
 */

#include "devd-block.h"

#include <errno.h>
#include <string.h>

static const char * const devd_block_outcome_table[_DEVD_BLOCK_OUTCOME_MAX] = {
        [DEVD_BLOCK_IGNORED] = "ignored",
        [DEVD_BLOCK_DISK_PENDING] = "disk-pending",
        [DEVD_BLOCK_PART_PENDING] = "partition-pending",
        [DEVD_BLOCK_PART_LATE] = "partition-late",
        [DEVD_BLOCK_PART_GONE] = "partition-gone",
        [DEVD_BLOCK_DISK_GONE] = "disk-gone",
};

const char *devd_block_outcome_to_string(DevdBlockOutcome o) {
        if (o < 0 || o >= _DEVD_BLOCK_OUTCOME_MAX)
                return "invalid";

        return devd_block_outcome_table[o];
}

void devd_block_init(DevdBlock *b, usec_t settle_usec, usec_t ceiling_usec) {
        if (!b)
                return;

        memset(b, 0, sizeof(*b));
        b->settle_usec = settle_usec > 0 ? settle_usec : DEVD_SETTLE_USEC;
        b->ceiling_usec = ceiling_usec > 0 ? ceiling_usec : DEVD_SETTLE_CEILING_USEC;
}

/* The last component of `path`, or NULL when there is not one. */
static const char *path_basename(const char *path) {
        const char *slash = strrchr(path, '/');

        if (!slash || slash[1] == '\0')
                return NULL;

        return slash + 1;
}

int devd_block_names(const DevdUevent *u, char *disk, size_t disk_size, char *part, size_t part_size) {
        char parent[DEVD_DEVPATH_MAX];
        const char *base, *pbase;
        char *slash;

        if (!u || !disk || !part)
                return -EINVAL;

        base = path_basename(u->devpath);
        if (!base)
                return -EINVAL;

        if (strcmp(u->devtype, "partition") != 0) {
                if (strlen(base) >= disk_size)
                        return -EINVAL;

                strcpy(disk, base);
                part[0] = '\0';
                return 0;
        }

        if (strlen(base) >= part_size)
                return -EINVAL;

        /* .../block/sda/sda1 -> the disk is the directory the partition sits
         * in. The kernel puts it there; nothing here has to know whether the
         * node is called sda1 or mmcblk0p1. */
        if (strlen(u->devpath) >= sizeof(parent))
                return -EINVAL;

        strcpy(parent, u->devpath);
        slash = strrchr(parent, '/');
        if (!slash || slash == parent)
                return -EINVAL;

        *slash = '\0';

        pbase = path_basename(parent);
        if (!pbase || strlen(pbase) >= disk_size)
                return -EINVAL;

        strcpy(disk, pbase);
        strcpy(part, base);
        return 0;
}

static DevdDisk *disk_find(DevdBlock *b, const char *name) {
        for (size_t i = 0; i < b->n_disks; i++)
                if (strcmp(b->disks[i].name, name) == 0)
                        return &b->disks[i];

        return NULL;
}

static DevdDisk *disk_add(DevdBlock *b, const char *name) {
        DevdDisk *d;

        if (b->n_disks >= DEVD_MAX_DISKS) {
                pico_log(PICO_LOG_WARNING, "devd: already tracking %d disks, ignoring %s", DEVD_MAX_DISKS, name);
                return NULL;
        }

        d = &b->disks[b->n_disks++];
        memset(d, 0, sizeof(*d));

        /* The caller checked the length against DEVD_NAME_MAX before this. */
        strcpy(d->name, name);
        return d;
}

/* Open or extend the window, never past the ceiling. */
static void window_touch(DevdBlock *b, DevdDisk *d, usec_t now) {
        usec_t deadline = now + b->settle_usec;

        if (!d->settling) {
                d->settling = true;
                d->ceiling = now + b->ceiling_usec;
        }

        d->deadline = deadline > d->ceiling ? d->ceiling : deadline;
}

static bool part_known(const DevdDisk *d, const char *part) {
        for (size_t i = 0; i < d->n_parts; i++)
                if (strcmp(d->parts[i], part) == 0)
                        return true;

        return false;
}

static void part_add(DevdDisk *d, const char *part) {
        if (part_known(d, part))
                return;

        if (d->n_parts >= DEVD_MAX_PARTS) {
                pico_log(PICO_LOG_WARNING,
                         "devd: %s already has %d partitions, ignoring %s",
                         d->name,
                         DEVD_MAX_PARTS,
                         part);
                return;
        }

        strcpy(d->parts[d->n_parts++], part);
}

static void part_drop(DevdDisk *d, const char *part) {
        for (size_t i = 0; i < d->n_parts; i++)
                if (strcmp(d->parts[i], part) == 0) {
                        memmove(&d->parts[i], &d->parts[i + 1], (d->n_parts - i - 1) * sizeof(d->parts[0]));
                        d->n_parts--;
                        return;
                }
}

int devd_block_event(
                DevdBlock *b,
                const DevdUevent *u,
                usec_t now,
                DevdBlockOutcome *ret,
                const char **ret_disk,
                const char **ret_part) {

        char disk[DEVD_NAME_MAX], part[DEVD_NAME_MAX];
        DevdBlockOutcome outcome = DEVD_BLOCK_IGNORED;
        bool is_partition;
        DevdDisk *d;
        int r;

        if (!b || !u || !ret)
                return -EINVAL;

        b->scratch_disk[0] = '\0';
        b->scratch_part[0] = '\0';

        if (ret_disk)
                *ret_disk = b->scratch_disk;
        if (ret_part)
                *ret_part = b->scratch_part;

        *ret = DEVD_BLOCK_IGNORED;

        if (strcmp(u->subsystem, "block") != 0)
                return 0;

        if (strncmp(u->devpath, DEVD_VIRTUAL_PREFIX, strlen(DEVD_VIRTUAL_PREFIX)) == 0)
                return 0;

        is_partition = strcmp(u->devtype, "partition") == 0;
        if (!is_partition && strcmp(u->devtype, "disk") != 0)
                return 0;

        /*
         * Only add and remove. A `change` on a block device means the medium
         * behind it changed, which would mean re-reading a table under a mount
         * devd already made; that is not handled.
         */
        if (u->action != DEVD_ACTION_ADD && u->action != DEVD_ACTION_REMOVE)
                return 0;

        r = devd_block_names(u, disk, sizeof(disk), part, sizeof(part));
        if (r < 0)
                return r;

        strcpy(b->scratch_disk, disk);
        strcpy(b->scratch_part, part);

        d = disk_find(b, disk);

        if (u->action == DEVD_ACTION_REMOVE) {
                if (!d)
                        return 0; /* never seen it; nothing to undo */

                if (is_partition) {
                        part_drop(d, part);
                        outcome = DEVD_BLOCK_PART_GONE;
                } else {
                        /* The disk record survives this call: the caller still
                         * needs its partition list to clean each one up, and
                         * calls devd_block_forget() when it is done. */
                        d->settling = false;
                        outcome = DEVD_BLOCK_DISK_GONE;
                }

                *ret = outcome;
                return 0;
        }

        if (!d) {
                d = disk_add(b, disk);
                if (!d)
                        return 0;
        }

        /* Recomputed on every add rather than latched: a slot whose disk name
         * is reused by different hardware must not inherit the last one's
         * answer. Partition devpaths carry their disk's prefix, so both event
         * kinds agree. */
        d->no_probe = strstr(u->devpath, DEVD_MTD_INFIX) != NULL;

        if (!is_partition) {
                /*
                 * A disk re-announcing itself reopens the window even if it
                 * settled before -- that is a card swapped in the same slot,
                 * and the partitions about to arrive are a different card's.
                 */
                d->settled = false;
                window_touch(b, d, now);
                *ret = DEVD_BLOCK_DISK_PENDING;
                return 0;
        }

        part_add(d, part);

        if (d->settled) {
                /* Late arrival: no window to reopen, act on this one alone. */
                *ret = DEVD_BLOCK_PART_LATE;
                return 0;
        }

        window_touch(b, d, now);
        *ret = DEVD_BLOCK_PART_PENDING;
        return 0;
}

usec_t devd_block_next_settle(const DevdBlock *b) {
        usec_t next = USEC_INFINITY;

        if (!b)
                return USEC_INFINITY;

        for (size_t i = 0; i < b->n_disks; i++)
                if (b->disks[i].settling && b->disks[i].deadline < next)
                        next = b->disks[i].deadline;

        return next;
}

const char *devd_block_take_settled(DevdBlock *b, usec_t now) {
        if (!b)
                return NULL;

        for (size_t i = 0; i < b->n_disks; i++) {
                DevdDisk *d = &b->disks[i];

                if (!d->settling || d->deadline > now)
                        continue;

                d->settling = false;
                d->settled = true;
                return d->name;
        }

        return NULL;
}

size_t devd_block_partitions(const DevdBlock *b, const char *disk, const char (**ret)[DEVD_NAME_MAX]) {
        if (!b || !disk || !ret)
                return 0;

        for (size_t i = 0; i < b->n_disks; i++)
                if (strcmp(b->disks[i].name, disk) == 0) {
                        *ret = b->disks[i].parts;
                        return b->disks[i].n_parts;
                }

        return 0;
}

bool devd_block_probe_excluded(const DevdBlock *b, const char *disk) {
        if (!b || !disk)
                return false;

        for (size_t i = 0; i < b->n_disks; i++)
                if (strcmp(b->disks[i].name, disk) == 0)
                        return b->disks[i].no_probe;

        return false;
}

void devd_block_forget(DevdBlock *b, const char *disk) {
        if (!b || !disk)
                return;

        for (size_t i = 0; i < b->n_disks; i++)
                if (strcmp(b->disks[i].name, disk) == 0) {
                        memmove(&b->disks[i], &b->disks[i + 1], (b->n_disks - i - 1) * sizeof(b->disks[0]));
                        b->n_disks--;
                        return;
                }
}
