/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * /etc/fstab: the parser, the option table, and the record of what became of
 * each line. The half of fstab processing that does no mounting, so every
 * decision in it can be tested against values; fstab-mount.h is the half that
 * talks to the kernel.
 *
 * The line grammar is libmount's (util-linux tab_parse.c), which is what
 * systemd's fstab-generator reads fstab through: source, mount point and type
 * are required, options/freq/passno are optional and default to "defaults", 0
 * and 0, and `\ooo` octal escapes are undone in every field.
 *
 * Options are split three ways, because the new mount API takes them three
 * different ways and rejects any of them offered the wrong way:
 *
 *  - per-mount (VFS) attributes -- ro, nosuid, nodev, noexec, the atime
 *    family, nosymfollow -- become MOUNT_ATTR_* bits for fsmount() and
 *    mount_setattr(). The kernel refuses these as fsconfig() parameters.
 *  - superblock flags -- ro/rw, sync/async, dirsync, lazytime, mand -- are
 *    fsconfig() flags, which the VFS itself handles for every filesystem.
 *  - everything else ("mode=0755", "size=10%", "errors=remount-ro") is passed
 *    through to the filesystem one fsconfig() call per option, in file order.
 *
 * Userspace-only options (defaults, auto/noauto, nofail, user/users/owner/
 * group, _netdev, comment=, and every x-/X- option) are consumed here and never
 * reach the kernel, which would fail the whole mount on any one of them.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util.h"

/* What became of one fstab line. */
typedef enum FstabOutcome {
        FSTAB_PENDING,   /* not processed (yet) */
        FSTAB_MOUNTED,   /* mounted by pico-init */
        FSTAB_REMOUNTED, /* already mounted, fstab's options reapplied */
        FSTAB_PRESENT,   /* already mounted, nothing to apply */
        FSTAB_NOAUTO,    /* noauto: deliberately left alone */
        FSTAB_SKIPPED,   /* not something pico-init can mount */
        FSTAB_FAILED,    /* attempted, and the kernel said no */
        _FSTAB_OUTCOME_MAX,
} FstabOutcome;

const char *fstab_outcome_to_string(FstabOutcome o);
FstabOutcome fstab_outcome_from_string(const char *s); /* _FSTAB_OUTCOME_MAX if unknown */

/* Whether an outcome means the machine is not what fstab describes: the two
 * that make `picoctl is-system-running` say "degraded". */
bool fstab_outcome_is_degraded(FstabOutcome o);

typedef struct FstabOptions {
        /*
         * MOUNT_ATTR_* bits. `attr_set` is what the line asks for; `attr_clr`
         * is what it explicitly turns off (suid, dev, exec, rw, ...). An atime
         * option puts MOUNT_ATTR__ATIME in attr_clr and its mode in attr_set,
         * which is the form mount_setattr() demands -- and since
         * MOUNT_ATTR_RELATIME is 0, _ATIME in attr_clr is also the only
         * record that an atime mode was chosen at all.
         */
        uint64_t attr_set;
        uint64_t attr_clr;

        /* Superblock flags other than ro/rw, for fsconfig(FSCONFIG_SET_FLAG). */
        char **sb_flags;

        /* Filesystem options, "key=value" or "flag", in file order. */
        char **data;

        bool noauto;
        bool nofail;
        bool netdev;    /* _netdev */
        bool automount; /* x-systemd.automount */
        bool bind;
        bool rbind;
        bool loop;
        bool propagation; /* shared/private/slave/unbindable and r* forms: ignored */

        /* x-systemd.device-timeout=, USEC_INFINITY when absent or unparsable
         * as well as for an explicit "infinity". */
        usec_t device_timeout;
} FstabOptions;

typedef struct FstabEntry {
        char *what;
        char *where; /* normalized: no doubled or trailing slashes */
        char *type;
        char *options; /* as written, unescaped; "defaults" when the field was missing */
        int freq;
        int passno;
        unsigned line; /* 1-based line number in the file */

        FstabOptions opts;

        FstabOutcome outcome;
        char *reason; /* why, in a few words; owned, may be NULL */
} FstabEntry;

typedef struct FstabTable {
        FstabEntry *entries;
        size_t n;
} FstabTable;

/* Undo fstab/mountinfo `\ooo` escapes in place. A backslash not followed by
 * three octal digits is kept as written, as libmount keeps it. */
void fstab_unescape(char *s);

/* The inverse, for writing a path into a whitespace-separated record: space,
 * tab, newline and backslash become `\ooo`. 0, or -ENAMETOOLONG. */
int fstab_escape(const char *s, char *buf, size_t size);

/*
 * Parse the option field into `ret`, which the caller releases with
 * fstab_options_done(). 0, -ENOMEM, or -EINVAL for an option string with an
 * empty option name in it ("mode=0755,,=x" is the latter; a doubled comma is
 * tolerated).
 */
int fstab_options_parse(const char *options, FstabOptions *ret);
void fstab_options_done(FstabOptions *o);

/*
 * True when applying `o` to a mount that is already read-write could change
 * nothing: no attribute set, nothing cleared but read-only, no superblock flag,
 * no filesystem option. "defaults" and "rw" are trivial.
 */
bool fstab_options_trivial(const FstabOptions *o);

/*
 * Parse one line. Returns 1 with *ret filled (release with fstab_entry_done()),
 * 0 for a blank or comment line, -EINVAL for a line with fewer than three
 * fields or a non-numeric freq/passno, -ENOMEM.
 */
int fstab_parse_line(const char *line, FstabEntry *ret);
void fstab_entry_done(FstabEntry *e);

/* Record an outcome on `e`; the reason is copied. */
void fstab_entry_set_outcome(FstabEntry *e, FstabOutcome o, const char *reason_fmt, ...)
                __attribute__((format(printf, 3, 4)));

/*
 * Read a whole fstab. Malformed lines are logged with their line number and
 * dropped. -ENOENT when the file does not exist, which callers treat as an
 * empty table; *ret is valid (and empty) on every error return.
 */
int fstab_load(const char *path, FstabTable *ret);
void fstab_table_done(FstabTable *t);

/* The last entry mounted on `where`, or NULL. The last, because a later line
 * for the same mount point is the one a path lookup would land on. */
FstabEntry *fstab_find(FstabTable *t, const char *where);

/* Number of path components: "/" is 0, "/var/volatile" is 2. */
unsigned fstab_path_depth(const char *path);

/*
 * The mount order: a stable sort by mount point depth, so a parent is mounted
 * before its child and lines of equal depth keep their file order. For a
 * serial pass that is all "dependency ordering" can mean. *ret_order is a
 * malloc'd array of t->n pointers into t->entries (NULL for an empty table),
 * which the caller frees. 0 or -ENOMEM.
 */
int fstab_mount_order(FstabTable *t, FstabEntry ***ret_order);

/*
 * The visibility record: one line per entry, "<mount point> <outcome>
 * <reason>", mount point escaped per fstab_escape(). Written to a temporary
 * file beside `path` and renamed into place, so a reader never sees half of
 * it. 0 or -errno.
 */
int fstab_record_write(const FstabTable *t, const char *path);

/* The number of degraded lines in a record file. -ENOENT when there is none,
 * -errno on other read errors. */
int fstab_record_count_degraded(const char *path);
