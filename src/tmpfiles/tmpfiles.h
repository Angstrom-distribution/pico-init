/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-tmpfiles: systemd-tmpfiles(8)'s --create, --clean and --remove, over
 * tmpfiles.d(5) files exactly as OE packages already install them.
 *
 * Seventeen oe-core recipes ship tmpfiles.d snippets (dbus, sudo, pam,
 * rpcbind, bind, util-linux's lastlog2, sysklogd, ...) and with systemd in
 * DISTRO_FEATURES several recipes *drop* their sysvinit-era volatiles
 * fallback on the assumption that systemd-tmpfiles will do the work. Under
 * pico-init this binary is what does it. The grammar and the precedence rules
 * are systemd v259's own, read from src/tmpfiles/tmpfiles.c and
 * src/basic/conf-files.c rather than from the man page alone, since the two
 * disagree in places (an `f` argument is written verbatim, no newline).
 *
 * What each implemented line type does under each operation:
 *
 *   d D v q Q  create a directory (v/q/Q are d on every non-btrfs root,
 *              which is upstream's own fallback; a btrfs subvolume is never
 *              created here); --clean ages out its contents; --remove
 *              empties a D directory
 *   e          adjust mode/owner of existing directories (globs); --clean
 *              ages out their contents
 *   f f+ F     create a regular file, F/f+ create-or-truncate, argument
 *              written verbatim
 *   L L+ L?    create a symlink, + replaces whatever is there, ? skips when
 *              the target is missing, default target /usr/share/factory/<path>
 *   C C+       copy a tree into place if the destination is missing or an
 *              empty directory (+ merges into a populated one); --clean ages
 *              out the copy's contents
 *   z Z        adjust mode/owner of an existing path (Z recursively), globs
 *   x X        exclude a path from --clean and --remove (X only the path
 *              itself, its contents are still aged out)
 *   r R        --remove deletes the path (R recursively), regardless of age;
 *              with an age, --clean deletes it once it is that old
 *
 * Every other letter (w p c b t T h H a A) parses as valid syntax and is
 * skipped with one WARNING per line, so a gap is visible in the boot log
 * rather than silent. Unknown letters are invalid configuration, as upstream.
 *
 * Modifiers: ! (boot-only, needs --boot), + (force/append), - (failure is
 * not an error), ? (L only), $ (purge marker; --purge is not implemented).
 * The three that need machinery this project does not have (= type-replace,
 * ~ base64, ^ credentials) skip the line with a WARNING.
 *
 * The age field is upstream's "[~][age-by:]span": ~ keeps the first level,
 * age-by picks among a/b/c/m (lower case for files, upper case for
 * directories), the span is systemd's time-span syntax. Timestamps come from
 * fstatat(), which has no birth time, so 'b' never holds an entry back --
 * upstream's own behaviour on a filesystem without btime. A mount boundary
 * is a change of st_dev, so a bind mount of the same filesystem is walked.
 *
 * File precedence is conf-files.c's: /etc/tmpfiles.d, /run/tmpfiles.d,
 * /usr/local/lib/tmpfiles.d, /usr/lib/tmpfiles.d in that order, the first
 * directory to hold a given basename wins the whole file (an override, never
 * a merge), a symlink to /dev/null masks the basename, and the surviving
 * files are then applied in lexicographic basename order regardless of
 * directory. Within one path the first line seen wins; conflicting later
 * lines are dropped with a notice. Parents are applied before children,
 * non-glob lines before glob lines; --clean and --remove run before
 * --create, children before parents.
 *
 * Deliberately not carried over from upstream: the CHASE_SAFE "unsafe
 * symlink transition" refusal on every parent walk, SELinux/SMACK labelling,
 * ACLs, xattrs, file attributes, and --purge. Each is a feature with no
 * consumer in this project's images, not an oversight.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Search order, most specific first -- systemd's CONF_PATHS("tmpfiles.d"). */
#define PICO_TMPFILES_CONF_DIRS \
        "/etc/tmpfiles.d", "/run/tmpfiles.d", "/usr/local/lib/tmpfiles.d", "/usr/lib/tmpfiles.d"

/* Where L and C lines without an argument look, per tmpfiles.d(5). */
#define PICO_TMPFILES_FACTORY_DIR "/usr/share/factory"

/* Which timestamps an age compares, tmpfiles.d(5)'s a/b/c/m. */
#define PICO_TMPFILES_AGE_BY_ATIME (1U << 0)
#define PICO_TMPFILES_AGE_BY_BTIME (1U << 1)
#define PICO_TMPFILES_AGE_BY_CTIME (1U << 2)
#define PICO_TMPFILES_AGE_BY_MTIME (1U << 3)
/* upstream leaves ctime out for directories: deleting an entry changes it */
#define PICO_TMPFILES_AGE_BY_DEFAULT_FILE                                                       \
        (PICO_TMPFILES_AGE_BY_ATIME | PICO_TMPFILES_AGE_BY_BTIME | PICO_TMPFILES_AGE_BY_CTIME | \
         PICO_TMPFILES_AGE_BY_MTIME)
#define PICO_TMPFILES_AGE_BY_DEFAULT_DIR \
        (PICO_TMPFILES_AGE_BY_ATIME | PICO_TMPFILES_AGE_BY_BTIME | PICO_TMPFILES_AGE_BY_MTIME)

/* pico_tmpfiles_remove_and_clean() operations. */
#define PICO_TMPFILES_REMOVE (1U << 0)
#define PICO_TMPFILES_CLEAN (1U << 1)

/* sysexits.h values systemd-tmpfiles itself exits with. */
#define PICO_TMPFILES_EX_DATAERR 65
#define PICO_TMPFILES_EX_CANTCREAT 73

typedef struct PicoTmpfilesItem {
        char type;
        char *path;     /* absolute, simplified, root-prefixed */
        char *argument; /* unescaped and expanded, or NULL */

        mode_t mode;
        bool mode_set;
        bool mode_only_create;
        bool mask_perms;

        uid_t uid;
        bool uid_set;
        bool uid_only_create;

        gid_t gid;
        bool gid_set;
        bool gid_only_create;

        bool append_or_force;
        bool allow_failure;
        bool ignore_if_target_missing;

        /* verbatim, for the duplicate-line comparison */
        char *age;
        /* parsed: microseconds, UINT64_MAX for "infinity" */
        uint64_t age_usec;
        bool age_set;
        bool keep_first_level;
        unsigned age_by_file;
        unsigned age_by_dir;

        bool done;
        bool cleanup_done;
} PicoTmpfilesItem;

/* Every line naming one path, in application order. */
typedef struct PicoTmpfilesArray {
        char *path;
        PicoTmpfilesItem *items;
        size_t n_items;
        struct PicoTmpfilesArray *parent;
} PicoTmpfilesArray;

typedef struct PicoTmpfiles {
        char *root; /* NULL for "/" */
        bool boot;
        bool graceful;
        char **prefixes;
        char **exclude_prefixes;

        /* Two ordered sets, keyed by path, insertion order preserved. */
        PicoTmpfilesArray **items;
        size_t n_items;
        PicoTmpfilesArray **globs;
        size_t n_globs;

        /* Set once any line was rejected as invalid; maps to EX_DATAERR. */
        bool invalid_config;
} PicoTmpfiles;

int pico_tmpfiles_new(PicoTmpfiles **ret);
PicoTmpfiles *pico_tmpfiles_free(PicoTmpfiles *t);

/* NULL, "" or "/" mean no root. The stored copy is simplified. 0 or -errno. */
int pico_tmpfiles_set_root(PicoTmpfiles *t, const char *root);
int pico_tmpfiles_add_prefix(PicoTmpfiles *t, const char *prefix);
int pico_tmpfiles_add_exclude_prefix(PicoTmpfiles *t, const char *prefix);

/*
 * The precedence rule on its own: every *.conf the four directories yield
 * after override and masking, as root-prefixed absolute paths sorted by
 * basename. *ret is a NULL-terminated vector the caller frees with
 * pico_strv_free(). 0 or -errno.
 */
int pico_tmpfiles_list_config_files(PicoTmpfiles *t, char ***ret);

/*
 * Parse one file. A bad line is logged and skipped, sets t->invalid_config,
 * and never stops the rest of the file. Returns 0, or -errno for a failure
 * to read the file at all (ENOENT included -- callers decide whether that
 * matters).
 */
int pico_tmpfiles_read_file(PicoTmpfiles *t, const char *path);

/* pico_tmpfiles_list_config_files() followed by pico_tmpfiles_read_file() on each. */
int pico_tmpfiles_read_config(PicoTmpfiles *t);

/*
 * One line, as pico_tmpfiles_read_file() would feed it (already stripped).
 * Exposed for the parser tests. 0, or -errno with t->invalid_config set
 * for anything that is a syntax or resolution error.
 */
int pico_tmpfiles_parse_line(PicoTmpfiles *t, const char *fname, unsigned line, const char *buffer);

/*
 * Apply every collected line. Returns 0 when everything applied, or the
 * first -errno seen (every line is still attempted). umask is 0 for the
 * duration, since every mode here is explicit.
 */
int pico_tmpfiles_create(PicoTmpfiles *t);

/*
 * --remove and/or --clean (PICO_TMPFILES_REMOVE | PICO_TMPFILES_CLEAN) over
 * every collected line, children before parents. Same return convention as
 * pico_tmpfiles_create(); run it first when both are wanted, as upstream
 * does, so creation builds on the cleaned-out tree.
 */
int pico_tmpfiles_remove_and_clean(PicoTmpfiles *t, unsigned operations);

/* Each array's closest ancestor with lines of its own; both passes call it. */
void pico_tmpfiles_link_parents(PicoTmpfiles *t);

/*
 * systemd's time-span syntax ("10d", "1h 30min", "2.5w", "infinity"), bare
 * numbers meaning seconds, into microseconds. Exposed for the parser tests.
 * 0 or -EINVAL/-ERANGE.
 */
int pico_tmpfiles_parse_sec(const char *s, uint64_t *ret);

/* Lookup by exact (root-prefixed) path across both sets; NULL if absent. */
PicoTmpfilesArray *pico_tmpfiles_find(PicoTmpfiles *t, const char *path);

/*
 * Shared path helpers, exposed for the tests. path_simplify collapses
 * duplicate slashes and "." components and a trailing slash, in place;
 * path_startswith is the component-wise prefix test.
 */
char *pico_tmpfiles_path_simplify(char *path);
const char *pico_tmpfiles_path_startswith(const char *path, const char *prefix);
