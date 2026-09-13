/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-tmpfiles: the creation half of systemd-tmpfiles(8), over tmpfiles.d(5)
 * files exactly as OE packages already install them.
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
 * What is implemented, all with --create semantics:
 *
 *   d D v q Q  create a directory (v/q/Q are d on every non-btrfs root,
 *              which is upstream's own fallback; a btrfs subvolume is never
 *              created here)
 *   f f+ F     create a regular file, F/f+ create-or-truncate, argument
 *              written verbatim
 *   L L+ L?    create a symlink, + replaces whatever is there, ? skips when
 *              the target is missing, default target /usr/share/factory/<path>
 *   C C+       copy a tree into place if the destination is missing or an
 *              empty directory (+ merges into a populated one)
 *   z Z        adjust mode/owner of an existing path (Z recursively), globs
 *   x X r R    accepted and no-ops: they only mean something to --clean and
 *              --remove, which are deferred with no consumer in these images
 *
 * Every other letter (w e p c b t T h H a A) parses as valid syntax and is
 * skipped with one WARNING per line, so a gap is visible in the boot log
 * rather than silent. Unknown letters are invalid configuration, as upstream.
 *
 * Modifiers: ! (boot-only, needs --boot), + (force/append), - (failure is
 * not an error), ? (L only), $ (purge marker, no effect on create). The
 * three that need machinery this project does not have (= type-replace,
 * ~ base64, ^ credentials) skip the line with a WARNING.
 *
 * File precedence is conf-files.c's: /etc/tmpfiles.d, /run/tmpfiles.d,
 * /usr/local/lib/tmpfiles.d, /usr/lib/tmpfiles.d in that order, the first
 * directory to hold a given basename wins the whole file (an override, never
 * a merge), a symlink to /dev/null masks the basename, and the surviving
 * files are then applied in lexicographic basename order regardless of
 * directory. Within one path the first line seen wins; conflicting later
 * lines are dropped with a notice. Parents are applied before children,
 * non-glob lines before glob lines.
 *
 * Deliberately not carried over from upstream: the CHASE_SAFE "unsafe
 * symlink transition" refusal on every parent walk, SELinux/SMACK labelling,
 * ACLs, xattrs, file attributes, and the age-based cleanup. Each is a
 * feature with no consumer in this project's images, not an oversight.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* Search order, most specific first -- systemd's CONF_PATHS("tmpfiles.d"). */
#define PICO_TMPFILES_CONF_DIRS \
        "/etc/tmpfiles.d", "/run/tmpfiles.d", "/usr/local/lib/tmpfiles.d", "/usr/lib/tmpfiles.d"

/* Where L and C lines without an argument look, per tmpfiles.d(5). */
#define PICO_TMPFILES_FACTORY_DIR "/usr/share/factory"

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

        /* Kept so a later --clean has it; never interpreted here. */
        char *age;

        bool done;
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

/* Lookup by exact (root-prefixed) path across both sets; NULL if absent. */
PicoTmpfilesArray *pico_tmpfiles_find(PicoTmpfiles *t, const char *path);

/*
 * Shared path helpers, exposed for the tests. path_simplify collapses
 * duplicate slashes and "." components and a trailing slash, in place;
 * path_startswith is the component-wise prefix test.
 */
char *pico_tmpfiles_path_simplify(char *path);
const char *pico_tmpfiles_path_startswith(const char *path, const char *prefix);
