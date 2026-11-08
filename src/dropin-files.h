/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The directory half of drop-in handling, shared by the unit loader
 * (unit-dropin.c) and netd (netd-network.c). It knows nothing about units,
 * .network files or the manager: callers decide which directories apply.
 */

#pragma once

#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>

/* The "*.d" (or "*.network.d") directories found in one search directory. */
typedef struct PicoDropinDirList {
        char **names; /* sorted once pico_dropin_dirlist_sort() has run */
        size_t n;
} PicoDropinDirList;

/* Record the entry when its name ends in `suffix`, is longer than it and is
 * not a plain file. 0 or -ENOMEM. */
int pico_dropin_dirlist_add(PicoDropinDirList *l, const struct dirent *de, const char *suffix);
void pico_dropin_dirlist_sort(PicoDropinDirList *l);
bool pico_dropin_dirlist_has(const PicoDropinDirList *l, const char *name);
void pico_dropin_dirlist_clear(PicoDropinDirList *l);

/*
 * The "*.conf" files of the NULL-terminated list of directories `dirs`, which
 * is in priority order. Hidden files are skipped; a name seen in an earlier
 * directory hides the same name in a later one, whatever the earlier file
 * holds, so an empty file or a link to /dev/null cancels a lower drop-in. The
 * result is sorted by file name, not by directory, and is NULL when nothing
 * applies. A directory that does not exist is skipped. 0 or -errno.
 */
int pico_dropin_files(char * const *dirs, char ***ret);
