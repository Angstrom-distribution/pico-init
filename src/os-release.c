/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * os-release(5) lookup. See os-release.h for the subset of the format this
 * accepts and why it is a subset.
 *
 * It is a handler over pico_conf_scan() rather than a reader of its own, for
 * the reason conf-scan.h states outright: that scanner already carries seven
 * backported upstream fixes -- the unbounded getline(), skipping a malformed
 * line instead of failing the file, the UTF-8 BOM -- and os-release syntax
 * (KEY=value, '#' comments, blank lines) is a subset of the INI syntax it
 * already scans. A second reader would inherit those fixes once and then
 * quietly stop inheriting them.
 *
 * os-release has no [Section] headers, so every assignment arrives with
 * section == NULL and this ignores the field entirely. The one thing the
 * scanner cannot do here is quotes: unit files have no quoting at the line
 * level, os-release values usually do.
 */

#include "os-release.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "conf-scan.h"
#include "util.h"

typedef struct OsReleaseLookup {
        const char *key;
        char *value; /* NULL until the key is seen; the last assignment wins */
} OsReleaseLookup;

/*
 * Strip one matching pair of surrounding quotes, in place, returning a
 * pointer into `v`. A lone leading quote is not a quoted string and is left
 * alone rather than guessed at: half-quoted input is malformed, and inventing
 * a reading for it would silently hand a caller a value the file never said.
 */
static char *os_release_unquote(char *v) {
        size_t n = strlen(v);

        if (n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n - 1] == v[0]) {
                v[n - 1] = '\0';
                return v + 1;
        }

        return v;
}

static int os_release_handler(
                const char *filename,
                unsigned line,
                const char *section,
                const char *key,
                const char *value,
                void *userdata) {
        OsReleaseLookup *l = userdata;
        char *copy, *keep;
        (void) filename;
        (void) line;
        (void) section;

        if (strcmp(key, l->key) != 0)
                return 0;

        /* Heap, not a VLA: `value` comes from conf-scan.c's unbounded
         * getline(), the same stack-overflow hazard unit-parse.c's
         * config_parse_unit_deps() documents -- see that file's header. */
        copy = pico_strdup(value);
        if (!copy)
                return -ENOMEM;

        /* Copied again rather than returning a pointer into `copy`: unquoting
         * moves the start of the string, and free() only accepts the pointer
         * malloc() handed out. */
        keep = pico_strdup(os_release_unquote(copy));
        free(copy);
        if (!keep)
                return -ENOMEM;

        l->value = pico_mfree(l->value);
        l->value = keep;

        return 0;
}

int os_release_get(const char *path, const char *key, char **ret) {
        OsReleaseLookup l = { .key = key };
        int r;

        if (!path || !key || !ret)
                return -EINVAL;

        /* A missing file arrives as the fopen() -ENOENT pico_conf_scan()
         * returns, which is already the answer this reports for a missing
         * key -- so no case below has to tell them apart. */
        r = pico_conf_scan(path, os_release_handler, &l);
        if (r < 0) {
                l.value = pico_mfree(l.value);
                return r;
        }

        if (!l.value)
                return -ENOENT;

        *ret = l.value;

        return 0;
}
