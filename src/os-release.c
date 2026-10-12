/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * os-release(5) lookup. See os-release.h for the subset of the format this
 * accepts and why it is a subset.
 *
 * It is a handler over pico_conf_scan() rather than a reader of its own:
 * os-release syntax (KEY=value, '#' comments, blank lines) is a subset of the
 * INI syntax that scanner handles, with its backported fixes (see conf-scan.h).
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

/*
 * os-release(5) lets /usr/lib/os-release stand in for an absent /etc/os-release,
 * which is what a stateless-/etc image has. Applies to any path ending in
 * /etc/os-release, so a tmpfiles --root gets the fallback under that root.
 */
static int os_release_fallback(const char *path, char **ret) {
        static const char suffix[] = "/etc/os-release", alt[] = "/usr/lib/os-release";
        size_t n = strlen(path), s = sizeof(suffix) - 1;
        char *p;

        if (n < s || strcmp(path + n - s, suffix) != 0)
                return -ENOENT;

        p = malloc(n - s + sizeof(alt));
        if (!p)
                return -ENOMEM;

        memcpy(p, path, n - s);
        memcpy(p + n - s, alt, sizeof(alt));
        *ret = p;

        return 0;
}

int os_release_get(const char *path, const char *key, char **ret) {
        OsReleaseLookup l = { .key = key };
        char *alt = NULL;
        int r;

        if (!path || !key || !ret)
                return -EINVAL;

        /* A missing file arrives as the fopen() -ENOENT pico_conf_scan()
         * returns, which is already the answer this reports for a missing
         * key -- so no case below has to tell them apart. */
        r = pico_conf_scan(path, os_release_handler, &l);
        if (r == -ENOENT && os_release_fallback(path, &alt) == 0) {
                r = pico_conf_scan(alt, os_release_handler, &l);
                free(alt);
        }
        if (r < 0) {
                l.value = pico_mfree(l.value);
                return r;
        }

        if (!l.value)
                return -ENOENT;

        *ret = l.value;

        return 0;
}
