/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "specifier.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

/* Grow *buf so it holds at least min_cap bytes, geometrically -- this is
 * the whole reason for departing from v30's per-specifier exact-fit
 * realloc: one grow every doubling, not one per substitution. */
static int buf_reserve(char **buf, size_t *cap, size_t min_cap) {
        size_t new_cap;
        char *n;

        if (*cap >= min_cap)
                return 0;

        new_cap = *cap ? *cap * 2 : 64;
        if (new_cap < min_cap)
                new_cap = min_cap;

        n = realloc(*buf, new_cap);
        if (!n)
                return -ENOMEM;

        *buf = n;
        *cap = new_cap;
        return 0;
}

static int buf_append(char **buf, size_t *len, size_t *cap, const char *s, size_t n) {
        int r = buf_reserve(buf, cap, *len + n);

        if (r < 0)
                return r;

        memcpy(*buf + *len, s, n);
        *len += n;
        return 0;
}

int pico_specifier_printf(const char *text, const PicoSpecifier table[], const void *userdata, char **ret) {
        char *buf = NULL;
        size_t len = 0, cap = 0;
        const char *f;
        int r;

        if (!text || !table || !ret)
                return -EINVAL;

        for (f = text; *f; f++) {
                char c;

                if (*f != '%') {
                        r = buf_append(&buf, &len, &cap, f, 1);
                        if (r < 0)
                                goto fail;
                        continue;
                }

                c = f[1];

                if (c == '\0') {
                        /* A lone trailing '%': v30 silently drops it, pico
                         * keeps it literal -- see specifier.h. The outer
                         * loop's f++ reaches the NUL next and stops. */
                        r = buf_append(&buf, &len, &cap, "%", 1);
                        if (r < 0)
                                goto fail;
                        continue;
                }

                f++; /* consume the specifier character too */

                if (c == '%') {
                        r = buf_append(&buf, &len, &cap, "%", 1);
                        if (r < 0)
                                goto fail;
                        continue;
                }

                {
                        const PicoSpecifier *i;

                        for (i = table; i->specifier; i++)
                                if (i->specifier == c)
                                        break;

                        if (!i->specifier) {
                                /* unknown specifier: passed through as-is,
                                 * the drop-in-tolerance property */
                                char lit[2] = { '%', c };

                                r = buf_append(&buf, &len, &cap, lit, 2);
                                if (r < 0)
                                        goto fail;
                                continue;
                        }

                        {
                                char *expansion = NULL;

                                r = i->lookup(c, i->data, userdata, &expansion);
                                if (r < 0)
                                        goto fail;

                                if (expansion) {
                                        r = buf_append(&buf, &len, &cap, expansion, strlen(expansion));
                                        free(expansion);
                                        if (r < 0)
                                                goto fail;
                                }
                        }
                }
        }

        r = buf_reserve(&buf, &cap, len + 1);
        if (r < 0)
                goto fail;
        buf[len] = '\0';

        *ret = buf;
        return 0;

fail:
        free(buf);
        return r;
}

int pico_specifier_string(char specifier, const void *data, const void *userdata, char **ret) {
        (void) specifier;
        (void) userdata;

        /*
         * v30's specifier_string() does assert(data) then
         * strdup(strempty(data)) -- contradictory, and reachable: unit.c's
         * %i table entry passes u->instance, which is NULL for any
         * non-instanced unit, so a stock unit file with a bare %i in
         * Requires= would abort PID 1. Empty string instead.
         */
        *ret = pico_strdup(data ? (const char *) data : "");
        return *ret ? 0 : -ENOMEM;
}
