/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "unit-name.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

/*
 * strndup(), which util.h deliberately does not carry -- it is grown only
 * when another file actually needs it (that file's own rule), and this is
 * the only one that does.
 */
static char *unit_name_strndup(const char *s, size_t n) {
        char *r = malloc(n + 1);

        if (!r)
                return NULL;

        memcpy(r, s, n);
        r[n] = '\0';
        return r;
}

/* v30's unhexchar(), renamed for the direction this file actually uses. */
static int unhex_digit(char c) {
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

int unit_name_to_instance(const char *n, char **ret) {
        const char *p, *d;
        size_t len;

        if (!n || !ret)
                return -EINVAL;

        p = strchr(n, '@');
        if (!p) {
                *ret = NULL;
                return 0;
        }

        d = strrchr(n, '.');
        /* v30 does assert_se(d)/assert(p < d) here; a malformed name (no
         * suffix, or one that sorts before the '@') carries no instance
         * either rather than aborting PID 1 over a bad Requires= token. */
        if (!d || d < p) {
                *ret = NULL;
                return 0;
        }

        len = (size_t) (d - p - 1);
        if (len == 0) {
                /* "foo@.service": a template, not an instance -- the
                 * deliberate NULL-vs-"" deviation, see unit-name.h. */
                *ret = NULL;
                return 0;
        }

        *ret = unit_name_strndup(p + 1, len);
        return *ret ? 0 : -ENOMEM;
}

char *unit_name_to_prefix_and_instance(const char *n) {
        const char *d;

        if (!n)
                return NULL;

        d = strrchr(n, '.');
        if (!d)
                return NULL; /* same de-assertion as unit_name_to_instance() */

        return unit_name_strndup(n, (size_t) (d - n));
}

char *unit_name_to_prefix(const char *n) {
        const char *p;

        if (!n)
                return NULL;

        p = strchr(n, '@');
        if (p)
                return unit_name_strndup(n, (size_t) (p - n));

        return unit_name_to_prefix_and_instance(n);
}

char *unit_name_template(const char *n) {
        const char *p, *d;
        char *r;
        size_t a, b;

        if (!n)
                return NULL;

        p = strchr(n, '@');
        if (!p)
                return pico_strdup(n);

        d = strrchr(n, '.');
        if (!d || d < p)
                return NULL; /* malformed: nothing sane to template */

        a = (size_t) (p - n) + 1; /* up to and including the '@' */
        b = strlen(d);            /* from the last '.' to the end */

        r = malloc(a + b + 1);
        if (!r)
                return NULL;

        memcpy(r, n, a);
        memcpy(r + a, d, b + 1);
        return r;
}

char *unit_name_replace_instance(const char *n, const char *instance) {
        const char *p, *d;
        char *r;
        size_t a, b, c;

        if (!n || !instance)
                return NULL;

        p = strchr(n, '@');
        if (!p)
                /*
                 * 8556879e0d: tested before any arithmetic on `p`, not
                 * after -- v30 computed `a = p - f` unconditionally and
                 * only checked `if (p)` afterwards, undefined behaviour on
                 * exactly this input. There is no instance slot to
                 * replace, so the name is returned as-is.
                 */
                return pico_strdup(n);

        d = strrchr(n, '.');
        if (!d || d < p)
                return NULL; /* malformed: nothing sane to replace */

        a = (size_t) (p - n) + 1; /* prefix, including the '@' */
        b = strlen(instance);
        c = strlen(d); /* suffix, from the last '.' */

        r = malloc(a + b + c + 1);
        if (!r)
                return NULL;

        memcpy(r, n, a);
        memcpy(r + a, instance, b);
        memcpy(r + a + b, d, c + 1);
        return r;
}

char *unit_name_unescape(const char *n) {
        char *r, *t;
        const char *f;

        if (!n)
                return NULL;

        r = pico_strdup(n); /* the output is never longer than the input */
        if (!r)
                return NULL;

        for (f = n, t = r; *f; f++) {
                if (*f == '-') {
                        *t++ = '/';
                } else if (*f == '\\') {
                        int a, b;

                        /* f[1] != 'x' short-circuits before f[2]/f[3] are
                         * ever read, so a backslash at the very end of the
                         * string (f[1] is the NUL terminator) never reads
                         * past it. */
                        if (f[1] != 'x' || (a = unhex_digit(f[2])) < 0 || (b = unhex_digit(f[3])) < 0) {
                                *t++ = '\\'; /* invalid or truncated escape, kept literal */
                        } else {
                                *t++ = (char) ((a << 4) | b);
                                f += 3;
                        }
                } else {
                        *t++ = *f;
                }
        }
        *t = '\0';

        return r;
}

bool unit_name_is_template(const char *n) {
        const char *p;

        if (!n)
                return false;

        p = strchr(n, '@');
        if (!p)
                return false;

        return p[1] == '.';
}

bool unit_name_is_instance(const char *n) {
        char *instance = NULL;
        bool is;

        if (unit_name_to_instance(n, &instance) < 0)
                return false;

        is = instance != NULL;
        free(instance);
        return is;
}
