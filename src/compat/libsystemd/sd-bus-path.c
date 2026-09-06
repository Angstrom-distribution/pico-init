/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Object-path label escaping (sd_bus_path_encode/decode) and the
 * template-driven multi-label variants, contract read from real sd-bus.c
 * (:4031-4075 encode/decode, :4077+ the _many variants, HEAD ded83144).
 * Pure string transforms -- no bus involved -- so these, like
 * sd-bus-validate.c, are genuinely real rather than stubbed.
 */

#include "sd-bus.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static int is_label_char(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

static int hex_digit(char c) {
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

/* external_id -> its escaped label: [A-Za-z0-9] verbatim, everything else
 * (including a NUL-length input) becomes "_" + two lowercase hex digits, an
 * empty input becomes the single label "_". *ret is malloc'd. */
static int label_escape(const char *s, char **ret) {
        size_t len = strlen(s);
        char *out, *p;
        size_t i;

        /* worst case: every byte expands to "_xx" (3 bytes), plus the
         * empty-input fallback ("_", 1 byte) needs at least 2 bytes total. */
        out = malloc(len * 3 + 2);
        if (!out)
                return -ENOMEM;

        p = out;
        for (i = 0; i < len; i++) {
                if (is_label_char(s[i]))
                        *p++ = s[i];
                else {
                        static const char hex[] = "0123456789abcdef";
                        *p++ = '_';
                        *p++ = hex[(unsigned char) s[i] >> 4];
                        *p++ = hex[(unsigned char) s[i] & 0xf];
                }
        }
        if (len == 0)
                *p++ = '_';
        *p = '\0';

        *ret = out;
        return 0;
}

/* Inverse of label_escape() over exactly `len` bytes of `s`. A lone or
 * malformed "_xx" escape is the caller's data being wrong, not this
 * shim's -- -EINVAL, same as sd_bus_path_decode's own contract. */
static int label_unescape(const char *s, size_t len, char **ret) {
        char *out, *p;
        size_t i;

        /* label_escape()'s own special case, inverted: a lone "_" (no hex
         * pair following) is not a truncated escape here, it is exactly
         * what an originally-empty label encodes to. */
        if (len == 1 && s[0] == '_') {
                out = strdup("");
                if (!out)
                        return -ENOMEM;
                *ret = out;
                return 0;
        }

        out = malloc(len + 1);
        if (!out)
                return -ENOMEM;

        p = out;
        for (i = 0; i < len; i++) {
                if (s[i] == '_') {
                        int hi, lo;

                        if (i + 2 >= len) { /* not enough room for two hex digits */
                                free(out);
                                return -EINVAL;
                        }
                        hi = hex_digit(s[i + 1]);
                        lo = hex_digit(s[i + 2]);
                        if (hi < 0 || lo < 0) {
                                free(out);
                                return -EINVAL;
                        }
                        *p++ = (char) ((hi << 4) | lo);
                        i += 2;
                } else
                        *p++ = s[i];
        }
        *p = '\0';

        *ret = out;
        return 0;
}

int sd_bus_path_encode(const char *prefix, const char *external_id, char **ret) {
        char *escaped, *out;
        size_t prefix_len;
        int r;

        if (!prefix || sd_bus_object_path_is_valid(prefix) <= 0 || !external_id || !ret)
                return -EINVAL;

        r = label_escape(external_id, &escaped);
        if (r < 0)
                return r;

        prefix_len = strlen(prefix);
        /* prefix is always either "/" or has no trailing slash (object paths
         * never do), so only the bare-root case needs the '/' suppressed to
         * avoid "//escaped". */
        out = malloc(prefix_len + 1 + strlen(escaped) + 1);
        if (!out) {
                free(escaped);
                return -ENOMEM;
        }

        if (prefix_len == 1 && prefix[0] == '/') {
                out[0] = '/';
                strcpy(out + 1, escaped);
        } else {
                memcpy(out, prefix, prefix_len);
                out[prefix_len] = '/';
                strcpy(out + prefix_len + 1, escaped);
        }

        free(escaped);
        *ret = out;
        return 0;
}

int sd_bus_path_decode(const char *path, const char *prefix, char **ret) {
        size_t prefix_len;
        const char *rest;

        if (!path || sd_bus_object_path_is_valid(path) <= 0 || !prefix ||
            sd_bus_object_path_is_valid(prefix) <= 0 || !ret)
                return -EINVAL;

        prefix_len = strlen(prefix);

        if (strncmp(path, prefix, prefix_len) != 0) {
                *ret = NULL;
                return 0;
        }

        if (prefix_len == 1 && prefix[0] == '/')
                rest = path + 1; /* prefix "/" has no separating slash to skip */
        else if (path[prefix_len] == '/')
                rest = path + prefix_len + 1;
        else {
                /* path == prefix exactly, or prefix is not a real ancestor
                 * (e.g. prefix "/foo", path "/foobar") */
                *ret = NULL;
                return 0;
        }

        {
                char *unescaped;
                int r = label_unescape(rest, strlen(rest), &unescaped);
                if (r < 0)
                        return r;
                *ret = unescaped;
                return 1;
        }
}

/* One '/'-separated element of a path or template: [off, off+len). */
struct segment {
        size_t off;
        size_t len;
};

/* Splits `s` (which must start with '/') into its elements. `s` == "/"
 * yields zero elements. Returns the element count, or -ENOMEM; *ret is a
 * malloc'd array the caller frees. */
static int split_path(const char *s, struct segment **ret) {
        size_t len = strlen(s);
        struct segment *segs = NULL;
        size_t n = 0, cap = 0;
        size_t i = 1; /* skip the leading '/' */

        while (i < len) {
                size_t start = i;

                while (i < len && s[i] != '/')
                        i++;

                if (n == cap) {
                        size_t new_cap = cap ? cap * 2 : 8;
                        struct segment *grown = realloc(segs, new_cap * sizeof(*grown));
                        if (!grown) {
                                free(segs);
                                return -ENOMEM;
                        }
                        segs = grown;
                        cap = new_cap;
                }
                segs[n].off = start;
                segs[n].len = i - start;
                n++;

                if (i < len)
                        i++; /* skip '/' */
        }

        *ret = segs;
        return (int) n;
}

int sd_bus_path_encode_many(char **ret, const char *path_template, ...) {
        struct segment *tsegs;
        int n_template;
        va_list ap;
        size_t out_cap, out_len = 0;
        char *out;
        int i;
        int r = 0;

        /* A template with no '%' at all is a plain valid path with nothing
         * to substitute -- accepted, matching upstream, which treats a
         * "%"-free template as a no-op encode. */
        if (!ret || !path_template)
                return -EINVAL;

        n_template = split_path(path_template, &tsegs);
        if (n_template < 0)
                return n_template;

        out_cap = strlen(path_template) + 16;
        out = malloc(out_cap);
        if (!out) {
                free(tsegs);
                return -ENOMEM;
        }
        out[0] = '\0';

        va_start(ap, path_template);

        for (i = 0; i < n_template; i++) {
                const char *piece;
                char *escaped = NULL;
                size_t piece_len;
                bool is_placeholder = tsegs[i].len == 1 && path_template[tsegs[i].off] == '%';

                if (is_placeholder) {
                        const char *arg = va_arg(ap, const char *);

                        if (!arg) {
                                r = -EINVAL;
                                break;
                        }
                        r = label_escape(arg, &escaped);
                        if (r < 0)
                                break;
                        piece = escaped;
                        piece_len = strlen(escaped);
                } else {
                        /* A literal element containing a bare '%' with more
                         * than one character is not a placeholder and not a
                         * valid path element either -- malformed template. */
                        size_t j;
                        for (j = 0; j < tsegs[i].len; j++)
                                if (path_template[tsegs[i].off + j] == '%') {
                                        r = -EINVAL;
                                        break;
                                }
                        if (r < 0)
                                break;
                        piece = path_template + tsegs[i].off;
                        piece_len = tsegs[i].len;
                }

                if (out_len + 1 + piece_len + 1 > out_cap) {
                        char *grown;
                        while (out_len + 1 + piece_len + 1 > out_cap)
                                out_cap *= 2;
                        grown = realloc(out, out_cap);
                        if (!grown) {
                                free(escaped);
                                r = -ENOMEM;
                                break;
                        }
                        out = grown;
                }
                out[out_len++] = '/';
                memcpy(out + out_len, piece, piece_len);
                out_len += piece_len;
                out[out_len] = '\0';

                free(escaped);
        }

        va_end(ap);
        free(tsegs);

        if (r < 0) {
                free(out);
                return r;
        }

        if (out_len == 0) {
                /* the template was "/" itself */
                out[0] = '/';
                out[1] = '\0';
        }

        *ret = out;
        return 0;
}

int sd_bus_path_decode_many(const char *path, const char *path_template, ...) {
        struct segment *psegs = NULL, *tsegs = NULL;
        int n_path, n_template;
        int n_placeholders = 0;
        char **captured = NULL;
        int i, r;
        va_list ap;

        if (!path || !path_template)
                return -EINVAL;

        if (sd_bus_object_path_is_valid(path) <= 0)
                return 0;

        n_path = split_path(path, &psegs);
        if (n_path < 0)
                return n_path;

        n_template = split_path(path_template, &tsegs);
        if (n_template < 0) {
                free(psegs);
                return n_template;
        }

        if (n_path != n_template) {
                free(psegs);
                free(tsegs);
                return 0;
        }

        /* Match first, touching no output at all yet. */
        for (i = 0; i < n_template; i++) {
                bool is_placeholder = tsegs[i].len == 1 && path_template[tsegs[i].off] == '%';

                if (is_placeholder) {
                        n_placeholders++;
                        continue;
                }

                if (tsegs[i].len != psegs[i].len ||
                    memcmp(path_template + tsegs[i].off, path + psegs[i].off, tsegs[i].len) != 0) {
                        free(psegs);
                        free(tsegs);
                        return 0;
                }
        }

        /* Full structural match. Unescape every placeholder into a local
         * array first, so a mid-way failure never touches a single caller
         * output pointer -- outputs stay genuinely untouched on error. */
        if (n_placeholders > 0) {
                captured = calloc((size_t) n_placeholders, sizeof(*captured));
                if (!captured) {
                        free(psegs);
                        free(tsegs);
                        return -ENOMEM;
                }
        }

        r = 0;
        {
                int slot = 0;
                for (i = 0; i < n_template; i++) {
                        bool is_placeholder = tsegs[i].len == 1 && path_template[tsegs[i].off] == '%';

                        if (!is_placeholder)
                                continue;

                        r = label_unescape(path + psegs[i].off, psegs[i].len, &captured[slot]);
                        if (r < 0)
                                break;
                        slot++;
                }
        }

        free(psegs);
        free(tsegs);

        if (r < 0) {
                for (i = 0; i < n_placeholders; i++)
                        free(captured[i]);
                free(captured);
                return r;
        }

        /* Only now walk the caller's varargs, and only to hand off already-
         * finished strings -- nothing here can still fail. */
        va_start(ap, path_template);
        for (i = 0; i < n_placeholders; i++) {
                char **slot_ptr = va_arg(ap, char **);

                if (slot_ptr)
                        *slot_ptr = captured[i];
                else
                        free(captured[i]);
        }
        va_end(ap);

        free(captured);
        return 1;
}
