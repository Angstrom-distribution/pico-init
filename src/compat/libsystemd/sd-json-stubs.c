/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The part of sd-json.h that needs a JSON engine: constructors, parsers,
 * the builder, the formatter and the functions that modify a variant.
 * There is no engine in this build, so every constructor, parser and
 * builder fails with -EOPNOTSUPP and no sd_json_variant can ever exist.
 * Programs that reference the interface load, and take their failure path.
 *
 * Each function first applies the argument checks upstream makes that
 * need no variant (a NULL output parameter or handle is -EINVAL), then
 * answers for the NULL variant, the only one that exists, where upstream
 * does something that needs no allocated variant. What is left is
 * -EOPNOTSUPP, never success. Output parameters are not touched on
 * failure, as upstream.
 *
 * The varargs forms (sd_json_build() and the *b() variants) build their
 * argument first upstream, so they fail before any other check.
 *
 * The NULL-handle answers are in sd-json-noop.c, dispatch in
 * sd-json-dispatch.c.
 */

#include "sd-json.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* constructors */
int sd_json_variant_new_string(sd_json_variant **ret, const char *s) {
        (void) s;
        return ret ? -EOPNOTSUPP : -EINVAL;
}

int sd_json_variant_new_stringn(sd_json_variant **ret, const char *s, size_t n) {
        if (!ret)
                return -EINVAL;
        if (!s)
                return n == 0 || n == SIZE_MAX ? -EOPNOTSUPP : -EINVAL;
        if (n != SIZE_MAX && memchr(s, 0, n))
                return -EINVAL; /* JSON cannot hold an embedded NUL */
        return -EOPNOTSUPP;
}

static int new_from_bytes(sd_json_variant **ret, const void *p, size_t n) {
        if (!ret || (n > 0 && !p))
                return -EINVAL;
        return -EOPNOTSUPP;
}

int sd_json_variant_new_base64(sd_json_variant **ret, const void *p, size_t n) {
        return new_from_bytes(ret, p, n);
}

int sd_json_variant_new_base32hex(sd_json_variant **ret, const void *p, size_t n) {
        return new_from_bytes(ret, p, n);
}

int sd_json_variant_new_hex(sd_json_variant **ret, const void *p, size_t n) {
        return new_from_bytes(ret, p, n);
}

int sd_json_variant_new_octescape(sd_json_variant **ret, const void *p, size_t n) {
        return new_from_bytes(ret, p, n);
}

int sd_json_variant_new_array_bytes(sd_json_variant **ret, const void *p, size_t n) {
        return new_from_bytes(ret, p, n);
}

int sd_json_variant_new_integer(sd_json_variant **ret, int64_t i) {
        (void) i;
        return ret ? -EOPNOTSUPP : -EINVAL;
}

int sd_json_variant_new_unsigned(sd_json_variant **ret, uint64_t u) {
        (void) u;
        return ret ? -EOPNOTSUPP : -EINVAL;
}

int sd_json_variant_new_real(sd_json_variant **ret, double d) {
        (void) d;
        return ret ? -EOPNOTSUPP : -EINVAL;
}

int sd_json_variant_new_boolean(sd_json_variant **ret, int b) {
        (void) b;
        return ret ? -EOPNOTSUPP : -EINVAL;
}

int sd_json_variant_new_null(sd_json_variant **ret) {
        return ret ? -EOPNOTSUPP : -EINVAL;
}

int sd_json_variant_new_id128(sd_json_variant **ret, sd_id128_t id) {
        (void) id;
        return ret ? -EOPNOTSUPP : -EINVAL;
}

int sd_json_variant_new_uuid(sd_json_variant **ret, sd_id128_t id) {
        (void) id;
        return ret ? -EOPNOTSUPP : -EINVAL;
}

int sd_json_variant_new_array_strv(sd_json_variant **ret, char **l) {
        (void) l;
        return ret ? -EOPNOTSUPP : -EINVAL;
}

int sd_json_variant_new_array(sd_json_variant **ret, sd_json_variant **array, size_t n) {
        if (!ret || (n > 0 && !array))
                return -EINVAL;
        return -EOPNOTSUPP;
}

int sd_json_variant_new_object(sd_json_variant **ret, sd_json_variant **array, size_t n) {
        if (!ret || (n > 0 && (!array || n % 2 != 0)))
                return -EINVAL;
        return -EOPNOTSUPP;
}

/* builder */
int sd_json_buildv(sd_json_variant **ret, va_list ap) {
        (void) ap;
        return ret ? -EOPNOTSUPP : -EINVAL;
}

int sd_json_build(sd_json_variant **ret, ...) {
        return ret ? -EOPNOTSUPP : -EINVAL;
}

/* parsers */
int sd_json_parse_with_source(
                const char *string,
                const char *source,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {
        (void) source;
        (void) flags;
        (void) ret;
        (void) reterr_line;
        (void) reterr_column;

        if (!string || !*string)
                return -ENODATA;
        return -EOPNOTSUPP;
}

int sd_json_parse_with_source_continue(
                const char **p,
                const char *source,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {
        (void) p;
        (void) source;
        (void) flags;
        (void) ret;
        (void) reterr_line;
        (void) reterr_column;
        return -EOPNOTSUPP;
}

int sd_json_parse(
                const char *string,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {
        return sd_json_parse_with_source(string, NULL, flags, ret, reterr_line, reterr_column);
}

int sd_json_parse_continue(
                const char **p,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {
        return sd_json_parse_with_source_continue(p, NULL, flags, ret, reterr_line, reterr_column);
}

int sd_json_parse_file_at(
                FILE *f,
                int dir_fd,
                const char *path,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {
        (void) f;
        (void) dir_fd;
        (void) path;
        (void) flags;
        (void) ret;
        (void) reterr_line;
        (void) reterr_column;
        return -EOPNOTSUPP;
}

int sd_json_parse_file(
                FILE *f,
                const char *path,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {
        return sd_json_parse_file_at(f, AT_FDCWD, path, flags, ret, reterr_line, reterr_column);
}

int sd_json_parse_fd(
                const char *path,
                int fd,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column) {
        (void) path;
        (void) ret;
        (void) reterr_line;
        (void) reterr_column;

        if (fd < 0)
                return -EBADF;
        if ((flags & SD_JSON_PARSE_REOPEN_FD) && (flags & SD_JSON_PARSE_DONATE_FD))
                return -EINVAL;

        /* A donated fd is the callee's on failure too */
        if (flags & SD_JSON_PARSE_DONATE_FD)
                close(fd);
        return -EOPNOTSUPP;
}

/* formatter */
int sd_json_variant_format(sd_json_variant *v, sd_json_format_flags_t flags, char **ret) {
        (void) flags;
        return v && ret ? -EOPNOTSUPP : -EINVAL;
}

/* A NULL variant prints nothing, or "[]" when asked for an empty array */
int sd_json_variant_dump(sd_json_variant *v, sd_json_format_flags_t flags, FILE *f, const char *prefix) {
        (void) prefix;

        if (v)
                return -EOPNOTSUPP;
        if (!(flags & SD_JSON_FORMAT_EMPTY_ARRAY))
                return 0;

        if (!f)
                f = stdout;

        if (flags & SD_JSON_FORMAT_SSE)
                fputs("data: ", f);
        if (flags & SD_JSON_FORMAT_SEQ)
                fputc('\x1e', f); /* ASCII record separator */

        fputs("[]", f);

        if (flags &
            (SD_JSON_FORMAT_PRETTY | SD_JSON_FORMAT_PRETTY_AUTO | SD_JSON_FORMAT_SEQ | SD_JSON_FORMAT_SSE |
             SD_JSON_FORMAT_NEWLINE))
                fputc('\n', f);
        if (flags & SD_JSON_FORMAT_SSE)
                fputc('\n', f);

        if (flags & SD_JSON_FORMAT_FLUSH) {
                errno = 0;
                fflush(f);
                if (ferror(f))
                        return errno > 0 ? -errno : -EIO;
        }
        return 0;
}

/* modification */
int sd_json_variant_filter(sd_json_variant **v, char **to_remove) {
        (void) to_remove;

        if (!v)
                return -EINVAL;
        if (!*v)
                return 0; /* a NULL variant is a blank object */
        return -EOPNOTSUPP;
}

int sd_json_variant_sort(sd_json_variant **v) {
        if (!v)
                return -EINVAL;
        if (!*v)
                return 0; /* already sorted */
        return -EOPNOTSUPP;
}

int sd_json_variant_normalize(sd_json_variant **v) {
        if (!v)
                return -EINVAL;
        if (!*v)
                return 0; /* already normalized */
        return -EOPNOTSUPP;
}

int sd_json_variant_set_field(sd_json_variant **v, const char *field, sd_json_variant *value) {
        (void) value;
        return v && field ? -EOPNOTSUPP : -EINVAL;
}

/* Upstream builds the value, which succeeds, and then calls sd_json_variant_set_field() */
static int set_field_value(sd_json_variant **v, const char *field) {
        return sd_json_variant_set_field(v, field, NULL);
}

int sd_json_variant_set_fieldb(sd_json_variant **v, const char *field, ...) {
        (void) v;
        (void) field;
        return -EOPNOTSUPP;
}

int sd_json_variant_set_field_string(sd_json_variant **v, const char *field, const char *value) {
        (void) value;
        return set_field_value(v, field);
}

int sd_json_variant_set_field_id128(sd_json_variant **v, const char *field, sd_id128_t value) {
        (void) value;
        return set_field_value(v, field);
}

int sd_json_variant_set_field_uuid(sd_json_variant **v, const char *field, sd_id128_t value) {
        (void) value;
        return set_field_value(v, field);
}

int sd_json_variant_set_field_integer(sd_json_variant **v, const char *field, int64_t value) {
        (void) value;
        return set_field_value(v, field);
}

int sd_json_variant_set_field_unsigned(sd_json_variant **v, const char *field, uint64_t value) {
        (void) value;
        return set_field_value(v, field);
}

int sd_json_variant_set_field_boolean(sd_json_variant **v, const char *field, int b) {
        (void) b;
        return set_field_value(v, field);
}

int sd_json_variant_set_field_strv(sd_json_variant **v, const char *field, char **l) {
        (void) l;
        return set_field_value(v, field);
}

int sd_json_variant_append_array(sd_json_variant **v, sd_json_variant *element) {
        return v && element ? -EOPNOTSUPP : -EINVAL;
}

int sd_json_variant_append_arrayb(sd_json_variant **v, ...) {
        (void) v;
        return -EOPNOTSUPP;
}

int sd_json_variant_append_array_nodup(sd_json_variant **v, sd_json_variant *element) {
        return sd_json_variant_append_array(v, element);
}

int sd_json_variant_merge_object(sd_json_variant **v, sd_json_variant *m) {
        if (!v)
                return -EINVAL;
        if (!*v && !m)
                return 0; /* nothing to merge */
        return -EOPNOTSUPP;
}

int sd_json_variant_merge_objectb(sd_json_variant **v, ...) {
        (void) v;
        return -EOPNOTSUPP;
}

/* conversion */
int sd_json_variant_get_source(
                sd_json_variant *v, const char **ret_source, unsigned *ret_line, unsigned *ret_column) {
        (void) ret_source;
        (void) ret_line;
        (void) ret_column;
        return v ? -EOPNOTSUPP : -EINVAL;
}

/* A NULL variant is an empty list */
int sd_json_variant_strv(sd_json_variant *v, char ***ret) {
        char **l;

        if (!ret)
                return -EINVAL;
        if (v)
                return -EOPNOTSUPP;

        l = calloc(1, sizeof(char *));
        if (!l)
                return -ENOMEM;

        *ret = l;
        return 0;
}

int sd_json_variant_unbase64(sd_json_variant *v, void **ret, size_t *ret_size) {
        (void) ret;
        (void) ret_size;
        return v ? -EOPNOTSUPP : -EINVAL;
}

int sd_json_variant_unhex(sd_json_variant *v, void **ret, size_t *ret_size) {
        (void) ret;
        (void) ret_size;
        return v ? -EOPNOTSUPP : -EINVAL;
}
