/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-init's declaration of the sd-json.h ABI surface, matching systemd's
 * src/systemd/sd-json.h in names, signatures, enum values and macros. There
 * is no JSON engine in this build, so no sd_json_variant can ever exist; see
 * sd-json-stubs.c, sd-json-noop.c and sd-json-dispatch.c.
 */

#pragma once

#include <fcntl.h>
#include <stdio.h>

#include "_sd-common.h"
#include "sd-id128.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_json_variant sd_json_variant;

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_json_variant_type_t) {
        SD_JSON_VARIANT_STRING,
        SD_JSON_VARIANT_INTEGER,
        SD_JSON_VARIANT_UNSIGNED,
        SD_JSON_VARIANT_REAL,
        SD_JSON_VARIANT_NUMBER, /* wildcard for integer, unsigned and real; never the type of a variant */
        SD_JSON_VARIANT_BOOLEAN,
        SD_JSON_VARIANT_ARRAY,
        SD_JSON_VARIANT_OBJECT,
        SD_JSON_VARIANT_NULL,
        _SD_JSON_VARIANT_TYPE_MAX,
        _SD_JSON_VARIANT_TYPE_INVALID = -EINVAL,
        _SD_ENUM_FORCE_S64(JSON_VARIANT_TYPE)
} sd_json_variant_type_t;

int sd_json_variant_new_string(sd_json_variant **ret, const char *s);
int sd_json_variant_new_stringn(sd_json_variant **ret, const char *s, size_t n);
int sd_json_variant_new_base64(sd_json_variant **ret, const void *p, size_t n);
int sd_json_variant_new_base32hex(sd_json_variant **ret, const void *p, size_t n);
int sd_json_variant_new_hex(sd_json_variant **ret, const void *p, size_t n);
int sd_json_variant_new_octescape(sd_json_variant **ret, const void *p, size_t n);
int sd_json_variant_new_integer(sd_json_variant **ret, int64_t i);
int sd_json_variant_new_unsigned(sd_json_variant **ret, uint64_t u);
int sd_json_variant_new_real(sd_json_variant **ret, double d);
int sd_json_variant_new_boolean(sd_json_variant **ret, int b);
int sd_json_variant_new_array(sd_json_variant **ret, sd_json_variant **array, size_t n);
int sd_json_variant_new_array_bytes(sd_json_variant **ret, const void *p, size_t n);
int sd_json_variant_new_array_strv(sd_json_variant **ret, char **l);
int sd_json_variant_new_object(sd_json_variant **ret, sd_json_variant **array, size_t n);
int sd_json_variant_new_null(sd_json_variant **ret);
int sd_json_variant_new_id128(sd_json_variant **ret, sd_id128_t id);
int sd_json_variant_new_uuid(sd_json_variant **ret, sd_id128_t id);

sd_json_variant *sd_json_variant_ref(sd_json_variant *v);
sd_json_variant *sd_json_variant_unref(sd_json_variant *v);
void sd_json_variant_unref_many(sd_json_variant **array, size_t n);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_json_variant, sd_json_variant_unref);

const char *sd_json_variant_string(sd_json_variant *v);
int64_t sd_json_variant_integer(sd_json_variant *v);
uint64_t sd_json_variant_unsigned(sd_json_variant *v);
double sd_json_variant_real(sd_json_variant *v);
int sd_json_variant_boolean(sd_json_variant *v);

sd_json_variant_type_t sd_json_variant_type(sd_json_variant *v);
int sd_json_variant_has_type(sd_json_variant *v, sd_json_variant_type_t type);

int sd_json_variant_is_string(sd_json_variant *v);
int sd_json_variant_is_integer(sd_json_variant *v);
int sd_json_variant_is_unsigned(sd_json_variant *v);
int sd_json_variant_is_real(sd_json_variant *v);
int sd_json_variant_is_number(sd_json_variant *v);
int sd_json_variant_is_boolean(sd_json_variant *v);
int sd_json_variant_is_array(sd_json_variant *v);
int sd_json_variant_is_object(sd_json_variant *v);
int sd_json_variant_is_null(sd_json_variant *v);

int sd_json_variant_is_negative(sd_json_variant *v);
int sd_json_variant_is_blank_object(sd_json_variant *v);
int sd_json_variant_is_blank_array(sd_json_variant *v);
int sd_json_variant_is_normalized(sd_json_variant *v);
int sd_json_variant_is_sorted(sd_json_variant *v);

size_t sd_json_variant_elements(sd_json_variant *v);
sd_json_variant *sd_json_variant_by_index(sd_json_variant *v, size_t index);
sd_json_variant *sd_json_variant_by_key(sd_json_variant *v, const char *key);
sd_json_variant *sd_json_variant_by_key_full(sd_json_variant *v, const char *key, sd_json_variant **ret_key);

int sd_json_variant_equal(sd_json_variant *a, sd_json_variant *b);

void sd_json_variant_sensitive(sd_json_variant *v);
int sd_json_variant_is_sensitive(sd_json_variant *v);
int sd_json_variant_is_sensitive_recursive(sd_json_variant *v);

int sd_json_variant_get_source(
                sd_json_variant *v, const char **ret_source, unsigned *ret_line, unsigned *ret_column);

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_json_format_flags_t) {
        SD_JSON_FORMAT_OFF = 1 << 0,               /* make sd_json_variant_format() fail with -ENOEXEC */
        SD_JSON_FORMAT_NEWLINE = 1 << 1,           /* end with a newline */
        SD_JSON_FORMAT_PRETTY = 1 << 2,            /* indent and break lines */
        SD_JSON_FORMAT_PRETTY_AUTO = 1 << 3,       /* PRETTY on a tty, NEWLINE otherwise */
        SD_JSON_FORMAT_COLOR = 1 << 4,             /* ANSI colour sequences */
        SD_JSON_FORMAT_COLOR_AUTO = 1 << 5,        /* COLOR if the environment allows colour */
        SD_JSON_FORMAT_SOURCE = 1 << 6,            /* prefix with source file, line and column */
        SD_JSON_FORMAT_SSE = 1 << 7,               /* W3C server-sent events framing */
        SD_JSON_FORMAT_SEQ = 1 << 8,               /* RFC 7464 application/json-seq framing */
        SD_JSON_FORMAT_FLUSH = 1 << 9,             /* fflush() after output */
        SD_JSON_FORMAT_EMPTY_ARRAY = 1 << 10,      /* print "[]" for a NULL variant */
        SD_JSON_FORMAT_CENSOR_SENSITIVE = 1 << 11, /* print "<sensitive data>" for sensitive variants */
        _SD_ENUM_FORCE_S64(JSON_FORMAT_FLAGS)
} sd_json_format_flags_t;

int sd_json_variant_format(sd_json_variant *v, sd_json_format_flags_t flags, char **ret);
int sd_json_variant_dump(sd_json_variant *v, sd_json_format_flags_t flags, FILE *f, const char *prefix);

int sd_json_variant_filter(sd_json_variant **v, char **to_remove);

int sd_json_variant_set_field(sd_json_variant **v, const char *field, sd_json_variant *value);
int sd_json_variant_set_fieldb(sd_json_variant **v, const char *field, ...);
#define sd_json_variant_set_fieldbo(v, field, ...) \
        sd_json_variant_set_fieldb((v), (field), SD_JSON_BUILD_OBJECT(__VA_ARGS__))
int sd_json_variant_set_field_string(sd_json_variant **v, const char *field, const char *value);
int sd_json_variant_set_field_id128(sd_json_variant **v, const char *field, sd_id128_t value);
int sd_json_variant_set_field_uuid(sd_json_variant **v, const char *field, sd_id128_t value);
int sd_json_variant_set_field_integer(sd_json_variant **v, const char *field, int64_t value);
int sd_json_variant_set_field_unsigned(sd_json_variant **v, const char *field, uint64_t value);
int sd_json_variant_set_field_boolean(sd_json_variant **v, const char *field, int b);
int sd_json_variant_set_field_strv(sd_json_variant **v, const char *field, char **l);

sd_json_variant *sd_json_variant_find(sd_json_variant *haystack, sd_json_variant *needle);

int sd_json_variant_append_array(sd_json_variant **v, sd_json_variant *element);
int sd_json_variant_append_arrayb(sd_json_variant **v, ...);
#define sd_json_variant_append_arraybo(v, ...) \
        sd_json_variant_append_arrayb((v), SD_JSON_BUILD_OBJECT(__VA_ARGS__))
int sd_json_variant_append_array_nodup(sd_json_variant **v, sd_json_variant *element);

int sd_json_variant_merge_object(sd_json_variant **v, sd_json_variant *m);
int sd_json_variant_merge_objectb(sd_json_variant **v, ...);
#define sd_json_variant_merge_objectbo(v, ...) \
        sd_json_variant_merge_objectb((v), SD_JSON_BUILD_OBJECT(__VA_ARGS__))

int sd_json_variant_sort(sd_json_variant **v);
int sd_json_variant_normalize(sd_json_variant **v);

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_json_parse_flags_t) {
        SD_JSON_PARSE_SENSITIVE = 1 << 0,      /* mark the result sensitive */
        SD_JSON_PARSE_MUST_BE_OBJECT = 1 << 1, /* refuse a top-level value that is not an object */
        SD_JSON_PARSE_MUST_BE_ARRAY = 1 << 2,  /* refuse a top-level value that is not an array */
        SD_JSON_PARSE_SEEK0 = 1 << 3,          /* seek to offset 0 before reading */
        SD_JSON_PARSE_DONATE_FD = 1 << 4,      /* the call owns the fd, also on failure */
        SD_JSON_PARSE_REOPEN_FD = 1 << 5,      /* reopen the fd instead of duplicating it */
        _SD_ENUM_FORCE_S64(JSON_PARSE_FLAGS)
} sd_json_parse_flags_t;

int sd_json_parse_with_source(
                const char *string,
                const char *source,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column);
int sd_json_parse_with_source_continue(
                const char **p,
                const char *source,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column);
int sd_json_parse(
                const char *string,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column);
int sd_json_parse_continue(
                const char **p,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column);
int sd_json_parse_file_at(
                FILE *f,
                int dir_fd,
                const char *path,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column);
int sd_json_parse_file(
                FILE *f,
                const char *path,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column);
int sd_json_parse_fd(
                const char *path,
                int fd,
                sd_json_parse_flags_t flags,
                sd_json_variant **ret,
                unsigned *reterr_line,
                unsigned *reterr_column);

enum {
        /* Opcodes of the sd_json_build() argument stream; use the SD_JSON_BUILD_*() macros instead. */
        _SD_JSON_BUILD_STRING,
        _SD_JSON_BUILD_INTEGER,
        _SD_JSON_BUILD_UNSIGNED,
        _SD_JSON_BUILD_REAL,
        _SD_JSON_BUILD_BOOLEAN,
        _SD_JSON_BUILD_ARRAY_BEGIN,
        _SD_JSON_BUILD_ARRAY_END,
        _SD_JSON_BUILD_OBJECT_BEGIN,
        _SD_JSON_BUILD_OBJECT_END,
        _SD_JSON_BUILD_PAIR,
        _SD_JSON_BUILD_PAIR_CONDITION,
        _SD_JSON_BUILD_NULL,
        _SD_JSON_BUILD_VARIANT,
        _SD_JSON_BUILD_VARIANT_ARRAY,
        _SD_JSON_BUILD_LITERAL,
        _SD_JSON_BUILD_STRV,
        _SD_JSON_BUILD_BASE64,
        _SD_JSON_BUILD_BASE32HEX,
        _SD_JSON_BUILD_HEX,
        _SD_JSON_BUILD_OCTESCAPE,
        _SD_JSON_BUILD_BYTE_ARRAY,
        _SD_JSON_BUILD_ID128,
        _SD_JSON_BUILD_UUID,
        _SD_JSON_BUILD_CALLBACK,
        _SD_JSON_BUILD_MAX
};

typedef int (*sd_json_build_callback_t)(sd_json_variant **ret, const char *name, void *userdata);

#define SD_JSON_BUILD_STRING(s)                 \
        _SD_JSON_BUILD_STRING, (const char *) { \
                s                               \
        }
#define SD_JSON_BUILD_INTEGER(i)            \
        _SD_JSON_BUILD_INTEGER, (int64_t) { \
                i                           \
        }
#define SD_JSON_BUILD_UNSIGNED(u)             \
        _SD_JSON_BUILD_UNSIGNED, (uint64_t) { \
                u                             \
        }
#define SD_JSON_BUILD_REAL(d)           \
        _SD_JSON_BUILD_REAL, (double) { \
                d                       \
        }
#define SD_JSON_BUILD_BOOLEAN(b)        \
        _SD_JSON_BUILD_BOOLEAN, (int) { \
                b                       \
        }
#define SD_JSON_BUILD_ARRAY(...) _SD_JSON_BUILD_ARRAY_BEGIN, __VA_ARGS__, _SD_JSON_BUILD_ARRAY_END
#define SD_JSON_BUILD_EMPTY_ARRAY _SD_JSON_BUILD_ARRAY_BEGIN, _SD_JSON_BUILD_ARRAY_END
#define SD_JSON_BUILD_OBJECT(...) _SD_JSON_BUILD_OBJECT_BEGIN, __VA_ARGS__, _SD_JSON_BUILD_OBJECT_END
#define SD_JSON_BUILD_EMPTY_OBJECT _SD_JSON_BUILD_OBJECT_BEGIN, _SD_JSON_BUILD_OBJECT_END
#define SD_JSON_BUILD_PAIR(n, ...) _SD_JSON_BUILD_PAIR, (const char *){ n }, __VA_ARGS__
#define SD_JSON_BUILD_PAIR_CONDITION(c, n, ...) \
        _SD_JSON_BUILD_PAIR_CONDITION, (int){ c }, (const char *){ n }, __VA_ARGS__
#define SD_JSON_BUILD_NULL _SD_JSON_BUILD_NULL
#define SD_JSON_BUILD_VARIANT(v)                      \
        _SD_JSON_BUILD_VARIANT, (sd_json_variant *) { \
                v                                     \
        }
#define SD_JSON_BUILD_VARIANT_ARRAY(v, n)                                   \
        _SD_JSON_BUILD_VARIANT_ARRAY, (sd_json_variant **){ v }, (size_t) { \
                n                                                           \
        }
#define SD_JSON_BUILD_LITERAL(l)                 \
        _SD_JSON_BUILD_LITERAL, (const char *) { \
                l                                \
        }
#define SD_JSON_BUILD_STRV(l)            \
        _SD_JSON_BUILD_STRV, (char **) { \
                l                        \
        }
#define SD_JSON_BUILD_BASE64(p, n)                             \
        _SD_JSON_BUILD_BASE64, (const void *){ p }, (size_t) { \
                n                                              \
        }
#define SD_JSON_BUILD_BASE32HEX(p, n)                             \
        _SD_JSON_BUILD_BASE32HEX, (const void *){ p }, (size_t) { \
                n                                                 \
        }
#define SD_JSON_BUILD_HEX(p, n)                             \
        _SD_JSON_BUILD_HEX, (const void *){ p }, (size_t) { \
                n                                           \
        }
#define SD_JSON_BUILD_OCTESCAPE(p, n)                             \
        _SD_JSON_BUILD_OCTESCAPE, (const void *){ p }, (size_t) { \
                n                                                 \
        }
#define SD_JSON_BUILD_BYTE_ARRAY(v, n)                             \
        _SD_JSON_BUILD_BYTE_ARRAY, (const void *){ v }, (size_t) { \
                n                                                  \
        }
#define SD_JSON_BUILD_ID128(id)                      \
        _SD_JSON_BUILD_ID128, (const sd_id128_t *) { \
                &(id)                                \
        }
#define SD_JSON_BUILD_UUID(id)                      \
        _SD_JSON_BUILD_UUID, (const sd_id128_t *) { \
                &(id)                               \
        }
#define SD_JSON_BUILD_CALLBACK(c, u)                                         \
        _SD_JSON_BUILD_CALLBACK, (sd_json_build_callback_t){ c }, (void *) { \
                u                                                            \
        }

#define SD_JSON_BUILD_PAIR_STRING(name, s) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_STRING(s))
#define SD_JSON_BUILD_PAIR_INTEGER(name, i) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_INTEGER(i))
#define SD_JSON_BUILD_PAIR_UNSIGNED(name, u) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_UNSIGNED(u))
#define SD_JSON_BUILD_PAIR_REAL(name, d) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_REAL(d))
#define SD_JSON_BUILD_PAIR_BOOLEAN(name, b) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_BOOLEAN(b))
#define SD_JSON_BUILD_PAIR_ARRAY(name, ...) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_ARRAY(__VA_ARGS__))
#define SD_JSON_BUILD_PAIR_EMPTY_ARRAY(name) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_EMPTY_ARRAY)
#define SD_JSON_BUILD_PAIR_OBJECT(name, ...) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_OBJECT(__VA_ARGS__))
#define SD_JSON_BUILD_PAIR_EMPTY_OBJECT(name) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_EMPTY_OBJECT)
#define SD_JSON_BUILD_PAIR_NULL(name) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_NULL)
#define SD_JSON_BUILD_PAIR_VARIANT(name, v) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_VARIANT(v))
#define SD_JSON_BUILD_PAIR_VARIANT_ARRAY(name, v, n) \
        SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_VARIANT_ARRAY(v, n))
#define SD_JSON_BUILD_PAIR_LITERAL(name, l) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_LITERAL(l))
#define SD_JSON_BUILD_PAIR_STRV(name, l) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_STRV(l))
#define SD_JSON_BUILD_PAIR_BASE64(name, p, n) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_BASE64(p, n))
#define SD_JSON_BUILD_PAIR_BASE32HEX(name, p, n) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_BASE32HEX(p, n))
#define SD_JSON_BUILD_PAIR_HEX(name, p, n) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_HEX(p, n))
#define SD_JSON_BUILD_PAIR_OCTESCAPE(name, p, n) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_OCTESCAPE(p, n))
#define SD_JSON_BUILD_PAIR_BYTE_ARRAY(name, v, n) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_BYTE_ARRAY(v, n))
#define SD_JSON_BUILD_PAIR_ID128(name, id) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_ID128(id))
#define SD_JSON_BUILD_PAIR_UUID(name, id) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_UUID(id))
#define SD_JSON_BUILD_PAIR_CALLBACK(name, c, u) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_CALLBACK(c, u))

int sd_json_build(sd_json_variant **ret, ...);
#define sd_json_buildo(ret, ...) sd_json_build((ret), SD_JSON_BUILD_OBJECT(__VA_ARGS__))
int sd_json_buildv(sd_json_variant **ret, va_list ap);

/* Combination of the flags passed to sd_json_dispatch() and the flags of the field entry being dispatched. */
__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_json_dispatch_flags_t) {
        SD_JSON_PERMISSIVE = 1 << 0,       /* errors for this field or object are not fatal */
        SD_JSON_MANDATORY = 1 << 1,        /* the field must be present */
        SD_JSON_LOG = 1 << 2,              /* log errors */
        SD_JSON_DEBUG = 1 << 3,            /* log at LOG_DEBUG at most */
        SD_JSON_WARNING = 1 << 4,          /* log at LOG_WARNING at most */
        SD_JSON_STRICT = 1 << 5,           /* stricter validation than usual */
        SD_JSON_RELAX = 1 << 6,            /* more relaxed validation than usual */
        SD_JSON_ALLOW_EXTENSIONS = 1 << 7, /* accept unknown fields, nothing else permissive */
        SD_JSON_NULLABLE = 1 << 8,         /* accept null as well as the field's type */
        SD_JSON_REFUSE_NULL = 1 << 9,      /* never accept null */
        _SD_ENUM_FORCE_S64(JSON_DISPATCH_FLAGS)
} sd_json_dispatch_flags_t;

typedef int (*sd_json_dispatch_callback_t)(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

typedef struct sd_json_dispatch_field {
        const char *name;
        sd_json_variant_type_t type;
        sd_json_dispatch_callback_t callback;
        size_t offset;
        sd_json_dispatch_flags_t flags;
} sd_json_dispatch_field;

int sd_json_dispatch_full(
                sd_json_variant *v,
                const sd_json_dispatch_field table[],
                sd_json_dispatch_callback_t bad,
                sd_json_dispatch_flags_t flags,
                void *userdata,
                const char **reterr_bad_field);
int sd_json_dispatch(
                sd_json_variant *v,
                const sd_json_dispatch_field table[],
                sd_json_dispatch_flags_t flags,
                void *userdata);

int sd_json_dispatch_string(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_const_string(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_strv(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_stdbool(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_intbool(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_tristate(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_variant(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_variant_noref(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_int64(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_uint64(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_uint32(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_int32(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_uint16(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_int16(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_int8(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_uint8(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_double(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_uid_gid(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_id128(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_signal(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_unsupported(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

#define sd_json_dispatch_uint sd_json_dispatch_uint32
#define sd_json_dispatch_int sd_json_dispatch_int32

int sd_json_variant_strv(sd_json_variant *v, char ***ret);
int sd_json_variant_unbase64(sd_json_variant *v, void **ret, size_t *ret_size);
int sd_json_variant_unhex(sd_json_variant *v, void **ret, size_t *ret_size);

const char *sd_json_variant_type_to_string(sd_json_variant_type_t i);
sd_json_variant_type_t sd_json_variant_type_from_string(const char *s);

static __inline__ int sd_json_format_enabled(sd_json_format_flags_t flags) {
        return !(flags & SD_JSON_FORMAT_OFF);
}

_SD_END_DECLARATIONS;
