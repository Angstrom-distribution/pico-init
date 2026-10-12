/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Calls every sd_json_*() function. No sd_json_variant can exist, so the
 * answers are upstream's for a NULL variant, -EINVAL for a missing handle
 * or output, and -EOPNOTSUPP wherever a JSON engine would be needed.
 */

#include "sd-json.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../test-util.h"

#define FAKE ((sd_json_variant *) 0x1)

static void check_constructors(void) {
        sd_json_variant *v = FAKE;
        sd_id128_t id = SD_ID128_NULL;
        char *strv[] = { (char *) "a", NULL };
        sd_json_variant *elements[2] = { NULL, NULL };

        ASSERT_EQ_INT(sd_json_variant_new_string(NULL, "x"), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_string(&v, "x"), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_string(&v, NULL), -EOPNOTSUPP);
        ASSERT_TRUE(v == FAKE); /* untouched on failure */

        ASSERT_EQ_INT(sd_json_variant_new_stringn(NULL, "x", 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_stringn(&v, "x", 1), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_stringn(&v, NULL, 0), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_stringn(&v, NULL, SIZE_MAX), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_stringn(&v, NULL, 3), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_stringn(&v, "a\0b", 3), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_stringn(&v, "a\0b", 1), -EOPNOTSUPP);

        ASSERT_EQ_INT(sd_json_variant_new_base64(NULL, "x", 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_base64(&v, NULL, 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_base64(&v, "x", 1), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_base64(&v, NULL, 0), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_base32hex(NULL, "x", 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_base32hex(&v, NULL, 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_base32hex(&v, "x", 1), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_hex(NULL, "x", 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_hex(&v, NULL, 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_hex(&v, "x", 1), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_octescape(NULL, "x", 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_octescape(&v, NULL, 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_octescape(&v, "x", 1), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_array_bytes(NULL, "x", 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_array_bytes(&v, NULL, 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_array_bytes(&v, "x", 1), -EOPNOTSUPP);

        ASSERT_EQ_INT(sd_json_variant_new_integer(NULL, 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_integer(&v, 1), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_unsigned(NULL, 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_unsigned(&v, 1), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_real(NULL, 1.5), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_real(&v, 1.5), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_boolean(NULL, 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_boolean(&v, 1), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_null(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_null(&v), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_id128(NULL, id), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_id128(&v, id), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_uuid(NULL, id), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_uuid(&v, id), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_array_strv(NULL, strv), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_array_strv(&v, strv), -EOPNOTSUPP);

        ASSERT_EQ_INT(sd_json_variant_new_array(NULL, elements, 2), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_array(&v, NULL, 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_array(&v, elements, 2), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_array(&v, NULL, 0), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_object(NULL, elements, 2), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_object(&v, NULL, 2), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_object(&v, elements, 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_new_object(&v, elements, 2), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_new_object(&v, NULL, 0), -EOPNOTSUPP);
        ASSERT_TRUE(v == FAKE);
}

static void check_null_variant(void) {
        sd_json_variant *key = FAKE;
        sd_json_variant **array = malloc(2 * sizeof(*array));

        ASSERT_TRUE(array != NULL);
        array[0] = array[1] = NULL;

        ASSERT_TRUE(sd_json_variant_ref(NULL) == NULL);
        ASSERT_TRUE(sd_json_variant_unref(NULL) == NULL);
        sd_json_variant_unref_many(array, 2); /* frees the array */
        sd_json_variant_unref_many(NULL, 0);

        ASSERT_TRUE(sd_json_variant_string(NULL) == NULL);
        ASSERT_EQ_INT(sd_json_variant_integer(NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_unsigned(NULL), 0);
        ASSERT_TRUE(sd_json_variant_real(NULL) == 0.0);
        ASSERT_EQ_INT(sd_json_variant_boolean(NULL), 0);

        ASSERT_EQ_INT(sd_json_variant_type(NULL), _SD_JSON_VARIANT_TYPE_INVALID);
        ASSERT_EQ_INT(sd_json_variant_type(NULL), -EINVAL);
        for (int t = 0; t < _SD_JSON_VARIANT_TYPE_MAX; t++)
                ASSERT_EQ_INT(sd_json_variant_has_type(NULL, (sd_json_variant_type_t) t), 0);

        ASSERT_EQ_INT(sd_json_variant_is_string(NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_is_integer(NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_is_unsigned(NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_is_real(NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_is_number(NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_is_boolean(NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_is_array(NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_is_object(NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_is_null(NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_is_negative(NULL), 0);

        /* NULL is blank, normalized and sorted, as upstream */
        ASSERT_EQ_INT(sd_json_variant_is_blank_object(NULL), 1);
        ASSERT_EQ_INT(sd_json_variant_is_blank_array(NULL), 1);
        ASSERT_EQ_INT(sd_json_variant_is_normalized(NULL), 1);
        ASSERT_EQ_INT(sd_json_variant_is_sorted(NULL), 1);

        ASSERT_EQ_INT(sd_json_variant_elements(NULL), 0);
        ASSERT_TRUE(sd_json_variant_by_index(NULL, 0) == NULL);
        ASSERT_TRUE(sd_json_variant_by_key(NULL, "k") == NULL);
        ASSERT_TRUE(sd_json_variant_by_key_full(NULL, "k", &key) == NULL);
        ASSERT_TRUE(key == NULL);
        ASSERT_TRUE(sd_json_variant_by_key_full(NULL, NULL, NULL) == NULL);

        ASSERT_EQ_INT(sd_json_variant_equal(NULL, NULL), 1);
        ASSERT_TRUE(sd_json_variant_find(NULL, NULL) == NULL);

        sd_json_variant_sensitive(NULL);
        ASSERT_EQ_INT(sd_json_variant_is_sensitive(NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_is_sensitive_recursive(NULL), 0);
}

static void check_type_strings(void) {
        static const char * const names[] = {
                "string", "integer", "unsigned", "real", "number", "boolean", "array", "object", "null",
        };

        for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++) {
                ASSERT_STREQ(sd_json_variant_type_to_string((sd_json_variant_type_t) i), names[i]);
                ASSERT_EQ_INT(sd_json_variant_type_from_string(names[i]), i);
        }

        ASSERT_TRUE(sd_json_variant_type_to_string(_SD_JSON_VARIANT_TYPE_MAX) == NULL);
        ASSERT_TRUE(sd_json_variant_type_to_string(_SD_JSON_VARIANT_TYPE_INVALID) == NULL);
        ASSERT_EQ_INT(sd_json_variant_type_from_string(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_type_from_string("bogus"), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_type_from_string(""), -EINVAL);

        ASSERT_EQ_INT(sd_json_format_enabled(SD_JSON_FORMAT_PRETTY), 1);
        ASSERT_EQ_INT(sd_json_format_enabled(SD_JSON_FORMAT_OFF), 0);
}

static void check_parse(void) {
        sd_json_variant *v = FAKE;
        const char *p = "{}";
        unsigned line = 7, column = 7;

        ASSERT_EQ_INT(sd_json_parse(NULL, 0, &v, &line, &column), -ENODATA);
        ASSERT_EQ_INT(sd_json_parse("", 0, &v, &line, &column), -ENODATA);
        ASSERT_EQ_INT(sd_json_parse("{}", 0, &v, &line, &column), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_parse_with_source("", "src", 0, &v, NULL, NULL), -ENODATA);
        ASSERT_EQ_INT(sd_json_parse_with_source("[]", "src", SD_JSON_PARSE_SENSITIVE, &v, NULL, NULL),
                      -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_parse_continue(&p, 0, &v, NULL, NULL), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_parse_with_source_continue(&p, "src", 0, &v, NULL, NULL), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_parse_file(NULL, "/nonexistent", 0, &v, NULL, NULL), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_parse_file_at(NULL, AT_FDCWD, "/nonexistent", 0, &v, NULL, NULL), -EOPNOTSUPP);
        ASSERT_TRUE(v == FAKE);
        ASSERT_EQ_INT(line, 7);
        ASSERT_EQ_INT(column, 7);

        ASSERT_EQ_INT(sd_json_parse_fd("x", -1, 0, &v, NULL, NULL), -EBADF);
        ASSERT_EQ_INT(sd_json_parse_fd("x", 0, SD_JSON_PARSE_REOPEN_FD | SD_JSON_PARSE_DONATE_FD, &v, NULL, NULL),
                      -EINVAL);
        ASSERT_EQ_INT(sd_json_parse_fd("x", 0, 0, &v, NULL, NULL), -EOPNOTSUPP);

        /* A donated fd is closed even though parsing fails */
        {
                int fds[2];

                ASSERT_EQ_INT(pipe(fds), 0);
                ASSERT_EQ_INT(sd_json_parse_fd("x", fds[0], SD_JSON_PARSE_DONATE_FD, &v, NULL, NULL),
                              -EOPNOTSUPP);
                ASSERT_EQ_INT(fcntl(fds[0], F_GETFD), -1);
                ASSERT_EQ_INT(errno, EBADF);
                close(fds[1]);
        }
}

static int build_callback(sd_json_variant **ret, const char *name, void *userdata) {
        (void) ret;
        (void) name;
        (void) userdata;
        return 0;
}

static void check_build(void) {
        sd_json_variant *v = FAKE;
        sd_id128_t id = SD_ID128_NULL;
        char *strv[] = { (char *) "a", NULL };

        ASSERT_EQ_INT(sd_json_build(NULL, SD_JSON_BUILD_NULL), -EINVAL);
        ASSERT_EQ_INT(sd_json_build(&v, SD_JSON_BUILD_NULL), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_buildo(NULL, SD_JSON_BUILD_PAIR_NULL("k")), -EINVAL);
        ASSERT_EQ_INT(sd_json_buildo(&v, SD_JSON_BUILD_PAIR_NULL("k")), -EOPNOTSUPP);

        /* Every builder macro has to compile */
        ASSERT_EQ_INT(sd_json_buildo(&v,
                                     SD_JSON_BUILD_PAIR_STRING("s", "x"),
                                     SD_JSON_BUILD_PAIR_INTEGER("i", -1),
                                     SD_JSON_BUILD_PAIR_UNSIGNED("u", 1),
                                     SD_JSON_BUILD_PAIR_REAL("r", 1.5),
                                     SD_JSON_BUILD_PAIR_BOOLEAN("b", 1),
                                     SD_JSON_BUILD_PAIR_ARRAY("a", SD_JSON_BUILD_STRING("x")),
                                     SD_JSON_BUILD_PAIR_EMPTY_ARRAY("ea"),
                                     SD_JSON_BUILD_PAIR_OBJECT("o", SD_JSON_BUILD_PAIR_NULL("n")),
                                     SD_JSON_BUILD_PAIR_EMPTY_OBJECT("eo"),
                                     SD_JSON_BUILD_PAIR_VARIANT("v", NULL),
                                     SD_JSON_BUILD_PAIR_VARIANT_ARRAY("va", NULL, 0),
                                     SD_JSON_BUILD_PAIR_LITERAL("l", "true"),
                                     SD_JSON_BUILD_PAIR_STRV("sv", strv),
                                     SD_JSON_BUILD_PAIR_BASE64("b64", "x", 1),
                                     SD_JSON_BUILD_PAIR_BASE32HEX("b32", "x", 1),
                                     SD_JSON_BUILD_PAIR_HEX("h", "x", 1),
                                     SD_JSON_BUILD_PAIR_OCTESCAPE("oe", "x", 1),
                                     SD_JSON_BUILD_PAIR_BYTE_ARRAY("ba", "x", 1),
                                     SD_JSON_BUILD_PAIR_ID128("id", id),
                                     SD_JSON_BUILD_PAIR_UUID("uuid", id),
                                     SD_JSON_BUILD_PAIR_CALLBACK("cb", build_callback, NULL),
                                     SD_JSON_BUILD_PAIR_CONDITION(1, "c", SD_JSON_BUILD_NULL)),
                      -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_build(&v,
                                    SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_EMPTY_ARRAY, SD_JSON_BUILD_EMPTY_OBJECT)),
                      -EOPNOTSUPP);
        ASSERT_TRUE(v == FAKE);
}

static int build_v(sd_json_variant **ret, ...) {
        va_list ap;
        int r;

        va_start(ap, ret);
        r = sd_json_buildv(ret, ap);
        va_end(ap);
        return r;
}

static void check_buildv(void) {
        sd_json_variant *v = FAKE;

        ASSERT_EQ_INT(build_v(NULL, SD_JSON_BUILD_NULL), -EINVAL);
        ASSERT_EQ_INT(build_v(&v, SD_JSON_BUILD_NULL), -EOPNOTSUPP);
}

static char *read_back(FILE *f) {
        static char buf[64];
        size_t n;

        fflush(f);
        rewind(f);
        n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = 0;
        rewind(f);
        ASSERT_EQ_INT(ftruncate(fileno(f), 0), 0);
        return buf;
}

static void check_format(void) {
        char *s = (char *) 0x1;
        FILE *f = tmpfile();

        ASSERT_TRUE(f != NULL);

        ASSERT_EQ_INT(sd_json_variant_format(NULL, 0, &s), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_format(FAKE, 0, NULL), -EINVAL);
        ASSERT_TRUE(s == (char *) 0x1);

        /* A NULL variant prints nothing, unless asked for "[]" */
        ASSERT_EQ_INT(sd_json_variant_dump(NULL, 0, f, NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_dump(NULL, SD_JSON_FORMAT_NEWLINE | SD_JSON_FORMAT_SEQ, f, NULL), 0);
        ASSERT_STREQ(read_back(f), "");

        ASSERT_EQ_INT(sd_json_variant_dump(NULL, SD_JSON_FORMAT_EMPTY_ARRAY, f, NULL), 0);
        ASSERT_STREQ(read_back(f), "[]");
        ASSERT_EQ_INT(sd_json_variant_dump(NULL, SD_JSON_FORMAT_EMPTY_ARRAY | SD_JSON_FORMAT_NEWLINE, f, "p"),
                      0);
        ASSERT_STREQ(read_back(f), "[]\n");
        ASSERT_EQ_INT(sd_json_variant_dump(NULL, SD_JSON_FORMAT_EMPTY_ARRAY | SD_JSON_FORMAT_PRETTY, f, NULL),
                      0);
        ASSERT_STREQ(read_back(f), "[]\n");
        ASSERT_EQ_INT(sd_json_variant_dump(
                                      NULL, SD_JSON_FORMAT_EMPTY_ARRAY | SD_JSON_FORMAT_PRETTY_AUTO, f, NULL),
                      0);
        ASSERT_STREQ(read_back(f), "[]\n");
        ASSERT_EQ_INT(sd_json_variant_dump(NULL, SD_JSON_FORMAT_EMPTY_ARRAY | SD_JSON_FORMAT_SEQ, f, NULL), 0);
        ASSERT_STREQ(read_back(f), "\x1e[]\n");
        ASSERT_EQ_INT(sd_json_variant_dump(
                                      NULL,
                                      SD_JSON_FORMAT_EMPTY_ARRAY | SD_JSON_FORMAT_SSE | SD_JSON_FORMAT_FLUSH,
                                      f,
                                      NULL),
                      0);
        ASSERT_STREQ(read_back(f), "data: []\n\n");
        ASSERT_EQ_INT(sd_json_variant_dump(
                                      NULL,
                                      SD_JSON_FORMAT_EMPTY_ARRAY | SD_JSON_FORMAT_COLOR |
                                                      SD_JSON_FORMAT_COLOR_AUTO,
                                      f,
                                      NULL),
                      0);
        ASSERT_STREQ(read_back(f), "[]");

        ASSERT_EQ_INT(sd_json_variant_dump(FAKE, 0, f, NULL), -EOPNOTSUPP);
        fclose(f);
}

static void check_modify(void) {
        sd_json_variant *null_variant = NULL, *v = FAKE;
        sd_id128_t id = SD_ID128_NULL;
        char *strv[] = { (char *) "a", NULL };

        ASSERT_EQ_INT(sd_json_variant_filter(NULL, strv), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_filter(&null_variant, strv), 0);
        ASSERT_EQ_INT(sd_json_variant_filter(&v, strv), -EOPNOTSUPP);

        ASSERT_EQ_INT(sd_json_variant_sort(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_sort(&null_variant), 0);
        ASSERT_EQ_INT(sd_json_variant_sort(&v), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_normalize(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_normalize(&null_variant), 0);
        ASSERT_EQ_INT(sd_json_variant_normalize(&v), -EOPNOTSUPP);

        ASSERT_EQ_INT(sd_json_variant_merge_object(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_merge_object(&null_variant, NULL), 0);
        ASSERT_EQ_INT(sd_json_variant_merge_object(&null_variant, FAKE), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_merge_objectb(&null_variant, SD_JSON_BUILD_EMPTY_OBJECT), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_merge_objectbo(&null_variant, SD_JSON_BUILD_PAIR_NULL("k")),
                      -EOPNOTSUPP);
        ASSERT_TRUE(null_variant == NULL);

        ASSERT_EQ_INT(sd_json_variant_append_array(NULL, FAKE), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_append_array(&null_variant, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_append_array(&null_variant, FAKE), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_append_array_nodup(NULL, FAKE), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_append_array_nodup(&null_variant, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_append_array_nodup(&null_variant, FAKE), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_append_arrayb(&null_variant, SD_JSON_BUILD_NULL), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_append_arraybo(&null_variant, SD_JSON_BUILD_PAIR_NULL("k")),
                      -EOPNOTSUPP);

        ASSERT_EQ_INT(sd_json_variant_set_field(NULL, "f", FAKE), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_set_field(&null_variant, NULL, FAKE), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_set_field(&null_variant, "f", FAKE), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_set_fieldb(&null_variant, "f", SD_JSON_BUILD_NULL), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_set_fieldbo(&null_variant, "f", SD_JSON_BUILD_PAIR_NULL("k")),
                      -EOPNOTSUPP);

        ASSERT_EQ_INT(sd_json_variant_set_field_string(NULL, "f", "x"), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_set_field_string(&null_variant, NULL, "x"), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_set_field_string(&null_variant, "f", "x"), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_set_field_id128(NULL, "f", id), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_set_field_id128(&null_variant, "f", id), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_set_field_uuid(NULL, "f", id), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_set_field_uuid(&null_variant, "f", id), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_set_field_integer(NULL, "f", 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_set_field_integer(&null_variant, "f", 1), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_set_field_unsigned(NULL, "f", 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_set_field_unsigned(&null_variant, "f", 1), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_set_field_boolean(NULL, "f", 1), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_set_field_boolean(&null_variant, "f", 1), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_json_variant_set_field_strv(NULL, "f", strv), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_set_field_strv(&null_variant, "f", strv), -EOPNOTSUPP);
        ASSERT_TRUE(null_variant == NULL);
}

static void check_conversion(void) {
        const char *source = (const char *) 0x1;
        unsigned line = 7, column = 7;
        char **l = NULL;
        void *buf = (void *) 0x1;
        size_t size = 7;

        ASSERT_EQ_INT(sd_json_variant_get_source(NULL, &source, &line, &column), -EINVAL);
        ASSERT_TRUE(source == (const char *) 0x1);
        ASSERT_EQ_INT(line, 7);
        ASSERT_EQ_INT(column, 7);

        ASSERT_EQ_INT(sd_json_variant_strv(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_strv(NULL, &l), 0);
        ASSERT_TRUE(l != NULL);
        ASSERT_TRUE(l[0] == NULL);
        free(l);

        ASSERT_EQ_INT(sd_json_variant_unbase64(NULL, &buf, &size), -EINVAL);
        ASSERT_EQ_INT(sd_json_variant_unhex(NULL, &buf, &size), -EINVAL);
        ASSERT_TRUE(buf == (void *) 0x1);
        ASSERT_EQ_INT(size, 7);
}

static const sd_json_dispatch_field mandatory_table[] = {
        { "optional", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_string, 0, 0 },
        { "required", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, 0, SD_JSON_MANDATORY },
        { 0 },
};

static const sd_json_dispatch_field optional_table[] = {
        { "optional", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_string, 0, 0 },
        { 0 },
};

static void check_dispatch(void) {
        const char *bad = NULL;
        char *dest = NULL;
        bool b = true;

        /* NULL is an empty object: only a mandatory field can fail it */
        ASSERT_EQ_INT(sd_json_dispatch(NULL, optional_table, 0, &dest), 0);
        ASSERT_EQ_INT(sd_json_dispatch(NULL, NULL, 0, NULL), 0);
        ASSERT_EQ_INT(sd_json_dispatch(NULL, mandatory_table, 0, &dest), -ENXIO);
        ASSERT_EQ_INT(sd_json_dispatch(NULL, mandatory_table, SD_JSON_PERMISSIVE, &dest), 0);
        ASSERT_EQ_INT(sd_json_dispatch_full(NULL, mandatory_table, NULL, 0, &dest, &bad), -ENXIO);
        ASSERT_STREQ(bad, "required");
        bad = NULL;
        ASSERT_EQ_INT(sd_json_dispatch_full(NULL, optional_table, NULL, 0, &dest, &bad), 0);
        ASSERT_TRUE(bad == NULL);
        ASSERT_EQ_INT(sd_json_dispatch_full(NULL, mandatory_table, NULL, SD_JSON_PERMISSIVE, &dest, &bad), 0);
        ASSERT_TRUE(bad == NULL);
        ASSERT_EQ_INT(sd_json_dispatch(FAKE, optional_table, 0, &dest), -EOPNOTSUPP);

        /* Callbacks reject what upstream's assert_return() rejects */
#define CHECK_CALLBACK(fn)                                           \
        do {                                                         \
                ASSERT_EQ_INT(fn("f", NULL, 0, &dest), -EINVAL);     \
                ASSERT_EQ_INT(fn("f", FAKE, 0, NULL), -EINVAL);      \
                ASSERT_EQ_INT(fn("f", FAKE, 0, &dest), -EOPNOTSUPP); \
        } while (0)
        CHECK_CALLBACK(sd_json_dispatch_string);
        CHECK_CALLBACK(sd_json_dispatch_const_string);
        CHECK_CALLBACK(sd_json_dispatch_strv);
        CHECK_CALLBACK(sd_json_dispatch_stdbool);
        CHECK_CALLBACK(sd_json_dispatch_intbool);
        CHECK_CALLBACK(sd_json_dispatch_tristate);
        CHECK_CALLBACK(sd_json_dispatch_variant);
        CHECK_CALLBACK(sd_json_dispatch_variant_noref);
        CHECK_CALLBACK(sd_json_dispatch_int64);
        CHECK_CALLBACK(sd_json_dispatch_uint64);
        CHECK_CALLBACK(sd_json_dispatch_uint32);
        CHECK_CALLBACK(sd_json_dispatch_int32);
        CHECK_CALLBACK(sd_json_dispatch_uint16);
        CHECK_CALLBACK(sd_json_dispatch_int16);
        CHECK_CALLBACK(sd_json_dispatch_int8);
        CHECK_CALLBACK(sd_json_dispatch_uint8);
        CHECK_CALLBACK(sd_json_dispatch_double);
        CHECK_CALLBACK(sd_json_dispatch_uid_gid);
        CHECK_CALLBACK(sd_json_dispatch_id128);
        CHECK_CALLBACK(sd_json_dispatch_signal);
        CHECK_CALLBACK(sd_json_dispatch_uint);
        CHECK_CALLBACK(sd_json_dispatch_int);
#undef CHECK_CALLBACK

        ASSERT_EQ_INT(sd_json_dispatch_unsupported("f", NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_json_dispatch_unsupported("f", FAKE, SD_JSON_LOG, &b), -EINVAL);
        ASSERT_TRUE(b);
}

int main(void) {
        check_constructors();
        check_null_variant();
        check_type_strings();
        check_parse();
        check_build();
        check_buildv();
        check_format();
        check_modify();
        check_conversion();
        check_dispatch();
        return 0;
}
