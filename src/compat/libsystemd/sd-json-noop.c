/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The sd-json.h entry points whose upstream answer for a NULL variant is a
 * plain value. No sd_json_variant can ever exist (sd-json-stubs.c: every
 * constructor and parser fails), so NULL is the only variant a program can
 * hold, and these return what upstream returns for it: ref/unref give NULL,
 * predicates are false, getters give their documented zero, lookups find
 * nothing.
 *
 * The exceptions upstream makes are kept: a NULL variant counts as a blank
 * object, blank array, normalized and sorted, and compares equal to NULL.
 */

#include "sd-json.h"

#include <stdlib.h>
#include <string.h>

sd_json_variant *sd_json_variant_ref(sd_json_variant *v) {
        (void) v;
        return NULL;
}

sd_json_variant *sd_json_variant_unref(sd_json_variant *v) {
        (void) v;
        return NULL;
}

/* Upstream drops the references and frees the array itself, which the caller
 * allocated; every element can only be NULL. */
void sd_json_variant_unref_many(sd_json_variant **array, size_t n) {
        (void) n;
        free(array);
}

const char *sd_json_variant_string(sd_json_variant *v) {
        (void) v;
        return NULL;
}

int64_t sd_json_variant_integer(sd_json_variant *v) {
        (void) v;
        return 0;
}

uint64_t sd_json_variant_unsigned(sd_json_variant *v) {
        (void) v;
        return 0;
}

double sd_json_variant_real(sd_json_variant *v) {
        (void) v;
        return 0.0;
}

int sd_json_variant_boolean(sd_json_variant *v) {
        (void) v;
        return 0;
}

sd_json_variant_type_t sd_json_variant_type(sd_json_variant *v) {
        (void) v;
        return _SD_JSON_VARIANT_TYPE_INVALID;
}

int sd_json_variant_has_type(sd_json_variant *v, sd_json_variant_type_t type) {
        (void) v;
        (void) type;
        return 0;
}

int sd_json_variant_is_string(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_STRING);
}

int sd_json_variant_is_integer(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_INTEGER);
}

int sd_json_variant_is_unsigned(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_UNSIGNED);
}

int sd_json_variant_is_real(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_REAL);
}

int sd_json_variant_is_number(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_NUMBER);
}

int sd_json_variant_is_boolean(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_BOOLEAN);
}

int sd_json_variant_is_array(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_ARRAY);
}

int sd_json_variant_is_object(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_OBJECT);
}

int sd_json_variant_is_null(sd_json_variant *v) {
        return sd_json_variant_has_type(v, SD_JSON_VARIANT_NULL);
}

int sd_json_variant_is_negative(sd_json_variant *v) {
        (void) v;
        return 0;
}

int sd_json_variant_is_blank_object(sd_json_variant *v) {
        return !v;
}

int sd_json_variant_is_blank_array(sd_json_variant *v) {
        return !v;
}

int sd_json_variant_is_normalized(sd_json_variant *v) {
        (void) v;
        return 1;
}

int sd_json_variant_is_sorted(sd_json_variant *v) {
        (void) v;
        return 1;
}

size_t sd_json_variant_elements(sd_json_variant *v) {
        (void) v;
        return 0;
}

sd_json_variant *sd_json_variant_by_index(sd_json_variant *v, size_t index) {
        (void) v;
        (void) index;
        return NULL;
}

sd_json_variant *sd_json_variant_by_key_full(sd_json_variant *v, const char *key, sd_json_variant **ret_key) {
        (void) v;
        (void) key;
        if (ret_key)
                *ret_key = NULL;
        return NULL;
}

sd_json_variant *sd_json_variant_by_key(sd_json_variant *v, const char *key) {
        return sd_json_variant_by_key_full(v, key, NULL);
}

int sd_json_variant_equal(sd_json_variant *a, sd_json_variant *b) {
        return a == b;
}

void sd_json_variant_sensitive(sd_json_variant *v) {
        (void) v;
}

int sd_json_variant_is_sensitive(sd_json_variant *v) {
        (void) v;
        return 0;
}

int sd_json_variant_is_sensitive_recursive(sd_json_variant *v) {
        (void) v;
        return 0;
}

sd_json_variant *sd_json_variant_find(sd_json_variant *haystack, sd_json_variant *needle) {
        (void) haystack;
        (void) needle;
        return NULL;
}

static const char * const sd_json_variant_type_table[_SD_JSON_VARIANT_TYPE_MAX] = {
        [SD_JSON_VARIANT_STRING] = "string",     [SD_JSON_VARIANT_INTEGER] = "integer",
        [SD_JSON_VARIANT_UNSIGNED] = "unsigned", [SD_JSON_VARIANT_REAL] = "real",
        [SD_JSON_VARIANT_NUMBER] = "number",     [SD_JSON_VARIANT_BOOLEAN] = "boolean",
        [SD_JSON_VARIANT_ARRAY] = "array",       [SD_JSON_VARIANT_OBJECT] = "object",
        [SD_JSON_VARIANT_NULL] = "null",
};

const char *sd_json_variant_type_to_string(sd_json_variant_type_t i) {
        if (i < 0 || i >= _SD_JSON_VARIANT_TYPE_MAX)
                return NULL;
        return sd_json_variant_type_table[i];
}

sd_json_variant_type_t sd_json_variant_type_from_string(const char *s) {
        if (!s)
                return (sd_json_variant_type_t) -EINVAL;

        for (int i = 0; i < _SD_JSON_VARIANT_TYPE_MAX; i++)
                if (sd_json_variant_type_table[i] && strcmp(sd_json_variant_type_table[i], s) == 0)
                        return (sd_json_variant_type_t) i;

        return (sd_json_variant_type_t) -EINVAL;
}
