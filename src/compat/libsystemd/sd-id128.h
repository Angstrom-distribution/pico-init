/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-init's own implementation of the sd-id128 public API surface (see
 * sd-id128(3) upstream). Function names, macro names/values and documented
 * error conventions below match real libsystemd byte-for-byte -- that is
 * the compatibility contract, so code written against the real header
 * builds and links unmodified against this one. Written from scratch
 * against the real, current sd-id128.h and the sd-id128.c/id128-util.c
 * implementation it documents (systemd.git, HEAD ded83144, 2026-08-23) for
 * signatures and error semantics only -- no text from that
 * LGPL-2.1-or-later source is reproduced here.
 *
 * sd-id128 carries no "is this systemd?" signal and this shim never invents
 * one: a missing or malformed backing file always maps to the specific
 * documented errno for that resource, never to "not systemd". See each
 * getter below, and id128-internal.h, for exactly which errno means what.
 *
 * sd_id128_t's layout (bytes[16] / qwords[2] union) is the wire/ABI
 * contract, not an implementation detail -- anything that marshals this
 * type across a boundary depends on it being exactly these 16 bytes in
 * this shape. The typedef is guarded by PICO_SD_ID128_T_DEFINED so this
 * real definition and sd-device.h's stand-in (see its own comment) agree
 * on one definition regardless of which header a translation unit includes
 * first.
 */

#pragma once

#include <stdarg.h>
#include <stdint.h>

#include "_sd-common.h"

#ifndef PICO_SD_ID128_T_DEFINED
#        define PICO_SD_ID128_T_DEFINED
typedef union sd_id128 {
        uint8_t bytes[16];
        uint64_t qwords[2];
} sd_id128_t;
#endif

_SD_BEGIN_DECLARATIONS;

#define SD_ID128_STRING_MAX 33U
#define SD_ID128_UUID_STRING_MAX 37U

char *sd_id128_to_string(sd_id128_t id, char s[_SD_ARRAY_STATIC SD_ID128_STRING_MAX]);
char *sd_id128_to_uuid_string(sd_id128_t id, char s[_SD_ARRAY_STATIC SD_ID128_UUID_STRING_MAX]);
int sd_id128_from_string(const char *s, sd_id128_t *ret);
int sd_id128_string_equal(const char *s, sd_id128_t id);

/* The buffer is a compound literal in the caller's own statement, valid until the end of that
 * statement's block -- long enough to pass straight into a printf-family call, never to store. */
#define SD_ID128_TO_STRING(id) sd_id128_to_string((id), (char[SD_ID128_STRING_MAX]){ 0 })
#define SD_ID128_TO_UUID_STRING(id) sd_id128_to_uuid_string((id), (char[SD_ID128_UUID_STRING_MAX]){ 0 })

int sd_id128_randomize(sd_id128_t *ret);

/*
 * sd_id128_get_boot()'s -ENOSYS is the one case worth calling out by name
 * here: it means /proc itself is not mounted, not "this kernel has no boot
 * id". sd_id128_get_invocation()'s -ENXIO is pico-init's permanent, honest
 * answer today (no service-exec INVOCATION_ID export yet) -- see the .c
 * file for why that is not a stand-in for a missing mechanism.
 */
int sd_id128_get_machine(sd_id128_t *ret);
int sd_id128_get_boot(sd_id128_t *ret);
int sd_id128_get_invocation(sd_id128_t *ret);

int sd_id128_get_app_specific(sd_id128_t base, sd_id128_t app_id, sd_id128_t *ret);
int sd_id128_get_machine_app_specific(sd_id128_t app_id, sd_id128_t *ret);
int sd_id128_get_boot_app_specific(sd_id128_t app_id, sd_id128_t *ret);
int sd_id128_get_invocation_app_specific(sd_id128_t app_id, sd_id128_t *ret);

#define SD_ID128_ARRAY(b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11, b12, b13, b14, b15) \
        {                                                                                              \
                .bytes = {                                                                             \
                        0x##b00,                                                                       \
                        0x##b01,                                                                       \
                        0x##b02,                                                                       \
                        0x##b03,                                                                       \
                        0x##b04,                                                                       \
                        0x##b05,                                                                       \
                        0x##b06,                                                                       \
                        0x##b07,                                                                       \
                        0x##b08,                                                                       \
                        0x##b09,                                                                       \
                        0x##b10,                                                                       \
                        0x##b11,                                                                       \
                        0x##b12,                                                                       \
                        0x##b13,                                                                       \
                        0x##b14,                                                                       \
                        0x##b15                                                                        \
                }                                                                                      \
        }

#define SD_ID128_MAKE(b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11, b12, b13, b14, b15) \
        ((const sd_id128_t) SD_ID128_ARRAY(                                                           \
                        b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11, b12, b13, b14, b15))

/* Evaluates x sixteen times -- fine for a variable or literal, never for an expression with side effects. */
#define SD_ID128_FORMAT_STR "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
#define SD_ID128_FORMAT_VAL(x)                                                                            \
        (x).bytes[0], (x).bytes[1], (x).bytes[2], (x).bytes[3], (x).bytes[4], (x).bytes[5], (x).bytes[6], \
                        (x).bytes[7], (x).bytes[8], (x).bytes[9], (x).bytes[10], (x).bytes[11],           \
                        (x).bytes[12], (x).bytes[13], (x).bytes[14], (x).bytes[15]

/* Like SD_ID128_FORMAT_STR, but 8-4-4-4-12 dashed. Always big-endian byte order, matching every other
 * Linux userspace UUID renderer, even for an id whose own variant bits say otherwise -- deliberate, not
 * a bug: see sd_id128_to_uuid_string()'s own comment in sd-id128.c. */
#define SD_ID128_UUID_FORMAT_STR "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"

#define SD_ID128_MAKE_STR(b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11, b12, b13, b14, b15) \
        #b00 #b01 #b02 #b03 #b04 #b05 #b06 #b07 #b08 #b09 #b10 #b11 #b12 #b13 #b14 #b15

#define SD_ID128_MAKE_UUID_STR(b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11, b12, b13, b14, b15) \
        #b00 #b01 #b02 #b03 "-" #b04 #b05 "-" #b06 #b07 "-" #b08 #b09 "-" #b10 #b11 #b12 #b13 #b14 #b15

/* One hex nibble to its lowercase digit -- pico's own building block for SD_ID128_CONST_STR below,
 * not a copy of upstream's inline-everywhere ternary text. */
#define _PICO_ID128_NIBBLE(n) ((char) ((n) < 10 ? '0' + (n) : 'a' + (n) - 10))

#define SD_ID128_CONST_STR(x)                                                         \
        ((const char[SD_ID128_STRING_MAX]){ _PICO_ID128_NIBBLE((x).bytes[0] >> 4),    \
                                            _PICO_ID128_NIBBLE((x).bytes[0] & 0x0f),  \
                                            _PICO_ID128_NIBBLE((x).bytes[1] >> 4),    \
                                            _PICO_ID128_NIBBLE((x).bytes[1] & 0x0f),  \
                                            _PICO_ID128_NIBBLE((x).bytes[2] >> 4),    \
                                            _PICO_ID128_NIBBLE((x).bytes[2] & 0x0f),  \
                                            _PICO_ID128_NIBBLE((x).bytes[3] >> 4),    \
                                            _PICO_ID128_NIBBLE((x).bytes[3] & 0x0f),  \
                                            _PICO_ID128_NIBBLE((x).bytes[4] >> 4),    \
                                            _PICO_ID128_NIBBLE((x).bytes[4] & 0x0f),  \
                                            _PICO_ID128_NIBBLE((x).bytes[5] >> 4),    \
                                            _PICO_ID128_NIBBLE((x).bytes[5] & 0x0f),  \
                                            _PICO_ID128_NIBBLE((x).bytes[6] >> 4),    \
                                            _PICO_ID128_NIBBLE((x).bytes[6] & 0x0f),  \
                                            _PICO_ID128_NIBBLE((x).bytes[7] >> 4),    \
                                            _PICO_ID128_NIBBLE((x).bytes[7] & 0x0f),  \
                                            _PICO_ID128_NIBBLE((x).bytes[8] >> 4),    \
                                            _PICO_ID128_NIBBLE((x).bytes[8] & 0x0f),  \
                                            _PICO_ID128_NIBBLE((x).bytes[9] >> 4),    \
                                            _PICO_ID128_NIBBLE((x).bytes[9] & 0x0f),  \
                                            _PICO_ID128_NIBBLE((x).bytes[10] >> 4),   \
                                            _PICO_ID128_NIBBLE((x).bytes[10] & 0x0f), \
                                            _PICO_ID128_NIBBLE((x).bytes[11] >> 4),   \
                                            _PICO_ID128_NIBBLE((x).bytes[11] & 0x0f), \
                                            _PICO_ID128_NIBBLE((x).bytes[12] >> 4),   \
                                            _PICO_ID128_NIBBLE((x).bytes[12] & 0x0f), \
                                            _PICO_ID128_NIBBLE((x).bytes[13] >> 4),   \
                                            _PICO_ID128_NIBBLE((x).bytes[13] & 0x0f), \
                                            _PICO_ID128_NIBBLE((x).bytes[14] >> 4),   \
                                            _PICO_ID128_NIBBLE((x).bytes[14] & 0x0f), \
                                            _PICO_ID128_NIBBLE((x).bytes[15] >> 4),   \
                                            _PICO_ID128_NIBBLE((x).bytes[15] & 0x0f), \
                                            0 })

static __inline__ int sd_id128_equal(sd_id128_t a, sd_id128_t b) {
        return a.qwords[0] == b.qwords[0] && a.qwords[1] == b.qwords[1];
}

static __inline__ int sd_id128_is_null(sd_id128_t a) {
        return a.qwords[0] == 0 && a.qwords[1] == 0;
}

static __inline__ int sd_id128_is_allf(sd_id128_t a) {
        return a.qwords[0] == UINT64_C(0xffffffffffffffff) && a.qwords[1] == UINT64_C(0xffffffffffffffff);
}

#define SD_ID128_NULL        \
        ((const sd_id128_t){ \
                        .qwords = { 0, 0 } \
        })
#define SD_ID128_ALLF        \
        ((const sd_id128_t){ \
                        .qwords = { UINT64_C(0xffffffffffffffff), UINT64_C(0xffffffffffffffff) } \
        })

static __inline__ int sd_id128_in_setv(sd_id128_t a, va_list ap) {
        for (;;) {
                sd_id128_t b = va_arg(ap, sd_id128_t);

                if (sd_id128_is_null(b))
                        return 0;
                if (sd_id128_equal(a, b))
                        return 1;
        }
}

static __inline__ int sd_id128_in_set_sentinel(sd_id128_t a, ...) {
        va_list ap;
        int r;

        va_start(ap, a);
        r = sd_id128_in_setv(a, ap);
        va_end(ap);

        return r;
}

/* Appends the SD_ID128_NULL sentinel so in_set_sentinel()'s va_arg loop always terminates, even
 * called with zero extra ids (sd_id128_in_set(x) is then simply always false). */
#define sd_id128_in_set(a, ...) sd_id128_in_set_sentinel((a), ##__VA_ARGS__, SD_ID128_NULL)

_SD_END_DECLARATIONS;
