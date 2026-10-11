/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The sd_bus_vtable layout and the SD_BUS_VTABLE_START/SD_BUS_METHOD/
 * SD_BUS_SIGNAL/SD_BUS_PROPERTY table-building macros, matching systemd's
 * src/systemd/sd-bus-vtable.h (HEAD ded83144) in macro name, usage and
 * struct layout; written from that contract, not copied. A caller's
 * existing vtable[] definitions compile unchanged. sd_bus_add_object_vtable()
 * itself always fails (sd-bus-stubs.c), but the table passed to it must
 * still be valid C.
 *
 * sd_bus_object_vtable_format's storage (extern here) lives in
 * sd-bus-noop.c: SD_BUS_VTABLE_START() takes its address, so any vtable[]
 * a caller defines at file scope needs the symbol to exist at link time
 * even though nothing in this shim ever reads it.
 */

#pragma once

#include "sd-bus-protocol.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sd_bus_vtable sd_bus_vtable;

enum {
        PICO_SD_BUS_VTABLE_START = '<',
        PICO_SD_BUS_VTABLE_END = '>',
        PICO_SD_BUS_VTABLE_METHOD = 'M',
        PICO_SD_BUS_VTABLE_SIGNAL = 'S',
        PICO_SD_BUS_VTABLE_PROPERTY = 'P',
        PICO_SD_BUS_VTABLE_WRITABLE_PROPERTY = 'W'
};

__extension__ enum {
        SD_BUS_VTABLE_DEPRECATED = 1ULL << 0,
        SD_BUS_VTABLE_HIDDEN = 1ULL << 1,
        SD_BUS_VTABLE_UNPRIVILEGED = 1ULL << 2,
        SD_BUS_VTABLE_METHOD_NO_REPLY = 1ULL << 3,
        SD_BUS_VTABLE_PROPERTY_CONST = 1ULL << 4,
        SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE = 1ULL << 5,
        SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION = 1ULL << 6,
        SD_BUS_VTABLE_PROPERTY_EXPLICIT = 1ULL << 7,
        SD_BUS_VTABLE_SENSITIVE = 1ULL << 8,
        SD_BUS_VTABLE_ABSOLUTE_OFFSET = 1ULL << 9,
        PICO_SD_BUS_VTABLE_CAPABILITY_MASK = 0xFFFFULL << 40
};

#define SD_BUS_VTABLE_CAPABILITY(x) ((uint64_t) (((x) + 1) & 0xFFFF) << 40)

enum { PICO_SD_BUS_VTABLE_PARAM_NAMES = 1 << 0 };

extern const unsigned sd_bus_object_vtable_format;

/* As upstream documents: unused areas in a sd_bus_vtable[] array must be
 * zero-initialized (the embedded union is not required to be
 * zero-filled by an aggregate initializer covering only some members). A
 * static/global array lands in .bss, already zero; a stack/heap one
 * needs an explicit memset first. */
struct sd_bus_vtable {
        __extension__ uint8_t type : 8;
        __extension__ uint64_t flags : 56;
        union {
                struct {
                        size_t element_size;
                        uint64_t features;
                        const unsigned *vtable_format_reference;
                } start;
                struct {
                        size_t _reserved;
                } end;
                struct {
                        const char *member;
                        const char *signature;
                        const char *result;
                        sd_bus_message_handler_t handler;
                        size_t offset;
                        const char *names;
                } method;
                struct {
                        const char *member;
                        const char *signature;
                        const char *names;
                } signal;
                struct {
                        const char *member;
                        const char *signature;
                        sd_bus_property_get_t get;
                        sd_bus_property_set_t set;
                        size_t offset;
                } property;
        } x;
};

#define SD_BUS_VTABLE_START(_flags)                                                   \
        {                                                                             \
                .type = PICO_SD_BUS_VTABLE_START, .flags = _flags, .x = {           \
                        .start = {                                                  \
                                .element_size = sizeof(sd_bus_vtable),              \
                                .features = PICO_SD_BUS_VTABLE_PARAM_NAMES,         \
                                .vtable_format_reference = &sd_bus_object_vtable_format, \
                        },                                                          \
                }, \
        }

#define SD_BUS_PARAM(x) #x "\0"

#define SD_BUS_METHOD_WITH_NAMES_OFFSET(                                                                \
                _member, _signature, _in_names, _result, _out_names, _handler, _offset, _flags)         \
        {                                                                                               \
                .type = PICO_SD_BUS_VTABLE_METHOD, .flags = _flags, .x = {                            \
                        .method = {                                                                   \
                                .member = _member,                                                    \
                                .signature = _signature,                                              \
                                .result = _result,                                                    \
                                .handler = _handler,                                                  \
                                .offset = _offset,                                                    \
                                .names = _in_names _out_names,                                        \
                        },                                                                            \
                }, \
        }
#define SD_BUS_METHOD_WITH_OFFSET(_member, _signature, _result, _handler, _offset, _flags) \
        SD_BUS_METHOD_WITH_NAMES_OFFSET(_member, _signature, "", _result, "", _handler, _offset, _flags)
#define SD_BUS_METHOD_WITH_NAMES(_member, _signature, _in_names, _result, _out_names, _handler, _flags) \
        SD_BUS_METHOD_WITH_NAMES_OFFSET(                                                                \
                        _member, _signature, _in_names, _result, _out_names, _handler, 0, _flags)
#define SD_BUS_METHOD(_member, _signature, _result, _handler, _flags) \
        SD_BUS_METHOD_WITH_NAMES_OFFSET(_member, _signature, "", _result, "", _handler, 0, _flags)

#define SD_BUS_SIGNAL_WITH_NAMES(_member, _signature, _out_names, _flags)   \
        {                                                                   \
                .type = PICO_SD_BUS_VTABLE_SIGNAL, .flags = _flags, .x = {\
                        .signal = {                                      \
                                .member = _member,                       \
                                .signature = _signature,                 \
                                .names = _out_names,                     \
                        },                                                \
                }, \
        }
#define SD_BUS_SIGNAL(_member, _signature, _flags) SD_BUS_SIGNAL_WITH_NAMES(_member, _signature, "", _flags)

#define SD_BUS_PROPERTY(_member, _signature, _get, _offset, _flags)            \
        {                                                                      \
                .type = PICO_SD_BUS_VTABLE_PROPERTY, .flags = _flags, .x = { \
                        .property = {                                 \
                                .member = _member,                    \
                                .signature = _signature,               \
                                .get = _get,                          \
                                .set = NULL,                          \
                                .offset = _offset,                    \
                        },                                             \
                }, \
        }

#define SD_BUS_WRITABLE_PROPERTY(_member, _signature, _get, _set, _offset, _flags)      \
        {                                                                               \
                .type = PICO_SD_BUS_VTABLE_WRITABLE_PROPERTY, .flags = _flags, .x = { \
                        .property = {                                             \
                                .member = _member,                                \
                                .signature = _signature,                          \
                                .get = _get,                                      \
                                .set = _set,                                      \
                                .offset = _offset,                                \
                        },                                                        \
                }, \
        }

#define SD_BUS_VTABLE_END                                           \
        {                                                           \
                .type = PICO_SD_BUS_VTABLE_END, .flags = 0, .x = {\
                        .end = {                                  \
                                ._reserved = 0,                    \
                        },                                         \
                }, \
        }

/*
 * Not provided: SD_BUS_METHOD_WITH_ARGS()/SD_BUS_SIGNAL_WITH_ARGS()/
 * SD_BUS_ARGS()/SD_BUS_RESULT(), which need a preprocessor ladder to split
 * a flat "type1, name1, type2, name2, ..." list into signature and name
 * strings. Nothing here needs it, since sd_bus_add_object_vtable() always
 * fails. Use SD_BUS_METHOD_WITH_NAMES()/SD_BUS_SIGNAL_WITH_NAMES() above
 * instead.
 */

#ifdef __cplusplus
}
#endif
