/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_json_dispatch*() and the sd_json_dispatch_*() field callbacks.
 *
 * The only variant a program can hold is NULL (see sd-json-stubs.c), and
 * upstream treats a NULL variant as an empty object: nothing is dispatched
 * and the only possible failure is a missing mandatory field. That is
 * implemented as upstream has it, minus the log line SD_JSON_LOG asks for.
 *
 * A callback is only ever invoked by the dispatcher with a field's value, so
 * a direct call is the only way to reach one here. Like upstream's, it
 * rejects a NULL variant or NULL userdata with -EINVAL.
 */

#include "sd-json.h"

#include <errno.h>

int sd_json_dispatch_full(
                sd_json_variant *v,
                const sd_json_dispatch_field table[],
                sd_json_dispatch_callback_t bad,
                sd_json_dispatch_flags_t flags,
                void *userdata,
                const char **reterr_bad_field) {

        (void) bad;
        (void) userdata;

        if (v)
                return -EOPNOTSUPP;

        for (const sd_json_dispatch_field *p = table; p && p->name; p++) {
                if (!(p->flags & SD_JSON_MANDATORY))
                        continue;
                if ((p->flags | flags) & SD_JSON_PERMISSIVE)
                        continue;

                if (reterr_bad_field)
                        *reterr_bad_field = p->name;
                return -ENXIO;
        }

        return 0;
}

int sd_json_dispatch(
                sd_json_variant *v,
                const sd_json_dispatch_field table[],
                sd_json_dispatch_flags_t flags,
                void *userdata) {
        return sd_json_dispatch_full(v, table, NULL, flags, userdata, NULL);
}

#define DISPATCH_CALLBACK(suffix)                       \
        int sd_json_dispatch_##suffix(                  \
                        const char *name,               \
                        sd_json_variant *variant,       \
                        sd_json_dispatch_flags_t flags, \
                        void *userdata) {               \
                (void) name;                            \
                (void) flags;                           \
                if (!variant || !userdata)              \
                        return -EINVAL;                 \
                return -EOPNOTSUPP;                     \
        }

DISPATCH_CALLBACK(string)
DISPATCH_CALLBACK(const_string)
DISPATCH_CALLBACK(strv)
DISPATCH_CALLBACK(stdbool)
DISPATCH_CALLBACK(intbool)
DISPATCH_CALLBACK(tristate)
DISPATCH_CALLBACK(variant)
DISPATCH_CALLBACK(variant_noref)
DISPATCH_CALLBACK(int64)
DISPATCH_CALLBACK(uint64)
DISPATCH_CALLBACK(uint32)
DISPATCH_CALLBACK(int32)
DISPATCH_CALLBACK(uint16)
DISPATCH_CALLBACK(int16)
DISPATCH_CALLBACK(int8)
DISPATCH_CALLBACK(uint8)
DISPATCH_CALLBACK(double)
DISPATCH_CALLBACK(uid_gid)
DISPATCH_CALLBACK(id128)
DISPATCH_CALLBACK(signal)

/* Upstream's answer for a field that must not appear, whatever it holds. */
int sd_json_dispatch_unsupported(
                const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        (void) name;
        (void) variant;
        (void) flags;
        (void) userdata;
        return -EINVAL;
}
