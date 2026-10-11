/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Generic %x-specifier substitution engine, quarried from systemd's v30
 * src/specifier.c + src/specifier.h. Split from unit-name.c as in v30: this
 * engine knows nothing about Unit, so it can be tested with a synthetic table.
 *
 * Departures from the v30 shape:
 *
 *  - int return with an out-param, not `char *`, so OOM (-ENOMEM) is
 *    distinct from a lookup result. Upstream's 487060c239 stopped treating a
 *    NULL return as OOM and fell back to the unexpanded rvalue; every lookup
 *    here is a pure string operation, so OOM is the only possible failure.
 *  - pico_specifier_string() returns "" for NULL data rather than v30's
 *    assert(data). NULL data is reachable: unit.c's %i table entry passes
 *    u->instance, which is NULL for any non-instanced unit.
 *  - a growable output buffer instead of v30's j/k/l realloc arithmetic,
 *    which drops a trailing lone '%'. Pico keeps it literal.
 */

#pragma once

#include <stddef.h>

typedef int (*PicoSpecifierLookup)(char specifier, const void *data, const void *userdata, char **ret);

typedef struct PicoSpecifier {
        char specifier;
        PicoSpecifierLookup lookup;
        const void *data;
} PicoSpecifier;

/*
 * Expand every %<specifier> in `text` against `table` (terminated by a row
 * with specifier == '\0', e.g. { { 'x', fn, NULL }, { 0, NULL, NULL } }).
 * "%%" becomes "%"; a specifier not in the table passes through as "%<c>"
 * verbatim, which is the whole of this project's drop-in tolerance for a
 * stock unit file carrying a specifier pico does not implement (%t, %c, ...).
 * *ret is the expanded, NUL-terminated string (caller owns it).
 * 0 on success, -ENOMEM, or whatever a table lookup itself returned < 0.
 */
int pico_specifier_printf(const char *text, const PicoSpecifier table[], const void *userdata, char **ret);

/* Generic lookup for a plain string held in `data`: expands to a copy of
 * data, or to "" when data is NULL. 0 or -ENOMEM. */
int pico_specifier_string(char specifier, const void *data, const void *userdata, char **ret);
