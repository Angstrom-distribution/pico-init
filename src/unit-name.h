/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Template/instance unit-name parsing, quarried from systemd's ~2011-era
 * src/unit-name.c (tag v30, commit 501c92c, copyright 2010 Lennart
 * Poettering, GPL-2.0-or-later): the seven functions this project actually
 * needs, plus one pico original. Everything that synthesizes or decodes a
 * .device/.mount name -- unit types pico has none of -- is not carried.
 *
 * Backported fix:
 *  - 8556879e0d "unit-name: rework unit_name_replace_instance function()"
 *    (2012-09-12, RH#855863) -- unit_name_replace_instance() below tests
 *    for the no-'@' case before touching the '@' pointer, not after
 *    computing an offset from it; the v30 original did the arithmetic
 *    first, which is undefined behaviour on a name with no '@' at all.
 *    See the function body for the shape of the bug.
 *
 * Deliberate deviation from upstream, not a bug carried forward:
 *  - unit_name_to_instance() sets *ret to NULL for a template name
 *    ("foo@.service"), where upstream returns a non-NULL "". That makes
 *    u->instance mean exactly "this unit is an instance" everywhere it is
 *    read, rather than needing a second check against the empty string.
 *
 * Every v30 assert()/assert_se() that could abort PID 1 on a malformed
 * name (a missing '.', or one that sorts before the '@') is a checked
 * early return instead -- a bad Requires= token must cost that token, never
 * the whole boot.
 */

#pragma once

#include <stdbool.h>

/*
 * Everything after the first '@' and before the last '.'. *ret is NULL, not
 * "", when n names no instance at all -- see the deviation note above.
 * 0 on success (including the no-instance case), or -ENOMEM.
 */
int unit_name_to_instance(const char *n, char **ret);

/* Text before the first '@', or before the last '.' when n has none.
 * NULL on OOM or on a malformed n (no '.' at all). */
char *unit_name_to_prefix(const char *n);

/* Text before the last '.', instance included. NULL on OOM or malformed n. */
char *unit_name_to_prefix_and_instance(const char *n);

/*
 * n with its instance collapsed down to a bare '@', e.g.
 * "foo@bar.service" -> "foo@.service"; a name with no '@' is returned
 * unchanged. NULL on OOM or malformed n.
 */
char *unit_name_template(const char *n);

/*
 * n with its instance replaced by `instance`; a name with no '@' has no
 * instance slot to replace and is returned unchanged (see the b9a3302630
 * note above). NULL on OOM or malformed n.
 */
char *unit_name_replace_instance(const char *n, const char *instance);

/* '-' -> '/'; '\xNN' -> that byte; any other escape (or one truncated by
 * the end of the string) is kept literal. NULL on OOM. */
char *unit_name_unescape(const char *n);

/* True when the first '@' is immediately followed by '.' -- a name that
 * loads only through an instance of it, never on its own. */
bool unit_name_is_template(const char *n);

/* Pico original, not a systemd function: true when n has an '@' and a
 * non-empty instance. The counterpart to unit_name_is_template() -- exactly
 * one of the two is true for any name containing an '@'. */
bool unit_name_is_instance(const char *n);
