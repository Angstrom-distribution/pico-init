/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * M0 placeholder: the INI parser (sections, escapes, line continuations)
 * quarried from systemd's conf-parser.c lands in M1. Stub returns -ENOSYS
 * without touching u or reading path.
 */

#include <errno.h>

#include "unit.h"

int unit_parse_file(Unit *u, const char *path) {
        (void) u;
        (void) path;
        return -ENOSYS;
}
