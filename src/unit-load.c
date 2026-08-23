/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * M0 placeholder: fragment search-path lookup and the load-fragment.c
 * quarry that turns a found file into unit_parse_file() + LOADED/ERROR
 * resolution land in M1. Stub returns -ENOSYS without touching u.
 */

#include <errno.h>

#include "unit.h"

int unit_load(Unit *u) {
        (void) u;
        return -ENOSYS;
}
