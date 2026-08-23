/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Placeholder. The real body is unit-parse.c's existing line scanner, moved
 * here verbatim so its eleven backported upstream fixes keep applying to every
 * caller rather than to unit files only -- see conf-scan.h for why that
 * matters and which four of those fixes live specifically in this layer.
 *
 * Registered in meson.build up front so the file that performs the move does
 * not also have to edit the build definition while other work is in flight.
 */

#include <errno.h>

#include "conf-scan.h"

int pico_conf_scan(const char *filename, pico_conf_handler_t handler, void *userdata) {
        (void) filename;
        (void) handler;
        (void) userdata;
        return -ENOSYS;
}
