/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd-id128.c internals, exposed so test-sd-id128.c can drive the
 * machine-id/boot-id reader through a memfd instead of the real
 * /etc/machine-id or /proc/sys/kernel/random/boot_id. Not part of the public
 * ABI.
 */

#pragma once

#include <stdbool.h>

#include "sd-id128.h"

/*
 * Reads and validates the contents already open on fd as a 128-bit id, in
 * the one shape sd_id128_get_machine()/sd_id128_get_boot() each need:
 * either the plain 32-hex-char form (uuid_format false) or the dashed
 * 8-4-4-4-12 form (uuid_format true), each with an optional single
 * trailing newline and nothing else, always refusing an all-zero result.
 * Upstream's id128_read_fd() (id128-util.c) takes an ID128_REFUSE_NULL flag
 * and accepts either format; both callers here refuse null and want exactly
 * one format, hence the bool.
 *
 * Returns 0, or:
 *   -ENOMEDIUM  empty file, or a well-formed but all-zero id
 *   -ENOPKG     content is literally "uninitialized" or "uninitialized\n"
 *   -EUCLEAN    wrong length, wrong format (dashed where plain was wanted
 *               or vice versa), or any other unparseable content
 *   -errno      a real read(2) failure
 */
int id128_read_fd(int fd, bool uuid_format, sd_id128_t *ret);

/* RFC 4122 v4 bit fixup (upstream's id128_make_v4_uuid()), shared by
 * sd_id128_randomize() and the sd_id128_get_*_app_specific() functions:
 * forces the version nibble to 4 and the variant bits to DCE. */
sd_id128_t id128_make_v4_uuid(sd_id128_t id);
