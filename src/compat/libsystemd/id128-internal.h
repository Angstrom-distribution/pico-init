/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd-id128.c's own internals, exposed here only so test-sd-id128.c can
 * drive every branch of the machine-id/boot-id wire-format reader through a
 * memfd -- never through the real /etc/machine-id or /proc/sys/kernel/
 * random/boot_id, which a test cannot control the contents of. Neither
 * declaration below is part of the public sd_id128 ABI in sd-id128.h.
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
 * Real upstream's id128_read_fd() (id128-util.c) also takes an
 * ID128_REFUSE_NULL flag and accepts either format unconditionally; this
 * shim's two callers always want refuse-null, so that flag isn't
 * threaded through, and each caller wants exactly one format, so
 * uuid_format is a bool rather than a bitmask.
 *
 * Returns 0, or:
 *   -ENOMEDIUM  empty file, or a well-formed but all-zero id
 *   -ENOPKG     content is literally "uninitialized" or "uninitialized\n"
 *   -EUCLEAN    wrong length, wrong format (dashed where plain was wanted
 *               or vice versa), or any other unparseable content
 *   -errno      a real read(2) failure
 */
int id128_read_fd(int fd, bool uuid_format, sd_id128_t *ret);

/* RFC-4122 v4 bit fixup, shared by sd_id128_randomize() and every
 * sd_id128_get_*_app_specific() (id128_make_v4_uuid() in real upstream's
 * id128-util.c): forces the version nibble to 4 and the variant bits to
 * DCE, "to be nice", per that function's own upstream comment. */
sd_id128_t id128_make_v4_uuid(sd_id128_t id);
