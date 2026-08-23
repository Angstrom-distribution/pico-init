/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The export-format writer and the /run ring (plan §3.3).
 *
 * Scaffolding: milestone J0 owns this file and lands the real body. It is
 * registered in the build now so that milestone adds code to a file that
 * already exists and is already compiled, rather than editing meson.build
 * while another milestone is also editing it.
 */

#include <errno.h>

#include "logd-write.h"

int logd_write_not_implemented(void) {
        return -ENOSYS;
}
