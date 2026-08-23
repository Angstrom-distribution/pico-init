/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The /dev/kmsg reader, with whole-ring backfill (plan §3.2).
 *
 * Scaffolding: milestone J2 owns this file and lands the real body. It is
 * registered in the build now so that milestone adds code to a file that
 * already exists and is already compiled, rather than editing meson.build
 * while another milestone is also editing it.
 */

#include <errno.h>

#include "logd-kmsg.h"

int logd_kmsg_not_implemented(void) {
        return -ENOSYS;
}
