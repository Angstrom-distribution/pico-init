/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Placeholder for M2's acceptance test: boot rooting (.wants/.requires dirs, presets, default.target).
 *
 * Registered in meson.build already so the milestone's implementer only has
 * to fill this in -- adding a test must never mean editing the build file
 * that every other in-flight milestone is also editing.
 */

#include <stdio.h>

#include "test-util.h"

int main(void) {
        /* TODO (M2): replace with the real acceptance test. */
        printf("test-boot-root: placeholder, M2 not implemented yet\n");
        return 0;
}
