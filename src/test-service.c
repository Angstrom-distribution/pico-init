/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Placeholder for M3's acceptance test: the service state machine (lifecycle, timeout, restart).
 *
 * Registered in meson.build already so the milestone's implementer only has
 * to fill this in -- adding a test must never mean editing the build file
 * that every other in-flight milestone is also editing.
 */

#include <stdio.h>

#include "test-util.h"

int main(void) {
        /* TODO (M3): replace with the real acceptance test. */
        printf("test-service: placeholder, M3 not implemented yet\n");
        return 0;
}
