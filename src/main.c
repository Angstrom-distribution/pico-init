/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * pico-init: a small systemd-inspired PID1 for angstrom-pico
 * (~64MiB RAM ARMv5TE targets). Scaffold only -- see this repository's
 * README for the current status and the angstrom-pico project's TODO for
 * the real scoping decisions. No PID1 logic exists yet.
 */

#include <stdio.h>

int main(void) {
        puts("pico-init: scaffold, not a real init system yet");
        return 0;
}
