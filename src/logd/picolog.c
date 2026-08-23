/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * picolog -- the on-device log reader (plan §3.4), the journalctl half of the
 * owner's on-device-tooling requirement.
 *
 * Scaffolding: milestone J3 owns this file. Named to avoid colliding with
 * BusyBox `logread`. It needs nothing from the daemon -- it reads the files --
 * and its reader lives in logd-read.c so picoctl can reuse it.
 *
 * -b needs no flag: a /run ring only ever holds the current boot.
 */

#include <stdio.h>

int main(int argc, char *argv[]) {
        (void) argc;
        (void) argv;

        fputs("picolog: not implemented yet (plan §3.4, milestone J3)\n", stderr);
        return 1;
}
