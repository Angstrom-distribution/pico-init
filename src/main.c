/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * PID1 entrypoint. Real init behaviour only kicks in when actually running
 * as PID 1, so the binary still builds, runs and exits cleanly from a
 * normal shell (see src/test-m0.sh). M0: manager_load_units() only
 * populates the unit table, nothing is started yet.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <unistd.h>

#include "manager.h"
#include "util.h"

int main(void) {
        if (getpid() != 1) {
                puts("pico-init: not running as PID 1, exiting");
                return EXIT_SUCCESS;
        }

        Manager *m = NULL;
        int r = manager_new(&m);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "manager_new: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        r = manager_load_units(m, NULL);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "manager_load_units: %s", strerror(-r));

        int objective = manager_loop(m);
        m = manager_free(m);

        if (objective < 0) {
                pico_log(PICO_LOG_ERR, "manager_loop: %s", strerror(-objective));
                return EXIT_FAILURE;
        }

        switch ((ManagerObjective) objective) {
        case MANAGER_REBOOT:
                sync();
                reboot(RB_AUTOBOOT);
                break;
        case MANAGER_POWEROFF:
                sync();
                reboot(RB_POWER_OFF);
                break;
        case MANAGER_EXIT:
        default:
                break;
        }

        return EXIT_SUCCESS;
}
