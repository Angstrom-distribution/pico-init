/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * devd's main(). Nothing else lives here, for the reason netd.c gives for
 * itself and main.c gives for PID 1: meson.build links devd-core into every
 * devd test binary and never links this file, so anything a test needs to call
 * has to be defined somewhere devd-core reaches. That is devd-loop.c.
 */

#include "devd.h"

#include <stdlib.h>
#include <string.h>

#include "../util.h"

int main(int argc, char *argv[]) {
        Devd *d = NULL;
        int r;

        (void) argc;
        (void) argv;

        r = devd_new(&d);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "devd: failed to allocate: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        r = devd_startup(d);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "devd: startup failed: %s", strerror(-r));
                devd_free(d);
                return EXIT_FAILURE;
        }

        r = devd_loop_run(d);
        devd_free(d);

        if (r < 0) {
                pico_log(PICO_LOG_ERR, "devd: event loop failed: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
