/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netd's main(). Nothing else lives here on purpose: meson.build's netd_exe
 * links this file directly, on top of netd_core, and netd_core is also what
 * every netd test executable links -- so anything a test needs to call
 * (netd_new(), netd_startup(), the setters, netd_free()) has to be defined
 * somewhere netd_core actually reaches, never in this file. That logic
 * lives in netd-loop.c now; see that file's header for the full reasoning.
 * This mirrors PID 1's own main.c/manager.c split for the same reason.
 */

#include "netd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../util.h"

int main(int argc, char *argv[]) {
        Netd *n = NULL;
        int r;

        (void) argc;
        (void) argv;

        r = netd_new(&n);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "netd: failed to allocate: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        r = netd_startup(n);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "netd: startup failed: %s", strerror(-r));
                netd_free(n);
                return EXIT_FAILURE;
        }

        r = netd_loop_run(n);
        netd_free(n);

        if (r < 0) {
                pico_log(PICO_LOG_ERR, "netd: event loop failed: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
