/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netd's main(). Everything a test needs to call lives in netd-loop.c, which
 * netd_core links; this file is linked only into the netd executable.
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
