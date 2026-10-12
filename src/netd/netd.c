/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netd's main(). Everything a test needs to call lives in netd-loop.c, which
 * netd_core links; this file is linked only into the netd executable.
 */

#include "netd.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../util.h"

/*
 * systemd-networkd v262 takes --help, --version and --bus-introspect=PATH and
 * rejects any other argument. There is no bus, so the introspection dump is
 * refused rather than answered with nothing.
 */
static void netd_usage(void) {
        puts("netd [OPTIONS...]\n"
             "\n"
             "Network manager.\n"
             "\n"
             "  -h --help      Show this help\n"
             "     --version   Show version");
}

/* 0 to run, 1 when --help or --version was all there was to do, -EINVAL otherwise. */
static int netd_parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_BUS_INTROSPECT,
        };
        static const struct option options[] = {
                {           "help",       no_argument, NULL,                'h' },
                {        "version",       no_argument, NULL,        ARG_VERSION },
                { "bus-introspect", required_argument, NULL, ARG_BUS_INTROSPECT },
                {             NULL,                 0, NULL,                  0 },
        };
        int c;

        optind = 0;
        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        netd_usage();
                        return 1;

                case ARG_VERSION:
                        puts("netd " PICO_INIT_VERSION);
                        return 1;

                case ARG_BUS_INTROSPECT:
                        pico_log(PICO_LOG_ERR, "netd: --bus-introspect is not supported, there is no bus");
                        return -EINVAL;

                default:
                        return -EINVAL;
                }
        }

        if (optind < argc) {
                pico_log(PICO_LOG_ERR, "netd: this program takes no arguments");
                return -EINVAL;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        Netd *n = NULL;
        int r;

        r = netd_parse_argv(argc, argv);
        if (r < 0)
                return EXIT_FAILURE;
        if (r > 0)
                return EXIT_SUCCESS;

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
