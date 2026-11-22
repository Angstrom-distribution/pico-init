/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-modules-load's main(): what systemd-modules-load does for
 * systemd-modules-load.service. Exits 1 when modprobe refused a module, so
 * the unit shows as failed; boot does not wait on it. systemd leaves a module
 * the kernel does not have out of that count; modprobe's exit status does not
 * tell the two apart.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../util.h"
#include "modules-load.h"

int main(int argc, char *argv[]) {
        const PicoModulesLoad c = {
                .dirs = pico_modules_load_dirs,
                .cmdline = "/proc/cmdline",
                .modprobe = PICO_MODULES_LOAD_MODPROBE,
        };
        size_t n = 0, failed = 0;
        int r;

        if (argc > 1) {
                fprintf(stderr, "Usage: pico-modules-load\n");
                return strcmp(argv[1], "--help") == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        }

        r = pico_modules_load_run(&c, &n, &failed);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "modules-load: %s", strerror(-r));
                return EXIT_FAILURE;
        }
        if (failed > 0) {
                pico_log(PICO_LOG_WARNING, "modules-load: %zu of %zu modules failed to load", failed, n);
                return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}
