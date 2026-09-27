/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-tmpfiles's main(): systemd-tmpfiles(8)'s command line, the subset
 * pico-tmpfiles.service and a person at a shell actually use. Nothing else
 * lives here, for the reason netd.c and devd.c give: meson links this file
 * into the binary alone, and tmpfiles-core into every test, so anything a
 * test needs has to be defined in the core.
 *
 * --purge is refused rather than silently accepted: it has no consumer in
 * these images, and a flag that "works" by doing nothing is exactly the
 * silent degradation the rest of pico-init exists to avoid.
 */

#include "tmpfiles.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../util.h"

static void help(void) {
        printf("Usage: pico-tmpfiles [OPTIONS...] [CONFIGURATION FILE...]\n"
               "\n"
               "Create, delete, and clean up files and directories from tmpfiles.d(5)\n"
               "configuration.\n"
               "\n"
               "Commands:\n"
               "     --create               Create and adjust files and directories\n"
               "     --clean                Clean up files and directories\n"
               "     --remove               Remove files and directories marked for removal\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "\n"
               "Options:\n"
               "     --boot                 Execute actions only safe at boot\n"
               "     --graceful             Quietly ignore unknown users or groups\n"
               "     --prefix=PATH          Only apply rules with the specified prefix\n"
               "     --exclude-prefix=PATH  Ignore rules with the specified prefix\n"
               "  -E                        Ignore rules prefixed with /dev, /proc, /run, /sys\n"
               "     --root=PATH            Operate on an alternate filesystem root\n"
               "\n"
               "--purge is not implemented.\n");
}

int main(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_CREATE,
                ARG_CLEAN,
                ARG_REMOVE,
                ARG_PURGE,
                ARG_BOOT,
                ARG_GRACEFUL,
                ARG_PREFIX,
                ARG_EXCLUDE_PREFIX,
                ARG_ROOT,
        };
        static const struct option options[] = {
                {           "help",       no_argument, NULL,                'h' },
                {        "version",       no_argument, NULL,        ARG_VERSION },
                {         "create",       no_argument, NULL,         ARG_CREATE },
                {          "clean",       no_argument, NULL,          ARG_CLEAN },
                {         "remove",       no_argument, NULL,         ARG_REMOVE },
                {          "purge",       no_argument, NULL,          ARG_PURGE },
                {           "boot",       no_argument, NULL,           ARG_BOOT },
                {       "graceful",       no_argument, NULL,       ARG_GRACEFUL },
                {         "prefix", required_argument, NULL,         ARG_PREFIX },
                { "exclude-prefix", required_argument, NULL, ARG_EXCLUDE_PREFIX },
                {           "root", required_argument, NULL,           ARG_ROOT },
                {             NULL,                 0, NULL,                  0 },
        };
        PicoTmpfiles *t = NULL;
        bool create = false;
        unsigned cleanup = 0;
        int c, r, q, ret = EXIT_FAILURE;

        r = pico_tmpfiles_new(&t);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "pico-tmpfiles: failed to allocate: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        while ((c = getopt_long(argc, argv, "hE", options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        help();
                        ret = EXIT_SUCCESS;
                        goto finish;

                case ARG_VERSION:
                        printf("pico-tmpfiles %s\n", PICO_INIT_VERSION);
                        ret = EXIT_SUCCESS;
                        goto finish;

                case ARG_CREATE:
                        create = true;
                        break;

                case ARG_CLEAN:
                        cleanup |= PICO_TMPFILES_CLEAN;
                        break;

                case ARG_REMOVE:
                        cleanup |= PICO_TMPFILES_REMOVE;
                        break;

                case ARG_PURGE:
                        pico_log(PICO_LOG_ERR, "pico-tmpfiles: --purge is not implemented");
                        goto finish;

                case ARG_BOOT:
                        t->boot = true;
                        break;

                case ARG_GRACEFUL:
                        t->graceful = true;
                        break;

                case ARG_PREFIX:
                        r = pico_tmpfiles_add_prefix(t, optarg);
                        if (r < 0)
                                goto oom;
                        break;

                case ARG_EXCLUDE_PREFIX:
                        r = pico_tmpfiles_add_exclude_prefix(t, optarg);
                        if (r < 0)
                                goto oom;
                        break;

                case 'E': {
                        static const char * const defaults[] = { "/dev", "/proc", "/run", "/sys" };
                        size_t k;

                        for (k = 0; k < sizeof(defaults) / sizeof(defaults[0]); k++) {
                                r = pico_tmpfiles_add_exclude_prefix(t, defaults[k]);
                                if (r < 0)
                                        goto oom;
                        }
                        break;
                }

                case ARG_ROOT:
                        r = pico_tmpfiles_set_root(t, optarg);
                        if (r == -EINVAL) {
                                pico_log(PICO_LOG_ERR, "pico-tmpfiles: --root must be an absolute path");
                                goto finish;
                        }
                        if (r < 0)
                                goto oom;
                        break;

                case '?':
                        goto finish;

                default:
                        pico_log(PICO_LOG_ERR, "pico-tmpfiles: unhandled option");
                        goto finish;
                }
        }

        if (!create && cleanup == 0) {
                pico_log(PICO_LOG_ERR,
                         "pico-tmpfiles: you need to specify at least one of --clean, --create, --remove");
                goto finish;
        }

        if (optind < argc) {
                /* named files only, as upstream: a path is read as is, a bare
                 * name is found through the same precedence walk */
                char **all = NULL;
                int k;

                r = pico_tmpfiles_list_config_files(t, &all);
                if (r < 0)
                        goto oom;

                for (k = optind; k < argc; k++) {
                        const char *arg = argv[k];
                        const char *chosen = NULL;
                        char **f;

                        if (strchr(arg, '/'))
                                chosen = arg;
                        else
                                for (f = all; *f; f++) {
                                        const char *bn = strrchr(*f, '/');

                                        if (bn && strcmp(bn + 1, arg) == 0) {
                                                chosen = *f;
                                                break;
                                        }
                                }

                        if (!chosen) {
                                pico_log(PICO_LOG_ERR, "pico-tmpfiles: failed to find '%s'", arg);
                                pico_strv_free(all);
                                goto finish;
                        }

                        r = pico_tmpfiles_read_file(t, chosen);
                        if (r < 0) {
                                pico_log(PICO_LOG_ERR,
                                         "pico-tmpfiles: failed to read '%s': %s",
                                         chosen,
                                         strerror(-r));
                                pico_strv_free(all);
                                goto finish;
                        }
                }
                pico_strv_free(all);
        } else {
                r = pico_tmpfiles_read_config(t);
                if (r < 0)
                        goto oom;
        }

        /* upstream's phase order: clear the ground first, then build on it */
        r = pico_tmpfiles_remove_and_clean(t, cleanup);
        if (create) {
                q = pico_tmpfiles_create(t);
                if (r >= 0)
                        r = q;
        }
        if (r == -ENOMEM)
                goto oom;

        /* systemd-tmpfiles's own exit codes, so a unit's SuccessExitStatus=
         * written for it reads the same here */
        if (t->invalid_config)
                ret = PICO_TMPFILES_EX_DATAERR;
        else if (r < 0)
                ret = PICO_TMPFILES_EX_CANTCREAT;
        else
                ret = EXIT_SUCCESS;
        goto finish;

oom:
        pico_log(PICO_LOG_ERR, "pico-tmpfiles: out of memory");
        ret = EXIT_FAILURE;

finish:
        pico_tmpfiles_free(t);
        return ret;
}
