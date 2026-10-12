/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-tmpfiles's main(): systemd-tmpfiles(8)'s command line, the subset
 * pico-tmpfiles.service and a person at a shell actually use. meson links
 * this file into the binary alone and tmpfiles-core into every test, so
 * anything a test needs has to be defined in the core.
 *
 * --purge, --dry-run, --user, --image and --image-policy are refused rather
 * than silently accepted as a no-op: a script passing them expects an effect
 * this binary does not have. --no-pager is accepted, as there is no pager.
 */

#include "tmpfiles.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../util.h"

#define COMMENT_CHARS "#;"

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
               "     --cat-config           Show configuration files\n"
               "     --tldr                 Show non-comment parts of configuration files\n"
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
               "     --replace=PATH         Treat arguments as replacement for PATH\n"
               "     --inline               Treat arguments as configuration lines\n"
               "     --no-pager             Accepted and ignored, there is no pager\n"
               "\n"
               "--purge, -n/--dry-run, --user, --image and --image-policy are not implemented.\n");
}

static int refuse(const char *what) {
        pico_log(PICO_LOG_ERR, "pico-tmpfiles: %s is not implemented", what);
        return EXIT_FAILURE;
}

/* Same output as systemd's cat_file() without colour or hyperlinks. */
static int cat_config(PicoTmpfiles *t, bool tldr) {
        char **files = NULL, **f;
        bool newline = false;
        int r, ret = EXIT_SUCCESS;

        r = pico_tmpfiles_list_config_files(t, &files);
        if (r < 0)
                return EXIT_FAILURE;

        for (f = files; *f; f++) {
                char *line = NULL;
                size_t cap = 0;
                ssize_t n;
                FILE *fp = fopen(*f, "re");

                if (!fp) {
                        pico_log(PICO_LOG_ERR, "pico-tmpfiles: failed to open '%s': %s", *f, strerror(errno));
                        ret = EXIT_FAILURE;
                        continue;
                }

                if (newline)
                        putchar('\n');
                newline = true;
                printf("# %s\n", *f);

                while ((n = getline(&line, &cap, fp)) >= 0) {
                        const char *l = line;

                        if (n > 0 && line[n - 1] == '\n')
                                line[--n] = '\0';

                        while (*l == ' ' || *l == '\t')
                                l++;

                        if (tldr && (*l == '\0' || strchr(COMMENT_CHARS, *l) || strcmp(l, "\\") == 0))
                                continue;

                        printf("%s\n", line);
                }

                free(line);
                fclose(fp);
        }

        pico_strv_free(files);
        return ret;
}

static const char *base_name(const char *path) {
        const char *b = strrchr(path, '/');

        return b ? b + 1 : path;
}

/* Feed one argument to the parser: a configuration line, or a file found by
 * path or, for a bare name, through the precedence walk. 0, -ENOMEM, or -1
 * once it has been logged as fatal. */
static int apply_arg(PicoTmpfiles *t, char **all, const char *arg, unsigned pos, bool inline_) {
        const char *chosen = NULL;
        char **f;
        int r;

        if (inline_) {
                while (*arg == ' ' || *arg == '\t')
                        arg++;
                r = pico_tmpfiles_parse_line(t, "(argument)", pos, arg);
                return r == -ENOMEM ? r : 0;
        }

        if (strchr(arg, '/'))
                chosen = arg;
        else
                for (f = all; *f; f++)
                        if (strcmp(base_name(*f), arg) == 0) {
                                chosen = *f;
                                break;
                        }

        if (!chosen) {
                pico_log(PICO_LOG_ERR, "pico-tmpfiles: failed to find '%s'", arg);
                return -1;
        }

        r = pico_tmpfiles_read_file(t, chosen);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "pico-tmpfiles: failed to read '%s': %s", chosen, strerror(-r));
                return -1;
        }
        return 0;
}

/* Index into PICO_TMPFILES_CONF_DIRS of the directory holding `path`, -1 if none. */
static int conf_dir_index(PicoTmpfiles *t, const char *path) {
        static const char * const dirs[] = { PICO_TMPFILES_CONF_DIRS };
        size_t k, rl = t->root ? strlen(t->root) : 0;

        for (k = 0; k < sizeof(dirs) / sizeof(dirs[0]); k++) {
                size_t dl = strlen(dirs[k]);

                if (rl > 0 && strncmp(path, t->root, rl) != 0)
                        continue;
                if (strncmp(path + rl, dirs[k], dl) == 0 && path[rl + dl] == '/' &&
                    strchr(path + rl + dl + 1, '/') == NULL)
                        return (int) k;
        }
        return -1;
}

/* --replace=: the arguments take the place of PATH in the sorted walk over all
 * files. A same-named file in a directory searched earlier still wins, as in
 * systemd's conf_files_list_with_replacement(). */
static int read_replaced(PicoTmpfiles *t, char **all, const char *replace, int argc, char **argv, bool inline_) {
        const char *base = base_name(replace);
        char *rooted = NULL;
        bool skip = false, done = false;
        int rd, r, k;
        char **f;

        r = asprintf(&rooted, "%s%s", t->root ? t->root : "", replace);
        if (r < 0)
                return -ENOMEM;
        rd = conf_dir_index(t, rooted);
        free(rooted);
        if (rd < 0) {
                pico_log(PICO_LOG_ERR, "pico-tmpfiles: --replace= must name a file in a tmpfiles.d directory");
                return -1;
        }

        for (f = all; *f; f++)
                if (strcmp(base_name(*f), base) == 0 && conf_dir_index(t, *f) < rd)
                        skip = true;

        for (f = all;; f++) {
                bool end = !*f;

                if (!skip && !done && (end || strcmp(base_name(*f), base) >= 0)) {
                        for (k = 0; k < argc; k++) {
                                r = apply_arg(t, all, argv[k], (unsigned) k + 1, inline_);
                                if (r < 0)
                                        return r;
                        }
                        done = true;
                }
                if (end)
                        break;
                if (!skip && strcmp(base_name(*f), base) == 0)
                        continue;

                r = pico_tmpfiles_read_file(t, *f);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING, "failed to read %s: %s", *f, strerror(-r));
        }
        return 0;
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
                ARG_CAT_CONFIG,
                ARG_TLDR,
                ARG_REPLACE,
                ARG_INLINE,
                ARG_NO_PAGER,
                ARG_DRY_RUN,
                ARG_USER,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
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
                {     "cat-config",       no_argument, NULL,     ARG_CAT_CONFIG },
                {           "tldr",       no_argument, NULL,           ARG_TLDR },
                {        "replace", required_argument, NULL,        ARG_REPLACE },
                {         "inline",       no_argument, NULL,         ARG_INLINE },
                {       "no-pager",       no_argument, NULL,       ARG_NO_PAGER },
                {        "dry-run",       no_argument, NULL,        ARG_DRY_RUN },
                {           "user",       no_argument, NULL,           ARG_USER },
                {          "image", required_argument, NULL,          ARG_IMAGE },
                {   "image-policy", required_argument, NULL,   ARG_IMAGE_POLICY },
                {             NULL,                 0, NULL,                  0 },
        };
        PicoTmpfiles *t = NULL;
        bool create = false, cat = false, tldr = false, inline_ = false;
        const char *replace = NULL;
        unsigned cleanup = 0;
        int c, r, q, ret = EXIT_FAILURE;

        r = pico_tmpfiles_new(&t);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "pico-tmpfiles: failed to allocate: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        while ((c = getopt_long(argc, argv, "hEn", options, NULL)) >= 0) {
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
                        ret = refuse("--purge");
                        goto finish;

                case 'n':
                case ARG_DRY_RUN:
                        ret = refuse("--dry-run");
                        goto finish;

                case ARG_USER:
                        ret = refuse("--user");
                        goto finish;

                case ARG_IMAGE:
                        ret = refuse("--image");
                        goto finish;

                case ARG_IMAGE_POLICY:
                        ret = refuse("--image-policy");
                        goto finish;

                case ARG_CAT_CONFIG:
                        cat = true;
                        break;

                case ARG_TLDR:
                        cat = tldr = true;
                        break;

                case ARG_REPLACE:
                        if (optarg[0] != '/') {
                                pico_log(PICO_LOG_ERR,
                                         "pico-tmpfiles: the argument to --replace= must be an absolute path");
                                goto finish;
                        }
                        r = (int) strlen(optarg);
                        if (r < 5 || strcmp(optarg + r - 5, ".conf") != 0) {
                                pico_log(PICO_LOG_ERR,
                                         "pico-tmpfiles: the argument to --replace= must have the extension '.conf'");
                                goto finish;
                        }
                        replace = optarg;
                        break;

                case ARG_INLINE:
                        inline_ = true;
                        break;

                case ARG_NO_PAGER:
                        break;

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

        if (!create && cleanup == 0 && !cat) {
                pico_log(PICO_LOG_ERR,
                         "pico-tmpfiles: you need to specify at least one of --clean, --create, --remove, "
                         "or --purge");
                goto finish;
        }

        if (cat && replace) {
                pico_log(PICO_LOG_ERR, "pico-tmpfiles: --replace= is not supported with --cat-config/--tldr");
                goto finish;
        }

        if (cat && inline_) {
                pico_log(PICO_LOG_ERR, "pico-tmpfiles: --inline is not supported with --cat-config/--tldr");
                goto finish;
        }

        if (replace && optind >= argc) {
                pico_log(PICO_LOG_ERR,
                         "pico-tmpfiles: when --replace= is given, some configuration items must be specified");
                goto finish;
        }

        if (cat) {
                ret = cat_config(t, tldr);
                goto finish;
        }

        if (optind < argc || replace) {
                /* named files or lines only, as upstream */
                char **all = NULL;
                int k;

                r = pico_tmpfiles_list_config_files(t, &all);
                if (r < 0)
                        goto oom;

                if (replace)
                        r = read_replaced(t, all, replace, argc - optind, argv + optind, inline_);
                else {
                        r = 0;
                        for (k = optind; r >= 0 && k < argc; k++)
                                r = apply_arg(t, all, argv[k], (unsigned) (k - optind) + 1, inline_);
                }
                pico_strv_free(all);
                if (r == -ENOMEM)
                        goto oom;
                if (r < 0)
                        goto finish;
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
