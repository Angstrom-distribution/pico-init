/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-unit-lint: run PID 1's own unit-file parser over an installed unit
 * tree and report what it would drop, without booting anything.
 *
 * The parser is the real one -- unit-load.c/unit-parse.c out of
 * pico-init-core -- so what this prints is exactly the degradation record a
 * booted pico-init would put in `picoctl show`. That is the point: a
 * compatibility gap shows up in a build log, per unit and per directive,
 * before anyone flashes a board.
 *
 * Templates are linted too. The manager's boot scan skips "foo@.service" on
 * purpose (it only loads under an instance name), so each template in the
 * tree is loaded here as "foo@lint.service" and reported under the template's
 * own name.
 *
 * Output, one line per finding, then one summary line:
 *   <unit>: <n> dropped: <directive> [<directive> ...]
 *   <unit>: FAILED TO LOAD
 *   pico-unit-lint: <n> units in tree, <d> degraded (<k> directives dropped), <f> failed to load
 *
 * Exit status: 0 with no findings, 1 with any (unless --warn-only), 2 when
 * the tree could not be scanned at all.
 *
 * The options of `systemd-analyze verify` that make sense for a directory
 * lint are accepted: -q, --root=, --instance=, --system, --no-pager, and
 * --recursive-errors=, --man, --generators as no-ops (only units in the tree
 * are reported, no man page is checked, no generator runs). --user, --global,
 * --image and --image-policy would change what is verified and are refused.
 */

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "manager.h"
#include "unit-name.h"
#include "unit.h"
#include "util.h"

#define LINT_INSTANCE "lint"

static const char *instance_name = LINT_INSTANCE;

static void usage(FILE *out) {
        fprintf(out,
                "usage: pico-unit-lint [OPTIONS...] DIR...\n"
                "\n"
                "Parse every unit file under each DIR with pico-init's own parser and\n"
                "report the directives it would drop and the units it would fail to load.\n"
                "\n"
                "  -h --help               show this help\n"
                "     --version            show package version\n"
                "     --warn-only          exit 0 even when there are findings\n"
                "     --verbose            also list units pico-init honours in full\n"
                "  -q --quiet              omit the summary line\n"
                "     --root=PATH          resolve each DIR below PATH\n"
                "     --instance=NAME      instance name templates are loaded as (default \"" LINT_INSTANCE
                "\")\n"
                "     --system             accepted, the only mode\n"
                "     --no-pager           accepted, there is no pager\n"
                "     --recursive-errors=MODE  accepted and ignored: yes, no, one\n"
                "     --man[=BOOL]         accepted and ignored: man pages are not checked\n"
                "     --generators[=BOOL]  accepted and ignored: generators are not run\n"
                "\n"
                "--user, --global, --image and --image-policy are not implemented.\n");
}

static int parse_bool(const char *s) {
        static const char * const yes[] = { "1", "yes", "y", "true", "t", "on" };
        static const char * const no[] = { "0", "no", "n", "false", "f", "off" };
        size_t k;

        for (k = 0; k < 6; k++) {
                if (strcasecmp(s, yes[k]) == 0)
                        return 1;
                if (strcasecmp(s, no[k]) == 0)
                        return 0;
        }
        return -EINVAL;
}

/* Load every template in `dir` under a fixed instance name so it gets parsed. */
static int load_templates(Manager *m, const char *dir) {
        struct dirent *de;
        DIR *d;

        d = opendir(dir);
        if (!d)
                return -errno;

        while ((de = readdir(d))) {
                char instance[UNIT_NAME_MAX + 1];
                const char *at, *dot;
                int n;

                if (!unit_name_is_valid(de->d_name) || !unit_name_is_template(de->d_name))
                        continue;

                at = strchr(de->d_name, '@');
                dot = strrchr(de->d_name, '.');
                n = snprintf(instance,
                             sizeof(instance),
                             "%.*s@%s%s",
                             (int) (at - de->d_name),
                             de->d_name,
                             instance_name,
                             dot);
                if (n < 0 || (size_t) n >= sizeof(instance))
                        continue;

                (void) manager_load_unit(m, instance, NULL);
        }

        closedir(d);
        return 0;
}

/* Whether `id` (or the template it instantiates) is a file in one of the
 * scanned directories, as opposed to a name another unit merely referenced. */
static bool in_tree(char **dirs, const char *id) {
        char *tmpl;
        size_t i;

        for (i = 0; dirs[i]; i++) {
                char path[4096];
                int n;

                n = snprintf(path, sizeof(path), "%s/%s", dirs[i], id);
                if (n > 0 && (size_t) n < sizeof(path) && access(path, F_OK) == 0)
                        return true;
        }

        tmpl = unit_name_template(id);
        if (!tmpl)
                return false;

        for (i = 0; dirs[i]; i++) {
                char path[4096];
                int n;

                n = snprintf(path, sizeof(path), "%s/%s", dirs[i], tmpl);
                if (n > 0 && (size_t) n < sizeof(path) && access(path, F_OK) == 0) {
                        free(tmpl);
                        return true;
                }
        }

        free(tmpl);
        return false;
}

/* The name to report: the template's own for an instance this tool created. */
static char *display_name(Unit *u) {
        if (u->instance && strcmp(u->instance, instance_name) == 0)
                return unit_name_template(u->id);

        return pico_strdup(u->id);
}

static int unit_id_cmp(const void *a, const void *b) {
        return strcmp((*(Unit * const *) a)->id, (*(Unit * const *) b)->id);
}

int main(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_WARN_ONLY,
                ARG_VERBOSE,
                ARG_ROOT,
                ARG_INSTANCE,
                ARG_SYSTEM,
                ARG_NO_PAGER,
                ARG_RECURSIVE_ERRORS,
                ARG_MAN,
                ARG_GENERATORS,
                ARG_USER,
                ARG_GLOBAL,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
        };
        static const struct option options[] = {
                {             "help",       no_argument, NULL,                  'h' },
                {          "version",       no_argument, NULL,          ARG_VERSION },
                {        "warn-only",       no_argument, NULL,        ARG_WARN_ONLY },
                {          "verbose",       no_argument, NULL,          ARG_VERBOSE },
                {            "quiet",       no_argument, NULL,                  'q' },
                {             "root", required_argument, NULL,             ARG_ROOT },
                {         "instance", required_argument, NULL,         ARG_INSTANCE },
                {           "system",       no_argument, NULL,           ARG_SYSTEM },
                {         "no-pager",       no_argument, NULL,         ARG_NO_PAGER },
                { "recursive-errors", required_argument, NULL, ARG_RECURSIVE_ERRORS },
                {              "man", optional_argument, NULL,              ARG_MAN },
                {       "generators", optional_argument, NULL,       ARG_GENERATORS },
                {             "user",       no_argument, NULL,             ARG_USER },
                {           "global",       no_argument, NULL,           ARG_GLOBAL },
                {            "image", required_argument, NULL,            ARG_IMAGE },
                {     "image-policy", required_argument, NULL,     ARG_IMAGE_POLICY },
                {               NULL,                 0, NULL,                    0 },
        };
        bool warn_only = false, verbose = false, quiet = false;
        const char *root = NULL;
        int c;
        size_t n_tree = 0, n_degraded = 0, n_directives = 0, n_failed = 0;
        char **dirs = NULL;
        Manager *m = NULL;
        Unit **units;
        size_t i;
        int r;

        while ((c = getopt_long(argc, argv, "hq", options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        usage(stdout);
                        return 0;
                case ARG_VERSION:
                        printf("pico-unit-lint %s\n", PICO_INIT_VERSION);
                        return 0;
                case ARG_WARN_ONLY:
                        warn_only = true;
                        break;
                case ARG_VERBOSE:
                        verbose = true;
                        break;
                case 'q':
                        quiet = true;
                        break;
                case ARG_ROOT:
                        root = optarg;
                        break;
                case ARG_INSTANCE: {
                        char probe[UNIT_NAME_MAX + 1];

                        if (snprintf(probe, sizeof(probe), "x@%s.service", optarg) >= (int) sizeof(probe) ||
                            !unit_name_is_valid(probe)) {
                                fprintf(stderr, "pico-unit-lint: invalid instance name '%s'\n", optarg);
                                return 2;
                        }
                        instance_name = optarg;
                        break;
                }
                case ARG_SYSTEM:
                case ARG_NO_PAGER:
                        break;
                case ARG_RECURSIVE_ERRORS:
                        if (strcmp(optarg, "help") == 0) {
                                printf("yes\nno\none\n");
                                return 0;
                        }
                        if (strcmp(optarg, "yes") != 0 && strcmp(optarg, "no") != 0 &&
                            strcmp(optarg, "one") != 0) {
                                fprintf(stderr,
                                        "pico-unit-lint: unknown mode '%s' for --recursive-errors=\n",
                                        optarg);
                                return 2;
                        }
                        break;
                case ARG_MAN:
                case ARG_GENERATORS:
                        if (optarg && parse_bool(optarg) < 0) {
                                fprintf(stderr, "pico-unit-lint: failed to parse boolean '%s'\n", optarg);
                                return 2;
                        }
                        break;
                case ARG_USER:
                case ARG_GLOBAL:
                case ARG_IMAGE:
                case ARG_IMAGE_POLICY:
                        fprintf(stderr, "pico-unit-lint: %s is not implemented\n", argv[optind - 1]);
                        return 2;
                default:
                        usage(stderr);
                        return 2;
                }
        }

        for (i = (size_t) optind; i < (size_t) argc; i++) {
                if (root) {
                        char *joined = NULL;

                        if (asprintf(&joined, "%s/%s", root, argv[i]) < 0)
                                return 2;
                        r = pico_strv_extend(&dirs, joined);
                        free(joined);
                } else
                        r = pico_strv_extend(&dirs, argv[i]);
                if (r < 0)
                        return 2;
        }

        if (!dirs) {
                usage(stderr);
                return 2;
        }

        for (i = 0; dirs[i]; i++)
                if (access(dirs[i], R_OK | X_OK) < 0) {
                        fprintf(stderr, "pico-unit-lint: %s: %s\n", dirs[i], strerror(errno));
                        return 2;
                }

        r = manager_new(&m);
        if (r < 0) {
                fprintf(stderr, "pico-unit-lint: manager_new: %s\n", strerror(-r));
                return 2;
        }

        r = manager_set_unit_path(m, (const char * const *) dirs);
        if (r < 0) {
                fprintf(stderr, "pico-unit-lint: setting unit path: %s\n", strerror(-r));
                return 2;
        }

        /* A bad directory is fatal; a bad unit file is a finding, so
         * manager_load_units()'s first-error return is not
         * treated as one. */
        (void) manager_load_units(m, NULL);
        for (i = 0; dirs[i]; i++)
                (void) load_templates(m, dirs[i]);

        units = calloc(m->n_units ? m->n_units : 1, sizeof(Unit *));
        if (!units)
                return 2;
        memcpy(units, m->units, m->n_units * sizeof(Unit *));
        qsort(units, m->n_units, sizeof(Unit *), unit_id_cmp);

        for (i = 0; i < m->n_units; i++) {
                Unit *u = units[i];
                char *name;

                if (!in_tree(dirs, u->id))
                        continue; /* referenced from the tree, not part of it */

                n_tree++;
                name = display_name(u);

                if (u->load_state != UNIT_LOADED) {
                        n_failed++;
                        printf("%s: FAILED TO LOAD\n", name ? name : u->id);
                } else if (u->n_degraded_directives > 0) {
                        char *list = unit_degraded_directives_string(u);

                        n_degraded++;
                        n_directives += u->n_degraded_directives;
                        printf("%s: %zu dropped: %s\n",
                               name ? name : u->id,
                               u->n_degraded_directives,
                               list ? list : "(out of memory)");
                        free(list);
                } else if (verbose)
                        printf("%s: ok\n", name ? name : u->id);

                free(name);
        }

        if (!quiet)
                printf("pico-unit-lint: %zu units in tree, %zu degraded (%zu directive%s dropped), %zu failed to load\n",
                       n_tree,
                       n_degraded,
                       n_directives,
                       n_directives == 1 ? "" : "s",
                       n_failed);

        free(units);
        manager_free(m);
        pico_strv_free(dirs);

        if ((n_degraded > 0 || n_failed > 0) && !warn_only)
                return 1;

        return 0;
}
