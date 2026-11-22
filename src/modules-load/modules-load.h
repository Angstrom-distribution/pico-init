/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * modules-load.d(5): the modules named in the "*.conf" files of the
 * modules-load.d directories and in modules_load=/rd.modules_load= on the
 * kernel command line are loaded with one "modprobe -b" run per name, as
 * systemd-modules-load.service does.
 *
 * The file listing is pico_dropin_files(): a name in an earlier directory
 * hides the same name in a later one. A module that fails to load is logged
 * and the rest are still tried.
 *
 * -b makes a modprobe.d "blacklist" apply to a module named directly, which
 * is KMOD_PROBE_APPLY_BLACKLIST in systemd's module_load_and_warn(). kmod,
 * busybox (built with or without FEATURE_MODPROBE_BLACKLIST) and toybox all
 * accept it, so it is passed without asking which modprobe this is. A module
 * that fails and is named in module_blacklist= on the kernel command line is
 * not counted as a failure, as in systemd.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#define PICO_MODULES_LOAD_MODPROBE "/sbin/modprobe"

typedef struct PicoModulesLoad {
        char * const *dirs;  /* NULL-terminated, in priority order */
        const char *cmdline; /* the kernel command line file, /proc/cmdline */
        const char *modprobe;
} PicoModulesLoad;

/* The default directories, in systemd's priority order. */
extern char * const pico_modules_load_dirs[];

/* The names in one modules-load.d file, appended to *names. 0 or -errno. */
int pico_modules_load_parse_file(const char *path, char ***names);

/* The names given by modules_load= and rd.modules_load= in a command line
 * (the "-" spellings too), appended to *names. 0 or -errno. */
int pico_modules_load_parse_cmdline(const char *line, char ***names);

/* The names given by module_blacklist= (and module-blacklist=), appended to
 * *names. 0 or -errno. */
int pico_modules_load_parse_denylist(const char *line, char ***names);

/*
 * Load every module that is asked for. When no directory has a file and the
 * command line names no module, nothing is run. *n_modules is the number of
 * distinct names and *n_failed how many of them modprobe refused (either may be NULL). 0, or
 * -errno when the list could not be built.
 */
int pico_modules_load_run(const PicoModulesLoad *c, size_t *n_modules, size_t *n_failed);
