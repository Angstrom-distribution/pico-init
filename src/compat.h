/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Shims for features the quarried ~2011-era systemd source expects but
 * pico-init removed: DBus feedback, cgroups v1, systemd's log_*() macros.
 * Quarried files get SYSTEMD_QUARRY_COMPAT defined and keep their call
 * sites; fresh pico-init code must not use anything from this header.
 */

#pragma once

#include "util.h"

#ifdef SYSTEMD_QUARRY_COMPAT

/* systemd's log macros, collapsed onto pico_log() */
#        define log_error(...) pico_log(PICO_LOG_ERR, __VA_ARGS__)
#        define log_warning(...) pico_log(PICO_LOG_WARNING, __VA_ARGS__)
#        define log_info(...) pico_log(PICO_LOG_INFO, __VA_ARGS__)
#        define log_debug(...) pico_log(PICO_LOG_DEBUG, __VA_ARGS__)

/* DBus feedback: no bus, all calls succeed as no-ops */
static inline int bus_init_noop(void) {
        return 0;
}
#        define unit_send_change_signal(u) \
                do {                       \
                        (void) (u);        \
                } while (0)
#        define manager_send_job_change(j) \
                do {                       \
                        (void) (j);        \
                } while (0)

/* cgroups v1 entry points: v2-only project, quarried call sites stubbed out */
#        define cgroup_bonding_realize(b) (0)
#        define cgroup_bonding_free_list(b) \
                do {                        \
                        (void) (b);         \
                } while (0)

#endif /* SYSTEMD_QUARRY_COMPAT */

/* compat.c's anchor symbol, so a test can check the TU linked */
int compat_noop(void);
