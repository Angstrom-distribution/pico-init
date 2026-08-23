/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Small shared helpers: time type, logging, string/strv basics.
 * Deliberately minimal -- grown only when another file actually needs it.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef uint64_t usec_t;

#define USEC_INFINITY ((usec_t) UINT64_MAX)
#define USEC_PER_SEC ((usec_t) 1000000ULL)
#define USEC_PER_MSEC ((usec_t) 1000ULL)

/* CLOCK_MONOTONIC in usec; USEC_INFINITY on failure */
usec_t now_monotonic(void);

typedef enum PicoLogLevel {
        PICO_LOG_ERR,
        PICO_LOG_WARNING,
        PICO_LOG_INFO,
        PICO_LOG_DEBUG,
} PicoLogLevel;

void pico_log_internal(PicoLogLevel level, const char *format, ...) __attribute__((format(printf, 2, 3)));

#define pico_log(level, ...) pico_log_internal((level), __VA_ARGS__)

/* strdup returning NULL on OOM (plain strdup, named to avoid confusion later) */
char *pico_strdup(const char *s);

/* free(p) and return NULL, for `x = pico_mfree(x)` */
void *pico_mfree(void *p);

/* NULL-terminated string vectors (argv-style) */
int pico_strv_extend(char ***strv, const char *value); /* 0 or -ENOMEM */
char **pico_strv_free(char **strv);                    /* frees elements + vector, returns NULL */
size_t pico_strv_length(char * const *strv);
