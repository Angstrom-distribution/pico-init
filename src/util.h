/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Small shared helpers: time type, logging, string/strv basics.
 * Deliberately minimal -- grown only when another file actually needs it.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint64_t usec_t;

#define USEC_INFINITY ((usec_t) UINT64_MAX)
#define USEC_PER_SEC ((usec_t) 1000000ULL)
#define USEC_PER_MSEC ((usec_t) 1000ULL)

/* CLOCK_MONOTONIC in usec; USEC_INFINITY on failure */
usec_t now_monotonic(void);

/*
 * Saturating a + b, for computing a deadline from "now + timeout". Every
 * caller that does that arithmetic must use this rather than a bare '+': a
 * timeout of USEC_INFINITY ("never") added to a real timestamp would wrap
 * uint64_t and produce a deadline in the past, firing immediately instead of
 * never (see B1 in service.c). Callers with a USEC_INFINITY timeout should
 * skip arming a timer at all rather than relying on this to no-op, per
 * timer.h's own rule -- this exists for the few places that still need a
 * concrete (possibly-saturated) deadline value.
 */
static inline usec_t usec_add(usec_t a, usec_t b) {
        usec_t c = a + b;
        return c < a ? USEC_INFINITY : c;
}

typedef enum PicoLogLevel {
        PICO_LOG_ERR,
        PICO_LOG_WARNING,
        PICO_LOG_INFO,
        PICO_LOG_DEBUG,
} PicoLogLevel;

void pico_log_internal(PicoLogLevel level, const char *format, ...) __attribute__((format(printf, 2, 3)));

/*
 * Redirect pico_log() to /dev/kmsg, with a real syslog priority prefix so the
 * kernel ring carries the level rather than flattening it.
 *
 * Opt-in at runtime, and deliberately not unconditional: pico_log() is shared
 * by the daemons AND by the interactive tools (picolog, picoctl), and an
 * interactive tool's diagnostics belong on the caller's own terminal, never in
 * the kernel ring. A settable sink also leaves pico_log()'s signature alone,
 * so no existing call site changes.
 *
 * Best-effort: if /dev/kmsg cannot be opened the sink stays stderr, which is
 * the pre-existing behaviour and always safe.
 */
void pico_log_to_kmsg(void);

#define pico_log(level, ...) pico_log_internal((level), __VA_ARGS__)

/* strdup returning NULL on OOM (plain strdup, named to avoid confusion later) */
char *pico_strdup(const char *s);

/* free(p) and return NULL, for `x = pico_mfree(x)` */
void *pico_mfree(void *p);

/* NULL-terminated string vectors (argv-style) */
int pico_strv_extend(char ***strv, const char *value); /* 0 or -ENOMEM */
char **pico_strv_free(char **strv);                    /* frees elements + vector, returns NULL */
size_t pico_strv_length(char * const *strv);

/*
 * "NAME=value" environment vectors, quarried from systemd v30's strv.c/util.c.
 * pico_strv_env_merge() takes `n_lists` strvs (any may be NULL) and returns a
 * freshly owned strv with every string copied: a later list's NAME= replaces
 * an earlier one in place, so each name appears once, at the position it was
 * first seen. NULL on OOM. pico_strv_env_get() points at NAME's value inside
 * `l`, or returns NULL when NAME is not set.
 */
char **pico_strv_env_merge(size_t n_lists, ...);
char *pico_strv_env_get(char * const *l, const char *name);

/*
 * Reads an EnvironmentFile=: one NAME=value per line; blank lines and
 * '#'/';' comments are skipped, surrounding whitespace and one pair of
 * matching quotes around the value are stripped. *ret is an owned strv, NULL
 * for a file with no assignments. 0 or -errno.
 */
int pico_load_env_file(const char *path, char ***ret);

/*
 * Extracts one whitespace-separated word from *state, honoring double quotes
 * ("a b" is one word) and backslash escapes. *state is advanced past the
 * word. 1 with *ret set (caller owns it), 0 at end of string, -EINVAL on an
 * unterminated quote or trailing garbage right after a closing quote, or
 * -ENOMEM. ExecStart=, Environment= and $VAR splitting all use this one.
 */
int pico_extract_first_word(const char **state, char **ret);

/*
 * $VAR expansion, v30's replace_env()/replace_env_argv(). pico_replace_env():
 * ${NAME} anywhere in `format` becomes NAME's value in `env` ("" when unset),
 * and $$ becomes a literal $; NULL on OOM. pico_replace_env_argv() appends
 * each word of `argv` to *strv: a word that is exactly $NAME becomes zero or
 * more words, NAME's value split by pico_extract_first_word() (none when
 * unset); any other word goes through pico_replace_env(). 0, -ENOMEM, or
 * -EINVAL for a $NAME value with malformed quoting. On error *strv holds
 * whatever was appended before it, still the caller's to free.
 */
char *pico_replace_env(const char *format, char * const *env);
int pico_replace_env_argv(char * const *argv, char * const *env, char ***strv);
