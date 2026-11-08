/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Small shared helpers: time type, logging, string/strv basics.
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
 * Saturating a + b, for computing a deadline from "now + timeout". A bare '+'
 * with a timeout of USEC_INFINITY ("never") would wrap uint64_t and produce a
 * deadline in the past, firing immediately instead of never. Callers with a
 * USEC_INFINITY timeout should skip arming a timer at all (see timer.h); this
 * is for the few places that need a concrete, possibly saturated, deadline.
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
 * Send pico_log() to logd while it is running and to /dev/kmsg otherwise,
 * like systemd's journal-or-kmsg log target. "Running" is the manager's
 * judgement (pico_log_set_journal_running()), not whether /dev/log accepts a
 * connection: PID 1 holds logd.socket itself, so connect() succeeds long
 * before logd exists, and a datagram sent then would queue unread, or
 * socket-activate logd from PID 1's own log line. While logd is running each
 * record goes to its /dev/log socket; if the datagram is not accepted it goes
 * to /dev/kmsg, and a failed send drops the connection so the next record
 * reconnects. The kernel ring holds no pico-init records of its own while
 * logd runs; logd imports the earlier ones when it starts. Both destinations
 * carry a real syslog priority.
 *
 * Opt-in at runtime: pico_log() is shared by the daemons and by the
 * interactive tools (picolog, picoctl), whose diagnostics belong on the
 * caller's terminal, not in the log.
 *
 * Best-effort: with neither destination available the sink stays stderr.
 * The _at variant takes the two paths and may be called again to start over
 * with logd not running; tests use it.
 */
void pico_log_to_journal_or_kmsg(void);
void pico_log_to_journal_or_kmsg_at(const char *syslog_path, const char *kmsg_path);

/* Tell the sink whether logd is up. Called by the manager when logd.socket or
 * logd.service changes state; closing the window drops the connection. */
void pico_log_set_journal_running(bool running);

/*
 * Drop pico_log() messages less severe than `max`. The default keeps every
 * level, as the daemons want; picoctl lowers it to INFO because systemctl
 * prints nothing at debug level.
 */
void pico_log_set_max_level(PicoLogLevel max);

#define pico_log(level, ...) pico_log_internal((level), __VA_ARGS__)

/* strdup returning NULL on OOM (plain strdup, named to avoid confusion later) */
char *pico_strdup(const char *s);

/* free(p) and return NULL, for `x = pico_mfree(x)` */
void *pico_mfree(void *p);

/*
 * True for an absolute path (starting '/', not ending '/') OR a bare
 * filename with no '/' at all (not "", ".", ".." -- matches systemd's own
 * filename_or_absolute_path_is_valid()/filename_is_valid(), src/basic/
 * path-util.{c,h}). A relative path WITH a slash ("foo/bar") is rejected
 * either way: it is neither absolute nor a single path component, and
 * nothing in Exec*=/exec-time lookup knows what to resolve it against.
 * Shared by unit-parse.c (parse time) and service.c (service_verify()'s
 * re-check).
 */
bool pico_exec_path_is_valid(const char *p);

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
 * Reads an EnvironmentFile=: NAME=value assignments with shell-like value
 * quoting ('..', "..", backslash escapes, quoted values spanning lines);
 * blank lines and '#'/';' comments are skipped. *ret is an owned strv, NULL
 * for a file with no assignments. 0 or -errno.
 */
int pico_load_env_file(const char *path, char ***ret);

/*
 * Extracts one whitespace-separated word from *state. Single and double
 * quotes group and are removed, and may be glued to unquoted text. C escapes
 * (\n, \t, \xNN, \NNN, \uNNNN, ...) are decoded; an unknown one stays as
 * written. *state is advanced past the word. 1 with *ret set (caller owns
 * it), 0 at end of string, -EINVAL on an unterminated quote, or -ENOMEM.
 * ExecStart=, Environment= and $VAR splitting all use this one.
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
