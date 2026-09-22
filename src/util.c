/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Small shared helpers: time type, logging, string/strv basics.
 *
 * The environment helpers at the end are quarried from systemd v30 (commit
 * 501c92c, copyright 2010 Lennart Poettering, GPL-2.0-or-later): strv.c's
 * env_append()/strv_env_merge()/strv_env_get() and util.c's load_env_file()/
 * normalize_env_assignment(). env_append() and pico_load_env_file() say where
 * they differ.
 */

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

usec_t now_monotonic(void) {
        struct timespec ts;

        if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
                return USEC_INFINITY;

        return (usec_t) ts.tv_sec * USEC_PER_SEC + (usec_t) ts.tv_nsec / 1000ULL;
}

static const char *log_level_prefix(PicoLogLevel level) {
        switch (level) {
        case PICO_LOG_ERR:
                return "err";
        case PICO_LOG_WARNING:
                return "warning";
        case PICO_LOG_INFO:
                return "info";
        case PICO_LOG_DEBUG:
                return "debug";
        }

        return "?";
}

/*
 * The syslog priority /dev/kmsg's own "<N>message" framing expects, so a
 * record's level survives into the kernel ring instead of being flattened to
 * whatever default the kernel assigns a plain write.
 */
static int log_level_syslog_priority(PicoLogLevel level) {
        switch (level) {
        case PICO_LOG_ERR:
                return 3; /* LOG_ERR */
        case PICO_LOG_WARNING:
                return 4; /* LOG_WARNING */
        case PICO_LOG_INFO:
                return 6; /* LOG_INFO */
        case PICO_LOG_DEBUG:
                return 7; /* LOG_DEBUG */
        }

        return 6;
}

/* Where pico_log() writes. stderr until a daemon opts into /dev/kmsg; see
 * pico_log_to_kmsg() and util.h for why that is opt-in rather than automatic. */
static int log_fd = STDERR_FILENO;
static bool log_fd_is_kmsg = false;

void pico_log_to_kmsg(void) {
        int fd;

        if (log_fd_is_kmsg)
                return;

        fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
        if (fd < 0)
                return; /* stay on stderr: always safe, and the old behaviour */

        log_fd = fd;
        log_fd_is_kmsg = true;
}

/*
 * One buffer, one write() -- not fprintf()+vfprintf()+fputc() as three
 * separate calls. Harmless against a plain console/pipe, but this is the
 * discipline a line-oriented destination needs in general (three writes
 * for what is meant to be one line can become three separate records
 * rather than one, exactly the property logd-recv.c's own stdout capture
 * cares about for the same reason), so it is applied here uniformly
 * rather than only where it happens to matter today.
 */
void pico_log_internal(PicoLogLevel level, const char *format, ...) {
        char buf[1024];
        int prefix_len, msg_len, total;
        va_list ap;

        if (log_fd_is_kmsg)
                prefix_len = snprintf(
                                buf,
                                sizeof(buf),
                                "<%d>pico-init[%s]: ",
                                log_level_syslog_priority(level),
                                log_level_prefix(level));
        else
                prefix_len = snprintf(buf, sizeof(buf), "pico-init[%s]: ", log_level_prefix(level));
        if (prefix_len < 0)
                prefix_len = 0;
        if ((size_t) prefix_len >= sizeof(buf))
                prefix_len = (int) sizeof(buf) - 1;

        va_start(ap, format);
        msg_len = vsnprintf(buf + prefix_len, sizeof(buf) - (size_t) prefix_len, format, ap);
        va_end(ap);
        if (msg_len < 0)
                msg_len = 0;

        total = prefix_len + msg_len;
        if (total >= (int) sizeof(buf) - 1)
                total = (int) sizeof(buf) - 2; /* leave room for the trailing '\n' */
        buf[total] = '\n';
        total += 1;

        /* Not `(void) write(...)`: a void cast does NOT suppress
         * warn_unused_result in GCC, and glibc marks write() __wur under
         * _FORTIFY_SOURCE -- which the target build enables and a -O0 host
         * build does not, so this is invisible until cross-compilation. */
        if (write(log_fd, buf, (size_t) total) < 0) {
                /* Nothing useful to do here: this is the logger. */
        }
}

char *pico_strdup(const char *s) {
        return strdup(s);
}

void *pico_mfree(void *p) {
        free(p);
        return NULL;
}

int pico_strv_extend(char ***strv, const char *value) {
        size_t n = pico_strv_length(*strv);
        char **new_strv;
        char *dup;

        new_strv = realloc(*strv, (n + 2) * sizeof(char *));
        if (!new_strv)
                return -ENOMEM;

        *strv = new_strv;
        new_strv[n] = NULL;
        new_strv[n + 1] = NULL;

        dup = pico_strdup(value);
        if (!dup)
                return -ENOMEM;

        new_strv[n] = dup;

        return 0;
}

char **pico_strv_free(char **strv) {
        char **p;

        if (!strv)
                return NULL;

        for (p = strv; *p; p++)
                free(*p);

        free(strv);

        return NULL;
}

size_t pico_strv_length(char * const *strv) {
        size_t n = 0;

        if (!strv)
                return 0;

        while (strv[n])
                n++;

        return n;
}

/*
 * v30's env_append(): appends each entry of `a` to r[0..*k), unless its NAME=
 * is already there, in which case that entry is replaced in place. `r` has
 * room for every entry (pico_strv_env_merge() sizes it). The copy is made
 * before anything is touched, so on -ENOMEM r[0..*k) is still a valid strv.
 * An entry with no '=' only matches itself: v30's prefix compare would have
 * let "FOO" replace "FOOBAR=x".
 */
static int env_append(char **r, size_t *k, char * const *a) {
        if (!a)
                return 0;

        for (; *a; a++) {
                size_t n = strcspn(*a, "="), j;
                bool has_eq = (*a)[n] == '=';
                char *dup;

                dup = pico_strdup(*a);
                if (!dup)
                        return -ENOMEM;

                for (j = 0; j < *k; j++)
                        if (has_eq ? strncmp(r[j], *a, n + 1) == 0 : strcmp(r[j], *a) == 0)
                                break;

                if (j < *k)
                        free(r[j]);
                else
                        (*k)++;
                r[j] = dup;
        }

        return 0;
}

char **pico_strv_env_merge(size_t n_lists, ...) {
        size_t n = 0, k = 0, i;
        char **r;
        va_list ap;

        va_start(ap, n_lists);
        for (i = 0; i < n_lists; i++)
                n += pico_strv_length(va_arg(ap, char **));
        va_end(ap);

        r = calloc(n + 1, sizeof(char *));
        if (!r)
                return NULL;

        va_start(ap, n_lists);
        for (i = 0; i < n_lists; i++)
                if (env_append(r, &k, va_arg(ap, char **)) < 0) {
                        va_end(ap);
                        return pico_strv_free(r); /* calloc'd: r[k] is the terminator */
                }
        va_end(ap);

        return r;
}

char *pico_strv_env_get(char * const *l, const char *name) {
        size_t k = strlen(name);

        if (!l)
                return NULL;

        for (; *l; l++)
                if (strncmp(*l, name, k) == 0 && (*l)[k] == '=')
                        return *l + k + 1;

        return NULL;
}

static char *env_strip(char *s) {
        char *end;

        s += strspn(s, " \t\n\r");

        end = s + strlen(s);
        while (end > s && strchr(" \t\n\r", end[-1]))
                end--;
        *end = '\0';

        return s;
}

/* v30's unquote(): one matching pair of surrounding quotes, in place. */
static char *env_unquote(char *v) {
        size_t n = strlen(v);

        if (n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n - 1] == v[0]) {
                v[n - 1] = '\0';
                return v + 1;
        }

        return v;
}

/*
 * v30's load_env_file() + normalize_env_assignment(), with three changes:
 * getline() instead of a LINE_MAX fgets() buffer (e6dde451a's reasoning, see
 * unit-parse.c: a long line is never silently split into two), NAME is
 * stripped as well as the value, and a line with no '=' or an empty NAME is
 * warned about and skipped rather than stored -- the same policy
 * Environment= itself applies at parse time.
 */
int pico_load_env_file(const char *path, char ***ret) {
        char **l = NULL, *line = NULL;
        size_t cap = 0;
        unsigned lineno = 0;
        int r = 0;
        FILE *f;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        for (;;) {
                char *p, *eq, *name, *value;
                size_t nlen, vlen;

                if (getline(&line, &cap, f) < 0) {
                        if (ferror(f))
                                r = errno > 0 ? -errno : -EIO;
                        break;
                }
                lineno++;

                p = env_strip(line);
                if (*p == '\0' || *p == '#' || *p == ';')
                        continue;

                eq = strchr(p, '=');
                if (!eq || eq == p) {
                        pico_log(PICO_LOG_WARNING, "%s:%u: '%s' is not an assignment, ignoring", path, lineno, p);
                        continue;
                }

                *eq = '\0';
                name = env_strip(p);
                value = env_unquote(env_strip(eq + 1));

                /* Reassembled in place: value always sits after name. */
                nlen = strlen(name);
                vlen = strlen(value);
                name[nlen] = '=';
                memmove(name + nlen + 1, value, vlen + 1);

                r = pico_strv_extend(&l, name);
                if (r < 0)
                        break;
        }

        free(line);
        fclose(f);

        if (r < 0) {
                pico_strv_free(l);
                return r;
        }

        *ret = l;
        return 0;
}
