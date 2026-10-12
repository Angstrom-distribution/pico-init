/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Small shared helpers: time type, logging, string/strv basics.
 *
 * The environment helpers at the end are quarried from systemd v30 (commit
 * 501c92c, copyright 2010 Lennart Poettering, GPL-2.0-or-later): strv.c's
 * env_append()/strv_env_merge()/strv_env_get() and util.c's load_env_file()/
 * normalize_env_assignment()/replace_env()/replace_env_argv().
 * env_append(), pico_load_env_file() and pico_replace_env_argv() say where
 * they differ.
 */

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h> /* NAME_MAX, for pico_exec_path_is_valid() */
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
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

/* Where pico_log() writes: stderr until a daemon opts into /dev/kmsg; see
 * pico_log_to_kmsg() in util.h. */
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
 * One buffer, one write(), not several. A line-oriented destination (kmsg,
 * logd's stdout capture) would otherwise see one line as several records.
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

        /* Not `(void) write(...)`: a void cast does not suppress
         * warn_unused_result in GCC, and glibc marks write() __wur under
         * _FORTIFY_SOURCE, which -O0 host builds do not enable. */
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

bool pico_exec_path_is_valid(const char *p) {
        size_t len;

        if (!p || !*p)
                return false;

        if (p[0] == '/')
                return p[strlen(p) - 1] != '/'; /* absolute, not a directory */

        if (strchr(p, '/'))
                return false; /* relative WITH a slash: neither case applies */

        if (strcmp(p, ".") == 0 || strcmp(p, "..") == 0)
                return false;

        len = strlen(p);
        return len <= NAME_MAX;
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

/* v30's strv_env_get_with_length(): `name` need not be NUL-terminated. */
static char *env_get_n(char * const *l, const char *name, size_t k) {
        if (!l)
                return NULL;

        for (; *l; l++)
                if (strncmp(*l, name, k) == 0 && (*l)[k] == '=')
                        return *l + k + 1;

        return NULL;
}

char *pico_strv_env_get(char * const *l, const char *name) {
        return env_get_n(l, name, strlen(name));
}

static int hex_digit(char c) {
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

static size_t utf8_encode(uint32_t c, char *out) {
        if (c < 0x80) {
                out[0] = (char) c;
                return 1;
        }
        if (c < 0x800) {
                out[0] = (char) (0xC0 | (c >> 6));
                out[1] = (char) (0x80 | (c & 0x3F));
                return 2;
        }
        if (c < 0x10000) {
                out[0] = (char) (0xE0 | (c >> 12));
                out[1] = (char) (0x80 | ((c >> 6) & 0x3F));
                out[2] = (char) (0x80 | (c & 0x3F));
                return 3;
        }
        out[0] = (char) (0xF0 | (c >> 18));
        out[1] = (char) (0x80 | ((c >> 12) & 0x3F));
        out[2] = (char) (0x80 | ((c >> 6) & 0x3F));
        out[3] = (char) (0x80 | (c & 0x3F));
        return 4;
}

/* Reads `n` hex digits at p; -1 if any is not one. */
static int64_t hex_number(const char *p, int n) {
        int64_t v = 0;

        for (int i = 0; i < n; i++) {
                int d = hex_digit(p[i]);

                if (d < 0)
                        return -1;
                v = (v << 4) | d;
        }

        return v;
}

/*
 * The C escape starting at p (just past the backslash). Returns how many
 * characters it spans and puts the bytes it stands for in out[0..*n_out), or
 * -EINVAL for anything that is not a complete, valid escape: the caller keeps
 * those verbatim. A NUL is never produced.
 */
static int c_unescape(const char *p, char out[4], size_t *n_out) {
        int64_t v;

        *n_out = 1;

        switch (*p) {
        case 'a':
                out[0] = '\a';
                return 1;
        case 'b':
                out[0] = '\b';
                return 1;
        case 'f':
                out[0] = '\f';
                return 1;
        case 'n':
                out[0] = '\n';
                return 1;
        case 'r':
                out[0] = '\r';
                return 1;
        case 't':
                out[0] = '\t';
                return 1;
        case 'v':
                out[0] = '\v';
                return 1;
        case '\\':
        case '"':
        case '\'':
                out[0] = *p;
                return 1;
        case 's':
                out[0] = ' ';
                return 1;
        case 'x':
                v = hex_number(p + 1, 2);
                if (v <= 0)
                        return -EINVAL;
                out[0] = (char) v;
                return 3;
        case 'u':
                v = hex_number(p + 1, 4);
                if (v <= 0 || (v >= 0xD800 && v <= 0xDFFF))
                        return -EINVAL;
                *n_out = utf8_encode((uint32_t) v, out);
                return 5;
        case 'U':
                v = hex_number(p + 1, 8);
                if (v <= 0 || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF) || (v & 0xFFFE) == 0xFFFE ||
                    (v >= 0xFDD0 && v <= 0xFDEF))
                        return -EINVAL;
                *n_out = utf8_encode((uint32_t) v, out);
                return 9;
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
                if (p[1] < '0' || p[1] > '7' || p[2] < '0' || p[2] > '7')
                        return -EINVAL;
                v = ((p[0] - '0') << 6) | ((p[1] - '0') << 3) | (p[2] - '0');
                if (v == 0 || v > 255)
                        return -EINVAL;
                out[0] = (char) v;
                return 3;
        default:
                return -EINVAL;
        }
}

/*
 * Pico's own tokenizer. A quote closing does not end the word (foo="a"b is
 * one word), and an unknown or incomplete escape stays as written, so a
 * sed expression like s/\./_/ survives intact.
 */
int pico_extract_first_word(const char **state, char **ret) {
        const char *p = *state;
        char *buf, *w;
        char quote = '\0'; /* the open quote character, or 0 outside quotes */

        while (*p == ' ' || *p == '\t')
                p++;
        if (*p == '\0') {
                *state = p;
                return 0;
        }

        /* An escape never decodes to more bytes than it spans. */
        buf = malloc(strlen(p) + 1);
        if (!buf)
                return -ENOMEM;
        w = buf;

        for (;;) {
                if (*p == '\0') {
                        if (quote) {
                                free(buf);
                                return -EINVAL; /* unterminated quote */
                        }
                        break;
                }
                /*
                 * Either quote character opens a quoted run, as in
                 * extract_first_word()'s UNQUOTE; inside one, the other
                 * character is literal.
                 */
                if ((*p == '"' || *p == '\'') && (!quote || *p == quote)) {
                        quote = quote ? '\0' : *p;
                        p++;
                        continue;
                }
                if (*p == '\\') {
                        char dec[4];
                        size_t n;
                        int len;

                        if (p[1] == '\0') {
                                if (quote) {
                                        free(buf);
                                        return -EINVAL;
                                }
                                *w++ = *p++; /* trailing backslash, kept */
                                continue;
                        }

                        len = c_unescape(p + 1, dec, &n);
                        if (len > 0) {
                                memcpy(w, dec, n);
                                w += n;
                                p += 1 + len;
                        } else {
                                *w++ = p[0];
                                *w++ = p[1];
                                p += 2;
                        }
                        continue;
                }
                if (!quote && (*p == ' ' || *p == '\t'))
                        break;
                *w++ = *p++;
        }
        *w = '\0';

        *state = p;
        *ret = buf;
        return 1;
}

static int buf_append(char **buf, size_t *len, const char *s, size_t n) {
        char *t = realloc(*buf, *len + n + 1);

        if (!t)
                return -ENOMEM;

        memcpy(t + *len, s, n);
        *len += n;
        t[*len] = '\0';
        *buf = t;
        return 0;
}

/* v30's replace_env() state machine; an unterminated ${ stays literal. */
char *pico_replace_env(const char *format, char * const *env) {
        enum { WORD, CURLY, VARIABLE } state = WORD;
        const char *e, *word = format;
        char *r = NULL;
        size_t len = 0;

        for (e = format; *e; e++) {
                switch (state) {
                case WORD:
                        if (*e == '$')
                                state = CURLY;
                        break;

                case CURLY:
                        if (*e == '{') {
                                if (buf_append(&r, &len, word, (size_t) (e - word - 1)) < 0)
                                        goto fail;
                                word = e - 1;
                                state = VARIABLE;
                        } else if (*e == '$') {
                                if (buf_append(&r, &len, word, (size_t) (e - word)) < 0)
                                        goto fail;
                                word = e + 1;
                                state = WORD;
                        } else
                                state = WORD;
                        break;

                case VARIABLE:
                        if (*e == '}') {
                                const char *t = env_get_n(env, word + 2, (size_t) (e - word - 2));

                                if (!t)
                                        t = "";
                                if (buf_append(&r, &len, t, strlen(t)) < 0)
                                        goto fail;
                                word = e + 1;
                                state = WORD;
                        }
                        break;
                }
        }

        if (buf_append(&r, &len, word, (size_t) (e - word)) < 0)
                goto fail;

        return r;

fail:
        free(r);
        return NULL;
}

#define ENV_NAME_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"

/*
 * v30's replace_env_argv(). The whole-word test is narrower than v30's
 * "starts with $, not ${": the rest must be a non-empty variable name, so a
 * word like $$ or $FOO/bar goes through pico_replace_env() instead of being
 * looked up as a name that can never exist and silently dropped.
 */
int pico_replace_env_argv(char * const *argv, char * const *env, char ***strv) {
        int r = 0;

        for (; argv && *argv; argv++) {
                const char *w = *argv;

                if (w[0] == '$' && w[1] != '\0' && w[1 + strspn(w + 1, ENV_NAME_CHARS)] == '\0') {
                        const char *p = pico_strv_env_get(env, w + 1);
                        char *word;

                        while (p && (r = pico_extract_first_word(&p, &word)) > 0) {
                                r = pico_strv_extend(strv, word);
                                free(word);
                                if (r < 0)
                                        return r;
                        }
                        if (p && r < 0) {
                                if (r == -EINVAL)
                                        pico_log(PICO_LOG_WARNING, "%s: malformed quoting in the value", w);
                                return r;
                        }
                        continue;
                }

                {
                        char *x = pico_replace_env(w, env);

                        if (!x)
                                return -ENOMEM;
                        r = pico_strv_extend(strv, x);
                        free(x);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
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
 * getline() instead of a LINE_MAX fgets() buffer (so a long line is never
 * silently split into two; see e6dde451a), NAME is
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
