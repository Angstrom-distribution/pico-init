/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Small shared helpers: time type, logging, string/strv basics.
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
