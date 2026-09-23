/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The /dev/kmsg reader, with whole-ring backfill. See logd-kmsg.h for the
 * mechanism (a fresh open() starts at the ring's beginning, not "now") and
 * the journald-kmsg.c reference citation (plan §3.5).
 *
 * Record format, confirmed against a real running kernel rather than
 * assumed: "<pri>,<seq>,<timestamp_usec>,<flags>[,extra];message\n", one
 * complete record per read(), e.g. b'6,0,0,-;Booting Linux on physical
 * CPU ...\n' as the very first record off a fresh open().
 */

#include "logd-kmsg.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../util.h"
#include "logd-kmsg-internal.h"

/* Generous over any real single kmsg record -- the kernel's own printk
 * ring caps a line well under this. */
#define KMSG_READ_BUF_SIZE ((size_t) 8192)

struct LogdKmsg {
        int fd;
};

int logd_kmsg_new(LogdKmsg **ret) {
        LogdKmsg *k;
        int fd;

        if (!ret)
                return -EINVAL;

        fd = open("/dev/kmsg", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
                return -errno;

        k = calloc(1, sizeof(*k));
        if (!k) {
                close(fd);
                return -ENOMEM;
        }

        k->fd = fd;
        *ret = k;
        return 0;
}

LogdKmsg *logd_kmsg_free(LogdKmsg *k) {
        if (!k)
                return NULL;

        if (k->fd >= 0)
                close(k->fd);

        free(k);
        return NULL;
}

int logd_kmsg_fd(LogdKmsg *k) {
        return k ? k->fd : -1;
}

int logd_kmsg_parse_record(const char *buf, size_t n, char **ret_line, size_t *ret_len, int *ret_priority) {
        const char *semi, *nl, *msg_start;
        size_t msg_len;
        int priority;

        if (!buf || !ret_line || !ret_len || !ret_priority)
                return -EINVAL;

        semi = memchr(buf, ';', n);
        if (!semi)
                return 0; /* malformed record -- skip it rather than crash on it */

        /* "<pri>,<seq>,<timestamp>,<flags>[,extra];message" -- pri is a
         * bare leading decimal (facility*8+severity), no angle brackets,
         * confirmed against a real kernel above. Only the severity
         * (value & 7) is kept; pico's field set (plan §3.3) carries no
         * facility. atoi() on anything unparseable returns 0, which masks
         * to priority 0 (emerg) -- an over-severe default for a line this
         * function otherwise still emits, but never a crash, and this
         * format has not been observed to vary. */
        priority = atoi(buf) & 7;

        msg_start = semi + 1;
        nl = memchr(msg_start, '\n', (size_t) (buf + n - msg_start));
        msg_len = nl ? (size_t) (nl - msg_start) : (size_t) (buf + n - msg_start);

        *ret_line = malloc(msg_len + 1);
        if (!*ret_line)
                return -ENOMEM;

        memcpy(*ret_line, msg_start, msg_len);
        (*ret_line)[msg_len] = '\0';
        *ret_len = msg_len;
        *ret_priority = priority;

        return 1;
}

int logd_kmsg_read(LogdKmsg *k, char **ret_line, size_t *ret_len, int *ret_priority) {
        char buf[KMSG_READ_BUF_SIZE];
        ssize_t n;

        if (!k || !ret_line || !ret_len || !ret_priority)
                return -EINVAL;

        n = read(k->fd, buf, sizeof(buf) - 1);
        if (n < 0) {
                if (errno == EAGAIN)
                        return 0;
                if (errno == EPIPE) {
                        /* We fell behind and the kernel dropped records to
                         * make room; the next read() resumes right after
                         * the gap on its own, nothing to seek or reopen. */
                        pico_log(PICO_LOG_WARNING,
                                 "logd: /dev/kmsg reader fell behind, some kernel messages were dropped");
                        return 0;
                }
                return -errno;
        }
        if (n == 0)
                return 0;

        buf[n] = '\0';

        return logd_kmsg_parse_record(buf, (size_t) n, ret_line, ret_len, ret_priority);
}

int logd_kmsg_drain(LogdKmsg *k, LogdWriter *writer) {
        int count = 0;

        if (!k || !writer)
                return -EINVAL;

        for (;;) {
                char *line = NULL;
                size_t len = 0;
                int priority = 6;
                int r = logd_kmsg_read(k, &line, &len, &priority);

                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                {
                        char prio_buf[4];
                        LogdField fields[3];

                        snprintf(prio_buf, sizeof(prio_buf), "%d", priority);
                        fields[0] = (LogdField){ "MESSAGE", line, len };
                        fields[1] = (LogdField){ "PRIORITY", prio_buf, strlen(prio_buf) };
                        fields[2] = (LogdField){ "_TRANSPORT", "kernel", 6 };

                        (void) logd_writer_append(writer, fields, 3);
                }

                free(line);
                count++;
        }

        return count;
}
