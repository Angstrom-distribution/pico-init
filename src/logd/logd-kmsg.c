/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The /dev/kmsg reader, with whole-ring backfill. See logd-kmsg.h.
 *
 * Record format: "<pri>,<seq>,<timestamp_usec>,<flags>[,extra];message\n",
 * one complete record per read(), e.g. "6,0,0,-;Booting Linux on physical
 * CPU ...\n" as the first record off a fresh open().
 */

#include "logd-kmsg.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../util.h"
#include "logd-kmsg-internal.h"

/* Well over the kernel's per-record printk limit. */
#define KMSG_READ_BUF_SIZE ((size_t) 8192)

/* Next expected record sequence number, kept beside the ring so that a
 * restart within the same boot resumes instead of re-reading the whole
 * kernel ring. */
#define KMSG_SEQNUM_NAME "kmsg-seqnum"

struct LogdKmsg {
        int fd;
        uint64_t next_seqnum;
        bool have_next;
        bool state_loaded;
        bool dirty;
};

int logd_kmsg_new_from_fd(int fd, LogdKmsg **ret) {
        LogdKmsg *k;

        if (fd < 0 || !ret)
                return -EINVAL;

        k = calloc(1, sizeof(*k));
        if (!k)
                return -ENOMEM;

        k->fd = fd;
        *ret = k;
        return 0;
}

int logd_kmsg_new(LogdKmsg **ret) {
        int fd, r;

        if (!ret)
                return -EINVAL;

        fd = open("/dev/kmsg", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
                return -errno;

        r = logd_kmsg_new_from_fd(fd, ret);
        if (r < 0)
                close(fd);
        return r;
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

static int hex_value(char c) {
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

int logd_kmsg_parse_record(
                const char *buf,
                size_t n,
                char **ret_line,
                size_t *ret_len,
                int *ret_priority,
                int *ret_facility,
                uint64_t *ret_seqnum) {
        const char *semi, *nl, *msg_start, *comma;
        size_t msg_len, out = 0;
        uint64_t seqnum = LOGD_KMSG_NO_SEQNUM;
        char *line;
        int value;

        if (!buf || !ret_line || !ret_len || !ret_priority)
                return -EINVAL;

        semi = memchr(buf, ';', n);
        if (!semi)
                return 0; /* malformed record -- skip it rather than crash on it */

        /* "<pri>,<seq>,<timestamp>,<flags>[,extra];message" -- pri is a
         * bare leading decimal (facility*8+severity), no angle brackets,
         * as in the format above. Only the severity
         * (value & 7) is kept; the log entry has no facility field. An
         * unparseable prefix yields priority 0 (emerg), not a failure. */
        value = atoi(buf);

        comma = memchr(buf, ',', (size_t) (semi - buf));
        if (comma && comma[1] >= '0' && comma[1] <= '9') {
                char *end;

                seqnum = strtoull(comma + 1, &end, 10);
                if (end == comma + 1 || *end != ',')
                        seqnum = LOGD_KMSG_NO_SEQNUM;
        }

        msg_start = semi + 1;
        nl = memchr(msg_start, '\n', (size_t) (buf + n - msg_start));
        msg_len = nl ? (size_t) (nl - msg_start) : (size_t) (buf + n - msg_start);

        line = malloc(msg_len + 1);
        if (!line)
                return -ENOMEM;

        /* The kernel escapes non-printables and '\' as \xNN. */
        for (size_t i = 0; i < msg_len; i++) {
                if (msg_start[i] == '\\' && i + 3 < msg_len && msg_start[i + 1] == 'x') {
                        int hi = hex_value(msg_start[i + 2]), lo = hex_value(msg_start[i + 3]);

                        if (hi >= 0 && lo >= 0) {
                                line[out++] = (char) (hi << 4 | lo);
                                i += 3;
                                continue;
                        }
                }
                line[out++] = msg_start[i];
        }
        line[out] = '\0';

        *ret_line = line;
        *ret_len = out;
        *ret_priority = value & 7;
        if (ret_facility)
                *ret_facility = (value & 0x3f8) >> 3;
        if (ret_seqnum)
                *ret_seqnum = seqnum;

        return 1;
}

/* Reads one record; records below the persisted sequence number (already
 * logged before a restart) are skipped here rather than reported as "nothing
 * to read", which would end the drain. */
static int kmsg_read_record(LogdKmsg *k, char **ret_line, size_t *ret_len, int *ret_priority, int *ret_facility) {
        char buf[KMSG_READ_BUF_SIZE];

        for (;;) {
                uint64_t seqnum;
                ssize_t n;
                int r;

                n = read(k->fd, buf, sizeof(buf) - 1);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        if (errno == EAGAIN)
                                return 0;
                        if (errno == EPIPE) {
                                /* Records were dropped; the next read() resumes after
                                 * the gap, where the sequence check reports the count. */
                                if (!k->have_next)
                                        pico_log(PICO_LOG_WARNING,
                                                 "logd: /dev/kmsg reader fell behind, some kernel messages were dropped");
                                continue;
                        }
                        return -errno;
                }
                if (n == 0)
                        return 0;

                buf[n] = '\0';

                r = logd_kmsg_parse_record(
                                buf, (size_t) n, ret_line, ret_len, ret_priority, ret_facility, &seqnum);
                if (r <= 0)
                        return r;

                if (seqnum != LOGD_KMSG_NO_SEQNUM) {
                        if (k->have_next && seqnum < k->next_seqnum) {
                                free(*ret_line);
                                *ret_line = NULL;
                                continue;
                        }
                        if (k->have_next && seqnum > k->next_seqnum)
                                pico_log(PICO_LOG_WARNING,
                                         "logd: missed %" PRIu64 " kernel messages",
                                         seqnum - k->next_seqnum);

                        k->next_seqnum = seqnum + 1;
                        k->have_next = true;
                        k->dirty = true;
                }

                return 1;
        }
}

int logd_kmsg_read(LogdKmsg *k, char **ret_line, size_t *ret_len, int *ret_priority) {
        int facility;

        if (!k || !ret_line || !ret_len || !ret_priority)
                return -EINVAL;

        return kmsg_read_record(k, ret_line, ret_len, ret_priority, &facility);
}

static char *seqnum_path(LogdWriter *writer) {
        char *ring, *slash, *path;
        size_t dirlen;

        if (logd_writer_active_path(writer, &ring) < 0)
                return NULL;

        slash = strrchr(ring, '/');
        dirlen = slash ? (size_t) (slash - ring) : 0;

        path = malloc(dirlen + sizeof("/" KMSG_SEQNUM_NAME));
        if (path)
                snprintf(path,
                         dirlen + sizeof("/" KMSG_SEQNUM_NAME),
                         "%.*s/%s",
                         (int) dirlen,
                         ring,
                         KMSG_SEQNUM_NAME);
        free(ring);
        return path;
}

static void seqnum_load(LogdKmsg *k, const char *path) {
        char buf[32] = "";
        char *end;
        ssize_t n;
        int fd;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return;
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0 || buf[0] < '0' || buf[0] > '9')
                return;

        k->next_seqnum = strtoull(buf, &end, 10);
        k->have_next = true;
}

static void seqnum_store(LogdKmsg *k, const char *path) {
        char tmp[PATH_MAX], buf[32];
        int fd, len;

        len = snprintf(buf, sizeof(buf), "%" PRIu64 "\n", k->next_seqnum);
        if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int) sizeof(tmp))
                return;

        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0)
                return;
        if (write(fd, buf, (size_t) len) != len) {
                close(fd);
                unlink(tmp);
                return;
        }
        close(fd);
        if (rename(tmp, path) < 0)
                unlink(tmp);
        else
                k->dirty = false;
}

int logd_kmsg_drain(LogdKmsg *k, LogdWriter *writer) {
        int count = 0, ret = 0;
        char *state_path;

        if (!k || !writer)
                return -EINVAL;

        state_path = seqnum_path(writer);
        if (state_path && !k->state_loaded) {
                seqnum_load(k, state_path);
                k->state_loaded = true;
        }

        for (;;) {
                char *line = NULL;
                size_t len = 0;
                int priority = 6, facility = 0;
                int r = kmsg_read_record(k, &line, &len, &priority, &facility);

                if (r < 0) {
                        ret = r;
                        break;
                }
                if (r == 0)
                        break;

                {
                        char prio_buf[4];
                        LogdField fields[4];
                        const char *msg = line, *ident = NULL;
                        size_t n = 0, ident_len = 0;

                        /* Userspace writes to /dev/kmsg carry a syslog tag. */
                        if (facility != 0)
                                (void) logd_syslog_parse_tag(&msg, &ident, &ident_len);

                        snprintf(prio_buf, sizeof(prio_buf), "%d", priority);
                        fields[n++] = (LogdField){ "MESSAGE", msg, len - (size_t) (msg - line) };
                        fields[n++] = (LogdField){ "PRIORITY", prio_buf, strlen(prio_buf) };
                        fields[n++] = (LogdField){ "_TRANSPORT", "kernel", 6 };
                        if (ident)
                                fields[n++] = (LogdField){ "SYSLOG_IDENTIFIER", ident, ident_len };

                        (void) logd_writer_append(writer, fields, n);
                }

                free(line);
                count++;
        }

        if (state_path && k->dirty)
                seqnum_store(k, state_path);
        free(state_path);

        return ret < 0 ? ret : count;
}
