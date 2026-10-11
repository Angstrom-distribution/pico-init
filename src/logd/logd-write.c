/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The export-format writer and the /run ring. See logd-write.h.
 *
 * Crash safety. /run is tmpfs, so a power loss loses the whole ring by
 * design; what remains is logd dying mid-append. Every entry is assembled
 * in one heap buffer and handed to the kernel in one write() (write_full()
 * retries only for EINTR and short writes). A single write() to a tmpfs
 * file copies its whole argument in kernel context before any signal,
 * SIGKILL included, is delivered, so a kill cannot leave a half-written
 * record. If write() itself fails partway (chiefly ENOSPC), the partial
 * write is truncated back to the pre-write size, so the file always ends on
 * a complete entry.
 *
 * Rotation keeps the property: rotate_if_needed() only runs after a complete
 * record has landed, and a crash between closing the old active fd and
 * reopening a fresh one leaves the next logd_writer_open() to resume
 * whichever half of the rename already happened.
 */

#include "logd-write.h"

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "../util.h"
#include "logd.h"

#define LOGD_BOOT_ID_BYTES 16
#define LOGD_BOOT_ID_STRLEN 32 /* excluding the NUL */

struct LogdWriter {
        char *runtime_dir;
        size_t max_bytes;
        int active_fd;
        size_t active_size;
        uint8_t boot_id[LOGD_BOOT_ID_BYTES];
        bool boot_id_set;
};

static int unhex_digit(char c) {
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;

        return -1;
}

static void boot_id_to_string(const uint8_t boot_id[LOGD_BOOT_ID_BYTES], char out[LOGD_BOOT_ID_STRLEN + 1]) {
        static const char hex[] = "0123456789abcdef";

        for (size_t i = 0; i < LOGD_BOOT_ID_BYTES; i++) {
                out[i * 2] = hex[boot_id[i] >> 4];
                out[i * 2 + 1] = hex[boot_id[i] & 0xf];
        }

        out[LOGD_BOOT_ID_STRLEN] = '\0';
}

/* /proc/sys/kernel/random/boot_id: the per-boot ID sd_id128_get_boot()
 * reads upstream. Dashes (the UUID form the kernel writes) are skipped. */
static int read_boot_id_from_proc(uint8_t boot_id[LOGD_BOOT_ID_BYTES]) {
        char buf[64];
        FILE *f;
        size_t n;
        int nibbles = 0;

        f = fopen("/proc/sys/kernel/random/boot_id", "re");
        if (!f)
                return -errno;

        n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);

        if (n == 0)
                return -EIO;
        buf[n] = '\0';

        for (size_t i = 0; buf[i] != '\0' && nibbles < LOGD_BOOT_ID_BYTES * 2; i++) {
                int v;

                if (buf[i] == '-')
                        continue;

                v = unhex_digit(buf[i]);
                if (v < 0)
                        break;

                if (nibbles % 2 == 0)
                        boot_id[nibbles / 2] = (uint8_t) (v << 4);
                else
                        boot_id[nibbles / 2] |= (uint8_t) v;

                nibbles++;
        }

        return nibbles == LOGD_BOOT_ID_BYTES * 2 ? 0 : -EINVAL;
}

/* Fallback only: /proc is mounted before any service starts. Blocking
 * getrandom(), because a predictable or all-zero _BOOT_ID is rejected by
 * journal-remote (see logd-write.h). */
static int read_boot_id_random(uint8_t boot_id[LOGD_BOOT_ID_BYTES]) {
        ssize_t n;

        n = getrandom(boot_id, LOGD_BOOT_ID_BYTES, 0);
        if (n < 0)
                return -errno;
        if ((size_t) n != LOGD_BOOT_ID_BYTES)
                return -EIO;

        return 0;
}

static int read_boot_id(uint8_t boot_id[LOGD_BOOT_ID_BYTES]) {
        int r = read_boot_id_from_proc(boot_id);

        return r == 0 ? 0 : read_boot_id_random(boot_id);
}

static int now_realtime(usec_t *ret) {
        struct timespec ts;

        if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
                return -errno;

        *ret = (usec_t) ts.tv_sec * USEC_PER_SEC + (usec_t) ts.tv_nsec / 1000ULL;
        return 0;
}

/*
 * Whether `value` can use the plain "NAME=value\n" form: JOURNAL_EXPORT_
 * FORMATS.md's rule -- non-control UTF-8 codepoints (>= 0x20, or TAB) only,
 * which also excludes a newline. Anything else (embedded NUL, control byte,
 * invalid or truncated UTF-8) gets the binary-safe encoding. Overlong
 * encodings count as invalid UTF-8, since strict and lax decoders disagree
 * on them (e.g. 0xC0 0x80 for NUL).
 */
static bool value_is_plain_safe(const uint8_t *value, size_t len) {
        size_t i = 0;

        while (i < len) {
                uint8_t b = value[i];
                size_t seqlen;

                if (b < 0x20 && b != 0x09)
                        return false;

                if (b < 0x80) {
                        i++;
                        continue;
                }

                if ((b & 0xE0) == 0xC0)
                        seqlen = 2;
                else if ((b & 0xF0) == 0xE0)
                        seqlen = 3;
                else if ((b & 0xF8) == 0xF0)
                        seqlen = 4;
                else
                        return false;

                if (i + seqlen > len)
                        return false;

                for (size_t j = 1; j < seqlen; j++)
                        if ((value[i + j] & 0xC0) != 0x80)
                                return false;

                if (seqlen == 2 && b < 0xC2)
                        return false;
                if (seqlen == 3 && b == 0xE0 && value[i + 1] < 0xA0)
                        return false;
                if (seqlen == 4 && b == 0xF0 && value[i + 1] < 0x90)
                        return false;
                if (seqlen == 4 && b > 0xF4)
                        return false;

                i += seqlen;
        }

        return true;
}

/* journal_field_valid() (journal-file.c, allow_protected=true, so a leading
 * underscore is fine): 1-64 bytes, first byte not a digit, every byte in
 * [A-Z0-9_]. A real importer silently drops a bad name, so
 * logd_writer_append() refuses the whole entry. */
static bool field_name_valid(const char *name) {
        size_t len;

        if (!name)
                return false;

        len = strlen(name);
        if (len == 0 || len > 64)
                return false;

        if (name[0] >= '0' && name[0] <= '9')
                return false;

        for (size_t i = 0; i < len; i++) {
                char c = name[i];

                if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
                        return false;
        }

        return true;
}

static size_t field_encoded_size(const LogdField *f) {
        size_t name_len = strlen(f->name);

        if (value_is_plain_safe(f->value, f->value_len))
                return name_len + 1 + f->value_len + 1; /* NAME=value\n */

        return name_len + 1 + sizeof(uint64_t) + f->value_len + 1; /* NAME\n<len><data>\n */
}

static size_t field_encode(char *out, const LogdField *f) {
        size_t name_len = strlen(f->name);
        size_t off = 0;

        memcpy(out + off, f->name, name_len);
        off += name_len;

        if (value_is_plain_safe(f->value, f->value_len)) {
                out[off++] = '=';
                if (f->value_len > 0) {
                        memcpy(out + off, f->value, f->value_len);
                        off += f->value_len;
                }
                out[off++] = '\n';
                return off;
        }

        out[off++] = '\n';

        {
                uint64_t len_le = htole64((uint64_t) f->value_len);

                memcpy(out + off, &len_le, sizeof(len_le));
                off += sizeof(len_le);
        }

        if (f->value_len > 0) {
                memcpy(out + off, f->value, f->value_len);
                off += f->value_len;
        }
        out[off++] = '\n';

        return off;
}

static int writer_ring_path(LogdWriter *w, const char *name, char **ret) {
        char buf[4096];
        int len;
        char *copy;

        len = snprintf(buf, sizeof(buf), "%s/%s", w->runtime_dir, name);
        if (len < 0 || (size_t) len >= sizeof(buf))
                return -ENAMETOOLONG;

        copy = pico_strdup(buf);
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return 0;
}

/* One write() for the whole entry (see the header comment), retried only
 * across EINTR and short writes. An error after some bytes landed is backed
 * out with ftruncate(). */
static int write_full(int fd, const char *buf, size_t len, size_t original_size) {
        size_t off = 0;

        while (off < len) {
                ssize_t n = write(fd, buf + off, len - off);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;

                        if (off > 0)
                                if (ftruncate(fd, (off_t) original_size) < 0) {
                                        /* Already on the error path; the
                                         * short record is the lesser evil. */
                                }
                        return -errno;
                }

                if (n == 0) {
                        if (off > 0)
                                if (ftruncate(fd, (off_t) original_size) < 0) {
                                        /* Already on the error path; the
                                         * short record is the lesser evil. */
                                }
                        return -EIO;
                }

                off += (size_t) n;
        }

        return 0;
}

/*
 * Rotate: close, rename active -> rotated (atomic; replaces any previous
 * rotated file), reopen a fresh empty active. Only called after a complete
 * record landed. Even if the rename fails, it still tries to leave
 * w->active_fd open on an active file so the writer stays usable.
 */
static int rotate_if_needed(LogdWriter *w) {
        char *active_path = NULL, *rotated_path = NULL;
        int r, new_fd;

        if (w->active_size < w->max_bytes / 2)
                return 0;

        r = writer_ring_path(w, LOGD_RING_ACTIVE_NAME, &active_path);
        if (r < 0)
                return r;

        r = writer_ring_path(w, LOGD_RING_ROTATED_NAME, &rotated_path);
        if (r < 0) {
                free(active_path);
                return r;
        }

        if (w->active_fd >= 0) {
                (void) close(w->active_fd);
                w->active_fd = -1;
        }

        r = 0;
        if (rename(active_path, rotated_path) < 0)
                r = -errno; /* still try to reopen active below */

        new_fd = open(active_path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0644);
        if (new_fd < 0) {
                if (r == 0)
                        r = -errno;
        } else {
                w->active_fd = new_fd;
                w->active_size = 0;
        }

        free(active_path);
        free(rotated_path);
        return r;
}

int logd_writer_new(LogdWriter **ret) {
        LogdWriter *w;

        if (!ret)
                return -EINVAL;

        w = calloc(1, sizeof(*w));
        if (!w)
                return -ENOMEM;

        w->active_fd = -1;
        w->max_bytes = LOGD_DEFAULT_MAX_BYTES;

        w->runtime_dir = pico_strdup(LOGD_RUNTIME_DIR);
        if (!w->runtime_dir) {
                free(w);
                return -ENOMEM;
        }

        *ret = w;
        return 0;
}

LogdWriter *logd_writer_free(LogdWriter *w) {
        if (!w)
                return NULL;

        if (w->active_fd >= 0)
                (void) close(w->active_fd);

        free(w->runtime_dir);
        free(w);
        return NULL;
}

int logd_writer_set_runtime_dir(LogdWriter *w, const char *dir) {
        char *copy;

        if (!w || !dir)
                return -EINVAL;

        if (w->active_fd >= 0)
                return -EBUSY;

        copy = pico_strdup(dir);
        if (!copy)
                return -ENOMEM;

        free(w->runtime_dir);
        w->runtime_dir = copy;
        return 0;
}

int logd_writer_set_max_bytes(LogdWriter *w, size_t max_bytes) {
        if (!w || max_bytes == 0)
                return -EINVAL;

        w->max_bytes = max_bytes;
        return 0;
}

int logd_writer_set_boot_id(LogdWriter *w, const char *id) {
        uint8_t parsed[LOGD_BOOT_ID_BYTES];

        if (!w || !id || strlen(id) != LOGD_BOOT_ID_STRLEN)
                return -EINVAL;

        for (size_t i = 0; i < LOGD_BOOT_ID_BYTES; i++) {
                int hi = unhex_digit(id[i * 2]);
                int lo = unhex_digit(id[i * 2 + 1]);

                if (hi < 0 || lo < 0)
                        return -EINVAL;

                parsed[i] = (uint8_t) ((hi << 4) | lo);
        }

        memcpy(w->boot_id, parsed, sizeof(parsed));
        w->boot_id_set = true;
        return 0;
}

int logd_writer_open(LogdWriter *w) {
        char *active_path;
        struct stat st;
        int r;

        if (!w || !w->runtime_dir)
                return -EINVAL;

        if (w->active_fd >= 0)
                return 0;

        if (mkdir(w->runtime_dir, 0755) < 0 && errno != EEXIST)
                return -errno;

        if (!w->boot_id_set) {
                r = read_boot_id(w->boot_id);
                if (r < 0)
                        return r;
                w->boot_id_set = true;
        }

        r = writer_ring_path(w, LOGD_RING_ACTIVE_NAME, &active_path);
        if (r < 0)
                return r;

        w->active_fd = open(active_path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0644);
        if (w->active_fd < 0) {
                r = -errno;
                free(active_path);
                return r;
        }
        free(active_path);

        w->active_size = fstat(w->active_fd, &st) == 0 ? (size_t) st.st_size : 0;

        return 0;
}

int logd_writer_append(LogdWriter *w, const LogdField *fields, size_t n_fields) {
        char realtime_buf[32], monotonic_buf[32], boot_id_buf[LOGD_BOOT_ID_STRLEN + 1];
        LogdField auto_fields[3];
        /* Initialised only to satisfy -Wmaybe-uninitialised at -Os. */
        usec_t realtime = 0;
        usec_t monotonic;
        char *buf;
        size_t total = 0, off = 0;
        int r;

        if (!w || (!fields && n_fields > 0))
                return -EINVAL;

        if (w->active_fd < 0)
                return -EBADF;

        r = now_realtime(&realtime);
        if (r < 0)
                return r;

        /* now_monotonic() (util.h) returns USEC_INFINITY on clock_gettime()
         * failure, which fails VALID_MONOTONIC's < 2^55 bound and would make
         * a real importer reject the entry. */
        monotonic = now_monotonic();
        if (monotonic == USEC_INFINITY)
                return -EIO;

        snprintf(realtime_buf, sizeof(realtime_buf), "%" PRIu64, (uint64_t) realtime);
        snprintf(monotonic_buf, sizeof(monotonic_buf), "%" PRIu64, (uint64_t) monotonic);
        boot_id_to_string(w->boot_id, boot_id_buf);

        auto_fields[0] = (LogdField){ "__REALTIME_TIMESTAMP", realtime_buf, strlen(realtime_buf) };
        auto_fields[1] = (LogdField){ "__MONOTONIC_TIMESTAMP", monotonic_buf, strlen(monotonic_buf) };
        auto_fields[2] = (LogdField){ "_BOOT_ID", boot_id_buf, strlen(boot_id_buf) };

        /* Validate and size everything before writing anything. */
        for (size_t i = 0; i < 3; i++)
                total += field_encoded_size(&auto_fields[i]);

        for (size_t i = 0; i < n_fields; i++) {
                if (!field_name_valid(fields[i].name))
                        return -EINVAL;
                total += field_encoded_size(&fields[i]);
        }
        total += 1; /* blank-line entry separator */

        if (total > w->max_bytes)
                return -EMSGSIZE;

        buf = malloc(total);
        if (!buf)
                return -ENOMEM;

        for (size_t i = 0; i < 3; i++)
                off += field_encode(buf + off, &auto_fields[i]);
        for (size_t i = 0; i < n_fields; i++)
                off += field_encode(buf + off, &fields[i]);
        buf[off++] = '\n';

        r = write_full(w->active_fd, buf, off, w->active_size);
        free(buf);
        if (r < 0)
                return r;

        w->active_size += off;

        return rotate_if_needed(w);
}

int logd_writer_active_path(LogdWriter *w, char **ret) {
        if (!w || !ret)
                return -EINVAL;

        return writer_ring_path(w, LOGD_RING_ACTIVE_NAME, ret);
}

int logd_writer_rotated_path(LogdWriter *w, char **ret) {
        if (!w || !ret)
                return -EINVAL;

        return writer_ring_path(w, LOGD_RING_ROTATED_NAME, ret);
}
