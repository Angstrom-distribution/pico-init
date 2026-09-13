/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The ring reader. Shared by picolog and picoctl -- see the header for the
 * ownership rules and the API split (plan §3.4, milestone J3).
 *
 * PARSER. The writer (logd-write.c) only ever produces well-formed entries
 * and only ever rotates right after one completes, so this does not need
 * to be adversarial-grade the way logd-write.c's tests hold the *writer* to
 * (a real journal-importer.c oracle) -- this reads our own trusted, root-
 * owned tmpfs ring back. What it must still get right, because both are
 * real and not merely theoretical: a torn final record from a crash mid-
 * append (logd-write.c's own crash-safety section), and a rotation racing
 * a `picolog -f` mid-read. Both are handled the same way -- an incomplete
 * span is never surfaced as data, only ever completed later or (for a
 * genuinely corrupt span, not expected in practice but not assumed
 * impossible either) skipped to the next entry boundary.
 *
 * libc only, deliberately: libsystemd-compat link_wholes this file for
 * sd-journal's read side, and a shared libsystemd.so must not carry
 * pico-init-core's util.c/log symbols -- so no "../util.h" here.
 */

#include "logd-read.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "logd.h"

#define MAX_FIELDS_PER_ENTRY 64
#define MAX_FIELD_VALUE_LEN \
        ((uint64_t) (16 * 1024 * 1024)) /* sanity ceiling against a corrupt length header */

struct LogdRing {
        char *buf;
        size_t buf_len;
        LogdEntry *entries;
        size_t n_entries;
};

struct LogdFollow {
        char *active_path;
        int fd;
        dev_t dev;
        ino_t ino;
        bool have_stat;
        char *buf; /* unconsumed bytes: a partial trailing entry, plus anything newly read */
        size_t buf_len;
};

static int ring_path(const char *runtime_dir, const char *name, char **ret) {
        char buf[4096];
        int len;
        char *copy;

        len = snprintf(buf, sizeof(buf), "%s/%s", runtime_dir, name);
        if (len < 0 || (size_t) len >= sizeof(buf))
                return -ENAMETOOLONG;

        copy = strdup(buf);
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return 0;
}

/* Append the whole content of `path` onto the (buf, len) pair. A missing
 * file is not an error -- the rotated file legitimately does not exist yet
 * on a young ring, and by design a missing ring altogether just yields zero
 * entries. */
static int append_file_contents(const char *path, char **buf, size_t *len) {
        int fd;
        struct stat st;
        char *new_buf;
        size_t off;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return errno == ENOENT ? 0 : -errno;

        if (fstat(fd, &st) < 0) {
                int r = -errno;

                close(fd);
                return r;
        }

        if (st.st_size <= 0) {
                close(fd);
                return 0;
        }

        new_buf = realloc(*buf, *len + (size_t) st.st_size);
        if (!new_buf) {
                close(fd);
                return -ENOMEM;
        }
        *buf = new_buf;

        off = 0;
        while (off < (size_t) st.st_size) {
                ssize_t n = read(fd, *buf + *len + off, (size_t) st.st_size - off);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;

                        close(fd);
                        return -errno;
                }
                if (n == 0)
                        break; /* file shrank/rotated mid-read: take what was read, not an error */

                off += (size_t) n;
        }

        *len += off;
        close(fd);
        return 0;
}

static uint64_t decode_le64(const uint8_t *p) {
        uint64_t v = 0;

        for (int i = 0; i < 8; i++)
                v |= ((uint64_t) p[i]) << (8 * i);

        return v;
}

/* Scan forward from `start` for the next blank-line separator; *end_out is
 * set to just past it on success. Used only on a corrupt span, to resync
 * without surfacing the bad bytes as an entry. */
static bool skip_to_blank_line(const char *buf, size_t len, size_t start, size_t *end_out) {
        for (size_t i = start; i + 1 < len; i++)
                if (buf[i] == '\n' && buf[i + 1] == '\n') {
                        *end_out = i + 2;
                        return true;
                }

        return false;
}

typedef enum {
        ENTRY_INCOMPLETE, /* need more data; end_out not set */
        ENTRY_OK,         /* fields_out, n_fields_out and end_out all set */
        ENTRY_SKIP,       /* corrupt and resynced; *end_out set, nothing else */
} ParseResult;

/*
 * Parse one entry starting at buf[start..len). Field values/names are
 * views into `buf` -- see this file's header on why that is safe as long
 * as the caller keeps `buf` alive at least as long as the result.
 */
static ParseResult
                parse_one_entry(const char *buf,
                                size_t len,
                                size_t start,
                                LogdReadField *fields_out,
                                size_t *n_fields_out,
                                size_t *end_out) {

        size_t pos = start;
        size_t n = 0;

        for (;;) {
                const char *nl;
                size_t line_len;
                const char *eq;

                if (pos >= len)
                        return ENTRY_INCOMPLETE;

                nl = memchr(buf + pos, '\n', len - pos);
                if (!nl)
                        return ENTRY_INCOMPLETE;

                line_len = (size_t) (nl - (buf + pos));

                if (line_len == 0) {
                        *end_out = pos + 1;
                        *n_fields_out = n;
                        return ENTRY_OK;
                }

                eq = memchr(buf + pos, '=', line_len);

                if (eq) {
                        if (n < MAX_FIELDS_PER_ENTRY) {
                                fields_out[n].name = buf + pos;
                                fields_out[n].name_len = (size_t) (eq - (buf + pos));
                                fields_out[n].value = eq + 1;
                                fields_out[n].value_len = (size_t) (nl - (eq + 1));
                                fields_out[n].binary = false;
                                n++;
                        }
                        pos = pos + line_len + 1;
                        continue;
                }

                {
                        size_t name_start = pos, name_len = line_len;
                        size_t header_start = pos + line_len + 1;
                        uint64_t value_len;
                        size_t data_start;

                        if (header_start + 8 > len)
                                return ENTRY_INCOMPLETE;

                        value_len = decode_le64((const uint8_t *) (buf + header_start));
                        if (value_len > MAX_FIELD_VALUE_LEN)
                                return skip_to_blank_line(buf, len, start, end_out) ? ENTRY_SKIP :
                                                                                      ENTRY_INCOMPLETE;

                        data_start = header_start + 8;

                        if (data_start + (size_t) value_len + 1 > len)
                                return ENTRY_INCOMPLETE;

                        if (buf[data_start + (size_t) value_len] != '\n')
                                return skip_to_blank_line(buf, len, start, end_out) ? ENTRY_SKIP :
                                                                                      ENTRY_INCOMPLETE;

                        if (n < MAX_FIELDS_PER_ENTRY) {
                                fields_out[n].name = buf + name_start;
                                fields_out[n].name_len = name_len;
                                fields_out[n].value = buf + data_start;
                                fields_out[n].value_len = (size_t) value_len;
                                fields_out[n].binary = true;
                                n++;
                        }
                        pos = data_start + (size_t) value_len + 1;
                }
        }
}

/* Parse as many complete entries as exist in buf[0..len), aliasing `buf`
 * (which must outlive the result). *consumed is how much of `buf` was part
 * of a complete (or skipped-corrupt) entry; anything after it is a
 * still-incomplete tail, left unconsumed on purpose. 0 or -ENOMEM. */
static int parse_entries(const char *buf, size_t len, LogdEntry **out, size_t *n_out, size_t *consumed) {
        LogdEntry *entries = NULL;
        size_t n = 0, cap = 0;
        size_t pos = 0;

        for (;;) {
                LogdReadField fields[MAX_FIELDS_PER_ENTRY];
                size_t n_fields = 0, end = 0;
                ParseResult r = parse_one_entry(buf, len, pos, fields, &n_fields, &end);

                if (r == ENTRY_INCOMPLETE)
                        break;

                if (r == ENTRY_SKIP) {
                        pos = end;
                        continue;
                }

                if (n == cap) {
                        size_t new_cap = cap == 0 ? 16 : cap * 2;
                        LogdEntry *tmp = realloc(entries, new_cap * sizeof(*entries));

                        if (!tmp) {
                                for (size_t i = 0; i < n; i++)
                                        free(entries[i].fields);
                                free(entries);
                                return -ENOMEM;
                        }
                        entries = tmp;
                        cap = new_cap;
                }

                entries[n].fields = n_fields > 0 ? malloc(n_fields * sizeof(LogdReadField)) : NULL;
                if (n_fields > 0 && !entries[n].fields) {
                        for (size_t i = 0; i < n; i++)
                                free(entries[i].fields);
                        free(entries);
                        return -ENOMEM;
                }
                if (n_fields > 0)
                        memcpy(entries[n].fields, fields, n_fields * sizeof(LogdReadField));
                entries[n].n_fields = n_fields;
                entries[n].raw = buf + pos;
                entries[n].raw_len = end - pos;
                n++;

                pos = end;
        }

        *out = entries;
        *n_out = n;
        *consumed = pos;
        return 0;
}

static void ring_init(LogdRing *ring, char *buf, size_t buf_len, LogdEntry *entries, size_t n_entries) {
        ring->buf = buf;
        ring->buf_len = buf_len;
        ring->entries = entries;
        ring->n_entries = n_entries;
}

const LogdReadField *logd_entry_field(const LogdEntry *e, const char *name) {
        size_t name_len;

        if (!e || !name)
                return NULL;

        name_len = strlen(name);

        for (size_t i = 0; i < e->n_fields; i++)
                if (e->fields[i].name_len == name_len && memcmp(e->fields[i].name, name, name_len) == 0)
                        return &e->fields[i];

        return NULL;
}

bool logd_field_equals(const LogdReadField *f, const char *s) {
        size_t s_len;

        if (!f || !s)
                return false;

        s_len = strlen(s);

        return f->value_len == s_len && memcmp(f->value, s, s_len) == 0;
}

bool logd_entry_matches_unit(const LogdEntry *e, const char *unit) {
        if (!unit)
                return true;

        return logd_field_equals(logd_entry_field(e, "_SYSTEMD_UNIT"), unit);
}

bool logd_entry_matches_priority(const LogdEntry *e, int max_priority) {
        const LogdReadField *f = logd_entry_field(e, "PRIORITY");
        char numbuf[16];
        char *endp;
        long v;

        if (!f || f->binary || f->value_len == 0 || f->value_len >= sizeof(numbuf))
                return false;

        memcpy(numbuf, f->value, f->value_len);
        numbuf[f->value_len] = '\0';

        v = strtol(numbuf, &endp, 10);
        if (endp == numbuf || *endp != '\0')
                return false;

        return v <= max_priority;
}

bool logd_entry_is_kernel(const LogdEntry *e) {
        return logd_field_equals(logd_entry_field(e, "_TRANSPORT"), "kernel");
}

int logd_ring_read(const char *runtime_dir, LogdRing **ret) {
        char *rotated_path = NULL, *active_path = NULL;
        char *buf = NULL;
        size_t len = 0, consumed = 0;
        LogdEntry *entries = NULL;
        size_t n_entries = 0;
        LogdRing *ring;
        int r;

        if (!runtime_dir || !ret)
                return -EINVAL;

        r = ring_path(runtime_dir, LOGD_RING_ROTATED_NAME, &rotated_path);
        if (r < 0)
                return r;

        r = ring_path(runtime_dir, LOGD_RING_ACTIVE_NAME, &active_path);
        if (r < 0) {
                free(rotated_path);
                return r;
        }

        r = append_file_contents(rotated_path, &buf, &len);
        if (r == 0)
                r = append_file_contents(active_path, &buf, &len);

        free(rotated_path);
        free(active_path);

        if (r < 0) {
                free(buf);
                return r;
        }

        r = parse_entries(buf, len, &entries, &n_entries, &consumed);
        if (r < 0) {
                free(buf);
                return r;
        }

        ring = calloc(1, sizeof(*ring));
        if (!ring) {
                for (size_t i = 0; i < n_entries; i++)
                        free(entries[i].fields);
                free(entries);
                free(buf);
                return -ENOMEM;
        }

        ring_init(ring, buf, len, entries, n_entries);

        *ret = ring;
        return 0;
}

LogdRing *logd_ring_free(LogdRing *r) {
        if (!r)
                return NULL;

        for (size_t i = 0; i < r->n_entries; i++)
                free(r->entries[i].fields);
        free(r->entries);
        free(r->buf);
        free(r);
        return NULL;
}

size_t logd_ring_n_entries(const LogdRing *r) {
        return r ? r->n_entries : 0;
}

const LogdEntry *logd_ring_entry(const LogdRing *r, size_t index) {
        if (!r || index >= r->n_entries)
                return NULL;

        return &r->entries[index];
}

int logd_ring_read_filtered(const char *runtime_dir, const char *unit, size_t max_entries, LogdRing **ret) {
        LogdRing *full;
        LogdRing *filtered;
        size_t n_match = 0, keep, skip_from_start;
        int r;

        if (!ret)
                return -EINVAL;

        r = logd_ring_read(runtime_dir, &full);
        if (r < 0)
                return r;

        /* Count matches first so the tail-N cutoff is exact without a
         * two-pass realloc dance below. */
        for (size_t i = 0; i < full->n_entries; i++)
                if (logd_entry_matches_unit(&full->entries[i], unit))
                        n_match++;

        keep = (max_entries > 0 && max_entries < n_match) ? max_entries : n_match;
        skip_from_start = n_match - keep;

        filtered = calloc(1, sizeof(*filtered));
        if (!filtered) {
                logd_ring_free(full);
                return -ENOMEM;
        }

        filtered->entries = keep > 0 ? malloc(keep * sizeof(LogdEntry)) : NULL;
        if (keep > 0 && !filtered->entries) {
                free(filtered);
                logd_ring_free(full);
                return -ENOMEM;
        }

        {
                size_t seen = 0, out_idx = 0;

                for (size_t i = 0; i < full->n_entries && out_idx < keep; i++) {
                        if (!logd_entry_matches_unit(&full->entries[i], unit))
                                continue;

                        if (seen < skip_from_start) {
                                seen++;
                                continue;
                        }

                        /* Steal this entry's field array; blank the source
                         * slot so freeing `full` below never double-frees
                         * it. */
                        filtered->entries[out_idx] = full->entries[i];
                        full->entries[i].fields = NULL;
                        full->entries[i].n_fields = 0;
                        out_idx++;
                        seen++;
                }

                filtered->n_entries = out_idx;
        }

        /* The kept entries' raw/value pointers still alias full->buf, so it
         * must outlive them -- move it into `filtered` rather than freeing
         * it along with the rest of `full`. */
        filtered->buf = full->buf;
        filtered->buf_len = full->buf_len;
        full->buf = NULL;

        logd_ring_free(full);

        *ret = filtered;
        return 0;
}

int logd_follow_new(const char *runtime_dir, LogdFollow **ret) {
        LogdFollow *f;
        int r;

        if (!runtime_dir || !ret)
                return -EINVAL;

        f = calloc(1, sizeof(*f));
        if (!f)
                return -ENOMEM;

        f->fd = -1;

        r = ring_path(runtime_dir, LOGD_RING_ACTIVE_NAME, &f->active_path);
        if (r < 0) {
                free(f);
                return r;
        }

        /* Best-effort: seek to the current end so no historical entries are
         * delivered. A ring that does not exist yet is not an error --
         * logd_follow_poll() opens it lazily on a later call. */
        {
                struct stat st;
                int fd = open(f->active_path, O_RDONLY | O_CLOEXEC);

                if (fd >= 0) {
                        if (fstat(fd, &st) == 0 && lseek(fd, st.st_size, SEEK_SET) >= 0) {
                                f->fd = fd;
                                f->dev = st.st_dev;
                                f->ino = st.st_ino;
                                f->have_stat = true;
                        } else
                                close(fd);
                }
        }

        *ret = f;
        return 0;
}

LogdFollow *logd_follow_free(LogdFollow *f) {
        if (!f)
                return NULL;

        if (f->fd >= 0)
                close(f->fd);

        free(f->active_path);
        free(f->buf);
        free(f);
        return NULL;
}

/* Drain whatever is currently readable on `fd` into f->buf. */
static int follow_drain(LogdFollow *f, int fd) {
        for (;;) {
                char tmp[65536];
                ssize_t n = read(fd, tmp, sizeof(tmp));
                char *grown;

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (n == 0)
                        return 0;

                grown = realloc(f->buf, f->buf_len + (size_t) n);
                if (!grown)
                        return -ENOMEM;

                f->buf = grown;
                memcpy(f->buf + f->buf_len, tmp, (size_t) n);
                f->buf_len += (size_t) n;
        }
}

int logd_follow_poll(LogdFollow *f, LogdRing **ret) {
        struct stat st;
        int r;

        if (!f || !ret)
                return -EINVAL;

        *ret = NULL;

        if (stat(f->active_path, &st) < 0)
                return errno == ENOENT ?
                                0 :
                                -errno; /* momentarily missing mid-rotation: nothing new, not an error */

        if (!f->have_stat || st.st_dev != f->dev || st.st_ino != f->ino) {
                /* First open, or rotation replaced the file underneath us.
                 * Drain whatever remains of the OLD fd first: logd-write.c
                 * only rotates right after a complete append, so there
                 * should be no leftover partial tail there, but read-and-
                 * parse rather than assume it. */
                if (f->fd >= 0) {
                        r = follow_drain(f, f->fd);
                        close(f->fd);
                        f->fd = -1;
                        if (r < 0)
                                return r;
                }

                {
                        int fd = open(f->active_path, O_RDONLY | O_CLOEXEC);

                        if (fd < 0)
                                return errno == ENOENT ? 0 : -errno;

                        f->fd = fd;
                        f->dev = st.st_dev;
                        f->ino = st.st_ino;
                        f->have_stat = true;
                }
        }

        r = follow_drain(f, f->fd);
        if (r < 0)
                return r;

        if (f->buf_len == 0)
                return 0;

        {
                LogdEntry *parsed = NULL;
                size_t n_parsed = 0, consumed = 0;
                char *batch_buf;
                LogdRing *ring;

                r = parse_entries(f->buf, f->buf_len, &parsed, &n_parsed, &consumed);
                if (r < 0)
                        return r;

                if (n_parsed == 0)
                        return 0; /* still accumulating a partial entry */

                /* Copy the consumed span into its own buffer so this batch
                 * outlives f->buf, which keeps mutating across future
                 * polls -- see logd-read.h. */
                batch_buf = malloc(consumed);
                if (!batch_buf) {
                        for (size_t i = 0; i < n_parsed; i++)
                                free(parsed[i].fields);
                        free(parsed);
                        return -ENOMEM;
                }
                memcpy(batch_buf, f->buf, consumed);

                for (size_t i = 0; i < n_parsed; i++) {
                        size_t raw_off = (size_t) ((const char *) parsed[i].raw - f->buf);

                        parsed[i].raw = batch_buf + raw_off;
                        for (size_t j = 0; j < parsed[i].n_fields; j++) {
                                size_t name_off = (size_t) (parsed[i].fields[j].name - f->buf);
                                size_t value_off = (size_t) ((const char *) parsed[i].fields[j].value - f->buf);

                                parsed[i].fields[j].name = batch_buf + name_off;
                                parsed[i].fields[j].value = batch_buf + value_off;
                        }
                }

                {
                        size_t remaining = f->buf_len - consumed;

                        if (remaining > 0)
                                memmove(f->buf, f->buf + consumed, remaining);
                        f->buf_len = remaining;
                }

                ring = calloc(1, sizeof(*ring));
                if (!ring) {
                        for (size_t i = 0; i < n_parsed; i++)
                                free(parsed[i].fields);
                        free(parsed);
                        free(batch_buf);
                        return -ENOMEM;
                }

                ring_init(ring, batch_buf, consumed, parsed, n_parsed);
                *ret = ring;
        }

        return 0;
}
