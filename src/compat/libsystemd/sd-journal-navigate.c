/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Position, seek, cursor and wakeup (inotify) functions. They walk the
 * LogdRing loaded by sd_journal_open() or the last sd_journal_process(); the
 * wakeup half watches logd's ring directory for the writer's renames/appends.
 *
 * Cursor format is pico-specific: "b=<32hex bootid>;m=<mono>;r=<realtime>".
 * Cursors are opaque per sd_journal_get_cursor(3), so a journalctl cursor
 * failing sd_journal_seek_cursor()'s parse with -EINVAL is expected.
 */

/* asprintf() is a GNU extension; -std=gnu17 alone does not imply _GNU_SOURCE. */
#define _GNU_SOURCE

#include "sd-journal-internal.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* --- next/previous --- */

static void land_on(sd_journal *j, size_t idx) {
        j->pos = idx;
        j->loc = SD_J_ON_ENTRY;
        j->seek_pending = false;
        j->data_idx = 0;
}

int sd_journal_next(sd_journal *j) {
        size_t n, start;

        if (!j)
                return -EINVAL;

        n = logd_ring_n_entries(j->ring);

        if (j->seek_pending)
                start = j->seek_boundary;
        else if (j->loc == SD_J_AFTER_TAIL)
                return 0; /* nothing after the tail, ever */
        else if (j->loc == SD_J_ON_ENTRY)
                start = j->pos + 1;
        else
                start = 0; /* SD_J_BEFORE_HEAD */

        for (size_t i = start; i < n; i++)
                if (journal_entry_matches(j, logd_ring_entry(j->ring, i))) {
                        land_on(j, i);
                        return 1;
                }

        j->loc = SD_J_AFTER_TAIL;
        j->seek_pending = false;
        return 0;
}

int sd_journal_previous(sd_journal *j) {
        ssize_t start;
        size_t n;

        if (!j)
                return -EINVAL;

        n = logd_ring_n_entries(j->ring);

        if (j->seek_pending)
                start = (ssize_t) j->seek_boundary - 1;
        else if (j->loc == SD_J_BEFORE_HEAD)
                return 0; /* nothing before the head, ever */
        else if (j->loc == SD_J_ON_ENTRY)
                start = (ssize_t) j->pos - 1;
        else
                start = (ssize_t) n - 1; /* SD_J_AFTER_TAIL */

        for (ssize_t i = start; i >= 0; i--)
                if (journal_entry_matches(j, logd_ring_entry(j->ring, (size_t) i))) {
                        land_on(j, (size_t) i);
                        return 1;
                }

        j->loc = SD_J_BEFORE_HEAD;
        j->seek_pending = false;
        return 0;
}

int sd_journal_step_one(sd_journal *j, int advanced) {
        if (!j)
                return -EINVAL;

        if (j->loc == SD_J_BEFORE_HEAD && !j->seek_pending)
                return sd_journal_next(j);
        if (j->loc == SD_J_AFTER_TAIL && !j->seek_pending)
                return sd_journal_previous(j);

        return advanced ? sd_journal_next(j) : sd_journal_previous(j);
}

int sd_journal_next_skip(sd_journal *j, uint64_t skip) {
        uint64_t count = 0;

        if (!j)
                return -EINVAL;

        if (skip == 0) {
                /* As upstream (real_journal_next_skip()): skip==0 resolves a
                 * pending seek or BEFORE_HEAD/AFTER_TAIL position via one
                 * sd_journal_next() but counts no movement and returns 0. */
                if (j->loc != SD_J_ON_ENTRY || j->seek_pending) {
                        int r = sd_journal_next(j);

                        if (r < 0)
                                return r;
                }
                return 0;
        }

        while (count < skip) {
                int r = sd_journal_next(j);

                if (r < 0)
                        return r;
                if (r == 0)
                        break;
                count++;
        }

        return (int) count;
}

int sd_journal_previous_skip(sd_journal *j, uint64_t skip) {
        uint64_t count = 0;

        if (!j)
                return -EINVAL;

        if (skip == 0) {
                /* Mirror of sd_journal_next_skip() above. */
                if (j->loc != SD_J_ON_ENTRY || j->seek_pending) {
                        int r = sd_journal_previous(j);

                        if (r < 0)
                                return r;
                }
                return 0;
        }

        while (count < skip) {
                int r = sd_journal_previous(j);

                if (r < 0)
                        return r;
                if (r == 0)
                        break;
                count++;
        }

        return (int) count;
}

/* --- seek --- */

int sd_journal_seek_head(sd_journal *j) {
        if (!j)
                return -EINVAL;

        j->loc = SD_J_BEFORE_HEAD;
        j->seek_pending = false;
        return 0;
}

int sd_journal_seek_tail(sd_journal *j) {
        if (!j)
                return -EINVAL;

        j->loc = SD_J_AFTER_TAIL;
        j->seek_pending = false;
        return 0;
}

/* Sets a pending boundary seek to the first index whose (monotonic,
 * realtime) key is >= (want_mono, want_real) -- realtime-only callers pass
 * want_mono=0 and skip_mono=true so a missing/unparsable clock on some
 * entry can't stop the scan; monotonic-only callers do the mirror. */
static int seek_boundary_by_clock(
                sd_journal *j, bool skip_mono, uint64_t want_mono, bool skip_real, uint64_t want_real) {
        size_t n = logd_ring_n_entries(j->ring);
        size_t found = n;

        for (size_t i = 0; i < n; i++) {
                uint64_t mono = 0, real = 0;
                int r = journal_entry_clocks(
                                logd_ring_entry(j->ring, i), skip_mono ? NULL : &mono, skip_real ? NULL : &real);

                if (r < 0)
                        continue; /* unparsable clock on one entry must not abort the whole seek */

                if ((skip_mono || mono >= want_mono) && (skip_real || real >= want_real)) {
                        found = i;
                        break;
                }
        }

        j->seek_boundary = found;
        j->seek_pending = true;
        j->loc = SD_J_BEFORE_HEAD; /* no current entry until next()/previous() lands */
        return 0;
}

int sd_journal_seek_realtime_usec(sd_journal *j, uint64_t usec) {
        if (!j)
                return -EINVAL;

        return seek_boundary_by_clock(j, true, 0, false, usec);
}

int sd_journal_seek_monotonic_usec(sd_journal *j, sd_id128_t boot_id, uint64_t usec) {
        static const sd_id128_t null_id = {
                .qwords = { 0, 0 }
        };
        sd_id128_t current;
        int r;

        if (!j)
                return -EINVAL;

        if (memcmp(&boot_id, &null_id, sizeof(boot_id)) != 0) {
                r = journal_current_boot_id(&current);
                if (r < 0)
                        return r;

                if (memcmp(&boot_id, &current, sizeof(boot_id)) != 0) {
                        /* A different, unknown boot: pico's /run ring only ever holds the
                         * current boot, so this genuinely has no data. */
                        j->loc = SD_J_AFTER_TAIL;
                        j->seek_pending = false;
                        return 0;
                }
        }

        return seek_boundary_by_clock(j, false, usec, true, 0);
}

/* --- cursor --- */

int sd_journal_get_cursor(sd_journal *j, char **ret) {
        const LogdEntry *e;
        const LogdReadField *boot;
        uint64_t mono, real;
        int r;

        if (!j || !ret)
                return -EINVAL;

        e = journal_current_entry(j);
        if (!e)
                return -EADDRNOTAVAIL;

        r = journal_entry_clocks(e, &mono, &real);
        if (r < 0)
                return r;

        boot = logd_entry_field(e, "_BOOT_ID");
        if (!boot || boot->binary || boot->value_len != 32)
                return -EBADMSG;

        if (asprintf(ret, "b=%.32s;m=%" PRIu64 ";r=%" PRIu64, (const char *) boot->value, mono, real) < 0)
                return -ENOMEM;

        return 0;
}

/* Shared by seek_cursor() and test_cursor(): parses "k=v;k=v;..." into the
 * three fields a pico cursor may carry. Returns 0, or -EINVAL for anything
 * outside that grammar, including a journalctl cursor. */
typedef struct ParsedCursor {
        bool have_boot;
        char boot[33];
        bool have_mono;
        uint64_t mono;
        bool have_real;
        uint64_t real;
} ParsedCursor;

static int parse_cursor(const char *cursor, ParsedCursor *out) {
        char *copy, *save = NULL, *tok;

        memset(out, 0, sizeof(*out));

        if (!cursor || cursor[0] == '\0')
                return -EINVAL;

        copy = strdup(cursor);
        if (!copy)
                return -ENOMEM;

        for (tok = strtok_r(copy, ";", &save); tok; tok = strtok_r(NULL, ";", &save)) {
                char *eq = strchr(tok, '=');
                char *endp;

                if (!eq || eq == tok) {
                        free(copy);
                        return -EINVAL;
                }

                if (eq[1] == '\0') {
                        free(copy);
                        return -EINVAL;
                }

                if (tok[0] == 'b' && eq == tok + 1) {
                        size_t len = strlen(eq + 1);

                        if (len != 32) {
                                free(copy);
                                return -EINVAL;
                        }
                        memcpy(out->boot, eq + 1, 32);
                        out->boot[32] = '\0';
                        out->have_boot = true;
                } else if (tok[0] == 'm' && eq == tok + 1) {
                        out->mono = strtoull(eq + 1, &endp, 10);
                        if (*endp != '\0') {
                                free(copy);
                                return -EINVAL;
                        }
                        out->have_mono = true;
                } else if (tok[0] == 'r' && eq == tok + 1) {
                        out->real = strtoull(eq + 1, &endp, 10);
                        if (*endp != '\0') {
                                free(copy);
                                return -EINVAL;
                        }
                        out->have_real = true;
                } else {
                        free(copy);
                        return -EINVAL;
                }
        }

        free(copy);

        if (!out->have_mono && !out->have_real)
                return -EINVAL;

        return 0;
}

int sd_journal_seek_cursor(sd_journal *j, const char *cursor) {
        ParsedCursor pc;
        int r;

        if (!j)
                return -EINVAL;

        r = parse_cursor(cursor, &pc);
        if (r < 0)
                return r;

        if (pc.have_boot) {
                sd_id128_t want, current;

                if (!journal_parse_boot_id(pc.boot, 32, &want))
                        return -EINVAL;

                r = journal_current_boot_id(&current);
                if (r < 0)
                        return r;

                if (memcmp(&want, &current, sizeof(want)) != 0) {
                        j->loc = SD_J_AFTER_TAIL;
                        j->seek_pending = false;
                        return 0;
                }
        }

        return seek_boundary_by_clock(j, !pc.have_mono, pc.mono, !pc.have_real, pc.real);
}

int sd_journal_test_cursor(sd_journal *j, const char *cursor) {
        const LogdEntry *e;
        ParsedCursor pc;
        int r;

        if (!j)
                return -EINVAL;

        e = journal_current_entry(j);
        if (!e)
                return -EADDRNOTAVAIL;

        r = parse_cursor(cursor, &pc);
        if (r < 0)
                return r;

        if (pc.have_boot) {
                const LogdReadField *boot = logd_entry_field(e, "_BOOT_ID");

                if (!boot || boot->binary || boot->value_len != 32 || memcmp(boot->value, pc.boot, 32) != 0)
                        return 0;
        }

        if (pc.have_mono || pc.have_real) {
                uint64_t mono = 0, real = 0;

                r = journal_entry_clocks(e, pc.have_mono ? &mono : NULL, pc.have_real ? &real : NULL);
                if (r < 0)
                        return 0;

                if (pc.have_mono && mono != pc.mono)
                        return 0;
                if (pc.have_real && real != pc.real)
                        return 0;
        }

        return 1;
}

/* --- wakeup --- */

int sd_journal_get_fd(sd_journal *j) {
        if (!j)
                return -EINVAL;

        if (j->flags & SD_JOURNAL_ASSUME_IMMUTABLE)
                return -EUNATCH;

        if (j->inotify_fd >= 0)
                return j->inotify_fd;

        j->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (j->inotify_fd < 0)
                return -errno;

        j->inotify_wd = inotify_add_watch(j->inotify_fd, j->runtime_dir, IN_CREATE | IN_MODIFY | IN_MOVED_TO);
        if (j->inotify_wd < 0) {
                int r = -errno;

                close(j->inotify_fd);
                j->inotify_fd = -1;
                return r;
        }

        return j->inotify_fd;
}

int sd_journal_get_events(sd_journal *j) {
        int r = sd_journal_get_fd(j);

        if (r < 0)
                return r;

        return POLLIN;
}

int sd_journal_get_timeout(sd_journal *j, uint64_t *timeout_usec) {
        int r;

        if (!j || !timeout_usec)
                return -EINVAL;

        r = sd_journal_get_fd(j);
        if (r < 0)
                return r;

        *timeout_usec = UINT64_MAX;
        return 0;
}

/* Re-locates `j`'s current entry (if any) in a freshly loaded ring by
 * (monotonic, realtime) key -- not by raw byte offset, which a re-read
 * ring buffer does not preserve. Not found (the entry rotated out from
 * under us) is reported by leaving *ret_idx untouched and returning false,
 * matching sd_journal_process()'s own "not found -> BEFORE_HEAD" rule. */
static bool relocate(LogdRing *new_ring, uint64_t old_mono, uint64_t old_real, size_t *ret_idx) {
        size_t n = logd_ring_n_entries(new_ring);

        for (size_t i = 0; i < n; i++) {
                uint64_t mono, real;

                if (journal_entry_clocks(logd_ring_entry(new_ring, i), &mono, &real) < 0)
                        continue;
                if (mono == old_mono && real == old_real) {
                        *ret_idx = i;
                        return true;
                }
        }

        return false;
}

int sd_journal_process(sd_journal *j) {
        char buf[4096];
        bool overflow = false;
        struct stat new_active_st, new_rotated_st;
        bool have_new_active, have_new_rotated;
        bool changed;
        bool was_on_entry = false;
        uint64_t old_mono = 0, old_real = 0;
        LogdRing *new_ring;
        int r;

        if (!j)
                return -EINVAL;

        r = sd_journal_get_fd(j);
        if (r < 0)
                return r;

        for (;;) {
                ssize_t n = read(j->inotify_fd, buf, sizeof(buf));

                if (n < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                                break;
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (n == 0)
                        break;

                for (ssize_t off = 0; off + (ssize_t) sizeof(struct inotify_event) <= n;) {
                        const struct inotify_event *ev = (const struct inotify_event *) (buf + off);

                        if (ev->mask & IN_Q_OVERFLOW)
                                overflow = true;
                        off += (ssize_t) sizeof(struct inotify_event) + ev->len;
                }
        }

        r = journal_stat_ring(
                        j->runtime_dir, &new_active_st, &have_new_active, &new_rotated_st, &have_new_rotated);
        if (r < 0)
                return r;

        changed = overflow || have_new_active != j->have_active_st || have_new_rotated != j->have_rotated_st;
        if (!changed && have_new_active)
                changed = new_active_st.st_dev != j->active_st.st_dev ||
                                new_active_st.st_ino != j->active_st.st_ino ||
                                new_active_st.st_size != j->active_st.st_size;
        if (!changed && have_new_rotated)
                changed = new_rotated_st.st_dev != j->rotated_st.st_dev ||
                                new_rotated_st.st_ino != j->rotated_st.st_ino ||
                                new_rotated_st.st_size != j->rotated_st.st_size;

        if (!changed)
                return SD_JOURNAL_NOP;

        /* Classify before overwriting the cached stat: the active file
         * keeping its (dev, ino) across the change means it only grew
         * (SD_JOURNAL_APPEND); appearing fresh or changing identity means a
         * rotation happened underneath us (SD_JOURNAL_INVALIDATE), same as
         * an inotify queue overflow forces INVALIDATE regardless. */
        int event = SD_JOURNAL_APPEND;

        if (overflow || !have_new_active || !j->have_active_st ||
            new_active_st.st_dev != j->active_st.st_dev || new_active_st.st_ino != j->active_st.st_ino)
                event = SD_JOURNAL_INVALIDATE;

        if (j->loc == SD_J_ON_ENTRY) {
                const LogdEntry *e = journal_current_entry(j);

                if (e && journal_entry_clocks(e, &old_mono, &old_real) == 0)
                        was_on_entry = true;
        }

        r = logd_ring_read(j->runtime_dir, &new_ring);
        if (r < 0)
                return r; /* stat baseline left stale on purpose: retry next call */

        logd_ring_free(j->ring);
        j->ring = new_ring;

        if (was_on_entry) {
                size_t idx;

                if (relocate(j->ring, old_mono, old_real, &idx))
                        land_on(j, idx);
                else {
                        j->loc = SD_J_BEFORE_HEAD;
                        j->seek_pending = false;
                }
        } else if (j->seek_pending) {
                /* The seek target's index may no longer mean the same thing
                 * against the reloaded ring; force a re-seek rather than
                 * silently landing somewhere wrong. */
                j->seek_pending = false;
                j->loc = SD_J_BEFORE_HEAD;
        }
        /* BEFORE_HEAD/AFTER_TAIL with no pending seek are boundary markers,
         * not indices -- they stay correct across a reload untouched. */

        j->active_st = new_active_st;
        j->rotated_st = new_rotated_st;
        j->have_active_st = have_new_active;
        j->have_rotated_st = have_new_rotated;

        return event;
}

int sd_journal_wait(sd_journal *j, uint64_t timeout_usec) {
        struct pollfd pfd;
        int ms;
        int r;

        if (!j)
                return -EINVAL;

        r = sd_journal_get_fd(j);
        if (r < 0)
                return r;

        if (timeout_usec == UINT64_MAX)
                ms = -1;
        else {
                uint64_t rounded_ms = (timeout_usec + 999) / 1000; /* usec -> ms, rounded up */

                ms = rounded_ms > (uint64_t) INT_MAX ? INT_MAX : (int) rounded_ms;
        }

        pfd.fd = j->inotify_fd;
        pfd.events = POLLIN;

        r = poll(&pfd, 1, ms);
        if (r < 0 && errno != EINTR)
                return -errno;

        return sd_journal_process(j);
}

int sd_journal_reliable_fd(sd_journal *j) {
        int r = sd_journal_get_fd(j);

        if (r < 0)
                return r;

        return 1;
}
