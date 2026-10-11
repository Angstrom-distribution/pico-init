/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Datagram receive, fragment handling, /dev/log parsing and ucred+cgroup
 * attribution. See logd-recv.h for the per-stream design.
 *
 * Not lifted from systemd; upstream was the reference:
 *   - src/journal/journald-syslog.c (syslog_parse_priority(),
 *     syslog_parse_identifier()) for the <N> prefix and identifier[pid]:
 *     tag grammar /dev/log parsing follows.
 *   - src/journal/journald-stream.c (stdout_stream_scan()) for the line-
 *     break scan: a literal NUL byte breaks a line like '\n' does
 *     (whichever occurs first within the window), because many consumers of
 *     a MESSAGE cannot handle an embedded NUL; and for the _LINE_BREAK
 *     field/value vocabulary (line-max/pid-change/eof), reused verbatim so a
 *     converted ring reads like a real journal.
 *   - src/basic/cgroup-util.c (cg_path_get_unit_full(), skip_slices(),
 *     cg_path_decode_unit()) for the unit-from-cgroup walk: skip a leading
 *     run of valid *.slice components, then the unit is the FIRST
 *     remaining component, not the last. Only the cgroup-v2 "0::" line is
 *     parsed (upstream removed the v1 fallback in b525a72f7b, and
 *     mount-setup.c only mounts cgroup2).
 */

/* struct ucred and SCM_CREDENTIALS are under glibc's __USE_GNU guard in
 * <sys/socket.h>, which -std=gnu17 does not imply; this must come before any
 * header, including logd-recv.h. */
#define _GNU_SOURCE

#include "logd-recv.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../util.h"
#include "logd.h"

/* TASK_COMM_LEN (16, including the NUL). */
#define LOGD_COMM_MAX 16

/* Matches unit.h's UNIT_NAME_MAX; duplicated so logd does not depend on
 * PID 1's headers. */
#define LOGD_UNIT_NAME_MAX 255

#define LOGD_RECV_BUF_SIZE ((size_t) 65536)

typedef struct LogdStream {
        bool valid;
        struct sockaddr_un addr;
        socklen_t addr_len;

        bool has_pid;
        pid_t last_pid;
        unsigned long long last_starttime; /* /proc/<pid>/stat field 22, ticks since boot; 0 = unknown */

        bool has_cred;
        uid_t last_uid;
        gid_t last_gid;

        bool attributed;
        char comm[LOGD_COMM_MAX];
        char unit[LOGD_UNIT_NAME_MAX + 1];

        char tail[LOGD_LINE_MAX];
        size_t tail_len;

        usec_t last_seen;
} LogdStream;

struct LogdRecv {
        LogdWriter *writer; /* not owned */
        LogdStream streams[LOGD_MAX_STREAMS];
};

/* --- /dev/log parsing (journald-syslog.c reference, see header) --- */

/*
 * "<N>" POSIX syslog PRI prefix, 1-3 decimal digits (journald-syslog.c's
 * syslog_parse_priority(..., with_facility=true) grammar: no upper bound
 * beyond digit count). Only the severity (value & 7) is kept; there is no
 * SYSLOG_FACILITY field. Returns false (and leaves *p untouched) if the buffer
 * does not start with a well-formed prefix.
 */
static bool syslog_parse_priority_prefix(const char **p, int *out_priority) {
        const char *s = *p;
        const char *end;
        size_t digits;
        int value = 0;

        if (s[0] != '<')
                return false;

        end = strchr(s, '>');
        if (!end)
                return false;

        digits = (size_t) (end - s - 1);
        if (digits < 1 || digits > 3)
                return false;

        for (size_t i = 1; i <= digits; i++) {
                if (s[i] < '0' || s[i] > '9')
                        return false;
                value = value * 10 + (s[i] - '0');
        }

        *out_priority = value & 7;
        *p = end + 1;
        return true;
}

/*
 * "identifier[pid]: " or "identifier: " tag (journald-syslog.c's
 * syslog_parse_identifier()): a run of non-whitespace ending in ':', with
 * an optional "[...]" suffix immediately before the colon stripped from
 * the identifier regardless of whether its content is numeric. The
 * bracketed pid is discarded: _PID always comes from the kernel-verified
 * ucred, never from sender-controlled text. Returns
 * false (and leaves *p untouched) if no ':'-terminated tag is found.
 */
static bool syslog_parse_tag(const char **p, const char **ident, size_t *ident_len) {
        const char *s = *p;
        size_t l, tag_len;

        while (*s == ' ' || *s == '\t')
                s++;

        l = 0;
        while (s[l] != '\0' && s[l] != ' ' && s[l] != '\t')
                l++;

        if (l == 0 || s[l - 1] != ':')
                return false;

        tag_len = l - 1;
        if (tag_len > LOGD_UNIT_NAME_MAX)
                return false; /* too long: treat as "no identifier" */

        if (tag_len > 0 && s[tag_len - 1] == ']') {
                size_t k = tag_len - 1;

                while (k > 0 && s[k] != '[')
                        k--;
                if (s[k] == '[')
                        tag_len = k;
        }

        *ident = s;
        *ident_len = tag_len;

        s += l;
        if (*s == ' ' || *s == '\t')
                s++;
        *p = s;
        return true;
}

/* --- cgroup-based unit attribution (cgroup-util.c reference, see header) --- */

static bool cgroup_chars_valid(const char *name, size_t len) {
        if (len == 0)
                return false;

        for (size_t i = 0; i < len; i++) {
                char c = name[i];

                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      c == ':' || c == '-' || c == '_' || c == '.' || c == '\\' || c == '@'))
                        return false;
        }

        return true;
}

static bool cgroup_component_is_slice(const char *name, size_t len) {
        static const char suffix[] = ".slice";
        size_t slen = sizeof(suffix) - 1;

        if (len <= slen || memcmp(name + len - slen, suffix, slen) != 0)
                return false;

        return cgroup_chars_valid(name, len);
}

/*
 * A cgroup path component shaped like a unit name: valid characters plus a
 * suffix from upstream's unit-type table. Broader than unit_name_is_valid()
 * (unit.c), which only knows the unit types pico-init loads, so a process
 * under e.g. a .scope or .mount cgroup is still attributed. ".slice" is
 * absent from the set: leading slices are already skipped by
 * cgroup_path_get_unit(), so a surviving one is rejected, as upstream does.
 */
static bool cgroup_component_is_unit_shaped(const char *name, size_t len) {
        static const char * const suffixes[] = {
                ".service", ".socket", ".target", ".mount", ".swap", ".device", ".timer", ".path", ".scope",
        };

        if (!cgroup_chars_valid(name, len))
                return false;

        for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
                size_t slen = strlen(suffixes[i]);

                if (len > slen && memcmp(name + len - slen, suffixes[i], slen) == 0)
                        return true;
        }

        return false;
}

/*
 * Extract the owning unit from a raw cgroup v2 path (e.g.
 * "/system.slice/netd.service"), cg_path_get_unit_full()'s walk: skip a
 * leading run of valid *.slice components, then the unit is the FIRST
 * remaining component, not the last. On the flat system.slice/<unit>/
 * layout the two coincide; they differ for a cgroup with sub-components.
 * Returns a pointer+length INTO `path` (no copy) on success, or NULL.
 */
static const char *cgroup_path_get_unit(const char *path, size_t *ret_len) {
        const char *p = path;
        size_t n;

        for (;;) {
                while (*p == '/')
                        p++;

                n = strcspn(p, "/");
                if (!cgroup_component_is_slice(p, n))
                        break;

                p += n;
        }

        n = strcspn(p, "/");
        if (!cgroup_component_is_unit_shaped(p, n))
                return NULL;

        *ret_len = n;
        return p;
}

/* /proc/<pid>/cgroup's "0::<path>" line (cgroup v2 only): a malloc'd copy of
 * the path field, or NULL. */
static char *read_proc_cgroup(pid_t pid) {
        char path[64];
        FILE *f;
        char *line = NULL;
        size_t linecap = 0;
        char *result = NULL;

        snprintf(path, sizeof(path), "/proc/%d/cgroup", (int) pid);

        f = fopen(path, "re");
        if (!f)
                return NULL;

        while (getline(&line, &linecap, f) >= 0) {
                if (strncmp(line, "0::", 3) == 0) {
                        char *nl = strchr(line, '\n');

                        if (nl)
                                *nl = '\0';
                        result = pico_strdup(line + 3);
                        break;
                }
        }

        free(line);
        fclose(f);
        return result;
}

/*
 * /proc/<pid>/stat field 22 (starttime, clock ticks since boot): differs
 * when `pid` has been recycled to another process (the PID-reuse defence
 * described in logd-recv.h). 0 means "unknown" (process gone, or a read
 * failure) and is never treated as "confirmed unchanged".
 */
static unsigned long long read_proc_starttime(pid_t pid) {
        char path[64];
        FILE *f;
        char buf[512];
        unsigned long long starttime = 0;

        snprintf(path, sizeof(path), "/proc/%d/stat", (int) pid);
        f = fopen(path, "re");
        if (!f)
                return 0;

        if (fgets(buf, sizeof(buf), f)) {
                /* comm (field 2) is parenthesized and may contain spaces or
                 * parens: split after the LAST ')' (see proc(5)). */
                char *rparen = strrchr(buf, ')');

                if (rparen) {
                        char *p = rparen + 1;
                        int field = 2;

                        while (*p) {
                                while (*p == ' ')
                                        p++;
                                if (!*p)
                                        break;
                                field++;
                                if (field == 22)
                                        break;
                                while (*p && *p != ' ')
                                        p++;
                        }

                        starttime = strtoull(p, NULL, 10);
                }
        }

        fclose(f);
        return starttime;
}

/* Best-effort: a process that has already exited just yields empty
 * comm/unit. */
static void attribute_pid(pid_t pid, char *comm_out, size_t comm_out_sz, char *unit_out, size_t unit_out_sz) {
        comm_out[0] = '\0';
        unit_out[0] = '\0';

        {
                char path[64];
                FILE *f;

                snprintf(path, sizeof(path), "/proc/%d/comm", (int) pid);
                f = fopen(path, "re");
                if (f) {
                        if (fgets(comm_out, (int) comm_out_sz, f)) {
                                size_t l = strlen(comm_out);

                                if (l > 0 && comm_out[l - 1] == '\n')
                                        comm_out[l - 1] = '\0';
                        }
                        fclose(f);
                }
        }

        {
                char *cgroup = read_proc_cgroup(pid);

                if (cgroup) {
                        size_t n;
                        const char *u = cgroup_path_get_unit(cgroup, &n);

                        if (u && n < unit_out_sz) {
                                memcpy(unit_out, u, n);
                                unit_out[n] = '\0';
                        }
                        free(cgroup);
                }
        }
}

/* --- stream table --- */

static LogdStream *find_stream(LogdRecv *r, const struct sockaddr_un *peer, socklen_t peer_len) {
        for (size_t i = 0; i < LOGD_MAX_STREAMS; i++) {
                LogdStream *s = &r->streams[i];

                if (s->valid && s->addr_len == peer_len && memcmp(&s->addr, peer, peer_len) == 0)
                        return s;
        }

        return NULL;
}

static void emit_stdout_line(
                LogdRecv *r, const LogdStream *s, const char *line, size_t line_len, const char *line_break);

static void flush_tail(LogdRecv *r, LogdStream *s, const char *line_break_reason) {
        if (s->tail_len == 0)
                return;

        emit_stdout_line(r, s, s->tail, s->tail_len, line_break_reason);
        s->tail_len = 0;
}

/* Find a stream by identity, or allocate one: a free slot if there is one,
 * otherwise the least-recently-seen slot (see logd.h). Evicting a live
 * stream flushes its tail first, tagged _LINE_BREAK=eof. */
static LogdStream *find_or_create_stream(LogdRecv *r, const struct sockaddr_un *peer, socklen_t peer_len) {
        LogdStream *s = find_stream(r, peer, peer_len);
        size_t slot = LOGD_MAX_STREAMS;
        size_t oldest = 0;
        usec_t oldest_seen = USEC_INFINITY;

        if (s)
                return s;

        for (size_t i = 0; i < LOGD_MAX_STREAMS; i++) {
                if (!r->streams[i].valid) {
                        slot = i;
                        break;
                }
                if (r->streams[i].last_seen < oldest_seen) {
                        oldest_seen = r->streams[i].last_seen;
                        oldest = i;
                }
        }
        if (slot == LOGD_MAX_STREAMS)
                slot = oldest;

        s = &r->streams[slot];
        if (s->valid)
                flush_tail(r, s, "eof");

        memset(s, 0, sizeof(*s));
        memcpy(&s->addr, peer, peer_len);
        s->addr_len = peer_len;
        s->valid = true;
        s->last_seen = now_monotonic();

        return s;
}

/*
 * Update a stream's cached pid/credentials/attribution for one datagram.
 * A PID change on the stream, or the same PID with a different starttime
 * (logd-recv.h), flushes the tail and marks attribution stale.
 */
static void update_stream_identity(LogdRecv *r, LogdStream *s, const struct ucred *cred) {
        if (!cred)
                return;

        if (s->has_pid && s->last_pid == cred->pid) {
                unsigned long long st = read_proc_starttime(cred->pid);

                if (st != 0 && s->last_starttime != 0 && st != s->last_starttime) {
                        flush_tail(r, s, "pid-change");
                        s->attributed = false;
                }
                if (st != 0)
                        s->last_starttime = st;
        } else if (s->has_pid) {
                flush_tail(r, s, "pid-change");
                s->attributed = false;
                s->last_starttime = read_proc_starttime(cred->pid);
        } else
                s->last_starttime = read_proc_starttime(cred->pid);

        s->last_pid = cred->pid;
        s->has_pid = true;
        s->has_cred = true;
        s->last_uid = cred->uid;
        s->last_gid = cred->gid;

        if (!s->attributed) {
                attribute_pid(cred->pid, s->comm, sizeof(s->comm), s->unit, sizeof(s->unit));
                s->attributed = true;
        }
}

static void emit_stdout_line(
                LogdRecv *r, const LogdStream *s, const char *line, size_t line_len, const char *line_break) {
        LogdField fields[9];
        size_t n = 0;
        char pid_buf[16], uid_buf[16], gid_buf[16];

        fields[n++] = (LogdField){ "MESSAGE", line, line_len };
        fields[n++] = (LogdField){ "PRIORITY", "6", 1 }; /* LOG_INFO: upstream's stdout-stream default
                                                          * (journald-stream.c); the shared socket has no
                                                          * handshake to say otherwise */
        fields[n++] = (LogdField){ "_TRANSPORT", "stdout", 6 };

        if (s->has_pid) {
                snprintf(pid_buf, sizeof(pid_buf), "%d", (int) s->last_pid);
                fields[n++] = (LogdField){ "_PID", pid_buf, strlen(pid_buf) };
        }
        if (s->has_cred) {
                snprintf(uid_buf, sizeof(uid_buf), "%u", (unsigned) s->last_uid);
                fields[n++] = (LogdField){ "_UID", uid_buf, strlen(uid_buf) };
                snprintf(gid_buf, sizeof(gid_buf), "%u", (unsigned) s->last_gid);
                fields[n++] = (LogdField){ "_GID", gid_buf, strlen(gid_buf) };
        }
        if (s->comm[0])
                fields[n++] = (LogdField){ "_COMM", s->comm, strlen(s->comm) };
        if (s->unit[0])
                fields[n++] = (LogdField){ "_SYSTEMD_UNIT", s->unit, strlen(s->unit) };
        if (line_break)
                fields[n++] = (LogdField){ "_LINE_BREAK", line_break, strlen(line_break) };

        (void) logd_writer_append(r->writer, fields, n);
}

/*
 * Scan `data`[0..len) for line breaks as journald-stream.c's
 * stdout_stream_scan() does (see the header): within each
 * LOGD_LINE_MAX-bounded window, whichever of '\n' or a literal NUL byte
 * occurs first ends the line; with neither found and a full LOGD_LINE_MAX
 * accumulated, force a split tagged "line-max". Whatever remains
 * unconsumed (less than one full line, no break found yet) becomes the
 * stream's new tail -- it is never emitted here.
 */
static void scan_and_emit(LogdRecv *r, LogdStream *s, const char *data, size_t len) {
        size_t pos = 0;

        while (pos < len) {
                size_t window = len - pos < LOGD_LINE_MAX ? len - pos : LOGD_LINE_MAX;
                const char *nl = memchr(data + pos, '\n', window);
                const char *nul = memchr(data + pos, '\0', nl ? (size_t) (nl - (data + pos)) : window);
                size_t found, skip;
                const char *reason;

                if (nul) {
                        found = (size_t) (nul - (data + pos));
                        skip = found + 1;
                        reason = "nul";
                } else if (nl) {
                        found = (size_t) (nl - (data + pos));
                        skip = found + 1;
                        reason = NULL; /* ordinary newline: no _LINE_BREAK field, matches upstream */
                } else if (len - pos >= LOGD_LINE_MAX) {
                        found = skip = LOGD_LINE_MAX;
                        reason = "line-max";
                } else
                        break;

                emit_stdout_line(r, s, data + pos, found, reason);
                pos += skip;
        }

        if (len - pos > 0) {
                memcpy(s->tail, data + pos, len - pos);
                s->tail_len = len - pos;
        } else
                s->tail_len = 0;
}

int logd_recv_new(LogdWriter *writer, LogdRecv **ret) {
        LogdRecv *r;

        if (!writer || !ret)
                return -EINVAL;

        r = calloc(1, sizeof(*r));
        if (!r)
                return -ENOMEM;

        r->writer = writer;
        *ret = r;
        return 0;
}

LogdRecv *logd_recv_free(LogdRecv *r) {
        if (!r)
                return NULL;

        for (size_t i = 0; i < LOGD_MAX_STREAMS; i++)
                if (r->streams[i].valid && r->streams[i].tail_len > 0)
                        flush_tail(r, &r->streams[i], "eof");

        free(r);
        return NULL;
}

int logd_recv_ensure_passcred(int fd) {
        int one = 1;

        if (fd < 0)
                return -EINVAL;

        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0)
                return -errno;

        return 0;
}

int logd_recv_bind_socket(const char *path, mode_t mode, int *ret_fd) {
        struct sockaddr_un addr;
        size_t len;
        int fd, r;

        if (!path || !ret_fd)
                return -EINVAL;

        len = strlen(path);
        if (len >= sizeof(addr.sun_path))
                return -ENAMETOOLONG;

        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        /* Before bind(): the ordering matters, see
         * logd_recv_ensure_passcred(). */
        r = logd_recv_ensure_passcred(fd);
        if (r < 0) {
                close(fd);
                return r;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        memcpy(addr.sun_path, path, len);

        (void) unlink(path); /* a stale socket from a prior run; ENOENT is fine */

        if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        if (chmod(path, mode) < 0) {
                r = -errno;
                close(fd);
                (void) unlink(path);
                return r;
        }

        *ret_fd = fd;
        return 0;
}

int logd_recv_process_stdout(
                LogdRecv *r,
                const void *payload,
                size_t payload_len,
                const struct sockaddr_un *peer,
                socklen_t peer_len,
                const struct ucred *cred) {

        LogdStream *s;
        char *combined;
        size_t combined_len;

        if (!r || (!payload && payload_len > 0))
                return -EINVAL;

        /* pid == 0 with the cmsg present means "unknown" (a datagram queued
         * before SO_PASSCRED took effect): treat as no credentials. */
        if (cred && cred->pid == 0)
                cred = NULL;

        if (!peer || peer_len == 0) {
                /* No stream identity: never carry a tail across calls.
                 * Emit what we have, flushing any remainder immediately
                 * under a throwaway stream. */
                LogdStream anon;

                memset(&anon, 0, sizeof(anon));
                if (cred) {
                        anon.has_pid = true;
                        anon.last_pid = cred->pid;
                        anon.has_cred = true;
                        anon.last_uid = cred->uid;
                        anon.last_gid = cred->gid;
                        attribute_pid(cred->pid, anon.comm, sizeof(anon.comm), anon.unit, sizeof(anon.unit));
                }

                scan_and_emit(r, &anon, payload, payload_len);
                flush_tail(r, &anon, "eof");
                return 0;
        }

        s = find_or_create_stream(r, peer, peer_len);
        if (!s)
                return -ENOMEM;

        update_stream_identity(r, s, cred);

        if (s->tail_len == 0) {
                /* Common case (no pending tail): scan the receive buffer
                 * directly instead of copying it. */
                scan_and_emit(r, s, payload, payload_len);
        } else {
                combined_len = s->tail_len + payload_len;
                combined = malloc(combined_len);
                if (!combined)
                        return -ENOMEM;

                memcpy(combined, s->tail, s->tail_len);
                if (payload_len > 0)
                        memcpy(combined + s->tail_len, payload, payload_len);
                s->tail_len = 0; /* consumed into `combined`; scan_and_emit() repopulates it */

                scan_and_emit(r, s, combined, combined_len);
                free(combined);
        }

        s->last_seen = now_monotonic();

        return 0;
}

int logd_recv_process_syslog(LogdRecv *r, const void *payload, size_t payload_len, const struct ucred *cred) {
        char *buf;
        const char *p;
        int priority = 6; /* LOG_INFO: journald-syslog.c's default */
        const char *ident = NULL;
        size_t ident_len = 0;
        LogdField fields[9];
        size_t n = 0;
        char prio_buf[4], pid_buf[16], uid_buf[16], gid_buf[16];
        char comm[LOGD_COMM_MAX] = "", unit[LOGD_UNIT_NAME_MAX + 1] = "";

        if (!r || (!payload && payload_len > 0))
                return -EINVAL;
        if (payload_len == 0)
                return 0;

        if (cred && cred->pid == 0)
                cred = NULL; /* see logd_recv_process_stdout()'s identical guard */

        buf = malloc(payload_len + 1);
        if (!buf)
                return -ENOMEM;
        memcpy(buf, payload, payload_len);
        buf[payload_len] = '\0';

        p = buf;
        (void) syslog_parse_priority_prefix(&p, &priority);
        (void) syslog_parse_tag(&p, &ident, &ident_len);

        fields[n++] = (LogdField){ "MESSAGE", p, strlen(p) };

        snprintf(prio_buf, sizeof(prio_buf), "%d", priority);
        fields[n++] = (LogdField){ "PRIORITY", prio_buf, strlen(prio_buf) };
        fields[n++] = (LogdField){ "_TRANSPORT", "syslog", 6 };

        if (ident)
                fields[n++] = (LogdField){ "SYSLOG_IDENTIFIER", ident, ident_len };

        if (cred) {
                snprintf(pid_buf, sizeof(pid_buf), "%d", (int) cred->pid);
                fields[n++] = (LogdField){ "_PID", pid_buf, strlen(pid_buf) };
                snprintf(uid_buf, sizeof(uid_buf), "%u", (unsigned) cred->uid);
                fields[n++] = (LogdField){ "_UID", uid_buf, strlen(uid_buf) };
                snprintf(gid_buf, sizeof(gid_buf), "%u", (unsigned) cred->gid);
                fields[n++] = (LogdField){ "_GID", gid_buf, strlen(gid_buf) };

                attribute_pid(cred->pid, comm, sizeof(comm), unit, sizeof(unit));
                if (comm[0])
                        fields[n++] = (LogdField){ "_COMM", comm, strlen(comm) };
                if (unit[0])
                        fields[n++] = (LogdField){ "_SYSTEMD_UNIT", unit, strlen(unit) };
        }

        {
                int rc = logd_writer_append(r->writer, fields, n);

                free(buf);
                return rc;
        }
}

/* One non-blocking recvmsg() with SCM_CREDENTIALS and peer-address
 * extraction, shared by both drain functions below. Returns 1 with n_out,
 * cred_out (and peer_out/peer_len_out, if requested) set, 0 at EAGAIN
 * (nothing more pending), or -errno. */
static int
                recv_one(int fd,
                         void *buf,
                         size_t bufsize,
                         size_t *n_out,
                         struct sockaddr_un *peer_out,
                         socklen_t *peer_len_out,
                         struct ucred *cred_out,
                         bool *has_cred_out) {

        char cmsgbuf[CMSG_SPACE(sizeof(struct ucred))];
        struct sockaddr_un peer;
        struct iovec iov = { .iov_base = buf, .iov_len = bufsize };
        struct msghdr msg = {
                .msg_name = &peer,
                .msg_namelen = sizeof(peer),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = cmsgbuf,
                .msg_controllen = sizeof(cmsgbuf),
        };
        ssize_t n;
        struct cmsghdr *cmsg;

        *has_cred_out = false;

        for (;;) {
                n = recvmsg(fd, &msg, MSG_DONTWAIT);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                                return 0;
                        return -errno;
                }
                break;
        }

        if (msg.msg_flags & MSG_TRUNC)
                pico_log(PICO_LOG_WARNING, "logd: datagram truncated at %zu bytes, some bytes lost", bufsize);

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
                        memcpy(cred_out, CMSG_DATA(cmsg), sizeof(*cred_out));
                        *has_cred_out = true;
                        break;
                }

        if (peer_out && peer_len_out) {
                if (msg.msg_namelen > 0 && (size_t) msg.msg_namelen <= sizeof(*peer_out)) {
                        memcpy(peer_out, &peer, (size_t) msg.msg_namelen);
                        *peer_len_out = msg.msg_namelen;
                } else
                        *peer_len_out = 0;
        }

        *n_out = (size_t) n;
        return 1;
}

int logd_recv_drain_stdout(LogdRecv *r, int fd) {
        int count = 0;

        if (!r || fd < 0)
                return -EINVAL;

        for (;;) {
                char buf[LOGD_RECV_BUF_SIZE];
                size_t n;
                struct sockaddr_un peer;
                socklen_t peer_len;
                struct ucred cred;
                bool has_cred;
                int rc;

                rc = recv_one(fd, buf, sizeof(buf), &n, &peer, &peer_len, &cred, &has_cred);
                if (rc < 0)
                        return rc;
                if (rc == 0)
                        break;

                rc = logd_recv_process_stdout(
                                r, buf, n, peer_len > 0 ? &peer : NULL, peer_len, has_cred ? &cred : NULL);
                if (rc < 0)
                        return rc;

                count++;
        }

        return count;
}

int logd_recv_drain_syslog(LogdRecv *r, int fd) {
        int count = 0;

        if (!r || fd < 0)
                return -EINVAL;

        for (;;) {
                char buf[LOGD_RECV_BUF_SIZE];
                size_t n;
                struct ucred cred;
                bool has_cred;
                int rc;

                rc = recv_one(fd, buf, sizeof(buf), &n, NULL, NULL, &cred, &has_cred);
                if (rc < 0)
                        return rc;
                if (rc == 0)
                        break;

                rc = logd_recv_process_syslog(r, buf, n, has_cred ? &cred : NULL);
                if (rc < 0)
                        return rc;

                count++;
        }

        return count;
}
