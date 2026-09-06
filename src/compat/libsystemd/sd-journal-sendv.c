/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_journal_sendv(): the one real choke point every write-side function
 * funnels through. Translates the iovec[] "NAME=value" pairs upstream's
 * journal wire format uses into one syslog(3)-shaped datagram addressed to
 * logd's /dev/log socket (src/logd/logd.h, src/logd/logd-recv.c) -- pico's
 * client-side half of the syslog transport logd's receive loop already
 * parses on the other end.
 *
 * Fidelity, by construction: only MESSAGE, PRIORITY, SYSLOG_FACILITY and
 * SYSLOG_IDENTIFIER survive the trip -- everything else a caller sets
 * (CODE_FILE=, MESSAGE_ID=, ERRNO=, arbitrary application fields) is
 * dropped here, not lost silently: it never claimed to travel past this
 * function. _PID/_UID/_GID/_COMM/_SYSTEMD_UNIT are added on the other end
 * by logd itself from the kernel-verified SCM_CREDENTIALS and a /proc
 * cgroup walk (logd-recv.c), so per-process attribution is fully real
 * despite none of it being any of this function's own business.
 *
 * Absent-vs-transient, mirroring journal-send.c's own documented contract:
 * sendto() failing ENOENT (no /dev/log at all -- logd never started) is a
 * silent 0, so a program on a logd-less system keeps running exactly as it
 * would against a real, absent journald; every other errno (ECONNREFUSED --
 * the path exists but logd died; ENOBUFS; EMSGSIZE; ...) propagates as
 * -errno, never disguised as success.
 */

#define SD_JOURNAL_SUPPRESS_LOCATION /* see sd-journal-send.c's file comment for why */

/* program_invocation_short_name and asprintf() are glibc/GNU extensions;
 * -std=gnu17 alone does not imply _GNU_SOURCE (socket.c's own note, same
 * reasoning here). This also flips glibc's strerror_r overload from the
 * XSI int-returning form to the GNU char*-returning one -- see
 * xpg_strerror_r()'s own comment below for why this file calls the XSI
 * algorithm directly instead of through that ambiguous name. */
#define _GNU_SOURCE

#include "sd-journal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "../../logd/logd.h"

/*
 * glibc exports both a POSIX/XSI strerror_r(3) (int return, always fills
 * `buf`, ERANGE if `buflen` was too small) and its own older GNU one (char*
 * return, may hand back a static string instead of using `buf` at all);
 * which one the plain name `strerror_r` resolves to depends on the exact
 * combination of feature-test macros in force at the call site, and this
 * file needs _GNU_SOURCE for other reasons (above). __xpg_strerror_r is the
 * real symbol glibc's own <string.h> redirects the plain name to when the
 * XSI form is selected -- calling it directly makes the choice explicit
 * rather than depending on macro interaction, which is exactly what
 * build_perror_message()'s grow-on-ERANGE loop below is written against.
 */
extern int __xpg_strerror_r(int errnum, char *buf, size_t buflen);

#define MAX_DATAGRAM ((size_t) 65536) /* logd's LOGD_RECV_BUF_SIZE, logd-recv.c */

static bool name_is(const char *data, size_t name_len, const char *literal) {
        return name_len == strlen(literal) && memcmp(data, literal, name_len) == 0;
}

typedef struct ParsedFields {
        const char *message;
        size_t message_len;
        bool have_priority;
        int priority; /* 0-7 */
        bool have_facility;
        int facility; /* 0-23, defaults to 1 (LOG_USER) if never set */
        const char *identifier;
        size_t identifier_len;
} ParsedFields;

static bool identifier_chars_ok(const char *s, size_t len) {
        if (len == 0)
                return false;

        for (size_t i = 0; i < len; i++)
                if (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\0')
                        return false;

        return true;
}

/* logd's own syslog_parse_tag() grammar (logd-recv.c) is a non-whitespace
 * run ending ':' -- an identifier containing any of those bytes would not
 * round-trip through it, so this shim never sends one that wouldn't. */
static int validate_iov(const struct iovec *iov, int n, ParsedFields *out) {
        bool have_message = false, have_identifier_field = false;

        memset(out, 0, sizeof(*out));
        out->facility = 1;

        if (!iov || n <= 0)
                return -EINVAL;

        for (int i = 0; i < n; i++) {
                const char *base = iov[i].iov_base;
                size_t len = iov[i].iov_len;
                const char *eq, *nl;
                size_t name_len;

                if (!base || len <= 1)
                        return -EINVAL;

                eq = memchr(base, '=', len);
                if (!eq || eq == base)
                        return -EINVAL;
                name_len = (size_t) (eq - base);

                nl = memchr(base, '\n', name_len);
                if (nl)
                        return -EINVAL;

                if (!have_message && name_is(base, name_len, "MESSAGE")) {
                        out->message = eq + 1;
                        out->message_len = len - name_len - 1;
                        have_message = true;
                } else if (!out->have_priority && name_is(base, name_len, "PRIORITY")) {
                        size_t vlen = len - name_len - 1;

                        if (vlen == 1 && eq[1] >= '0' && eq[1] <= '7') {
                                out->priority = eq[1] - '0';
                                out->have_priority = true;
                        }
                } else if (!out->have_facility && name_is(base, name_len, "SYSLOG_FACILITY")) {
                        size_t vlen = len - name_len - 1;
                        const char *v = eq + 1;
                        long val = 0;
                        bool ok = vlen > 0;

                        for (size_t k = 0; ok && k < vlen; k++) {
                                if (v[k] < '0' || v[k] > '9') {
                                        ok = false;
                                        break;
                                }
                                val = val * 10 + (v[k] - '0');
                        }
                        if (ok && val >= 0 && val <= 23) {
                                out->facility = (int) val;
                                out->have_facility = true;
                        }
                } else if (!have_identifier_field && name_is(base, name_len, "SYSLOG_IDENTIFIER")) {
                        size_t vlen = len - name_len - 1;

                        have_identifier_field = true;
                        if (identifier_chars_ok(eq + 1, vlen)) {
                                out->identifier = eq + 1;
                                out->identifier_len = vlen;
                        }
                        /* present but invalid: dropped, no fallback -- a field WAS given */
                }
        }

        if (!have_identifier_field) {
                const char *prog = program_invocation_short_name;

                if (prog && identifier_chars_ok(prog, strlen(prog))) {
                        out->identifier = prog;
                        out->identifier_len = strlen(prog);
                }
        }

        return 0;
}

/* Process-wide cached client socket, installed exactly once regardless of
 * how many threads race to create it: each loser closes its own fd and
 * re-reads the winner's, so every caller ends up sharing one real socket()
 * rather than leaking one per losing thread. */
static int get_client_fd(void) {
        static int fd_plus_one = 0;
        int cur = __atomic_load_n(&fd_plus_one, __ATOMIC_ACQUIRE);
        int fd, expected;

        if (cur != 0)
                return cur - 1;

        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        expected = 0;
        if (!__atomic_compare_exchange_n(&fd_plus_one, &expected, fd + 1, false, __ATOMIC_ACQ_REL,
                                          __ATOMIC_ACQUIRE)) {
                close(fd);
                return expected - 1;
        }

        return fd;
}

int sd_journal_sendv(const struct iovec *iov, int n) {
        int saved_errno = errno;
        ParsedFields pf;
        int r;
        char *composed;
        size_t cap, len = 0;
        char *message_copy = NULL;
        const char *message = NULL;
        size_t message_len = 0;
        int fd;
        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        ssize_t sent;

        r = validate_iov(iov, n, &pf);
        if (r < 0) {
                errno = saved_errno;
                return r;
        }

        if (pf.message) {
                message = pf.message;
                message_len = pf.message_len;
                if (memchr(message, '\0', message_len)) {
                        message_copy = malloc(message_len ? message_len : 1);
                        if (!message_copy) {
                                errno = saved_errno;
                                return -ENOMEM;
                        }
                        memcpy(message_copy, message, message_len);
                        for (size_t i = 0; i < message_len; i++)
                                if (message_copy[i] == '\0')
                                        message_copy[i] = ' ';
                        message = message_copy;
                }
        }

        /* "<NNN>" is at most 5 bytes (facility 0-23 << 3 | severity 0-7 tops
         * out at 191); 8 leaves a little headroom rather than cutting it exactly. */
        cap = 8 + pf.identifier_len + 2 + message_len;
        composed = malloc(cap > 0 ? cap : 1);
        if (!composed) {
                free(message_copy);
                errno = saved_errno;
                return -ENOMEM;
        }

        if (pf.have_priority) {
                int pri = (pf.facility << 3) | pf.priority;
                int wrote = snprintf(composed, cap, "<%d>", pri);

                len = (size_t) wrote;
        }

        if (pf.identifier) {
                memcpy(composed + len, pf.identifier, pf.identifier_len);
                len += pf.identifier_len;
                composed[len++] = ':';
                composed[len++] = ' ';
        }

        if (message_len > 0) {
                memcpy(composed + len, message, message_len);
                len += message_len;
        }

        free(message_copy);

        if (len > MAX_DATAGRAM) {
                free(composed);
                errno = saved_errno;
                return -EMSGSIZE;
        }

        fd = get_client_fd();
        if (fd < 0) {
                free(composed);
                errno = saved_errno;
                return fd;
        }

        strncpy(addr.sun_path, LOGD_SYSLOG_SOCKET_PATH, sizeof(addr.sun_path) - 1);

        for (;;) {
                sent = sendto(fd, composed, len, 0, (struct sockaddr *) &addr, sizeof(addr));
                if (sent < 0 && errno == EINTR)
                        continue;
                break;
        }

        free(composed);

        if (sent < 0) {
                int e = errno;

                errno = saved_errno;
                return e == ENOENT ? 0 : -e;
        }

        errno = saved_errno;
        return 0;
}

int sd_journal_sendv_with_location(const char *file, const char *line, const char *func, const struct iovec *iov,
                                    int n) {
        struct iovec *niov;
        char funcbuf[256];
        int rc;

        if (!iov || n <= 0)
                return -EINVAL;

        niov = malloc((size_t) (n + 3) * sizeof(*niov));
        if (!niov)
                return -ENOMEM;

        niov[0].iov_base = (void *) file;
        niov[0].iov_len = strlen(file);
        niov[1].iov_base = (void *) line;
        niov[1].iov_len = strlen(line);
        snprintf(funcbuf, sizeof(funcbuf), "CODE_FUNC=%s", func);
        niov[2].iov_base = funcbuf;
        niov[2].iov_len = strlen(funcbuf);

        memcpy(niov + 3, iov, (size_t) n * sizeof(*iov));

        rc = sd_journal_sendv(niov, n + 3);

        free(niov);
        return rc;
}

/* --- perror --- */

static int build_perror_message(int saved_errno, const char *message, char **ret) {
        char *errbuf = malloc(64);
        size_t errcap = 64;
        int r;

        if (!errbuf)
                return -ENOMEM;

        for (;;) {
                r = __xpg_strerror_r(saved_errno, errbuf, errcap);
                if (r == 0)
                        break;
                if (r == ERANGE) {
                        char *bigger;

                        errcap *= 2;
                        bigger = realloc(errbuf, errcap);
                        if (!bigger) {
                                free(errbuf);
                                return -ENOMEM;
                        }
                        errbuf = bigger;
                        continue;
                }
                free(errbuf);
                return -EINVAL;
        }

        if (!message || message[0] == '\0') {
                *ret = errbuf;
                return 0;
        }

        {
                char *combined;

                if (asprintf(&combined, "%s: %s", message, errbuf) < 0) {
                        free(errbuf);
                        return -ENOMEM;
                }
                free(errbuf);
                *ret = combined;
                return 0;
        }
}

int sd_journal_perror_with_location(const char *file, const char *line, const char *func, const char *message) {
        int saved_errno = errno;
        char *msg_text;
        char msg_field[512];
        char errno_field[32];
        struct iovec iov[6];
        int r, rc;

        r = build_perror_message(saved_errno, message, &msg_text);
        if (r < 0) {
                errno = saved_errno;
                return r;
        }

        snprintf(msg_field, sizeof(msg_field), "MESSAGE=%s", msg_text);
        free(msg_text);
        snprintf(errno_field, sizeof(errno_field), "ERRNO=%d", saved_errno);

        iov[0].iov_base = (void *) file;
        iov[0].iov_len = strlen(file);
        iov[1].iov_base = (void *) line;
        iov[1].iov_len = strlen(line);
        {
                static char funcbuf[256];

                snprintf(funcbuf, sizeof(funcbuf), "CODE_FUNC=%s", func);
                iov[2].iov_base = funcbuf;
                iov[2].iov_len = strlen(funcbuf);
        }
        iov[3].iov_base = msg_field;
        iov[3].iov_len = strlen(msg_field);
        iov[4].iov_base = (void *) "PRIORITY=3";
        iov[4].iov_len = strlen("PRIORITY=3");
        iov[5].iov_base = errno_field;
        iov[5].iov_len = strlen(errno_field);

        rc = sd_journal_sendv(iov, 6);

        errno = saved_errno;
        return rc;
}

int sd_journal_perror(const char *message) {
        int saved_errno = errno;
        char *msg_text;
        char msg_field[512];
        char errno_field[32];
        struct iovec iov[3];
        int r, rc;

        r = build_perror_message(saved_errno, message, &msg_text);
        if (r < 0) {
                errno = saved_errno;
                return r;
        }

        snprintf(msg_field, sizeof(msg_field), "MESSAGE=%s", msg_text);
        free(msg_text);
        snprintf(errno_field, sizeof(errno_field), "ERRNO=%d", saved_errno);

        iov[0].iov_base = msg_field;
        iov[0].iov_len = strlen(msg_field);
        iov[1].iov_base = (void *) "PRIORITY=3";
        iov[1].iov_len = strlen("PRIORITY=3");
        iov[2].iov_base = errno_field;
        iov[2].iov_len = strlen(errno_field);

        rc = sd_journal_sendv(iov, 3);

        errno = saved_errno;
        return rc;
}
