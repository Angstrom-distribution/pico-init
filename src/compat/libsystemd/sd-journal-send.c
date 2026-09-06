/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_journal_print()/printv()/send() and their _with_location twins: the
 * printf-shaped write API, real down to sd_journal_sendv() (sd-journal-
 * sendv.c), the one choke point that actually talks to logd.
 *
 * SD_JOURNAL_SUPPRESS_LOCATION is defined before including the public
 * header on purpose: sd-journal.h's own macros redirect a caller's plain
 * sd_journal_print()/send()/sendv() to the *_with_location() variant, which
 * is right for an external caller but wrong here -- this file's own calls
 * into sd_journal_printv()/sd_journal_sendv() must reach the real,
 * undecorated symbol, not silently gain a CODE_FILE/CODE_LINE/CODE_FUNC
 * pointing at *this* file's internals instead of the original caller's.
 *
 * sd_journal_send()'s variadic scanning follows the documented calling
 * convention (a format string, its own conversions' worth of args, then
 * the next format string, NULL-terminated) rather than upstream's private
 * VA_FORMAT_ADVANCE macro, which this project cannot use verbatim (GNU
 * statement-expression-free, per netd-compat.h's own reasoning for the
 * same upstream macro family). advance_va() below is the portable
 * equivalent: format each field with vasprintf() on a va_copy (leaving the
 * caller's own va_list untouched), then separately walk that same format
 * string's conversions against the *real* va_list purely to consume the
 * matching va_arg()s -- which is exactly what's needed to leave the real
 * va_list positioned at the next format string, and nothing more.
 */

#define SD_JOURNAL_SUPPRESS_LOCATION

#include "sd-journal.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Trims trailing ' '/'\t'/'\n' from s[0..*len) in place (leading whitespace
 * is kept -- upstream only ever strips the tail, journal-send.c's own
 * rule). *len is updated; the buffer itself is not reallocated or
 * NUL-moved by the caller here, since every caller already tracks length
 * explicitly for the iovec it is about to build. */
static void strip_trailing_ws(const char *s, size_t *len) {
        while (*len > 0 && (s[*len - 1] == ' ' || s[*len - 1] == '\t' || s[*len - 1] == '\n'))
                (*len)--;
}

enum { LEN_NONE, LEN_HH, LEN_H, LEN_L, LEN_LL, LEN_LD, LEN_Z, LEN_J, LEN_T };

/* Walks the '%' conversions in `format` and va_arg()s the matching type off
 * *ap for each -- the standard-C substitute for upstream's private
 * VA_FORMAT_ADVANCE. Only what a message-field format string plausibly
 * uses is covered (see the file comment); an unrecognized conversion is
 * left unconsumed rather than guessed at, which is safe here because it can
 * only make sd_journal_send()'s very next va_arg() read one of the current
 * field's own already-intended arguments back out as if it were the next
 * format string -- the caller passed something outside the documented
 * calling convention either way, and this fails by taking the immediately
 * next field literally rather than by reading further into unrelated
 * memory.
 */
static void advance_va(const char *format, va_list *ap) {
        for (const char *p = format; *p; p++) {
                int length = LEN_NONE;

                if (*p != '%')
                        continue;
                p++;
                if (*p == '%')
                        continue; /* literal '%', consumes nothing */

                while (*p && strchr("-+ #0", *p))
                        p++;

                if (*p == '*') {
                        (void) va_arg(*ap, int);
                        p++;
                } else
                        while (*p && isdigit((unsigned char) *p))
                                p++;

                if (*p == '.') {
                        p++;
                        if (*p == '*') {
                                (void) va_arg(*ap, int);
                                p++;
                        } else
                                while (*p && isdigit((unsigned char) *p))
                                        p++;
                }

                if (*p == 'h') {
                        p++;
                        if (*p == 'h') {
                                p++;
                                length = LEN_HH;
                        } else
                                length = LEN_H;
                } else if (*p == 'l') {
                        p++;
                        if (*p == 'l') {
                                p++;
                                length = LEN_LL;
                        } else
                                length = LEN_L;
                } else if (*p == 'L') {
                        p++;
                        length = LEN_LD;
                } else if (*p == 'z') {
                        p++;
                        length = LEN_Z;
                } else if (*p == 'j') {
                        p++;
                        length = LEN_J;
                } else if (*p == 't') {
                        p++;
                        length = LEN_T;
                }

                if (!*p)
                        break; /* malformed trailing '%': nothing left to consume */

                switch (*p) {
                case 'd':
                case 'i':
                case 'o':
                case 'u':
                case 'x':
                case 'X':
                        switch (length) {
                        case LEN_L:
                                (void) va_arg(*ap, long);
                                break;
                        case LEN_LL:
                                (void) va_arg(*ap, long long);
                                break;
                        case LEN_Z:
                                (void) va_arg(*ap, size_t);
                                break;
                        case LEN_J:
                                (void) va_arg(*ap, intmax_t);
                                break;
                        case LEN_T:
                                (void) va_arg(*ap, ptrdiff_t);
                                break;
                        default: /* LEN_NONE/LEN_HH/LEN_H: char/short promote to int */
                                (void) va_arg(*ap, int);
                                break;
                        }
                        break;
                case 'e':
                case 'E':
                case 'f':
                case 'F':
                case 'g':
                case 'G':
                case 'a':
                case 'A':
                        if (length == LEN_LD)
                                (void) va_arg(*ap, long double);
                        else
                                (void) va_arg(*ap, double); /* float promotes to double */
                        break;
                case 'c':
                        if (length == LEN_L)
                                (void) va_arg(*ap, wint_t);
                        else
                                (void) va_arg(*ap, int); /* char promotes to int */
                        break;
                case 's':
                        if (length == LEN_L)
                                (void) va_arg(*ap, wchar_t *);
                        else
                                (void) va_arg(*ap, char *);
                        break;
                case 'p':
                        (void) va_arg(*ap, void *);
                        break;
                case 'n':
                        (void) va_arg(*ap, int *); /* %n with a length modifier is not used in practice here */
                        break;
                case 'm':
                        break; /* strerror(errno), consumes nothing */
                default:
                        break; /* unrecognized conversion: leave *ap alone, see function comment */
                }
        }
}

int sd_journal_printv(int priority, const char *format, va_list ap) {
        char stackbuf[8192];
        char *buf = stackbuf;
        size_t bufsize = sizeof(stackbuf);
        bool heap = false;
        va_list ap2;
        int r;
        size_t msg_len;
        struct iovec iov[2];
        char priobuf[16];
        int rc;

        if (priority < 0 || priority > 7 || !format)
                return -EINVAL;

        memcpy(buf, "MESSAGE=", 8);

        va_copy(ap2, ap);
        r = vsnprintf(buf + 8, bufsize - 8, format, ap2);
        va_end(ap2);
        if (r < 0)
                return -EINVAL;

        if ((size_t) r >= bufsize - 8) {
                bufsize = (size_t) r + 9; /* "MESSAGE=" (8) + formatted text (r) + NUL (1) */
                buf = malloc(bufsize);
                if (!buf)
                        return -ENOMEM;
                heap = true;

                memcpy(buf, "MESSAGE=", 8);
                va_copy(ap2, ap);
                r = vsnprintf(buf + 8, bufsize - 8, format, ap2);
                va_end(ap2);
                if (r < 0) {
                        free(buf);
                        return -EINVAL;
                }
        }

        msg_len = (size_t) r;
        strip_trailing_ws(buf + 8, &msg_len);

        if (msg_len == 0) {
                if (heap)
                        free(buf);
                return 0; /* upstream suppresses an empty line rather than sending it */
        }

        iov[0].iov_base = buf;
        iov[0].iov_len = 8 + msg_len;

        snprintf(priobuf, sizeof(priobuf), "PRIORITY=%d", priority & LOG_PRIMASK);
        iov[1].iov_base = priobuf;
        iov[1].iov_len = strlen(priobuf);

        rc = sd_journal_sendv(iov, 2);

        if (heap)
                free(buf);

        return rc;
}

int sd_journal_print(int priority, const char *format, ...) {
        va_list ap;
        int r;

        va_start(ap, format);
        r = sd_journal_printv(priority, format, ap);
        va_end(ap);

        return r;
}

int sd_journal_printv_with_location(
                int priority, const char *file, const char *line, const char *func, const char *format, va_list ap) {
        /* CODE_FILE=/CODE_LINE=/CODE_FUNC= are forwarded to sd_journal_sendv()
         * and dropped there (not transportable); this file never special-
         * cases them, which keeps the no-location and with-location paths
         * byte-identical apart from those three extra iovs. Reimplemented
         * rather than delegating to sd_journal_printv(), since that function
         * builds exactly two iovs and calling sd_journal_sendv() is the only
         * shared choke point both paths actually need. */
        char stackbuf[8192];
        char *buf = stackbuf;
        size_t bufsize = sizeof(stackbuf);
        bool heap = false;
        va_list ap2;
        int r;
        size_t msg_len;
        struct iovec iov[5];
        char priobuf[16];
        char funcbuf[256];
        int rc;

        if (priority < 0 || priority > 7 || !format)
                return -EINVAL;

        memcpy(buf, "MESSAGE=", 8);

        va_copy(ap2, ap);
        r = vsnprintf(buf + 8, bufsize - 8, format, ap2);
        va_end(ap2);
        if (r < 0)
                return -EINVAL;

        if ((size_t) r >= bufsize - 8) {
                bufsize = (size_t) r + 9;
                buf = malloc(bufsize);
                if (!buf)
                        return -ENOMEM;
                heap = true;

                memcpy(buf, "MESSAGE=", 8);
                va_copy(ap2, ap);
                r = vsnprintf(buf + 8, bufsize - 8, format, ap2);
                va_end(ap2);
                if (r < 0) {
                        free(buf);
                        return -EINVAL;
                }
        }

        msg_len = (size_t) r;
        strip_trailing_ws(buf + 8, &msg_len);

        if (msg_len == 0) {
                if (heap)
                        free(buf);
                return 0;
        }

        iov[0].iov_base = buf;
        iov[0].iov_len = 8 + msg_len;

        snprintf(priobuf, sizeof(priobuf), "PRIORITY=%d", priority & LOG_PRIMASK);
        iov[1].iov_base = priobuf;
        iov[1].iov_len = strlen(priobuf);

        iov[2].iov_base = (void *) file;
        iov[2].iov_len = strlen(file);
        iov[3].iov_base = (void *) line;
        iov[3].iov_len = strlen(line);

        snprintf(funcbuf, sizeof(funcbuf), "CODE_FUNC=%s", func);
        iov[4].iov_base = funcbuf;
        iov[4].iov_len = strlen(funcbuf);

        rc = sd_journal_sendv(iov, 5);

        if (heap)
                free(buf);

        return rc;
}

int sd_journal_print_with_location(
                int priority, const char *file, const char *line, const char *func, const char *format, ...) {
        va_list ap;
        int r;

        va_start(ap, format);
        r = sd_journal_printv_with_location(priority, file, line, func, format, ap);
        va_end(ap);

        return r;
}

/* Formats one sd_journal_send()/_with_location() field, appending it as a
 * malloc'd iovec entry. `format`'s own conversions are then consumed off
 * `*ap` via advance_va() so the caller's va_list is correctly positioned at
 * the next format-string argument. Returns 0, or a negative error (freeing
 * nothing itself -- the caller owns the whole batch and frees it on any
 * failure). */
static int send_one_field(const char *format, va_list *ap, struct iovec *iov, size_t *n) {
        va_list copy;
        char *s;
        int r;
        size_t len;

        va_copy(copy, *ap);
        r = vasprintf(&s, format, copy);
        va_end(copy);
        if (r < 0)
                return -ENOMEM;

        advance_va(format, ap);

        len = (size_t) r;
        strip_trailing_ws(s, &len);

        iov[*n].iov_base = s;
        iov[*n].iov_len = len;
        (*n)++;

        return 0;
}

static void free_iov_strings(struct iovec *iov, size_t n_reserved, size_t n) {
        for (size_t i = n_reserved; i < n; i++)
                free(iov[i].iov_base);
}

/* Shared by sd_journal_send() and sd_journal_send_with_location(): scans
 * format,args,format,args,...,NULL starting at iov[n_reserved] (the caller
 * has already filled in any location iovs below that index), then makes
 * the one real sd_journal_sendv() call and frees the strings this function
 * itself allocated -- never the caller's reserved (borrowed) location
 * pointers. `ap` must already be va_start()ed by the caller, who also owns
 * the matching va_end().
 *
 * Takes va_list* rather than va_list: where va_list is an array type
 * (x86-64), a by-value parameter decays to a pointer, so &ap yields the
 * wrong type -- an error under -Werror there while building fine on
 * aarch64, where va_list is a struct. */
static int scan_fields_and_send(
                struct iovec *iov, size_t cap, size_t n_reserved, const char *format, va_list *ap) {
        size_t n = n_reserved;
        const char *fmt;
        int r = 0, rc;

        for (fmt = format; fmt; fmt = va_arg(*ap, const char *)) {
                if (n >= cap) {
                        r = -EOVERFLOW;
                        break;
                }
                r = send_one_field(fmt, ap, iov, &n);
                if (r < 0)
                        break;
        }

        if (r < 0) {
                free_iov_strings(iov, n_reserved, n);
                return r;
        }

        rc = sd_journal_sendv(iov, (int) n);
        free_iov_strings(iov, n_reserved, n);

        return rc;
}

int sd_journal_send_with_location(const char *file, const char *line, const char *func, const char *format, ...) {
        va_list ap;
        struct iovec iov[64]; /* upstream has no fixed cap either; this is a generous, documented one for pico */
        char funcbuf[256];
        int rc;

        iov[0].iov_base = (void *) file;
        iov[0].iov_len = strlen(file);
        iov[1].iov_base = (void *) line;
        iov[1].iov_len = strlen(line);
        snprintf(funcbuf, sizeof(funcbuf), "CODE_FUNC=%s", func);
        iov[2].iov_base = funcbuf;
        iov[2].iov_len = strlen(funcbuf);

        va_start(ap, format);
        rc = scan_fields_and_send(iov, sizeof(iov) / sizeof(iov[0]), 3, format, &ap);
        va_end(ap);

        return rc;
}

int sd_journal_send(const char *format, ...) {
        va_list ap;
        struct iovec iov[64];
        int rc;

        va_start(ap, format);
        rc = scan_fields_and_send(iov, sizeof(iov) / sizeof(iov[0]), 0, format, &ap);
        va_end(ap);

        return rc;
}
