/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_journal_print()/printv()/send() and their _with_location twins: the
 * printf-shaped write API, built on sd_journal_sendv() (sd-journal-sendv.c),
 * the one function that talks to logd.
 *
 * SD_JOURNAL_SUPPRESS_LOCATION is defined before including the public
 * header because sd-journal.h's macros redirect plain
 * sd_journal_print()/send()/sendv() to the *_with_location() variant; this
 * file's own calls must reach the undecorated symbol instead of recording
 * CODE_FILE/CODE_LINE/CODE_FUNC of this file.
 *
 * sd_journal_send() scans its variadic arguments per the documented
 * convention (a format string, its conversions' arguments, the next format
 * string, ..., NULL) without upstream's VA_FORMAT_ADVANCE macro, which needs
 * GNU statement expressions (netd-compat.h gives the same reason for the
 * same macro family). advance_va() is the portable equivalent: each field is
 * formatted with vasprintf() on a va_copy, then the format's conversions are
 * walked against the real va_list only to consume the matching va_arg()s,
 * leaving it positioned at the next format string.
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

/* Trims trailing ' '/'\t'/'\n' from s[0..*len) in place and updates *len;
 * leading whitespace is kept, as upstream. The buffer is not NUL-moved. */
static void strip_trailing_ws(const char *s, size_t *len) {
        while (*len > 0 && (s[*len - 1] == ' ' || s[*len - 1] == '\t' || s[*len - 1] == '\n'))
                (*len)--;
}

enum { LEN_NONE, LEN_HH, LEN_H, LEN_L, LEN_LL, LEN_LD, LEN_Z, LEN_J, LEN_T };

/* Walks the '%' conversions in `format` and va_arg()s the matching type off
 * *ap for each. An unrecognized conversion is left unconsumed: the caller is
 * outside the documented calling convention either way, and this way the
 * next va_arg() reads at most the current field's own argument as a format
 * string rather than unrelated memory.
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
        /* CODE_FILE=/CODE_LINE=/CODE_FUNC= are passed to sd_journal_sendv(),
         * which drops them. Not delegated to sd_journal_printv() because that
         * builds exactly two iovs. */
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
 * malloc'd iovec entry, then consumes `format`'s arguments off `*ap` via
 * advance_va(). Returns 0 or a negative error; the caller frees the batch on
 * failure. */
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
 * fills the location iovs below that), calls sd_journal_sendv() and frees
 * the strings allocated here, not the caller's borrowed location pointers.
 * `ap` must already be va_start()ed; the caller owns the va_end().
 *
 * Takes va_list* rather than va_list: where va_list is an array type
 * (x86-64) a by-value parameter decays to a pointer, so &ap has the wrong
 * type. */
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
        struct iovec iov[64]; /* fixed cap on fields per call */
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
