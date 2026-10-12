/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * picolog -- the on-device log reader, the journalctl equivalent. Named to
 * avoid colliding with BusyBox `logread`. It reads the ring files directly
 * and needs nothing from the daemon. Reading lives in logd-read.c so picoctl
 * can reuse it; this file is CLI parsing and display only.
 *
 * The option set follows journalctl 262. Where the ring has no data or no
 * subsystem behind an option it is handled one of three ways, listed in
 * docs/LOGD.md: implemented on the stored fields, accepted as a no-op where
 * doing nothing is the right outcome for a runtime-only journal, or refused
 * with a diagnostic and status 1 where silent acceptance would let a script
 * believe something happened.
 *
 * A /run ring only ever holds the current boot, so the boot filter that
 * journalctl implies for -k, -f and -e is not applied, and -b selects by an
 * explicit boot ID only.
 *
 * The LOGD_RUNTIME_DIR environment variable (not the logd.h macro of the
 * same name) overrides the compiled-in ring location, so test-picolog.c can
 * point it at a fixture tree. Production never sets it.
 */

#define _GNU_SOURCE /* timegm() */

#include "logd-read.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../pico-color.h"
#include "logd.h"

typedef enum {
        OUTPUT_SHORT,
        OUTPUT_SHORT_ISO,
        OUTPUT_SHORT_ISO_PRECISE,
        OUTPUT_SHORT_PRECISE,
        OUTPUT_SHORT_MONOTONIC,
        OUTPUT_SHORT_DELTA,
        OUTPUT_SHORT_UNIX,
        OUTPUT_SHORT_FULL,
        OUTPUT_VERBOSE,
        OUTPUT_EXPORT,
        OUTPUT_JSON,
        OUTPUT_JSON_PRETTY,
        OUTPUT_JSON_SSE,
        OUTPUT_JSON_SEQ,
        OUTPUT_CAT,
        OUTPUT_WITH_UNIT,
        _OUTPUT_MAX,
} OutputMode;

/* In journalctl's order, which -o help prints. */
static const char * const output_names[_OUTPUT_MAX] = {
        [OUTPUT_SHORT] = "short",
        [OUTPUT_SHORT_ISO] = "short-iso",
        [OUTPUT_SHORT_ISO_PRECISE] = "short-iso-precise",
        [OUTPUT_SHORT_PRECISE] = "short-precise",
        [OUTPUT_SHORT_MONOTONIC] = "short-monotonic",
        [OUTPUT_SHORT_DELTA] = "short-delta",
        [OUTPUT_SHORT_UNIX] = "short-unix",
        [OUTPUT_SHORT_FULL] = "short-full",
        [OUTPUT_VERBOSE] = "verbose",
        [OUTPUT_EXPORT] = "export",
        [OUTPUT_JSON] = "json",
        [OUTPUT_JSON_PRETTY] = "json-pretty",
        [OUTPUT_JSON_SSE] = "json-sse",
        [OUTPUT_JSON_SEQ] = "json-seq",
        [OUTPUT_CAT] = "cat",
        [OUTPUT_WITH_UNIT] = "with-unit",
};

typedef enum {
        ACTION_SHOW,
        ACTION_NEW_ID128,
        ACTION_LIST_FIELD_NAMES,
        ACTION_LIST_FIELDS,
        ACTION_LIST_BOOTS,
        ACTION_LIST_INVOCATIONS,
        ACTION_LIST_NAMESPACES,
        ACTION_DISK_USAGE,
        ACTION_VACUUM,
        ACTION_NOOP,    /* --flush and the relinquish-var pair: nothing is stored on disk */
        ACTION_REFUSED, /* arg_refusal holds the diagnostic */
} Action;

enum {
        LINES_DEFAULT = -2,
        LINES_ALL = -1,
};

/* A message or field value at or over this is ellipsized, blobbed or nulled unless -a. */
#define PRINT_CHAR_THRESHOLD 300U
#define PRINT_LINE_THRESHOLD 3U
#define JSON_THRESHOLD 4096U

#define ID_LEN 32

typedef struct MatchTerm {
        const char *name;
        size_t name_len;
        const char *value;
        size_t value_len;
        size_t group;
} MatchTerm;

/* State carried between printed entries: the -- Boot -- separator and
 * short-delta's reference point. */
typedef struct OutState {
        char sep_boot[ID_LEN + 1];
        bool have_sep_boot;
        char boot_id[ID_LEN + 1];
        uint64_t mono, real;
        bool have_prev;
        char cursor[128];
        bool have_cursor;
} OutState;

static Action arg_action = ACTION_SHOW;
static const char *arg_refusal;
static OutputMode arg_output = OUTPUT_SHORT;
static bool arg_follow;
static bool arg_full = true;
static bool arg_all;
static bool arg_quiet;
static bool arg_utc;
static bool arg_no_hostname;
static bool arg_reverse;
static bool arg_show_cursor;
static bool arg_truncate_newline;
static bool arg_no_tail;
static bool arg_dmesg;
static bool arg_merge;
static bool arg_pager_end;
static long arg_lines = LINES_DEFAULT;
static bool arg_lines_oldest;
static bool arg_boot;
static char arg_boot_id[ID_LEN + 1];
static int arg_boot_offset;
static int arg_priorities; /* bit n set: PRIORITY=n is shown; 0 means no filter */
static uint64_t arg_facilities;
static const char **arg_units;
static size_t arg_n_units;
static const char **arg_identifiers;
static size_t arg_n_identifiers;
static const char **arg_exclude_identifiers;
static size_t arg_n_exclude_identifiers;
static const char **arg_output_fields;
static size_t arg_n_output_fields;
static const char **arg_files;
static size_t arg_n_files;
static const char *arg_directory;
static const char *arg_root;
static const char *arg_namespace;
static const char *arg_field;
static const char *arg_cursor;
static const char *arg_after_cursor;
static const char *arg_cursor_file;
static const char *arg_pattern;
static int arg_case = -1; /* -1 smart case, 0 insensitive, 1 sensitive */
static uint64_t arg_since, arg_until;
static bool arg_since_set, arg_until_set;
static bool arg_invocation;
static char arg_invocation_id[ID_LEN + 1];
static int arg_invocation_offset;
static uint64_t arg_vacuum_size, arg_vacuum_n_files, arg_vacuum_time;

static MatchTerm *match_terms;
static size_t n_match_terms;
static size_t n_match_groups = 1;

static regex_t compiled_pattern;
static bool have_pattern;

static OutState out_state;
static char local_host[256];
static bool have_local_host;

static volatile sig_atomic_t stop_requested;

static void on_stop(int sig) {
        (void) sig;
        stop_requested = 1;
}

static int fail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static int fail(const char *fmt, ...) {
        va_list ap;

        fputs("picolog: ", stderr);
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fputc('\n', stderr);
        return 1;
}

static int push(const char ***v, size_t *n, const char *s) {
        const char **t = realloc(*v, (*n + 1) * sizeof(**v));

        if (!t)
                return -ENOMEM;
        *v = t;
        t[(*n)++] = s;
        return 0;
}

/* ---- argument parsing ------------------------------------------------- */

static int parse_priority(const char *s) {
        static const char * const names[] = {
                "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
        };

        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
                if (strcmp(s, names[i]) == 0)
                        return (int) i;

        {
                char *endp;
                long v = strtol(s, &endp, 10);

                if (endp != s && *endp == '\0' && v >= 0 && v <= 7)
                        return (int) v;
        }

        return -1;
}

/* "LEVEL" is that level and everything more severe, "FROM..TO" the
 * inclusive range in either order. */
static int parse_priorities(const char *arg) {
        const char *dots = strstr(arg, "..");
        int mask = 0;

        if (dots) {
                char *a = strndup(arg, (size_t) (dots - arg));
                int from, to;

                if (!a)
                        return fail("out of memory");
                from = parse_priority(a);
                free(a);
                to = parse_priority(dots + 2);
                if (from < 0 || to < 0)
                        return fail("Failed to parse log level range %s", arg);

                for (int i = from < to ? from : to; i <= (from < to ? to : from); i++)
                        mask |= 1 << i;
        } else {
                int p = parse_priority(arg);

                if (p < 0)
                        return fail("Unknown log level %s", arg);
                for (int i = 0; i <= p; i++)
                        mask |= 1 << i;
        }

        arg_priorities = mask;
        return 0;
}

static const char * const facility_names[] = {
        "kern",   "user",   "mail",     "daemon", "auth",   "syslog",   "lpr",     "news",
        "uucp",   "cron",   "authpriv", "ftp",    "ntp",    "security", "console", "solaris-cron",
        "local0", "local1", "local2",   "local3", "local4", "local5",   "local6",  "local7",
};
#define N_FACILITIES (sizeof(facility_names) / sizeof(facility_names[0]))

static int parse_facility(const char *s) {
        for (size_t i = 0; i < N_FACILITIES; i++)
                if (strcmp(s, facility_names[i]) == 0)
                        return (int) i;

        {
                char *endp;
                long v = strtol(s, &endp, 10);

                if (endp != s && *endp == '\0' && v >= 0 && v < (long) N_FACILITIES)
                        return (int) v;
        }

        return -1;
}

static bool parse_int(const char *s, int *ret) {
        char *endp;
        long v;

        errno = 0;
        v = strtol(s, &endp, 10);
        if (endp == s || *endp != '\0' || errno != 0 || v < INT_MIN || v > INT_MAX)
                return false;
        *ret = (int) v;
        return true;
}

static bool starts_with_id(const char *s) {
        if (strlen(s) < ID_LEN)
                return false;
        for (size_t i = 0; i < ID_LEN; i++)
                if (!isxdigit((unsigned char) s[i]))
                        return false;
        return s[ID_LEN] == '\0' || s[ID_LEN] == '+' || s[ID_LEN] == '-';
}

/* A boot or invocation descriptor: "all", an ID with an optional signed
 * offset, or just an offset. 1 for a descriptor, 0 for "all", -1 for garbage. */
static int parse_id_descriptor(const char *x, char id[ID_LEN + 1], int *offset) {
        id[0] = '\0';
        *offset = 0;

        if (strcmp(x, "all") == 0)
                return 0;

        if (starts_with_id(x)) {
                for (size_t i = 0; i < ID_LEN; i++)
                        id[i] = (char) tolower((unsigned char) x[i]);
                id[ID_LEN] = '\0';

                if (x[ID_LEN] != '\0' && !parse_int(x + ID_LEN, offset))
                        return -1;
                return 1;
        }

        return parse_int(x, offset) ? 1 : -1;
}

/* -n's argument: "5", "+5" or "all". With `graceful` a word that is not one
 * is left alone (the argument was only a guess at the next word). Returns 1
 * if `arg` was consumed, 0 if not, -1 for a bad explicit value. */
static int parse_lines(const char *arg, bool graceful) {
        const char *num;
        int n;

        if (!arg)
                goto default_noarg;

        if (strcmp(arg, "all") == 0) {
                arg_lines = LINES_ALL;
                return 1;
        }

        num = arg[0] == '+' ? arg + 1 : arg;
        if (!parse_int(num, &n) || n < 0) {
                if (graceful)
                        goto default_noarg;
                return -1;
        }

        arg_lines = n;
        arg_lines_oldest = arg[0] == '+';
        return 1;

default_noarg:
        arg_lines = 10;
        arg_lines_oldest = false;
        return 0;
}

static bool lines_needs_seek_end(void) {
        return arg_lines >= 0 && !arg_lines_oldest;
}

#define USEC_PER_SEC ((uint64_t) 1000000)

static const struct {
        const char *name;
        uint64_t usec;
} span_units[] = {
        {    "usec",                        1 },
        {      "us",                        1 },
        {    "msec",                     1000 },
        {      "ms",                     1000 },
        { "seconds",             USEC_PER_SEC },
        {  "second",             USEC_PER_SEC },
        {     "sec",             USEC_PER_SEC },
        {       "s",             USEC_PER_SEC },
        { "minutes",        60 * USEC_PER_SEC },
        {  "minute",        60 * USEC_PER_SEC },
        {     "min",        60 * USEC_PER_SEC },
        {       "m",        60 * USEC_PER_SEC },
        {   "hours",      3600 * USEC_PER_SEC },
        {    "hour",      3600 * USEC_PER_SEC },
        {      "hr",      3600 * USEC_PER_SEC },
        {       "h",      3600 * USEC_PER_SEC },
        {    "days",     86400 * USEC_PER_SEC },
        {     "day",     86400 * USEC_PER_SEC },
        {       "d",     86400 * USEC_PER_SEC },
        {   "weeks", 7 * 86400 * USEC_PER_SEC },
        {    "week", 7 * 86400 * USEC_PER_SEC },
        {       "w", 7 * 86400 * USEC_PER_SEC },
        {  "months",   2629800 * USEC_PER_SEC },
        {   "month",   2629800 * USEC_PER_SEC },
        {       "M",   2629800 * USEC_PER_SEC },
        {   "years",  31557600 * USEC_PER_SEC },
        {    "year",  31557600 * USEC_PER_SEC },
        {       "y",  31557600 * USEC_PER_SEC },
};

/* "1h 30min": one or more number/unit pairs. */
static bool parse_span(const char *s, uint64_t *ret) {
        uint64_t total = 0;
        bool any = false;

        for (;;) {
                char *endp;
                unsigned long long v;
                size_t ulen = 0;
                bool found = false;

                while (*s == ' ')
                        s++;
                if (*s == '\0')
                        break;
                if (!isdigit((unsigned char) *s))
                        return false;

                v = strtoull(s, &endp, 10);
                s = endp;
                while (*s == ' ')
                        s++;

                while (isalpha((unsigned char) s[ulen]))
                        ulen++;
                if (ulen == 0)
                        return false;

                for (size_t i = 0; i < sizeof(span_units) / sizeof(span_units[0]); i++)
                        if (strlen(span_units[i].name) == ulen && memcmp(span_units[i].name, s, ulen) == 0) {
                                total += v * span_units[i].usec;
                                found = true;
                                break;
                        }
                if (!found)
                        return false;

                s += ulen;
                any = true;
        }

        *ret = total;
        return any;
}

/* A bare number is seconds, as for parse_sec(). */
static bool parse_sec(const char *s, uint64_t *ret) {
        char *endp;
        unsigned long long v;

        if (isdigit((unsigned char) s[0])) {
                v = strtoull(s, &endp, 10);
                if (*endp == '\0') {
                        *ret = v * USEC_PER_SEC;
                        return true;
                }
        }
        return parse_span(s, ret);
}

/* Bytes with an optional K/M/G/T suffix, base 1024. */
static bool parse_size(const char *s, uint64_t *ret) {
        char *endp;
        unsigned long long v;
        uint64_t mult = 1;

        if (!isdigit((unsigned char) s[0]))
                return false;
        v = strtoull(s, &endp, 10);
        switch (*endp) {
        case '\0':
                break;
        case 'K':
                mult = 1ULL << 10;
                endp++;
                break;
        case 'M':
                mult = 1ULL << 20;
                endp++;
                break;
        case 'G':
                mult = 1ULL << 30;
                endp++;
                break;
        case 'T':
                mult = 1ULL << 40;
                endp++;
                break;
        default:
                return false;
        }
        if (*endp != '\0')
                return false;
        *ret = v * mult;
        return true;
}

static uint64_t now_usec(void) {
        struct timespec ts;

        clock_gettime(CLOCK_REALTIME, &ts);
        return (uint64_t) ts.tv_sec * USEC_PER_SEC + (uint64_t) ts.tv_nsec / 1000;
}

static bool two_digits(const char *s, int *ret) {
        if (!isdigit((unsigned char) s[0]) || !isdigit((unsigned char) s[1]))
                return false;
        *ret = (s[0] - '0') * 10 + (s[1] - '0');
        return true;
}

static uint64_t parse_fraction(const char **sp) {
        char digits[7] = "000000";
        size_t n = 0;
        const char *s = *sp;

        for (s++; isdigit((unsigned char) *s); s++)
                if (n < 6)
                        digits[n++] = *s;
        *sp = s;
        return strtoull(digits, NULL, 10);
}

/*
 * The forms of journalctl's parse_timestamp() that matter for a log range:
 * now, today, yesterday, tomorrow, @EPOCH, "+5min", "-1h", "5min ago",
 * "5min left", and "[WEEKDAY] YYYY-MM-DD [HH:MM[:SS[.FRAC]]] [UTC|Z|+HH:MM]"
 * or a bare time of day. Local time unless a zone is given.
 */
static bool parse_timestamp(const char *input, uint64_t *ret) {
        char buf[128];
        const char *s = input;
        struct tm tm;
        time_t t;
        size_t len;
        long gmtoff = 0;
        bool utc = false, have_date = false;
        uint64_t frac = 0, span;

        while (*s == ' ')
                s++;
        len = strlen(s);
        while (len > 0 && s[len - 1] == ' ')
                len--;
        if (len == 0 || len >= sizeof(buf))
                return false;
        memcpy(buf, s, len);
        buf[len] = '\0';
        s = buf;

        if (strcmp(s, "now") == 0) {
                *ret = now_usec();
                return true;
        }

        if (s[0] == '@') {
                char *endp;
                unsigned long long v = strtoull(s + 1, &endp, 10);

                if (endp == s + 1)
                        return false;
                if (*endp == '.') {
                        const char *p = endp;

                        frac = parse_fraction(&p);
                        endp = (char *) p;
                }
                if (*endp != '\0')
                        return false;
                *ret = v * USEC_PER_SEC + frac;
                return true;
        }

        if ((s[0] == '+' || s[0] == '-') && parse_span(s + 1, &span)) {
                uint64_t now = now_usec();

                *ret = s[0] == '+' ? now + span : (now > span ? now - span : 0);
                return true;
        }
        if (len > 4 && strcmp(s + len - 4, " ago") == 0) {
                buf[len - 4] = '\0';
                if (!parse_span(s, &span))
                        return false;
                *ret = now_usec() > span ? now_usec() - span : 0;
                return true;
        }
        if (len > 5 && strcmp(s + len - 5, " left") == 0) {
                buf[len - 5] = '\0';
                if (!parse_span(s, &span))
                        return false;
                *ret = now_usec() + span;
                return true;
        }

        t = (time_t) (now_usec() / USEC_PER_SEC);
        localtime_r(&t, &tm);
        tm.tm_isdst = -1;

        if (strcmp(s, "today") == 0 || strcmp(s, "yesterday") == 0 || strcmp(s, "tomorrow") == 0) {
                tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
                if (s[0] == 'y')
                        tm.tm_mday--;
                else if (s[0] == 't' && s[1] == 'o' && s[2] == 'm')
                        tm.tm_mday++;
                t = mktime(&tm);
                if (t == (time_t) -1)
                        return false;
                *ret = (uint64_t) t * USEC_PER_SEC;
                return true;
        }

        /* An optional weekday name is accepted and not checked against the date. */
        if (isalpha((unsigned char) s[0])) {
                size_t n = 0;

                while (isalpha((unsigned char) s[n]))
                        n++;
                if (n < 3 || s[n] != ' ')
                        return false;
                s += n + 1;
                while (*s == ' ')
                        s++;
        }

        if (isdigit((unsigned char) s[0]) && isdigit((unsigned char) s[1]) &&
            isdigit((unsigned char) s[2]) && isdigit((unsigned char) s[3]) && s[4] == '-') {
                int mon, day;

                if (!two_digits(s + 5, &mon) || s[7] != '-' || !two_digits(s + 8, &day))
                        return false;
                if (mon < 1 || mon > 12 || day < 1 || day > 31)
                        return false;
                tm.tm_year = atoi(s) - 1900;
                tm.tm_mon = mon - 1;
                tm.tm_mday = day;
                tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
                have_date = true;
                s += 10;
                if (*s == ' ' || *s == 'T')
                        s++;
        }

        if (isdigit((unsigned char) s[0])) {
                int h, m, sec = 0;

                if (!two_digits(s, &h) || s[2] != ':' || !two_digits(s + 3, &m))
                        return false;
                s += 5;
                if (*s == ':') {
                        if (!two_digits(s + 1, &sec))
                                return false;
                        s += 3;
                }
                if (h > 23 || m > 59 || sec > 60)
                        return false;
                tm.tm_hour = h;
                tm.tm_min = m;
                tm.tm_sec = sec;
                if (*s == '.')
                        frac = parse_fraction(&s);
        } else if (!have_date)
                return false;

        while (*s == ' ')
                s++;
        if (strcmp(s, "UTC") == 0 || strcmp(s, "Z") == 0 || strcmp(s, "GMT") == 0) {
                utc = true;
                s += strlen(s);
        } else if (*s == '+' || *s == '-') {
                int sign = *s == '-' ? -1 : 1, h, m = 0;

                if (!two_digits(s + 1, &h))
                        return false;
                s += 3;
                if (*s == ':') {
                        if (!two_digits(s + 1, &m))
                                return false;
                        s += 3;
                } else if (isdigit((unsigned char) *s)) {
                        if (!two_digits(s, &m))
                                return false;
                        s += 2;
                }
                gmtoff = sign * (h * 3600L + m * 60L);
                utc = true;
        }
        if (*s != '\0')
                return false;

        t = utc ? timegm(&tm) - gmtoff : mktime(&tm);
        if (t == (time_t) -1)
                return false;

        *ret = (uint64_t) t * USEC_PER_SEC + frac;
        return true;
}

/* ---- entry access ----------------------------------------------------- */

static bool field_u64(const LogdEntry *e, const char *name, uint64_t *ret) {
        const LogdReadField *f = logd_entry_field(e, name);
        char tmp[24];
        char *endp;

        if (!f || f->binary || f->value_len == 0 || f->value_len >= sizeof(tmp))
                return false;
        memcpy(tmp, f->value, f->value_len);
        tmp[f->value_len] = '\0';

        errno = 0;
        *ret = strtoull(tmp, &endp, 10);
        return *endp == '\0' && errno == 0;
}

static bool entry_realtime(const LogdEntry *e, uint64_t *ret) {
        return field_u64(e, "__REALTIME_TIMESTAMP", ret) && *ret > 0;
}

/* What is shown: the sender's own timestamp when it supplied one. */
static bool entry_display_realtime(const LogdEntry *e, uint64_t *ret) {
        if (field_u64(e, "_SOURCE_REALTIME_TIMESTAMP", ret) && *ret > 0)
                return true;
        return entry_realtime(e, ret);
}

static bool entry_boot_id(const LogdEntry *e, char out[ID_LEN + 1]) {
        const LogdReadField *f = logd_entry_field(e, "_BOOT_ID");

        if (!f || f->binary || f->value_len != ID_LEN) {
                memset(out, '0', ID_LEN);
                out[ID_LEN] = '\0';
                return false;
        }
        memcpy(out, f->value, ID_LEN);
        out[ID_LEN] = '\0';
        return true;
}

/* -1 when absent or not a single digit. */
static int entry_priority_strict(const LogdEntry *e) {
        const LogdReadField *f = logd_entry_field(e, "PRIORITY");
        const unsigned char *v = f ? f->value : NULL;

        if (f && !f->binary && f->value_len == 1 && v[0] >= '0' && v[0] <= '7')
                return v[0] - '0';

        return -1;
}

/* Defaults to LOG_INFO, like output_short()'s PRIORITY= parse (logs-show.c),
 * so a missing or malformed field never colours a line. */
static int entry_priority(const LogdEntry *e) {
        int p = entry_priority_strict(e);

        return p < 0 ? 6 : p;
}

static bool value_equals(const LogdReadField *f, const char *s) {
        return logd_field_equals(f, s);
}

static const char *local_hostname(void) {
        if (!have_local_host) {
                if (gethostname(local_host, sizeof(local_host)) < 0 || local_host[0] == '\0')
                        snprintf(local_host,
                                 sizeof(local_host),
                                 "(none)"); /* the kernel's name for an unset hostname */
                local_host[sizeof(local_host) - 1] = '\0';
                have_local_host = true;
        }
        return local_host;
}

/* ---- text helpers ----------------------------------------------------- */

/* Length of the valid, printable UTF-8 character at p, or 0. TAB is
 * printable; a newline only when allowed. */
static size_t utf8_printable_len(const unsigned char *p, size_t rem, bool allow_newline) {
        unsigned char c = p[0];
        uint32_t cp;
        size_t n;

        if (c < 0x80) {
                if (c >= 0x20 && c != 0x7f)
                        return 1;
                return (c == '\t' || (allow_newline && c == '\n')) ? 1 : 0;
        }

        if ((c & 0xe0) == 0xc0) {
                n = 2;
                cp = c & 0x1f;
        } else if ((c & 0xf0) == 0xe0) {
                n = 3;
                cp = c & 0x0f;
        } else if ((c & 0xf8) == 0xf0) {
                n = 4;
                cp = c & 0x07;
        } else
                return 0;

        if (rem < n)
                return 0;
        for (size_t i = 1; i < n; i++) {
                if ((p[i] & 0xc0) != 0x80)
                        return 0;
                cp = (cp << 6) | (p[i] & 0x3f);
        }

        if ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) || cp > 0x10ffff ||
            (cp >= 0xd800 && cp <= 0xdfff) || (cp >= 0x80 && cp <= 0x9f))
                return 0;

        return n;
}

static bool utf8_is_printable(const void *s, size_t len, bool allow_newline) {
        const unsigned char *p = s;

        for (size_t i = 0; i < len;) {
                size_t n = utf8_printable_len(p + i, len - i, allow_newline);

                if (n == 0)
                        return false;
                i += n;
        }
        return true;
}

static bool shall_print(const void *p, size_t l) {
        if (arg_all)
                return true;
        return l < PRINT_CHAR_THRESHOLD && utf8_is_printable(p, l, false);
}

/* -a's rendering: printable text as is, anything else as \xNN, so no raw
 * control or invalid byte reaches the terminal. NULL when nothing needed
 * escaping. */
static char *escape_unprintable(const void *value, size_t len, size_t *ret_len) {
        const unsigned char *p = value;
        char *out;
        size_t o = 0;
        bool changed = false;

        out = malloc(len * 4 + 1);
        if (!out)
                return NULL;

        for (size_t i = 0; i < len;) {
                size_t n = utf8_printable_len(p + i, len - i, true);

                if (n > 0) {
                        memcpy(out + o, p + i, n);
                        o += n;
                        i += n;
                } else {
                        o += (size_t) sprintf(out + o, "\\x%02x", p[i]);
                        i++;
                        changed = true;
                }
        }

        if (!changed) {
                free(out);
                return NULL;
        }
        *ret_len = o;
        return out;
}

/*
 * What journalctl does to a message without -a: TAB becomes 8 spaces, ANSI
 * colour (ESC [ ... m) and OSC (ESC ] ... BEL or ESC \) sequences are
 * dropped, and carriage returns before a newline or at the end are dropped.
 * Offsets in hl[] are carried across.
 */
static char *strip_tab_ansi(const char *in, size_t len, size_t *ret_len, size_t hl[2]) {
        char *out = malloc(len * 8 + 1);
        size_t o = 0, pending_cr = 0, nhl[2] = { hl ? hl[0] : 0, hl ? hl[1] : 0 };

        if (!out)
                return NULL;

        for (size_t i = 0; i <= len; i++) {
                if (hl) {
                        if (i == hl[0])
                                nhl[0] = o;
                        if (i == hl[1])
                                nhl[1] = o;
                }
                if (i == len)
                        break;

                if (in[i] == '\r') {
                        pending_cr++;
                        continue;
                }
                if (in[i] == '\n')
                        pending_cr = 0;
                for (; pending_cr > 0; pending_cr--)
                        out[o++] = '\r';

                if (in[i] == '\x1b' && i + 1 < len && in[i + 1] == '[') {
                        size_t j = i + 2;

                        while (j < len && (isdigit((unsigned char) in[j]) || in[j] == ';' || in[j] == ':'))
                                j++;
                        if (j < len && in[j] == 'm') {
                                i = j;
                                continue;
                        }
                } else if (in[i] == '\x1b' && i + 1 < len && in[i + 1] == ']') {
                        size_t j = i + 2;

                        while (j < len && in[j] != '\a' &&
                               !(in[j] == '\x1b' && j + 1 < len && in[j + 1] == '\\'))
                                j++;
                        if (j < len) {
                                i = in[j] == '\a' ? j : j + 1;
                                continue;
                        }
                }

                if (in[i] == '\t') {
                        memset(out + o, ' ', 8);
                        o += 8;
                } else
                        out[o++] = in[i];
        }

        if (hl) {
                hl[0] = nhl[0];
                hl[1] = nhl[1];
        }
        *ret_len = o;
        return out;
}

/* FORMAT_BYTES(): IEC units, one decimal when non-zero, "B" only below 1K. */
static const char *format_bytes(char *buf, size_t sz, uint64_t t) {
        static const struct {
                char suffix;
                uint64_t factor;
        } table[] = {
                { 'E', 1ULL << 60 },
                { 'P', 1ULL << 50 },
                { 'T', 1ULL << 40 },
                { 'G', 1ULL << 30 },
                { 'M', 1ULL << 20 },
                { 'K', 1ULL << 10 },
        };

        for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
                uint64_t whole, tenth;

                if (t < table[i].factor)
                        continue;

                whole = t / table[i].factor;
                tenth = (t % table[i].factor) * 10 / table[i].factor;
                if (tenth > 0)
                        snprintf(buf, sz, "%" PRIu64 ".%" PRIu64 "%c", whole, tenth, table[i].suffix);
                else
                        snprintf(buf, sz, "%" PRIu64 "%c", whole, table[i].suffix);
                return buf;
        }

        snprintf(buf, sz, "%" PRIu64 "B", t);
        return buf;
}

static unsigned columns(void) {
        struct winsize ws;
        const char *e = getenv("COLUMNS");

        if (e) {
                int v;

                if (parse_int(e, &v) && v > 0)
                        return (unsigned) v;
        }
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) >= 0 && ws.ws_col > 0)
                return ws.ws_col;
        return 80;
}

/* get_log_colors() (src/basic/terminal-util.c): the priority-based on/off
 * wrap applied to message text, and the colour of a --grep match inside it.
 * LOG_INFO gets nothing. */
static void log_colors_for(int priority, const char **on, const char **off, const char **highlight) {
        *on = *off = *highlight = "";

        if (priority < 0)
                return;

        if (priority <= 3) { /* LOG_EMERG..LOG_ERR */
                *on = pico_ansi_highlight_red();
                *off = pico_ansi_normal();
                *highlight = pico_ansi_highlight();
        } else if (priority == 4) { /* LOG_WARNING */
                *on = pico_ansi_highlight_yellow();
                *off = pico_ansi_normal();
                *highlight = pico_ansi_highlight();
        } else if (priority == 5) { /* LOG_NOTICE */
                *on = pico_ansi_highlight();
                *off = pico_ansi_normal();
                *highlight = pico_ansi_highlight_red();
        } else if (priority >= 7) { /* LOG_DEBUG */
                *on = pico_ansi_grey();
                *off = pico_ansi_normal();
                *highlight = pico_ansi_highlight_red();
        }
}

/* ellipsize_mem(): keep `percent` of the retained text before the dots. The
 * dots are ASCII and width is counted in bytes. */
static void print_ellipsized(const char *s, size_t len, size_t width, unsigned percent) {
        size_t keep, head;

        if (len <= width) {
                fwrite(s, 1, len, stdout);
                return;
        }
        if (width <= 3) {
                fputs("...", stdout);
                return;
        }

        keep = width - 3;
        head = keep * percent / 100;
        fwrite(s, 1, head, stdout);
        fputs("...", stdout);
        fwrite(s + len - (keep - head), 1, keep - head, stdout);
}

/*
 * print_multiline() (logs-show.c): lines after the first are indented by
 * `prefix`, each line wrapped in the priority colour, and without -l/-a a
 * long message is ellipsized to the terminal width, to three lines and to
 * 300 characters. A negative priority turns colour off. hl[] is the byte
 * range of a --grep match to highlight, NULL for none.
 */
static void
                print_multiline(unsigned prefix,
                                unsigned n_columns,
                                bool full_width,
                                int priority,
                                const char *message,
                                size_t message_len,
                                const size_t hl[2]) {

        const char *color_on, *color_off, *highlight_on;
        const char *pos, *end;
        unsigned line = 0;

        log_colors_for(priority, &color_on, &color_off, &highlight_on);

        /* An empty message still gets its newline. */
        if (message_len == 0)
                fputs("\n", stdout);

        for (pos = message; pos < message + message_len; pos = end + 1, line++) {
                unsigned indent = line > 0 ? prefix : 0;
                size_t len, off = (size_t) (pos - message);
                bool tail_line;

                for (end = pos; end < message + message_len && *end != '\n'; end++)
                        ;
                len = (size_t) (end - pos);

                tail_line = line + 1 == PRINT_LINE_THRESHOLD ||
                                (size_t) (end - message) + 1 >= PRINT_CHAR_THRESHOLD;

                if (full_width || (prefix + len + 1 < n_columns && !tail_line)) {
                        if (hl && hl[0] >= off && hl[0] < off + len && highlight_on[0] != '\0') {
                                size_t hs = hl[0] - off, he = hl[1] > off + len ? len : hl[1] - off;

                                printf("%*s%s%.*s", (int) indent, "", color_on, (int) hs, pos);
                                printf("%s%.*s", highlight_on, (int) (he - hs), pos + hs);
                                printf("%s%.*s%s\n", color_on, (int) (len - he), pos + he, color_off);
                        } else
                                printf("%*s%s%.*s%s\n", (int) indent, "", color_on, (int) len, pos, color_off);
                        continue;
                }

                if (prefix < n_columns && n_columns - prefix >= 3) {
                        printf("%*s%s", (int) indent, "", color_on);
                        if (n_columns - prefix > len + 3)
                                printf("%.*s...", (int) len, pos);
                        else
                                print_ellipsized(pos, len, n_columns - prefix, tail_line ? 100 : 90);
                        printf("%s\n", color_off);
                } else
                        fputs("...\n", stdout);

                if (tail_line)
                        break;
        }
}

/* ---- filters ---------------------------------------------------------- */

static bool entry_has_pair(const LogdEntry *e, const MatchTerm *t) {
        for (size_t i = 0; i < e->n_fields; i++) {
                const LogdReadField *f = &e->fields[i];

                if (f->name_len == t->name_len && memcmp(f->name, t->name, t->name_len) == 0 &&
                    f->value_len == t->value_len && memcmp(f->value, t->value, t->value_len) == 0)
                        return true;
        }
        return false;
}

static bool same_name(const MatchTerm *a, const MatchTerm *b) {
        return a->name_len == b->name_len && memcmp(a->name, b->name, a->name_len) == 0;
}

/* Terms of one field are alternatives; different fields in a group all have
 * to match. */
static bool group_matches(const LogdEntry *e, size_t group) {
        for (size_t i = 0; i < n_match_terms; i++) {
                bool first = true, ok = false;

                if (match_terms[i].group != group)
                        continue;
                for (size_t j = 0; j < i; j++)
                        if (match_terms[j].group == group && same_name(&match_terms[i], &match_terms[j])) {
                                first = false;
                                break;
                        }
                if (!first)
                        continue;

                for (size_t j = i; j < n_match_terms; j++)
                        if (match_terms[j].group == group && same_name(&match_terms[i], &match_terms[j]) &&
                            entry_has_pair(e, &match_terms[j])) {
                                ok = true;
                                break;
                        }
                if (!ok)
                        return false;
        }
        return true;
}

static bool matches_pass(const LogdEntry *e) {
        if (n_match_terms == 0)
                return true;
        for (size_t g = 0; g < n_match_groups; g++)
                if (group_matches(e, g))
                        return true;
        return false;
}

static bool unit_matches(const LogdEntry *e) {
        const LogdReadField *f;
        char tmp[256];

        if (arg_n_units == 0)
                return true;

        f = logd_entry_field(e, "_SYSTEMD_UNIT");
        if (!f || f->binary || f->value_len >= sizeof(tmp))
                return false;
        memcpy(tmp, f->value, f->value_len);
        tmp[f->value_len] = '\0';

        for (size_t i = 0; i < arg_n_units; i++)
                if (fnmatch(arg_units[i], tmp, FNM_NOESCAPE) == 0)
                        return true;
        return false;
}

static bool identifier_in(const LogdEntry *e, const char **list, size_t n) {
        const LogdReadField *f = logd_entry_field(e, "SYSLOG_IDENTIFIER");

        for (size_t i = 0; f && i < n; i++)
                if (value_equals(f, list[i]))
                        return true;
        return false;
}

static bool grep_match(const LogdEntry *e, size_t hl[2]) {
        const LogdReadField *m = logd_entry_field(e, "MESSAGE");
        regmatch_t pm[1];
        char *tmp;
        int r;

        if (!m)
                return false;
        tmp = malloc(m->value_len + 1);
        if (!tmp)
                return false;
        memcpy(tmp, m->value, m->value_len);
        tmp[m->value_len] = '\0';

        r = regexec(&compiled_pattern, tmp, 1, pm, 0);
        free(tmp);
        if (r != 0)
                return false;

        if (hl) {
                hl[0] = (size_t) pm[0].rm_so;
                hl[1] = (size_t) pm[0].rm_eo;
        }
        return true;
}

static bool entry_passes(const LogdEntry *e) {
        uint64_t rt = 0;

        if (arg_dmesg && !logd_entry_is_kernel(e))
                return false;

        if (arg_boot_id[0] != '\0') {
                const LogdReadField *b = logd_entry_field(e, "_BOOT_ID");

                if (!b || b->value_len != ID_LEN || strncasecmp(b->value, arg_boot_id, ID_LEN) != 0)
                        return false;
        }

        if (!unit_matches(e))
                return false;

        if (arg_n_identifiers > 0 && !identifier_in(e, arg_identifiers, arg_n_identifiers))
                return false;
        if (arg_n_exclude_identifiers > 0 &&
            identifier_in(e, arg_exclude_identifiers, arg_n_exclude_identifiers))
                return false;

        if (arg_priorities != 0) {
                int p = entry_priority_strict(e);

                if (p < 0 || !(arg_priorities & (1 << p)))
                        return false;
        }

        if (arg_facilities != 0) {
                uint64_t fac;

                if (!field_u64(e, "SYSLOG_FACILITY", &fac) || fac >= 64 || !((arg_facilities >> fac) & 1))
                        return false;
        }

        if (!matches_pass(e))
                return false;

        if (arg_since_set || arg_until_set) {
                if (!entry_realtime(e, &rt))
                        return false;
                if (arg_since_set && rt < arg_since)
                        return false;
                if (arg_until_set && rt > arg_until)
                        return false;
        }

        if (have_pattern && !grep_match(e, NULL))
                return false;

        return true;
}

/* ---- cursors ---------------------------------------------------------- */

/* The ring has no sequence numbers, so an entry is named by its boot ID and
 * its two timestamps: "b=BOOTID;m=MONOHEX;t=REALHEX". */
static bool make_cursor(const LogdEntry *e, char *buf, size_t sz) {
        char boot[ID_LEN + 1];
        uint64_t mono, real;

        if (!field_u64(e, "__MONOTONIC_TIMESTAMP", &mono) || !entry_realtime(e, &real))
                return false;
        entry_boot_id(e, boot);
        snprintf(buf, sz, "b=%s;m=%" PRIx64 ";t=%" PRIx64, boot, mono, real);
        return true;
}

static bool parse_cursor(const char *c, char boot[ID_LEN + 1], uint64_t *mono, uint64_t *real) {
        bool have_b = false, have_m = false, have_t = false;

        while (*c) {
                const char *semi = strchr(c, ';');
                size_t n = semi ? (size_t) (semi - c) : strlen(c);

                if (n >= 2 && c[1] == '=') {
                        char tmp[64];
                        char *endp;

                        if (n - 2 >= sizeof(tmp))
                                return false;
                        memcpy(tmp, c + 2, n - 2);
                        tmp[n - 2] = '\0';

                        if (c[0] == 'b') {
                                if (strlen(tmp) != ID_LEN)
                                        return false;
                                memcpy(boot, tmp, ID_LEN + 1);
                                have_b = true;
                        } else if (c[0] == 'm') {
                                *mono = strtoull(tmp, &endp, 16);
                                have_m = *tmp && !*endp;
                        } else if (c[0] == 't') {
                                *real = strtoull(tmp, &endp, 16);
                                have_t = *tmp && !*endp;
                        }
                }
                if (!semi)
                        break;
                c = semi + 1;
        }

        return have_b && have_m && have_t;
}

/* Position of `cursor` in the ring: the exact entry, else the first entry at
 * or after its time. SIZE_MAX if the cursor is malformed. */
static size_t find_cursor(const LogdRing *ring, const char *cursor, bool *exact) {
        char boot[ID_LEN + 1], cur[128];
        uint64_t mono, real;
        size_t n = logd_ring_n_entries(ring);

        *exact = false;
        if (!parse_cursor(cursor, boot, &mono, &real))
                return SIZE_MAX;

        for (size_t i = 0; i < n; i++)
                if (make_cursor(logd_ring_entry(ring, i), cur, sizeof(cur)) && strcasecmp(cur, cursor) == 0) {
                        *exact = true;
                        return i;
                }

        for (size_t i = 0; i < n; i++) {
                uint64_t rt;

                if (entry_realtime(logd_ring_entry(ring, i), &rt) && rt >= real)
                        return i;
        }
        return n;
}

/* ---- output ----------------------------------------------------------- */

static int format_realtime(char *buf, size_t sz, OutputMode mode, uint64_t usec) {
        time_t sec = (time_t) (usec / USEC_PER_SEC);
        unsigned long frac = (unsigned long) (usec % USEC_PER_SEC);
        struct tm tm;
        size_t n;

        if (!(arg_utc ? gmtime_r(&sec, &tm) : localtime_r(&sec, &tm)))
                return -1;

        switch (mode) {
        case OUTPUT_SHORT_UNIX:
                return snprintf(buf, sz, "%10" PRIu64 ".%06lu", (uint64_t) sec, frac);

        case OUTPUT_SHORT_FULL:
        case OUTPUT_WITH_UNIT:
                n = strftime(buf, sz, "%a %Y-%m-%d %H:%M:%S", &tm);
                if (n == 0)
                        return -1;
                if (arg_utc)
                        return (int) n + snprintf(buf + n, sz - n, " UTC");
                return (int) n + (int) strftime(buf + n, sz - n, " %Z", &tm);

        case OUTPUT_SHORT_ISO:
        case OUTPUT_SHORT_ISO_PRECISE:
                n = strftime(buf, sz, "%Y-%m-%dT%H:%M:%S", &tm);
                if (n == 0)
                        return -1;
                if (mode == OUTPUT_SHORT_ISO_PRECISE)
                        n += (size_t) snprintf(buf + n, sz - n, ".%06lu", frac);
                return (int) n +
                                snprintf(buf + n,
                                         sz - n,
                                         "%+03d:%02d",
                                         (int) (tm.tm_gmtoff / 3600),
                                         (int) (tm.tm_gmtoff < 0 ? -tm.tm_gmtoff : tm.tm_gmtoff) / 60 % 60);

        case OUTPUT_SHORT_PRECISE:
                n = strftime(buf, sz, "%b %d %H:%M:%S", &tm);
                if (n == 0)
                        return -1;
                return (int) n + snprintf(buf + n, sz - n, ".%06lu", frac);

        default:
                n = strftime(buf, sz, "%b %d %H:%M:%S", &tm);
                return n == 0 ? -1 : (int) n;
        }
}

/* The verbose header's "Mon 2026-10-12 10:00:00.123456 CEST". */
static int format_realtime_us(char *buf, size_t sz, uint64_t usec) {
        time_t sec = (time_t) (usec / USEC_PER_SEC);
        struct tm tm;
        size_t n;

        if (!(arg_utc ? gmtime_r(&sec, &tm) : localtime_r(&sec, &tm)))
                return -1;
        n = strftime(buf, sz, "%a %Y-%m-%d %H:%M:%S", &tm);
        if (n == 0)
                return -1;
        n += (size_t) snprintf(buf + n, sz - n, ".%06lu", (unsigned long) (usec % USEC_PER_SEC));
        if (arg_utc)
                return (int) n + snprintf(buf + n, sz - n, " UTC");
        return (int) n + (int) strftime(buf + n, sz - n, " %Z", &tm);
}

static void print_blob(size_t len) {
        char b[48];

        printf("[%s blob data]", format_bytes(b, sizeof(b), len));
}

static int print_monotonic_stamp(const LogdEntry *e, OutputMode mode) {
        uint64_t mono, real = 0;
        char boot[ID_LEN + 1];
        int written;

        if (!field_u64(e, "__MONOTONIC_TIMESTAMP", &mono))
                return -1;
        entry_boot_id(e, boot);
        (void) entry_realtime(e, &real);

        written = printf("[%5" PRIu64 ".%06" PRIu64, mono / USEC_PER_SEC, mono % USEC_PER_SEC);

        if (mode == OUTPUT_SHORT_DELTA) {
                uint64_t delta;
                bool reliable = true;

                if (out_state.have_prev && strcmp(boot, out_state.boot_id) == 0)
                        delta = mono > out_state.mono ? mono - out_state.mono : 0;
                else if (out_state.have_prev && real > 0 && out_state.real > 0) {
                        delta = real > out_state.real ? real - out_state.real : 0;
                        reliable = false;
                } else {
                        written += printf("%16s", "");
                        goto finish;
                }
                written += printf(
                                " <%5" PRIu64 ".%06" PRIu64 "%s>",
                                delta / USEC_PER_SEC,
                                delta % USEC_PER_SEC,
                                reliable ? " " : "*");
        }
finish:
        written += printf("]");

        out_state.mono = mono;
        out_state.real = real;
        memcpy(out_state.boot_id, boot, sizeof(boot));
        out_state.have_prev = true;
        return written;
}

/* output_short(): "TIME host identifier[pid]: message". */
static void print_short(const LogdEntry *e) {
        const LogdReadField *msg = logd_entry_field(e, "MESSAGE");
        const LogdReadField *ident = logd_entry_field(e, "SYSLOG_IDENTIFIER");
        const LogdReadField *comm = logd_entry_field(e, "_COMM");
        const LogdReadField *pid = logd_entry_field(e, "_PID");
        const LogdReadField *fake_pid = logd_entry_field(e, "SYSLOG_PID");
        const LogdReadField *unit = logd_entry_field(e, "_SYSTEMD_UNIT");
        const LogdReadField *host = logd_entry_field(e, "_HOSTNAME");
        char ts[96];
        const char *mdata;
        size_t mlen, hl[2] = { 0, 0 };
        char *owned = NULL;
        bool have_hl = false;
        int n, p = entry_priority(e);
        uint64_t usec;

        if (!msg)
                return;

        if (arg_output == OUTPUT_SHORT_MONOTONIC || arg_output == OUTPUT_SHORT_DELTA) {
                /* The stamp prints straight to stdout; nothing precedes it. */
                n = print_monotonic_stamp(e, arg_output);
                if (n < 0)
                        return;
        } else {
                /* Like output_timestamp_realtime() (logs-show.c), skip the entry when
                 * there is no valid realtime timestamp. */
                if (!entry_display_realtime(e, &usec) || format_realtime(ts, sizeof(ts), arg_output, usec) < 0)
                        return;
                n = printf("%s", ts);
        }

        if (!arg_no_hostname) {
                if (host) {
                        if (shall_print(host->value, host->value_len)) {
                                n += printf(" %.*s", (int) host->value_len, (const char *) host->value);
                        }
                } else
                        n += printf(" %s", local_hostname());
        }

        if (arg_output == OUTPUT_WITH_UNIT && unit && shall_print(unit->value, unit->value_len))
                n += printf(" %.*s", (int) unit->value_len, (const char *) unit->value);
        else if (ident && shall_print(ident->value, ident->value_len))
                n += printf(" %.*s", (int) ident->value_len, (const char *) ident->value);
        else if (comm && shall_print(comm->value, comm->value_len))
                n += printf(" %.*s", (int) comm->value_len, (const char *) comm->value);
        else
                n += printf(" unknown"); /* journalctl's fallback text (logs-show.c) */

        if (pid && shall_print(pid->value, pid->value_len))
                n += printf("[%.*s]", (int) pid->value_len, (const char *) pid->value);
        else if (fake_pid && shall_print(fake_pid->value, fake_pid->value_len))
                n += printf("[%.*s]", (int) fake_pid->value_len, (const char *) fake_pid->value);

        fputs(": ", stdout);

        mdata = msg->value;
        mlen = msg->value_len;

        if (have_pattern && pico_colors_enabled())
                have_hl = grep_match(e, hl);

        if (!arg_all && !utf8_is_printable(mdata, mlen, true)) {
                print_blob(mlen);
                fputc('\n', stdout);
                return;
        }

        if (!arg_all) {
                size_t len;

                owned = strip_tab_ansi(mdata, mlen, &len, have_hl ? hl : NULL);
                if (owned) {
                        mdata = owned;
                        mlen = len;
                }
        } else {
                size_t len;
                char *esc = escape_unprintable(mdata, mlen, &len);

                if (esc) {
                        owned = esc;
                        mdata = esc;
                        mlen = len;
                        have_hl = false;
                }
        }

        if (arg_truncate_newline) {
                const char *nl = memchr(mdata, '\n', mlen);

                if (nl)
                        mlen = (size_t) (nl - mdata);
                if (have_hl && hl[0] > mlen)
                        have_hl = false;
                else if (have_hl && hl[1] > mlen)
                        hl[1] = mlen;
        }

        print_multiline((unsigned) n + 2, columns(), arg_full || arg_all, p, mdata, mlen, have_hl ? hl : NULL);
        free(owned);
}

static bool name_is(const LogdReadField *f, const char *name) {
        return f->name_len == strlen(name) && memcmp(f->name, name, f->name_len) == 0;
}

/* The fields the ring always stores, which --output-fields does not hide. */
static bool is_time_field(const LogdReadField *f) {
        return name_is(f, "__REALTIME_TIMESTAMP") || name_is(f, "__MONOTONIC_TIMESTAMP");
}

static bool is_header_field(const LogdReadField *f) {
        return is_time_field(f) || name_is(f, "_BOOT_ID");
}

static bool output_field_wanted(const char *name, size_t len) {
        if (arg_n_output_fields == 0)
                return true;
        for (size_t i = 0; i < arg_n_output_fields; i++)
                if (strlen(arg_output_fields[i]) == len && memcmp(arg_output_fields[i], name, len) == 0)
                        return true;
        return false;
}

static void print_verbose(const LogdEntry *e) {
        char ts[96], cursor[128];
        uint64_t usec;
        bool color = pico_colors_enabled();

        if (!entry_display_realtime(e, &usec))
                return;
        if (!make_cursor(e, cursor, sizeof(cursor)))
                snprintf(cursor, sizeof(cursor), "(no cursor)");

        if (format_realtime_us(ts, sizeof(ts), usec) < 0)
                snprintf(ts, sizeof(ts), "(no timestamp)");
        printf("%s%s%s %s[%s]%s\n",
               color ? pico_ansi_underline() : "",
               ts,
               color ? pico_ansi_normal() : "",
               pico_ansi_grey(),
               cursor,
               pico_ansi_grey());

        for (size_t i = 0; i < e->n_fields; i++) {
                const LogdReadField *f = &e->fields[i];
                const char *on = "", *off = "";
                const void *val = f->value;
                size_t vlen = f->value_len;
                char *esc = NULL;

                if (is_time_field(f))
                        continue;
                if (!output_field_wanted(f->name, f->name_len))
                        continue;

                if (color) {
                        if (f->name_len == 7 && memcmp(f->name, "MESSAGE", 7) == 0) {
                                on = pico_ansi_highlight();
                                off = pico_ansi_normal();
                        } else if (f->name[0] == '_') {
                                on = pico_ansi_green();
                                off = pico_ansi_normal();
                        }
                }

                if (arg_all ||
                    ((f->name_len + 1 + vlen < PRINT_CHAR_THRESHOLD || arg_full) &&
                     utf8_is_printable(val, vlen, true))) {
                        if (arg_all) {
                                size_t elen;

                                esc = escape_unprintable(val, vlen, &elen);
                                if (esc) {
                                        val = esc;
                                        vlen = elen;
                                }
                        }
                        printf("    %s%.*s=", on, (int) f->name_len, f->name);
                        print_multiline((unsigned) (4 + f->name_len + 1), 0, true, -1, val, vlen, NULL);
                        fputs(off, stdout);
                        free(esc);
                } else {
                        printf("    %s%.*s=", on, (int) f->name_len, f->name);
                        print_blob(vlen);
                        printf("%s\n", off);
                }
        }
}

static void print_export_field(const LogdReadField *f) {
        if (!f->binary) {
                printf("%.*s=", (int) f->name_len, f->name);
                fwrite(f->value, 1, f->value_len, stdout);
        } else {
                uint8_t le[8];

                printf("%.*s\n", (int) f->name_len, f->name);
                for (size_t i = 0; i < 8; i++)
                        le[i] = (uint8_t) ((uint64_t) f->value_len >> (8 * i));
                fwrite(le, 1, 8, stdout);
                fwrite(f->value, 1, f->value_len, stdout);
        }
        fputc('\n', stdout);
}

/* -o export passes the entry's on-disk bytes through unchanged, so a
 * filtered subset still feeds systemd-journal-remote. --output-fields has
 * to re-serialize, keeping the three header fields the ring always stores. */
static void print_export(const LogdEntry *e) {
        if (arg_n_output_fields == 0) {
                fwrite(e->raw, 1, e->raw_len, stdout);
                return;
        }

        for (size_t i = 0; i < e->n_fields; i++) {
                const LogdReadField *f = &e->fields[i];
                if (is_header_field(f) || output_field_wanted(f->name, f->name_len))
                        print_export_field(f);
        }
        fputc('\n', stdout);
}

static void json_string(const char *p, size_t l) {
        fputc('"', stdout);
        for (size_t i = 0; i < l; i++) {
                unsigned char c = (unsigned char) p[i];

                switch (c) {
                case '"':
                        fputs("\\\"", stdout);
                        break;
                case '\\':
                        fputs("\\\\", stdout);
                        break;
                case '\b':
                        fputs("\\b", stdout);
                        break;
                case '\f':
                        fputs("\\f", stdout);
                        break;
                case '\n':
                        fputs("\\n", stdout);
                        break;
                case '\r':
                        fputs("\\r", stdout);
                        break;
                case '\t':
                        fputs("\\t", stdout);
                        break;
                default:
                        if (c < ' ' || c == 0x7f)
                                printf("\\u%04x", c);
                        else
                                fputc(c, stdout);
                }
        }
        fputc('"', stdout);
}

/* A value is null when oversized, a string when printable text, else an
 * array of byte values (update_json_data() in logs-show.c). */
static void json_value(size_t name_len, const void *v, size_t l, bool pretty, unsigned depth) {
        if (!arg_all && name_len + 1 + l >= JSON_THRESHOLD)
                fputs("null", stdout);
        else if (utf8_is_printable(v, l, true))
                json_string(v, l);
        else {
                const unsigned char *p = v;

                fputc('[', stdout);
                for (size_t i = 0; i < l; i++) {
                        if (pretty)
                                printf("%s\n%*s", i ? "," : "", (int) (8 * (depth + 1)), "");
                        else if (i)
                                fputc(',', stdout);
                        printf("%u", p[i]);
                }
                if (pretty && l > 0)
                        printf("\n%*s", (int) (8 * depth), "");
                fputc(']', stdout);
        }
}

#define JSON_MAX_KEYS 72 /* 64 stored fields plus __CURSOR and slack */
#define JSON_MAX_VALUES 16

typedef struct JsonKey {
        const char *name;
        size_t name_len;
        const LogdReadField *vals[JSON_MAX_VALUES];
        size_t n_vals;
        const char *synthetic; /* __CURSOR: a value that is no stored field */
} JsonKey;

static void print_json(const LogdEntry *e) {
        bool pretty = arg_output == OUTPUT_JSON_PRETTY;
        JsonKey keys[JSON_MAX_KEYS];
        size_t n_keys = 0;
        char cursor[128];
        bool first = true;

        if (!make_cursor(e, cursor, sizeof(cursor)))
                return;

        keys[n_keys++] = (JsonKey){ .name = "__CURSOR", .name_len = 8, .synthetic = cursor };

        for (size_t i = 0; i < e->n_fields && n_keys < JSON_MAX_KEYS; i++) {
                const LogdReadField *f = &e->fields[i];
                size_t k;

                if (!is_header_field(f) && !output_field_wanted(f->name, f->name_len))
                        continue;

                for (k = 0; k < n_keys; k++)
                        if (!keys[k].synthetic && keys[k].name_len == f->name_len &&
                            memcmp(keys[k].name, f->name, f->name_len) == 0)
                                break;
                if (k == n_keys)
                        keys[n_keys++] = (JsonKey){ .name = f->name, .name_len = f->name_len };
                if (keys[k].n_vals < JSON_MAX_VALUES)
                        keys[k].vals[keys[k].n_vals++] = f;
        }

        if (arg_output == OUTPUT_JSON_SEQ)
                fputc('\x1e', stdout);
        else if (arg_output == OUTPUT_JSON_SSE)
                fputs("data: ", stdout);

        fputc('{', stdout);
        for (size_t k = 0; k < n_keys; k++) {
                if (!first)
                        fputc(',', stdout);
                first = false;
                if (pretty)
                        printf("\n%*s", 8, "");
                json_string(keys[k].name, keys[k].name_len);
                fputs(pretty ? " : " : ":", stdout);

                if (keys[k].synthetic)
                        json_string(keys[k].synthetic, strlen(keys[k].synthetic));
                else if (keys[k].n_vals == 1)
                        json_value(keys[k].name_len,
                                   keys[k].vals[0]->value,
                                   keys[k].vals[0]->value_len,
                                   pretty,
                                   1);
                else {
                        fputc('[', stdout);
                        for (size_t v = 0; v < keys[k].n_vals; v++) {
                                if (v)
                                        fputc(',', stdout);
                                if (pretty)
                                        printf("\n%*s", 16, "");
                                json_value(keys[k].name_len,
                                           keys[k].vals[v]->value,
                                           keys[k].vals[v]->value_len,
                                           pretty,
                                           2);
                        }
                        if (pretty)
                                printf("\n%*s", 8, "");
                        fputc(']', stdout);
                }
        }
        if (pretty)
                fputc('\n', stdout);
        fputc('}', stdout);
        fputs(arg_output == OUTPUT_JSON_SSE ? "\n\n" : "\n", stdout);
}

static void print_cat_field(const LogdEntry *e, const char *field, int prio, const size_t hl[2]) {
        const LogdReadField *f = logd_entry_field(e, field);
        const char *on, *off, *highlight_on;
        const char *d;
        size_t l;

        if (!f)
                return;
        d = f->value;
        l = f->value_len;
        log_colors_for(pico_colors_enabled() ? prio : -1, &on, &off, &highlight_on);

        if (hl && highlight_on[0] != '\0') {
                fputs(on, stdout);
                fwrite(d, 1, hl[0], stdout);
                fputs(highlight_on, stdout);
                fwrite(d + hl[0], 1, hl[1] - hl[0], stdout);
                fputs(on, stdout);
                fwrite(d + hl[1], 1, l - hl[1], stdout);
                fputs(off, stdout);
        } else {
                fputs(on, stdout);
                fwrite(d, 1, l, stdout);
                fputs(off, stdout);
        }
        fputc('\n', stdout);
}

static void print_cat(const LogdEntry *e) {
        int prio = entry_priority(e);
        size_t hl[2] = { 0, 0 };
        bool have_hl = have_pattern && pico_colors_enabled() && grep_match(e, hl);

        if (arg_n_output_fields == 0) {
                print_cat_field(e, "MESSAGE", prio, have_hl ? hl : NULL);
                return;
        }
        for (size_t i = 0; i < arg_n_output_fields; i++)
                print_cat_field(e,
                                arg_output_fields[i],
                                prio,
                                (have_hl && strcmp(arg_output_fields[i], "MESSAGE") == 0) ? hl : NULL);
}

static void print_entry(const LogdEntry *e) {
        char boot[ID_LEN + 1];

        if (!arg_quiet && !arg_merge && entry_boot_id(e, boot)) {
                if (out_state.have_sep_boot && strcmp(boot, out_state.sep_boot) != 0)
                        printf("%s-- Boot %s --%s\n", pico_ansi_highlight(), boot, pico_ansi_normal());
                memcpy(out_state.sep_boot, boot, sizeof(boot));
                out_state.have_sep_boot = true;
        }

        switch (arg_output) {
        case OUTPUT_VERBOSE:
                print_verbose(e);
                break;
        case OUTPUT_EXPORT:
                print_export(e);
                break;
        case OUTPUT_JSON:
        case OUTPUT_JSON_PRETTY:
        case OUTPUT_JSON_SSE:
        case OUTPUT_JSON_SEQ:
                print_json(e);
                break;
        case OUTPUT_CAT:
                print_cat(e);
                break;
        default:
                print_short(e);
        }

        out_state.have_cursor = make_cursor(e, out_state.cursor, sizeof(out_state.cursor));
}

/* ---- ring access ------------------------------------------------------ */

static const char *runtime_dir(void) {
        static char buf[PATH_MAX];
        const char *e;

        if (arg_directory)
                return arg_directory;
        if (arg_root) {
                snprintf(buf, sizeof(buf), "%s%s", arg_root, LOGD_RUNTIME_DIR);
                return buf;
        }

        e = getenv("LOGD_RUNTIME_DIR");
        return (e && e[0] != '\0') ? e : LOGD_RUNTIME_DIR;
}

/* Only the default namespace exists; any other name opens an empty journal. */
static bool namespace_is_foreign(void) {
        return arg_namespace && arg_namespace[0] != '\0' && arg_namespace[0] != '*' && arg_namespace[0] != '+';
}

static int load_ring(LogdRing **ret) {
        int r;

        if (namespace_is_foreign())
                r = logd_ring_read_files(NULL, 0, ret);
        else if (arg_n_files > 0)
                r = logd_ring_read_files(arg_files, arg_n_files, ret);
        else
                r = logd_ring_read(runtime_dir(), ret);

        if (r < 0)
                fail("Failed to open journal: %s", strerror(-r));
        return r < 0 ? -1 : 0;
}

static int note_boot_has_no_effect(void) {
        fputs("picolog: Specifying boot ID or boot offset has no effect, no persistent journal was found.\n",
              stderr);
        return 0;
}

static bool ring_has_boot(const LogdRing *ring, const char *id) {
        size_t n = logd_ring_n_entries(ring);

        for (size_t i = 0; i < n; i++) {
                char b[ID_LEN + 1];

                if (entry_boot_id(logd_ring_entry(ring, i), b) && strcasecmp(b, id) == 0)
                        return true;
        }
        return false;
}

static int read_cursor_file(char **ret) {
        FILE *f = fopen(arg_cursor_file, "r");
        char line[256];

        *ret = NULL;
        if (!f)
                return errno == ENOENT ? 0 : -errno;
        if (fgets(line, sizeof(line), f)) {
                line[strcspn(line, "\n")] = '\0';
                if (line[0] != '\0')
                        *ret = strdup(line);
        }
        fclose(f);
        return 0;
}

static int update_cursor(void) {
        if (!arg_show_cursor && !arg_cursor_file)
                return 0;
        if (!out_state.have_cursor)
                return 0;

        if (arg_show_cursor)
                printf("-- cursor: %s\n", out_state.cursor);

        if (arg_cursor_file) {
                char tmp[PATH_MAX];
                FILE *f;

                snprintf(tmp, sizeof(tmp), "%s.tmp%ld", arg_cursor_file, (long) getpid());
                f = fopen(tmp, "w");
                if (!f || fprintf(f, "%s", out_state.cursor) < 0 || fclose(f) != 0 ||
                    rename(tmp, arg_cursor_file) < 0) {
                        int e = errno;

                        unlink(tmp);
                        return fail("Failed to write new cursor to %s: %s", arg_cursor_file, strerror(e));
                }
        }
        return 0;
}

/* ---- actions ---------------------------------------------------------- */

static int acquire_unit(const char *option, const char **ret) {
        if (arg_n_units == 0)
                return fail("Using %s requires a unit. Please specify a unit name with -u/--unit=/--user-unit=.",
                            option);
        if (arg_n_units > 1)
                return fail("Using %s with multiple units is not supported.", option);

        *ret = arg_units[0];
        return 0;
}

/* The ring does not record invocation IDs, so no invocation can be found. */
static int invocation_not_found(void) {
        return fail("No journal entry found for the invocation (%s%+i).",
                    arg_invocation_id,
                    arg_invocation_offset);
}

static int run_show(void) {
        LogdRing *ring = NULL;
        LogdFollow *follow = NULL;
        size_t n, n_list = 0, n_out = 0, *list = NULL, *out = NULL;
        char *file_cursor = NULL;
        const char *cursor = arg_cursor ? arg_cursor : arg_after_cursor;
        bool after = arg_after_cursor != NULL, has_cursor = false, have_watermark = false;
        uint64_t wm_real = 0, wm_mono = 0;
        int r, status = 0;

        if (arg_invocation) {
                if (arg_invocation_offset != 0 || arg_invocation_id[0] == '\0') {
                        const char *unit;

                        if (acquire_unit("-I/--invocation= with an offset", &unit) != 0)
                                return 1;
                }
                return invocation_not_found();
        }

        if (arg_boot_offset != 0)
                return note_boot_has_no_effect();

        if (!cursor && arg_cursor_file) {
                r = read_cursor_file(&file_cursor);
                if (r < 0)
                        return fail("Failed to read cursor file %s: %s", arg_cursor_file, strerror(-r));
                if (file_cursor) {
                        cursor = file_cursor;
                        after = true;
                }
        }

        if (arg_follow) {
                if (arg_n_files > 0 || namespace_is_foreign())
                        return fail("The --follow switch is not supported when reading files.");

                /* Opened before the ring is read, so nothing written in between is lost. */
                r = logd_follow_new(runtime_dir(), &follow);
                if (r < 0)
                        return fail("Failed to get journal fd: %s", strerror(-r));
        }

        if (load_ring(&ring) < 0) {
                status = 1;
                goto finish;
        }
        n = logd_ring_n_entries(ring);

        if (arg_boot_id[0] != '\0' && !ring_has_boot(ring, arg_boot_id)) {
                status = fail("No journal boot entry found for the specified boot (%s+0).", arg_boot_id);
                goto finish;
        }

        list = n > 0 ? malloc(n * sizeof(*list)) : NULL;
        out = n > 0 ? malloc(n * sizeof(*out)) : NULL;
        if (n > 0 && (!list || !out)) {
                status = fail("out of memory");
                goto finish;
        }

        for (size_t i = 0; i < n; i++)
                if (entry_passes(logd_ring_entry(ring, i)))
                        list[n_list++] = i;

        if (n > 0) {
                const LogdEntry *last = logd_ring_entry(ring, n - 1);

                have_watermark = entry_realtime(last, &wm_real);
                (void) field_u64(last, "__MONOTONIC_TIMESTAMP", &wm_mono);
        }

        if (cursor) {
                bool exact;
                size_t cpos = find_cursor(ring, cursor, &exact), kept = 0;

                if (cpos == SIZE_MAX) {
                        status = fail("Failed to seek to cursor: Invalid argument");
                        goto finish;
                }
                has_cursor = true;

                for (size_t i = 0; i < n_list; i++) {
                        size_t ri = list[i];
                        bool keep;

                        if (!arg_reverse)
                                keep = (after && exact) ? ri > cpos : ri >= cpos;
                        else
                                keep = ((after && exact) || !exact) ? ri < cpos : ri <= cpos;
                        if (keep)
                                list[kept++] = ri;
                }
                n_list = kept;
        }

        if (has_cursor || arg_reverse) {
                size_t want = (arg_lines >= 0 && !arg_follow) ? (size_t) arg_lines : n_list;

                if (want > n_list)
                        want = n_list;
                for (size_t i = 0; i < want; i++)
                        out[n_out++] = arg_reverse ? list[n_list - 1 - i] : list[i];
        } else if (arg_lines >= 0 && arg_lines_oldest) {
                size_t want = (size_t) arg_lines < n_list ? (size_t) arg_lines : n_list;

                for (size_t i = 0; i < want; i++)
                        out[n_out++] = list[i];
        } else if (arg_lines >= 0) {
                size_t want = (size_t) arg_lines < n_list ? (size_t) arg_lines : n_list;

                for (size_t i = n_list - want; i < n_list; i++)
                        out[n_out++] = list[i];
        } else {
                for (size_t i = 0; i < n_list; i++)
                        out[n_out++] = list[i];
        }

        for (size_t i = 0; i < n_out; i++)
                print_entry(logd_ring_entry(ring, out[i]));

        if (!arg_follow) {
                if (n_out == 0 && !arg_quiet)
                        printf("-- No entries --\n");
                if (update_cursor() != 0)
                        status = 1;
                else if (have_pattern && n_out == 0)
                        status = 1; /* like grep(1), so a script can test for a match */
                goto finish;
        }

        fflush(stdout);
        while (!stop_requested) {
                LogdRing *fresh = NULL;

                r = logd_follow_poll(follow, &fresh);
                if (r < 0) {
                        status = fail("Failed to iterate through journal: %s", strerror(-r));
                        break;
                }

                if (fresh) {
                        size_t nf = logd_ring_n_entries(fresh);

                        for (size_t i = 0; i < nf; i++) {
                                const LogdEntry *e = logd_ring_entry(fresh, i);
                                uint64_t real = 0, mono = 0;

                                /* Skip what the initial dump already covered. */
                                if (have_watermark && entry_realtime(e, &real)) {
                                        (void) field_u64(e, "__MONOTONIC_TIMESTAMP", &mono);
                                        if (real < wm_real || (real == wm_real && mono <= wm_mono))
                                                continue;
                                }
                                if (entry_passes(e))
                                        print_entry(e);
                        }
                        fflush(stdout);
                        logd_ring_free(fresh);
                }

                usleep(200000);
        }

        if (status == 0 && update_cursor() != 0)
                status = 1;

finish:
        logd_follow_free(follow);
        logd_ring_free(ring);
        free(list);
        free(out);
        free(file_cursor);
        return status;
}

static bool field_list_has_scope_options(void) {
        return arg_boot || arg_invocation || arg_dmesg || arg_cursor || arg_after_cursor ||
                        arg_cursor_file || arg_n_units > 0 || arg_n_identifiers > 0 ||
                        arg_n_exclude_identifiers > 0 || arg_priorities != 0 || arg_facilities != 0 ||
                        arg_since_set || arg_until_set || arg_pattern;
}

static bool seen_add(const LogdReadField ***seen, size_t *n, size_t *cap, const LogdReadField *f) {
        if (*n == *cap) {
                const LogdReadField **t = realloc(*seen, (*cap ? *cap * 2 : 32) * sizeof(*t));

                if (!t)
                        return false;
                *seen = t;
                *cap = *cap ? *cap * 2 : 32;
        }
        (*seen)[(*n)++] = f;
        return true;
}

static int run_list_fields(void) {
        LogdRing *ring;
        size_t n, n_shown = 0, cap = 0, n_seen = 0;
        const LogdReadField **seen = NULL;
        int status = 0;

        if (arg_boot_offset != 0)
                return note_boot_has_no_effect();
        if (load_ring(&ring) < 0)
                return 1;
        n = logd_ring_n_entries(ring);

        for (size_t i = 0; i < n; i++) {
                const LogdEntry *e = logd_ring_entry(ring, i);

                for (size_t k = 0; k < e->n_fields; k++) {
                        const LogdReadField *f = &e->fields[k];
                        bool dup = false;

                        if (arg_action == ACTION_LIST_FIELD_NAMES) {
                                if (f->name_len >= 2 && f->name[0] == '_' && f->name[1] == '_')
                                        continue;
                                for (size_t s = 0; s < n_seen && !dup; s++)
                                        dup = seen[s]->name_len == f->name_len &&
                                                        memcmp(seen[s]->name, f->name, f->name_len) == 0;
                                if (dup)
                                        continue;
                                if (!seen_add(&seen, &n_seen, &cap, f)) {
                                        status = fail("out of memory");
                                        goto done;
                                }
                                printf("%.*s\n", (int) f->name_len, f->name);
                                continue;
                        }

                        if (f->name_len != strlen(arg_field) || memcmp(f->name, arg_field, f->name_len) != 0)
                                continue;
                        if (arg_lines >= 0 && n_shown >= (size_t) arg_lines)
                                goto done;

                        for (size_t s = 0; s < n_seen && !dup; s++)
                                dup = seen[s]->value_len == f->value_len &&
                                                memcmp(seen[s]->value, f->value, f->value_len) == 0;
                        if (dup)
                                continue;

                        if (!seen_add(&seen, &n_seen, &cap, f)) {
                                status = fail("out of memory");
                                goto done;
                        }
                        fwrite(f->value, 1, f->value_len, stdout);
                        fputc('\n', stdout);
                        n_shown++;
                }
        }

done:
        free(seen);
        logd_ring_free(ring);
        return status;
}

typedef struct Boot {
        char id[ID_LEN + 1];
        uint64_t first, last;
} Boot;

/* -n N is the newest N boots, +N the oldest N. The index counts back from 0,
 * the latest boot, or up from 1 for +N. */
static long boot_index(size_t k, size_t n_boots) {
        return (arg_lines >= 0 && arg_lines_oldest) ? (long) k + 1 : (long) k - (long) (n_boots - 1);
}

static int run_list_boots(void) {
        LogdRing *ring;
        Boot *boots = NULL;
        size_t n_boots = 0, n, first_shown = 0, last_shown;
        int status = 0, w_idx = 3;

        if (load_ring(&ring) < 0)
                return 1;
        n = logd_ring_n_entries(ring);

        boots = n > 0 ? calloc(n, sizeof(*boots)) : NULL;
        for (size_t i = 0; boots && i < n; i++) {
                const LogdEntry *e = logd_ring_entry(ring, i);
                char id[ID_LEN + 1];
                uint64_t rt;
                size_t b;

                if (!entry_boot_id(e, id) || !entry_realtime(e, &rt))
                        continue;
                for (b = 0; b < n_boots; b++)
                        if (strcmp(boots[b].id, id) == 0)
                                break;
                if (b == n_boots) {
                        memcpy(boots[b].id, id, sizeof(id));
                        boots[b].first = rt;
                        n_boots++;
                }
                if (rt < boots[b].first)
                        boots[b].first = rt;
                if (rt > boots[b].last)
                        boots[b].last = rt;
        }

        if (n_boots == 0) {
                if (!arg_quiet)
                        fail("No boot found.");
                status = 1;
                goto done;
        }

        last_shown = n_boots;
        if (arg_lines >= 0 && (size_t) arg_lines < n_boots) {
                if (arg_lines_oldest)
                        last_shown = (size_t) arg_lines;
                else
                        first_shown = n_boots - (size_t) arg_lines;
        }

        for (size_t k = first_shown; k < last_shown; k++) {
                char b[48];
                int l = snprintf(b, sizeof(b), "%ld", boot_index(k, n_boots));

                if (l > w_idx)
                        w_idx = l;
        }

        if (!arg_quiet)
                printf("%*s %-*s %-28s LAST ENTRY\n", w_idx, "IDX", ID_LEN, "BOOT ID", "FIRST ENTRY");

        for (size_t i = 0; i < last_shown - first_shown; i++) {
                size_t k = arg_reverse ? last_shown - 1 - i : first_shown + i;
                char t1[96], t2[96];

                if (format_realtime(t1, sizeof(t1), OUTPUT_SHORT_FULL, boots[k].first) < 0)
                        t1[0] = '\0';
                if (format_realtime(t2, sizeof(t2), OUTPUT_SHORT_FULL, boots[k].last) < 0)
                        t2[0] = '\0';
                printf("%*ld %s %-28s %s\n", w_idx, boot_index(k, n_boots), boots[k].id, t1, t2);
        }

done:
        free(boots);
        logd_ring_free(ring);
        return status;
}

static uint64_t file_usage(const char *dir, const char *name) {
        char path[PATH_MAX];
        struct stat st;

        snprintf(path, sizeof(path), "%s/%s", dir, name);
        return stat(path, &st) < 0 ? 0 : (uint64_t) st.st_blocks * 512;
}

static int run_disk_usage(void) {
        char b[48];
        const char *dir = runtime_dir();
        uint64_t total = 0;

        if (arg_n_files > 0) {
                for (size_t i = 0; i < arg_n_files; i++) {
                        struct stat st;

                        if (stat(arg_files[i], &st) < 0)
                                return fail("Failed to open files: %s", strerror(errno));
                        total += (uint64_t) st.st_blocks * 512;
                }
        } else {
                struct stat st;

                if (stat(dir, &st) < 0 && errno != ENOENT)
                        return fail("Failed to open journal: %s", strerror(errno));
                total = file_usage(dir, LOGD_RING_ACTIVE_NAME) + file_usage(dir, LOGD_RING_ROTATED_NAME);
        }

        printf("Archived and active journals take up %s in the file system.\n",
               format_bytes(b, sizeof(b), total));
        return 0;
}

/* Only the rotated file is "archived"; the active file is never removed,
 * as with journald's .journal files. */
static int run_vacuum(void) {
        const char *dir = runtime_dir();
        char rot[PATH_MAX], act[PATH_MAX], b[48], b2[48];
        struct stat sd, sa, sr;
        bool have_a, have_r;
        uint64_t freed = 0, sum;

        if (stat(dir, &sd) < 0)
                return fail("Failed to vacuum %s: %s", dir, strerror(errno));

        if (arg_vacuum_size == 0 && arg_vacuum_time == 0 && arg_vacuum_n_files == 0)
                return 0;

        snprintf(rot, sizeof(rot), "%s/%s", dir, LOGD_RING_ROTATED_NAME);
        snprintf(act, sizeof(act), "%s/%s", dir, LOGD_RING_ACTIVE_NAME);
        have_r = stat(rot, &sr) == 0;
        have_a = stat(act, &sa) == 0;
        sum = (have_a ? (uint64_t) sa.st_blocks * 512 : 0) + (have_r ? (uint64_t) sr.st_blocks * 512 : 0);

        if (have_r) {
                uint64_t limit = 0, mtime = (uint64_t) sr.st_mtime * USEC_PER_SEC;
                uint64_t usage = (uint64_t) sr.st_blocks * 512;
                bool keep;

                if (arg_vacuum_time > 0)
                        limit = now_usec() > arg_vacuum_time ? now_usec() - arg_vacuum_time : 0;

                keep = sr.st_size > 0 && (arg_vacuum_time == 0 || mtime >= limit) &&
                                (arg_vacuum_size == 0 || sum <= arg_vacuum_size) &&
                                (arg_vacuum_n_files == 0 || (have_a ? 2 : 1) <= arg_vacuum_n_files);

                if (!keep) {
                        if (unlink(rot) < 0 && errno != ENOENT)
                                fail("Failed to delete archived journal %s: %s", rot, strerror(errno));
                        else {
                                if (!arg_quiet)
                                        fprintf(stderr,
                                                "picolog: Deleted archived journal %s (%s).\n",
                                                rot,
                                                format_bytes(b2, sizeof(b2), usage));
                                freed += usage;
                        }
                }
        }

        if (!arg_quiet)
                fprintf(stderr,
                        "picolog: Vacuuming done, freed %s of archived journals from %s.\n",
                        format_bytes(b, sizeof(b), freed),
                        dir);
        return 0;
}

static bool namespace_name_valid(const char *s) {
        size_t n = strlen(s);

        if (n == 0 || n > 255 || s[0] == '.')
                return false;
        for (size_t i = 0; i < n; i++)
                if (!isalnum((unsigned char) s[i]) && s[i] != '-' && s[i] != '_' && s[i] != '.')
                        return false;
        return true;
}

static int run_list_namespaces(void) {
        static const char * const dirs[] = { "/var/log/journal", "/run/log/journal" };
        char path[PATH_MAX], machine[ID_LEN + 2] = "";
        const char **names = NULL;
        size_t n_names = 0;
        FILE *f;

        snprintf(path, sizeof(path), "%s/etc/machine-id", arg_root ? arg_root : "");
        f = fopen(path, "r");
        if (!f || !fgets(machine, sizeof(machine), f) || strlen(machine) < ID_LEN) {
                int e = f ? EINVAL : errno;

                if (f)
                        fclose(f);
                return fail("Failed to get machine ID: %s", strerror(e));
        }
        fclose(f);
        machine[ID_LEN] = '\0';

        for (size_t d = 0; d < sizeof(dirs) / sizeof(dirs[0]); d++) {
                DIR *dp;
                struct dirent *de;

                snprintf(path, sizeof(path), "%s%s", arg_root ? arg_root : "", dirs[d]);
                dp = opendir(path);
                if (!dp)
                        continue;

                while ((de = readdir(dp))) {
                        const char *dot = strchr(de->d_name, '.');
                        bool dup = false;

                        if (!dot || (size_t) (dot - de->d_name) != ID_LEN ||
                            strncasecmp(de->d_name, machine, ID_LEN) != 0 || !namespace_name_valid(dot + 1))
                                continue;
                        for (size_t i = 0; i < n_names && !dup; i++)
                                dup = strcmp(names[i], dot + 1) == 0;
                        if (!dup) {
                                char *copy = strdup(dot + 1);

                                if (copy && push(&names, &n_names, copy) < 0)
                                        free(copy);
                        }
                }
                closedir(dp);
        }

        if (n_names == 0) {
                if (!arg_quiet)
                        fputs("picolog: No namespaces found.\n", stderr);
                free(names);
                return 0;
        }

        for (size_t i = 1; i < n_names; i++) /* sorted, as the table is */
                for (size_t j = i; j > 0 && strcmp(names[j - 1], names[j]) > 0; j--) {
                        const char *t = names[j];

                        names[j] = names[j - 1];
                        names[j - 1] = t;
                }

        if (!arg_quiet)
                puts("NAMESPACE");
        for (size_t i = 0; i < n_names; i++)
                puts(names[i]);
        free(names);
        return 0;
}

/* sd_id128_randomize() plus id128_pretty_print_sample(). */
static int run_new_id128(void) {
        unsigned char id[16];
        const char *on = pico_ansi_highlight(), *off = pico_ansi_normal();

        if (getrandom(id, sizeof(id), 0) != (ssize_t) sizeof(id))
                return fail("Failed to generate ID: %s", strerror(errno));
        id[6] = (id[6] & 0x0f) | 0x40; /* UUID version 4, variant 1 */
        id[8] = (id[8] & 0x3f) | 0x80;

        printf("As string:\n%s", on);
        for (size_t i = 0; i < 16; i++)
                printf("%02x", id[i]);
        printf("%s\n\nAs UUID:\n%s", off, on);
        for (size_t i = 0; i < 16; i++)
                printf("%02x%s", id[i], (i == 3 || i == 5 || i == 7 || i == 9) ? "-" : "");
        printf("%s\n\nAs systemd-id128(1) macro:\n%s#define XYZ SD_ID128_MAKE(", off, on);
        for (size_t i = 0; i < 16; i++)
                printf("%02x%s", id[i], i < 15 ? "," : "");
        printf(")%s\n\nAs Python constant:\n>>> import uuid\n>>> %sXYZ = uuid.UUID('", off, on);
        for (size_t i = 0; i < 16; i++)
                printf("%02x%s", id[i], (i == 3 || i == 5 || i == 7 || i == 9) ? "-" : "");
        printf("')%s\n", off);
        return 0;
}

/* ---- command line ----------------------------------------------------- */

static const char help_text[] =
                "picolog [OPTIONS...] [MATCHES...]\n"
                "\n"
                "Query the log ring.\n"
                "\n"
                "Source Options:\n"
                "     --system             Show the system journal (the only one)\n"
                "  -m --merge              Accepted; there is only one ring\n"
                "  -D --directory=PATH     Read the ring files in PATH\n"
                "  -i --file=PATH          Read an export-format file, repeatable\n"
                "     --root=PATH          Operate on an alternate filesystem root\n"
                "     --namespace=NAME     Only the default namespace has entries\n"
                "\n"
                "Filtering Options:\n"
                "  -S --since=DATE         Show entries not older than the specified date\n"
                "  -U --until=DATE         Show entries not newer than the specified date\n"
                "  -c --cursor=CURSOR      Show entries starting at the specified cursor\n"
                "     --after-cursor=CURSOR\n"
                "                          Show entries after the specified cursor\n"
                "     --cursor-file=FILE   Show entries after cursor in FILE and update FILE\n"
                "  -b --boot[=ID]          Show the current boot or the specified boot ID\n"
                "  -u --unit=UNIT          Show logs from the specified unit, globs allowed\n"
                "  -I --invocation=ID      Refused: invocation IDs are not recorded\n"
                "  -t --identifier=ID      Show entries with the specified syslog identifier\n"
                "  -T --exclude-identifier=ID\n"
                "                          Hide entries with the specified syslog identifier\n"
                "  -p --priority=RANGE     Show entries within the specified priority range\n"
                "     --facility=FACILITY...\n"
                "                          Show entries with the specified facilities\n"
                "  -g --grep=PATTERN       Show entries with MESSAGE matching PATTERN (POSIX ERE)\n"
                "     --case-sensitive[=BOOL]\n"
                "                          Force case sensitive or insensitive matching\n"
                "  -k --dmesg              Show kernel messages\n"
                "\n"
                "Output Control Options:\n"
                "  -o --output=STRING      Change output mode (-o help lists them)\n"
                "     --output-fields=LIST Select fields to print in verbose/export/json/cat modes\n"
                "  -n --lines[=[+]INTEGER] Number of entries to show\n"
                "  -r --reverse            Show the newest entries first\n"
                "     --show-cursor        Print the cursor after all the entries\n"
                "     --utc                Express time in Coordinated Universal Time (UTC)\n"
                "  -x --catalog            Accepted; there is no message catalog\n"
                "  -W --no-hostname        Suppress output of hostname field\n"
                "  -l --full               Do not ellipsize fields (the default)\n"
                "     --no-full            Ellipsize fields\n"
                "  -a --all                Show all fields, including long and unprintable\n"
                "  -f --follow             Follow the ring\n"
                "     --no-tail            Show all lines, even in follow mode\n"
                "     --truncate-newline   Truncate entries by first newline character\n"
                "  -q --quiet              Do not show info messages\n"
                "     --synchronize-on-exit=BOOL\n"
                "                          Accepted; there is nothing to synchronize\n"
                "\n";

static const char help_text2[] =
                "Pager Control Options:\n"
                "     --no-pager           Accepted; there is no pager\n"
                "  -e --pager-end          Show the last 1000 entries\n"
                "\n"
                "Commands:\n"
                "  -h --help               Show this help\n"
                "     --version            Show package version\n"
                "  -N --fields             List all field names currently used\n"
                "  -F --field=FIELD        List all values that a specified field takes\n"
                "     --list-boots         Show terse information about recorded boots\n"
                "     --list-invocations   Refused: invocation IDs are not recorded\n"
                "     --list-namespaces    Show list of journal namespaces\n"
                "     --disk-usage         Show total disk usage of the ring files\n"
                "     --vacuum-size=BYTES  Remove the rotated file if usage exceeds BYTES\n"
                "     --vacuum-files=INT   Remove the rotated file if more than INT files exist\n"
                "     --vacuum-time=TIME   Remove the rotated file if older than TIME\n"
                "     --flush              Accepted; nothing is stored on disk\n"
                "     --relinquish-var     Accepted; nothing is stored on disk\n"
                "     --smart-relinquish-var\n"
                "                          Accepted; nothing is stored on disk\n"
                "     --new-id128          Generate a new 128-bit ID\n"
                "\n";

static const char help_text3[] =
                "Refused, as logd has no counterpart: --user, --user-unit, -M/--machine, --image,\n"
                "--image-policy, --sync, --rotate, --header, --verify, --verify-key, --interval,\n"
                "--force, --setup-keys, --list-catalog, --dump-catalog, --update-catalog.\n"
                "\n"
                "MATCHES are FIELD=VALUE terms, '+' separating alternatives, or the path of an\n"
                "executable, which matches its _COMM.\n";

static int parse_boolean(const char *s) {
        static const char * const yes[] = { "1", "yes", "y", "true", "t", "on" };
        static const char * const no[] = { "0", "no", "n", "false", "f", "off" };

        for (size_t i = 0; i < sizeof(yes) / sizeof(yes[0]); i++)
                if (strcasecmp(s, yes[i]) == 0)
                        return 1;
        for (size_t i = 0; i < sizeof(no) / sizeof(no[0]); i++)
                if (strcasecmp(s, no[i]) == 0)
                        return 0;
        return -1;
}

static bool field_name_valid(const char *s, size_t len) {
        if (len == 0 || len > 64 || isdigit((unsigned char) s[0]))
                return false;
        for (size_t i = 0; i < len; i++)
                if (!(isupper((unsigned char) s[i]) || isdigit((unsigned char) s[i]) || s[i] == '_'))
                        return false;
        return true;
}

static char *mangle_unit(const char *unit) {
        static const char * const suffixes[] = {
                ".service", ".socket", ".target", ".device", ".mount", ".automount",
                ".swap",    ".timer",  ".path",   ".slice",  ".scope",
        };
        size_t len = strlen(unit);
        char *out;

        if (len == 0)
                return NULL;
        if (strpbrk(unit, "*?[") != NULL)
                return strdup(unit);

        for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
                size_t sl = strlen(suffixes[i]);

                if (len > sl && memcmp(unit + len - sl, suffixes[i], sl) == 0)
                        return strdup(unit);
        }

        out = malloc(len + sizeof(".service"));
        if (out)
                sprintf(out, "%s.service", unit);
        return out;
}

static int add_match_term(const char *name, size_t name_len, const char *value, size_t value_len) {
        MatchTerm *t = realloc(match_terms, (n_match_terms + 1) * sizeof(*t));

        if (!t)
                return -ENOMEM;
        match_terms = t;
        t[n_match_terms++] = (MatchTerm){ name, name_len, value, value_len, n_match_groups - 1 };
        return 0;
}

static int add_matches(char **args) {
        bool have_term = false;

        if (!args[0])
                return 0;

        for (; *args; args++) {
                const char *a = *args;

                if (strcmp(a, "+") == 0) {
                        if (!have_term)
                                break;
                        n_match_groups++;
                        have_term = false;
                } else if (a[0] == '/') {
                        char resolved[PATH_MAX];
                        struct stat st;
                        const char *base;
                        char *comm;

                        if (!realpath(a, resolved) || stat(resolved, &st) < 0)
                                return fail("Couldn't canonicalize path '%s': %s", a, strerror(errno));
                        if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
                                return fail("Matching a device node is not supported: _KERNEL_DEVICE is not recorded.");
                        if (!S_ISREG(st.st_mode) || !(st.st_mode & 0111))
                                return fail("File is neither a device node nor executable: %s", resolved);

                        /* _EXE is not recorded; the 15-character comm name is the closest stored field. */
                        base = strrchr(resolved, '/') + 1;
                        comm = strndup(base, 15);
                        if (!comm || add_match_term("_COMM", 5, comm, strlen(comm)) < 0)
                                return fail("out of memory");
                        have_term = true;
                } else {
                        const char *eq = strchr(a, '=');

                        if (!eq || !field_name_valid(a, (size_t) (eq - a)))
                                return fail("Failed to add match '%s': Invalid argument", a);
                        if (add_match_term(a, (size_t) (eq - a), eq + 1, strlen(eq + 1)) < 0)
                                return fail("out of memory");
                        have_term = true;
                }
        }

        if (!have_term)
                return fail("\"+\" can only be used between terms.");
        return 0;
}

enum {
        ARG_VERSION = 0x100,
        ARG_SYSTEM,
        ARG_USER,
        ARG_ROOT,
        ARG_IMAGE,
        ARG_IMAGE_POLICY,
        ARG_NAMESPACE,
        ARG_AFTER_CURSOR,
        ARG_CURSOR_FILE,
        ARG_THIS_BOOT,
        ARG_USER_UNIT,
        ARG_INVOCATION,
        ARG_FACILITY,
        ARG_CASE_SENSITIVE,
        ARG_OUTPUT_FIELDS,
        ARG_SHOW_CURSOR,
        ARG_UTC,
        ARG_NO_FULL,
        ARG_NO_TAIL,
        ARG_TRUNCATE_NEWLINE,
        ARG_SYNCHRONIZE_ON_EXIT,
        ARG_NO_PAGER,
        ARG_INTERVAL,
        ARG_VERIFY_KEY,
        ARG_FORCE,
        ARG_LIST_BOOTS,
        ARG_LIST_INVOCATIONS,
        ARG_LIST_NAMESPACES,
        ARG_DISK_USAGE,
        ARG_VACUUM_SIZE,
        ARG_VACUUM_FILES,
        ARG_VACUUM_TIME,
        ARG_VERIFY,
        ARG_SYNC,
        ARG_RELINQUISH_VAR,
        ARG_SMART_RELINQUISH_VAR,
        ARG_FLUSH,
        ARG_ROTATE,
        ARG_HEADER,
        ARG_LIST_CATALOG,
        ARG_DUMP_CATALOG,
        ARG_UPDATE_CATALOG,
        ARG_SETUP_KEYS,
        ARG_NEW_ID128,
};

static void refuse(const char *msg) {
        arg_action = ACTION_REFUSED;
        arg_refusal = msg;
}

/* Returns -1 to carry on, else the exit status. */
static int parse_argv(int argc, char *argv[], char ***rest) {
        static const struct option options[] = {
                {                 "help",       no_argument, NULL,                      'h' },
                {              "version",       no_argument, NULL,              ARG_VERSION },
                {               "system",       no_argument, NULL,               ARG_SYSTEM },
                {                 "user",       no_argument, NULL,                 ARG_USER },
                {              "machine", required_argument, NULL,                      'M' },
                {                "merge",       no_argument, NULL,                      'm' },
                {            "directory", required_argument, NULL,                      'D' },
                {                 "file", required_argument, NULL,                      'i' },
                {                 "root", required_argument, NULL,                 ARG_ROOT },
                {                "image", required_argument, NULL,                ARG_IMAGE },
                {         "image-policy", required_argument, NULL,         ARG_IMAGE_POLICY },
                {            "namespace", required_argument, NULL,            ARG_NAMESPACE },
                {                "since", required_argument, NULL,                      'S' },
                {                "until", required_argument, NULL,                      'U' },
                {               "cursor", required_argument, NULL,                      'c' },
                {         "after-cursor", required_argument, NULL,         ARG_AFTER_CURSOR },
                {          "cursor-file", required_argument, NULL,          ARG_CURSOR_FILE },
                {            "this-boot",       no_argument, NULL,            ARG_THIS_BOOT },
                {                 "boot", optional_argument, NULL,                      'b' },
                {                 "unit", required_argument, NULL,                      'u' },
                {            "user-unit", required_argument, NULL,            ARG_USER_UNIT },
                {           "invocation", required_argument, NULL,           ARG_INVOCATION },
                {           "identifier", required_argument, NULL,                      't' },
                {   "exclude-identifier", required_argument, NULL,                      'T' },
                {             "priority", required_argument, NULL,                      'p' },
                {             "facility", required_argument, NULL,             ARG_FACILITY },
                {                 "grep", required_argument, NULL,                      'g' },
                {       "case-sensitive", optional_argument, NULL,       ARG_CASE_SENSITIVE },
                {                "dmesg",       no_argument, NULL,                      'k' },
                {               "output", required_argument, NULL,                      'o' },
                {        "output-fields", required_argument, NULL,        ARG_OUTPUT_FIELDS },
                {                "lines", optional_argument, NULL,                      'n' },
                {              "reverse",       no_argument, NULL,                      'r' },
                {          "show-cursor",       no_argument, NULL,          ARG_SHOW_CURSOR },
                {                  "utc",       no_argument, NULL,                  ARG_UTC },
                {              "catalog",       no_argument, NULL,                      'x' },
                {          "no-hostname",       no_argument, NULL,                      'W' },
                {                 "full",       no_argument, NULL,                      'l' },
                {              "no-full",       no_argument, NULL,              ARG_NO_FULL },
                {                  "all",       no_argument, NULL,                      'a' },
                {               "follow",       no_argument, NULL,                      'f' },
                {              "no-tail",       no_argument, NULL,              ARG_NO_TAIL },
                {     "truncate-newline",       no_argument, NULL,     ARG_TRUNCATE_NEWLINE },
                {                "quiet",       no_argument, NULL,                      'q' },
                {  "synchronize-on-exit", required_argument, NULL,  ARG_SYNCHRONIZE_ON_EXIT },
                {             "no-pager",       no_argument, NULL,             ARG_NO_PAGER },
                {            "pager-end",       no_argument, NULL,                      'e' },
                {             "interval", required_argument, NULL,             ARG_INTERVAL },
                {           "verify-key", required_argument, NULL,           ARG_VERIFY_KEY },
                {                "force",       no_argument, NULL,                ARG_FORCE },
                {               "fields",       no_argument, NULL,                      'N' },
                {                "field", required_argument, NULL,                      'F' },
                {           "list-boots",       no_argument, NULL,           ARG_LIST_BOOTS },
                {     "list-invocations",       no_argument, NULL,     ARG_LIST_INVOCATIONS },
                {      "list-namespaces",       no_argument, NULL,      ARG_LIST_NAMESPACES },
                {           "disk-usage",       no_argument, NULL,           ARG_DISK_USAGE },
                {          "vacuum-size", required_argument, NULL,          ARG_VACUUM_SIZE },
                {         "vacuum-files", required_argument, NULL,         ARG_VACUUM_FILES },
                {          "vacuum-time", required_argument, NULL,          ARG_VACUUM_TIME },
                {               "verify",       no_argument, NULL,               ARG_VERIFY },
                {                 "sync",       no_argument, NULL,                 ARG_SYNC },
                {       "relinquish-var",       no_argument, NULL,       ARG_RELINQUISH_VAR },
                { "smart-relinquish-var",       no_argument, NULL, ARG_SMART_RELINQUISH_VAR },
                {                "flush",       no_argument, NULL,                ARG_FLUSH },
                {               "rotate",       no_argument, NULL,               ARG_ROTATE },
                {               "header",       no_argument, NULL,               ARG_HEADER },
                {         "list-catalog",       no_argument, NULL,         ARG_LIST_CATALOG },
                {         "dump-catalog",       no_argument, NULL,         ARG_DUMP_CATALOG },
                {       "update-catalog",       no_argument, NULL,       ARG_UPDATE_CATALOG },
                {           "setup-keys",       no_argument, NULL,           ARG_SETUP_KEYS },
                {            "new-id128",       no_argument, NULL,            ARG_NEW_ID128 },
                {                   NULL,                 0, NULL,                        0 },
        };
        int c, r;

        while ((c = getopt_long(argc, argv, "hfaqkrxlmeWINF:D:i:M:S:U:c:u:t:T:p:g:o:n::b::", options, NULL)) >=
               0) {
                switch (c) {
                case 'h':
                        fputs(help_text, stdout);
                        fputs(help_text2, stdout);
                        fputs(help_text3, stdout);
                        return 0;

                case ARG_VERSION:
                        printf("picolog " PICO_INIT_VERSION " (pico-init; not systemd, see picolog.c)\n");
                        return 0;

                case ARG_SYSTEM: /* the only journal there is */
                case 'x':        /* --catalog: no catalog, so no explanations to add */
                case 'l':        /* --full is already the default */
                case ARG_NO_PAGER:
                        break;

                case 'm': /* one ring, nothing to merge; still conflicts with -b like upstream */
                        arg_merge = true;
                        break;

                case ARG_USER:
                case ARG_USER_UNIT:
                        return fail("--user and --user-unit are not supported: there are no per-user journals.");
                case 'M':
                        return fail("-M/--machine is not supported: picolog reads the local ring only.");
                case ARG_IMAGE:
                case ARG_IMAGE_POLICY:
                        return fail("--image is not supported: picolog cannot dissect disk images.");

                case ARG_INTERVAL:
                case ARG_VERIFY_KEY:
                case ARG_FORCE:
                case ARG_SETUP_KEYS:
                        return fail("Compiled without forward-secure sealing support.");

                case 'D':
                        arg_directory = optarg;
                        break;

                case 'i':
                        if (strcmp(optarg, "-") == 0)
                                return fail("Reading a journal file from stdin is not supported.");
                        if (push(&arg_files, &arg_n_files, optarg) < 0)
                                return fail("out of memory");
                        break;

                case ARG_ROOT:
                        arg_root = optarg;
                        break;

                case ARG_NAMESPACE:
                        arg_namespace = optarg;
                        break;

                case 'S':
                        if (!parse_timestamp(optarg, &arg_since))
                                return fail("Failed to parse timestamp: %s", optarg);
                        arg_since_set = true;
                        break;

                case 'U':
                        if (!parse_timestamp(optarg, &arg_until))
                                return fail("Failed to parse timestamp: %s", optarg);
                        arg_until_set = true;
                        break;

                case 'c':
                        arg_cursor = optarg;
                        break;

                case ARG_AFTER_CURSOR:
                        arg_after_cursor = optarg;
                        break;

                case ARG_CURSOR_FILE:
                        arg_cursor_file = optarg;
                        break;

                case ARG_THIS_BOOT:
                        arg_boot = true;
                        arg_boot_id[0] = '\0';
                        arg_boot_offset = 0;
                        break;

                case 'b': {
                        const char *d = optarg;

                        arg_boot = true;
                        arg_boot_id[0] = '\0';
                        arg_boot_offset = 0;

                        if (!d && optind < argc) {
                                char id[ID_LEN + 1];
                                int off;

                                /* "-b -1": the word after a bare -b is its argument if it parses as one. */
                                if (parse_id_descriptor(argv[optind], id, &off) >= 0)
                                        d = argv[optind++];
                        }
                        if (d) {
                                r = parse_id_descriptor(d, arg_boot_id, &arg_boot_offset);
                                if (r < 0)
                                        return fail("Failed to parse boot descriptor '%s'", d);
                                arg_boot = r > 0;
                        }
                        break;
                }

                case 'u': {
                        char *m = mangle_unit(optarg);

                        if (!m)
                                return fail("Failed to mangle unit name '%s': Invalid argument", optarg);
                        if (push(&arg_units, &arg_n_units, m) < 0)
                                return fail("out of memory");
                        break;
                }

                case ARG_INVOCATION:
                        r = parse_id_descriptor(optarg, arg_invocation_id, &arg_invocation_offset);
                        if (r < 0)
                                return fail("Failed to parse invocation descriptor: %s", optarg);
                        arg_invocation = r > 0;
                        break;

                case 'I':
                        arg_invocation = true;
                        arg_invocation_id[0] = '\0';
                        arg_invocation_offset = 0;
                        break;

                case 't':
                        if (push(&arg_identifiers, &arg_n_identifiers, optarg) < 0)
                                return fail("out of memory");
                        break;

                case 'T':
                        if (push(&arg_exclude_identifiers, &arg_n_exclude_identifiers, optarg) < 0)
                                return fail("out of memory");
                        break;

                case 'p':
                        if (parse_priorities(optarg) != 0)
                                return 1;
                        break;

                case ARG_FACILITY: {
                        char *copy = strdup(optarg), *save = NULL, *tok;

                        if (!copy)
                                return fail("out of memory");
                        for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
                                int fac;

                                if (strcmp(tok, "help") == 0) {
                                        if (!arg_quiet)
                                                puts("Available facilities:");
                                        for (size_t i = 0; i < N_FACILITIES; i++)
                                                puts(facility_names[i]);
                                        free(copy);
                                        return 0;
                                }
                                fac = parse_facility(tok);
                                if (fac < 0) {
                                        free(copy);
                                        return fail("Bad --facility= argument \"%s\".", tok);
                                }
                                arg_facilities |= 1ULL << fac;
                        }
                        free(copy);
                        break;
                }

                case 'g':
                        arg_pattern = optarg;
                        break;

                case ARG_CASE_SENSITIVE:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return fail("Bad --case-sensitive= argument \"%s\": Invalid argument",
                                                    optarg);
                                arg_case = r;
                        } else
                                arg_case = 1;
                        break;

                case 'k':
                        arg_dmesg = true;
                        break;

                case 'o': {
                        size_t i;

                        if (strcmp(optarg, "help") == 0) {
                                for (i = 0; i < _OUTPUT_MAX; i++)
                                        puts(output_names[i]);
                                return 0;
                        }
                        for (i = 0; i < _OUTPUT_MAX; i++)
                                if (strcmp(optarg, output_names[i]) == 0)
                                        break;
                        if (i == _OUTPUT_MAX)
                                return fail("Unknown output format '%s'.", optarg);
                        arg_output = (OutputMode) i;
                        if (arg_output == OUTPUT_EXPORT || arg_output == OUTPUT_CAT ||
                            (arg_output >= OUTPUT_JSON && arg_output <= OUTPUT_JSON_SEQ))
                                arg_quiet = true;
                        break;
                }

                case ARG_OUTPUT_FIELDS: {
                        char *copy = strdup(optarg), *save = NULL, *tok;

                        if (!copy)
                                return fail("out of memory");
                        for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save))
                                if (push(&arg_output_fields, &arg_n_output_fields, tok) < 0)
                                        return fail("out of memory");
                        break;
                }

                case 'n': {
                        const char *p = optarg;

                        if (!p && optind < argc)
                                p = argv[optind];
                        r = parse_lines(p, optarg == NULL);
                        if (r < 0)
                                return fail("Failed to parse --lines='%s'.", p);
                        if (r > 0 && !optarg)
                                optind++;
                        break;
                }

                case 'r':
                        arg_reverse = true;
                        break;

                case ARG_SHOW_CURSOR:
                        arg_show_cursor = true;
                        break;

                case ARG_UTC:
                        arg_utc = true;
                        break;

                case 'W':
                        arg_no_hostname = true;
                        break;

                case ARG_NO_FULL:
                        arg_full = false;
                        break;

                case 'a':
                        arg_all = true;
                        break;

                case 'f':
                        arg_follow = true;
                        break;

                case ARG_NO_TAIL:
                        arg_no_tail = true;
                        break;

                case ARG_TRUNCATE_NEWLINE:
                        arg_truncate_newline = true;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_SYNCHRONIZE_ON_EXIT:
                        if (parse_boolean(optarg) < 0)
                                return fail("Failed to parse boolean argument to --synchronize-on-exit: %s.",
                                            optarg);
                        break;

                case 'e':
                        arg_pager_end = true;
                        break;

                case 'N':
                        arg_action = ACTION_LIST_FIELD_NAMES;
                        break;

                case 'F':
                        arg_action = ACTION_LIST_FIELDS;
                        arg_field = optarg;
                        break;

                case ARG_LIST_BOOTS:
                        arg_action = ACTION_LIST_BOOTS;
                        break;

                case ARG_LIST_INVOCATIONS:
                        arg_action = ACTION_LIST_INVOCATIONS;
                        break;

                case ARG_LIST_NAMESPACES:
                        arg_action = ACTION_LIST_NAMESPACES;
                        break;

                case ARG_DISK_USAGE:
                        arg_action = ACTION_DISK_USAGE;
                        break;

                case ARG_VACUUM_SIZE:
                        if (!parse_size(optarg, &arg_vacuum_size))
                                return fail("Failed to parse vacuum size: %s", optarg);
                        arg_action = ACTION_VACUUM;
                        break;

                case ARG_VACUUM_FILES: {
                        char *endp;

                        arg_vacuum_n_files = strtoull(optarg, &endp, 10);
                        if (!isdigit((unsigned char) optarg[0]) || *endp != '\0')
                                return fail("Failed to parse vacuum files: %s", optarg);
                        arg_action = ACTION_VACUUM;
                        break;
                }

                case ARG_VACUUM_TIME:
                        if (!parse_sec(optarg, &arg_vacuum_time))
                                return fail("Failed to parse vacuum time: %s", optarg);
                        arg_action = ACTION_VACUUM;
                        break;

                case ARG_RELINQUISH_VAR:
                case ARG_SMART_RELINQUISH_VAR:
                case ARG_FLUSH:
                        arg_action = ACTION_NOOP;
                        break;

                case ARG_VERIFY:
                        refuse("--verify is not supported: the ring has no journal file structure or sealing to verify.");
                        break;
                case ARG_SYNC:
                        refuse("--sync is not supported: logd has no control interface to synchronize through.");
                        break;
                case ARG_ROTATE:
                        refuse("--rotate is not supported: logd rotates by size only and cannot be asked to rotate.");
                        break;
                case ARG_HEADER:
                        refuse("--header is not supported: the ring is plain export text with no journal header.");
                        break;
                case ARG_LIST_CATALOG:
                case ARG_DUMP_CATALOG:
                        refuse("Failed to list catalog: No such file or directory");
                        break;
                case ARG_UPDATE_CATALOG:
                        refuse("--update-catalog is not supported: there is no message catalog.");
                        break;

                case ARG_NEW_ID128:
                        arg_action = ACTION_NEW_ID128;
                        break;

                case '?':
                default:
                        /* getopt_long already printed its own diagnostic. */
                        return 1;
                }
        }

        *rest = argv + optind;
        return -1;
}

static int validate_and_prepare(char **args) {
        int r;

        if (arg_no_tail)
                arg_lines = LINES_ALL;

        if (arg_lines == LINES_DEFAULT) {
                if (arg_follow && !arg_since_set)
                        arg_lines = 10;
                else if (arg_pager_end)
                        arg_lines = 1000;
        }
        if (arg_lines == LINES_DEFAULT || arg_lines == LINES_ALL)
                arg_lines = -1;

        if (!!arg_directory + !!arg_n_files + !!arg_root > 1)
                return fail("Please specify at most one of -D/--directory=, --file=, -M/--machine=, --root=, "
                            "--image=.");

        if (arg_since_set && arg_until_set && arg_since > arg_until)
                return fail("--since= must be before --until=.");

        if (!!arg_cursor + !!arg_after_cursor + !!arg_cursor_file + !!arg_since_set > 1)
                return fail("Please specify only one of --since=, --cursor=, --cursor-file=, and "
                            "--after-cursor=.");

        if (arg_follow && arg_reverse)
                return fail("Please specify either --reverse or --follow, not both.");

        if (arg_action == ACTION_SHOW && arg_lines >= 0 && arg_lines_oldest && (arg_reverse || arg_follow))
                return fail("--lines=+N is unsupported when --reverse or --follow is specified.");

        if (arg_action != ACTION_SHOW && args[0])
                return fail("Extraneous arguments starting with '%s'", args[0]);

        if ((arg_action == ACTION_LIST_FIELDS || arg_action == ACTION_LIST_FIELD_NAMES) &&
            field_list_has_scope_options())
                return fail("-F/--field= and -N/--fields cannot be combined with options that limit the "
                            "journal.");

        if ((arg_boot || arg_action == ACTION_LIST_BOOTS) && arg_merge)
                return fail("Using --boot or --list-boots with --merge is not supported.");

        if (arg_pattern) {
                int flags = REG_EXTENDED;
                bool insensitive = arg_case == 0;

                if (arg_case < 0) { /* smart case: insensitive unless the pattern has an upper-case letter */
                        insensitive = true;
                        for (const char *p = arg_pattern; *p; p++)
                                if (isupper((unsigned char) *p))
                                        insensitive = false;
                }
                if (insensitive)
                        flags |= REG_ICASE;

                r = regcomp(&compiled_pattern, arg_pattern, flags);
                if (r != 0) {
                        char err[128];

                        regerror(r, &compiled_pattern, err, sizeof(err));
                        return fail("Failed to compile regular expression %s: %s", arg_pattern, err);
                }
                have_pattern = true;

                /* journalctl searches backwards to find the last N matches, which
                 * prints them newest first. */
                if (lines_needs_seek_end() && !arg_follow)
                        arg_reverse = true;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        struct sigaction sa = { .sa_handler = on_stop };
        char **rest = NULL;
        int r;

        r = parse_argv(argc, argv, &rest);
        if (r >= 0)
                return r;

        if (arg_action == ACTION_SHOW && add_matches(rest) != 0)
                return 1;

        r = validate_and_prepare(rest);
        if (r != 0)
                return r;

        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);

        switch (arg_action) {
        case ACTION_SHOW:
                r = run_show();
                break;
        case ACTION_NEW_ID128:
                r = run_new_id128();
                break;
        case ACTION_LIST_FIELD_NAMES:
        case ACTION_LIST_FIELDS:
                r = run_list_fields();
                break;
        case ACTION_LIST_BOOTS:
                r = run_list_boots();
                break;
        case ACTION_LIST_INVOCATIONS: {
                const char *unit;

                if (acquire_unit("--list-invocations", &unit) == 0 && !arg_quiet)
                        fail("No invocation ID for %s found.", unit);
                r = 1;
                break;
        }
        case ACTION_LIST_NAMESPACES:
                r = run_list_namespaces();
                break;
        case ACTION_DISK_USAGE:
                r = run_disk_usage();
                break;
        case ACTION_VACUUM:
                r = run_vacuum();
                break;
        case ACTION_NOOP:
                /* A runtime-only ring has no persistent storage to flush to or relinquish. */
                r = 0;
                break;
        case ACTION_REFUSED:
        default:
                r = fail("%s", arg_refusal);
        }

        if (fflush(stdout) != 0 && r == 0)
                r = 1;
        return r;
}
