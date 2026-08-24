/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * picolog -- the on-device log reader (plan §3.4), the journalctl half of the
 * owner's on-device-tooling requirement. Named to avoid colliding with
 * BusyBox `logread`. It needs nothing from the daemon -- it reads the files
 * -- and the reading itself lives in logd-read.c so picoctl (plan §1.7, C1)
 * can reuse it; this file is CLI parsing and display only.
 *
 * -b needs no flag: a /run ring only ever holds the current boot.
 *
 * LOGD_RUNTIME_DIR (the env var, not the logd.h macro of the same name)
 * overrides the compiled-in ring location -- test-picolog.c points this at
 * a fixture tree so tests need neither root nor a real /run, the same
 * manager-owned-path idea the rest of this project's tests use, here as an
 * env var rather than a setter because there is no daemon object for a
 * one-shot CLI to hang one off of. Production never sets it.
 */

#include "logd-read.h"

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "logd.h"

typedef enum {
        OUTPUT_SHORT,
        OUTPUT_EXPORT,
} OutputMode;

struct options {
        bool follow;
        const char *unit;
        int max_priority; /* -1: no -p filter */
        bool kernel_only;
        long tail_n; /* 0: no -n limit */
        OutputMode output;
        bool show_all; /* -a */
};

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

static void hostname_buf(char *buf, size_t len) {
        if (gethostname(buf, len) < 0 || buf[0] == '\0')
                snprintf(buf, len, "(none)"); /* this board's own observed hostname when unset, plan Status */

        buf[len - 1] = '\0';
}

/* -a's non-printable escaping: \xNN for anything outside printable ASCII,
 * never a raw byte reaching the terminal (logd-write.h's same UTF-8/control
 * concern, applied on the way back out). */
static void print_escaped(const void *value, size_t len) {
        const unsigned char *p = value;

        for (size_t i = 0; i < len; i++) {
                unsigned char c = p[i];

                if (c >= 0x20 && c < 0x7f)
                        putchar((int) c);
                else
                        printf("\\x%02x", c);
        }
}

/* journalctl's short format: "MMM dd HH:MM:SS host identifier[pid]: message"
 * (plan §3.4). A binary-safe MESSAGE prints as the fixed "blob data"
 * placeholder unless -a was given (plan's 2026-08-24 addition), matching
 * real journalctl's own default rather than ever writing raw bytes to a
 * TTY. */
static void print_short(const LogdEntry *e, bool show_all) {
        const LogdReadField *rt = logd_entry_field(e, "__REALTIME_TIMESTAMP");
        const LogdReadField *msg = logd_entry_field(e, "MESSAGE");
        const LogdReadField *ident = logd_entry_field(e, "SYSLOG_IDENTIFIER");
        const LogdReadField *comm = logd_entry_field(e, "_COMM");
        const LogdReadField *pid = logd_entry_field(e, "_PID");
        char host[256];
        char timebuf[32];
        struct tm tmv;
        time_t sec = 0;

        hostname_buf(host, sizeof(host));

        if (rt && !rt->binary && rt->value_len > 0 && rt->value_len < 24) {
                char numbuf[24];
                unsigned long long usec;

                memcpy(numbuf, rt->value, rt->value_len);
                numbuf[rt->value_len] = '\0';
                usec = strtoull(numbuf, NULL, 10);
                sec = (time_t) (usec / 1000000ULL);
        }

        if (sec > 0 && localtime_r(&sec, &tmv))
                strftime(timebuf, sizeof(timebuf), "%b %e %H:%M:%S", &tmv);
        else
                snprintf(timebuf, sizeof(timebuf), "(no timestamp)");

        printf("%s %s ", timebuf, host);

        if (ident)
                fwrite(ident->value, 1, ident->value_len, stdout);
        else if (comm)
                fwrite(comm->value, 1, comm->value_len, stdout);
        else
                fputs("-", stdout);

        if (pid && !pid->binary) {
                putchar('[');
                fwrite(pid->value, 1, pid->value_len, stdout);
                putchar(']');
        }

        fputs(": ", stdout);

        if (msg && !msg->binary)
                fwrite(msg->value, 1, msg->value_len, stdout);
        else if (msg && show_all)
                print_escaped(msg->value, msg->value_len);
        else if (msg)
                fputs("blob data", stdout);

        putchar('\n');
}

/* -o export's byte-for-byte passthrough: the entry's exact on-disk bytes,
 * never re-serialized from parsed fields, so a filtered subset still feeds
 * systemd-journal-remote unmodified (plan §3.4). */
static void print_export(const LogdEntry *e) {
        fwrite(e->raw, 1, e->raw_len, stdout);
}

static bool matches(const struct options *opts, const LogdEntry *e) {
        if (!logd_entry_matches_unit(e, opts->unit))
                return false;
        if (opts->max_priority >= 0 && !logd_entry_matches_priority(e, opts->max_priority))
                return false;
        if (opts->kernel_only && !logd_entry_is_kernel(e))
                return false;

        return true;
}

static void print_entry(const struct options *opts, const LogdEntry *e) {
        if (opts->output == OUTPUT_EXPORT)
                print_export(e);
        else
                print_short(e, opts->show_all);
}

static int run_dump(const char *runtime_dir, const struct options *opts) {
        LogdRing *ring;
        size_t n, n_match = 0, start, i;
        size_t *match_idx;
        int r;

        r = logd_ring_read(runtime_dir, &ring);
        if (r < 0)
                return r;

        n = logd_ring_n_entries(ring);

        match_idx = n > 0 ? malloc(n * sizeof(*match_idx)) : NULL;
        if (n > 0 && !match_idx) {
                logd_ring_free(ring);
                return -ENOMEM;
        }

        for (i = 0; i < n; i++)
                if (matches(opts, logd_ring_entry(ring, i)))
                        match_idx[n_match++] = i;

        start = (opts->tail_n > 0 && (size_t) opts->tail_n < n_match) ? n_match - (size_t) opts->tail_n : 0;

        for (i = start; i < n_match; i++)
                print_entry(opts, logd_ring_entry(ring, match_idx[i]));

        free(match_idx);
        logd_ring_free(ring);
        return 0;
}

static int run_follow(const char *runtime_dir, const struct options *opts) {
        LogdFollow *f;
        int r;

        if (opts->tail_n > 0) {
                r = run_dump(runtime_dir, opts);
                if (r < 0)
                        return r;
        }

        r = logd_follow_new(runtime_dir, &f);
        if (r < 0)
                return r;

        for (;;) {
                LogdRing *ring = NULL;

                r = logd_follow_poll(f, &ring);
                if (r < 0) {
                        logd_follow_free(f);
                        return r;
                }

                if (ring) {
                        size_t n = logd_ring_n_entries(ring);

                        for (size_t i = 0; i < n; i++) {
                                const LogdEntry *e = logd_ring_entry(ring, i);

                                if (matches(opts, e))
                                        print_entry(opts, e);
                        }
                        fflush(stdout);
                        logd_ring_free(ring);
                }

                usleep(200000);
        }
}

int main(int argc, char *argv[]) {
        struct options opts = { .max_priority = -1, .output = OUTPUT_SHORT };
        const char *runtime_dir;
        int c, r;

        while ((c = getopt(argc, argv, "fu:p:kn:o:ah")) != -1) {
                switch (c) {
                case 'f':
                        opts.follow = true;
                        break;

                case 'u':
                        opts.unit = optarg;
                        break;

                case 'p': {
                        int p = parse_priority(optarg);

                        if (p < 0) {
                                fprintf(stderr, "picolog: invalid -p priority '%s'\n", optarg);
                                return 1;
                        }
                        opts.max_priority = p;
                        break;
                }

                case 'k':
                        opts.kernel_only = true;
                        break;

                case 'n': {
                        char *endp;
                        long v = strtol(optarg, &endp, 10);

                        if (endp == optarg || *endp != '\0' || v < 0) {
                                fprintf(stderr, "picolog: invalid -n value '%s'\n", optarg);
                                return 1;
                        }
                        opts.tail_n = v;
                        break;
                }

                case 'o':
                        if (strcmp(optarg, "export") == 0)
                                opts.output = OUTPUT_EXPORT;
                        else if (strcmp(optarg, "short") == 0)
                                opts.output = OUTPUT_SHORT;
                        else {
                                fprintf(stderr,
                                        "picolog: unknown -o format '%s' (want short or export)\n",
                                        optarg);
                                return 1;
                        }
                        break;

                case 'a':
                        opts.show_all = true;
                        break;

                case 'h':
                default:
                        fputs("usage: picolog [-f] [-u UNIT] [-p PRIO] [-k] [-n LINES] [-o short|export] [-a]\n",
                              stderr);
                        return c == 'h' ? 0 : 1;
                }
        }

        runtime_dir = getenv("LOGD_RUNTIME_DIR");
        if (!runtime_dir || runtime_dir[0] == '\0')
                runtime_dir = LOGD_RUNTIME_DIR;

        r = opts.follow ? run_follow(runtime_dir, &opts) : run_dump(runtime_dir, &opts);
        if (r < 0) {
                fprintf(stderr, "picolog: %s\n", strerror(-r));
                return 1;
        }

        return 0;
}
