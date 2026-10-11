/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The INI line scanner, quarried from systemd's ~2011-era src/conf-parser.c
 * (tag v30, commit 501c92c, copyright 2010 Lennart Poettering,
 * GPL-2.0-or-later), factored out of unit-parse.c so its backported fixes
 * apply to every INI-syntax config this project parses (see conf-scan.h).
 * These upstream fixes (github.com/systemd/systemd commit hashes) are
 * properties of this layer:
 *
 *  - e6dde451a "conf-parser: use fgets_with_tabs... unbounded read" --
 *    getline() below is inherently unbounded, so a long line is never
 *    silently truncated the way a fixed LINE_MAX buffer would.
 *  - 2d4fffb00 "conf-parser: ignore lines without '='" -- one malformed
 *    line is logged and skipped, not a whole-file -EINVAL.
 *  - 9adbfeb38 + 0ef695858 -- a comment line is skipped entirely: it must not
 *    start a continuation, and it must not end one already in progress
 *    (a comment mid-continuation is transparent, only a blank line ends it).
 *  - 4f29e0db1 "conf-parser: parse last line of file even if it's an
 *    unterminated continuation" -- flushed explicitly after the read loop.
 *  - 9dd7ea9a7 "conf-parser: skip UTF-8 byte order mark" -- a BOM on the
 *    first line must not break "[Section]" matching.
 *  - 8ea913b2e "conf-parser: fix invalid free" -- the continuation buffer's
 *    allocation check below tests its own lvalue, not a stale nearby one.
 *  - 91ffff962 "conf-parser: free old section on error" -- the current
 *    section name is freed before being replaced, not leaked.
 *
 * unit-parse.c's header keeps the remaining three (35b1078e1/c853953658
 * ExecStart= parsing, a2a5291b3/b2fadec60 quoting, 92c1622e14/36c16a7cdd
 * Timeout*Sec= zero-semantics): those are unit-file value semantics, not
 * scanner behaviour, and stay in the file that owns that semantics.
 *
 * What lives here knows about sections, comments, continuations, the BOM
 * and the key/value split, and nothing about which sections or keys are
 * meaningful: every assignment is handed to the caller's handler together
 * with its section name.
 */

#include "conf-scan.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

static char *cs_strip(char *s) {
        char *end;

        while (*s == ' ' || *s == '\t')
                s++;

        end = s + strlen(s);
        while (end > s && (end[-1] == ' ' || end[-1] == '\t'))
                end--;
        *end = '\0';

        return s;
}

static bool cs_line_is_blank_or_comment(const char *l) {
        l += strspn(l, " \t");
        return *l == '\0' || *l == '#' || *l == ';';
}

/* A genuinely empty line (after stripping whitespace), as opposed to a
 * comment -- see the continuation-vs-comment split below for why the two
 * cannot share one predicate there. */
static bool cs_line_is_blank(const char *l) {
        l += strspn(l, " \t");
        return *l == '\0';
}

/* A non-blank comment line. */
static bool cs_line_is_comment(const char *l) {
        l += strspn(l, " \t");
        return *l == '#' || *l == ';';
}

/*
 * Scans one complete logical line (continuations already joined). `section`
 * is the caller's current-section slot: replaced in place on a [Section]
 * header, the old value freed first (91ffff962). Returns whatever the
 * handler returned for an assignment, or 0 for a header/blank/malformed
 * line -- none of those ever reach the handler.
 */
static int
                cs_scan_line(pico_conf_handler_t handler,
                             void *userdata,
                             const char *filename,
                             unsigned line,
                             char **section,
                             char *l) {
        char *lvalue, *rvalue, *eq;

        l = cs_strip(l);
        if (cs_line_is_blank_or_comment(l))
                return 0;

        if (l[0] == '[') {
                char *close = strchr(l, ']');
                char *name;

                if (!close) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: '[' without closing ']', ignoring line",
                                 filename,
                                 line);
                        return 0;
                }
                *close = '\0';

                name = pico_strdup(l + 1);
                if (!name)
                        return -ENOMEM;

                *section = pico_mfree(*section); /* 91ffff962: free before replacing */
                *section = name;
                return 0;
        }

        /* 2d4fffb00: skip just this line rather than failing the whole file. */
        eq = strchr(l, '=');
        if (!eq) {
                pico_log(PICO_LOG_WARNING, "%s:%u: no '=' found, ignoring line", filename, line);
                return 0;
        }
        *eq = '\0';
        lvalue = cs_strip(l);
        rvalue = cs_strip(eq + 1);

        return handler(filename, line, *section, lvalue, rvalue, userdata);
}

int pico_conf_scan(const char *filename, pico_conf_handler_t handler, void *userdata) {
        FILE *f;
        char *rawline = NULL;
        size_t rawcap = 0;
        char *continuation = NULL;
        char *section = NULL;
        unsigned line = 0;
        bool first_line = true;
        int r = 0;

        if (!filename || !handler)
                return -EINVAL;

        f = fopen(filename, "re");
        if (!f)
                return -errno;

        for (;;) {
                ssize_t n = getline(&rawline, &rawcap, f);
                char *l;

                if (n < 0) {
                        if (!feof(f))
                                r = -errno;
                        break;
                }
                line++;

                l = rawline;

                /* 9dd7ea9a7: a UTF-8 BOM on the file's first line must not
                 * shift "[Section]" matching. */
                if (first_line) {
                        first_line = false;
                        if (n >= 3 && (unsigned char) l[0] == 0xEF && (unsigned char) l[1] == 0xBB &&
                            (unsigned char) l[2] == 0xBF) {
                                l += 3;
                                n -= 3;
                        }
                }

                while (n > 0 && (l[n - 1] == '\n' || l[n - 1] == '\r'))
                        l[--n] = '\0';

                if (continuation) {
                        /*
                         * Behaviour of upstream 0ef69585d8: a comment is
                         * skipped with the continuation untouched; only a
                         * blank line ends an in-progress continuation.
                         * Flushing on a comment would drop the rest of an
                         * ExecStart= line that has a comment in the middle.
                         */
                        if (cs_line_is_comment(l))
                                continue;

                        if (cs_line_is_blank(l)) {
                                r = cs_scan_line(handler, userdata, filename, line, &section, continuation);
                                continuation = pico_mfree(continuation);
                                if (r < 0)
                                        break;
                                continue;
                        }

                        size_t clen = strlen(continuation);
                        char *joined = realloc(continuation, clen + 1 + strlen(l) + 1);
                        if (!joined) {
                                r = -ENOMEM;
                                break;
                        }
                        continuation = joined;
                        continuation[clen] = ' ';
                        strcpy(continuation + clen + 1, l);
                        l = continuation;
                } else if (cs_line_is_blank_or_comment(l)) {
                        /* 9adbfeb38: a comment ending in backslash must not
                         * start a continuation. */
                        continue;
                }

                n = (ssize_t) strlen(l);
                if (n > 0 && l[n - 1] == '\\') {
                        l[n - 1] = '\0';

                        if (l != continuation) {
                                char *c = pico_strdup(l);
                                if (!c) { /* 8ea913b2e: check the var just assigned, not a stale one */
                                        r = -ENOMEM;
                                        break;
                                }
                                continuation = c;
                        }
                        continue;
                }

                r = cs_scan_line(handler, userdata, filename, line, &section, l);
                if (l == continuation)
                        continuation = pico_mfree(continuation);
                if (r < 0)
                        break;
        }

        /* 4f29e0db1: a file ending mid-continuation must still parse that
         * last line. */
        if (r == 0 && continuation)
                r = cs_scan_line(handler, userdata, filename, line, &section, continuation);
        continuation = pico_mfree(continuation);
        section = pico_mfree(section);

        free(rawline);
        fclose(f);

        return r;
}
