/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * INI-style unit-file parser, quarried from systemd's ~2011-era
 * src/conf-parser.c + src/load-fragment.c (tag v30, commit 501c92c,
 * copyright 2010 Lennart Poettering, GPL-2.0-or-later). Only
 * [Unit]/[Service]/[Install] and the directives service.h/unit.h actually
 * have fields for are implemented -- everything else (dbus, socket
 * activation, cgroup v1, SELinux, specifiers) is recognized as valid INI
 * syntax and dropped at debug level rather than erroring, matching real
 * unit-file tolerance.
 *
 * Backported fixes from the 2011 baseline's real upstream history (see
 * plans/29-pico-init.md quarrying-discipline note); commit hashes below
 * are from github.com/systemd/systemd:
 *
 *  - 35b1078e1 "load-fragment: Don't assert() on invalid exec flags" --
 *    the original code hit assert(skip < l) on "ExecStart=- /bin/true"
 *    (a modifier separated from the path by whitespace) and aborted the
 *    whole manager process. A malformed unit file must never be able to
 *    kill PID1, so parse_exec_line() below rejects that shape with a
 *    warning instead.
 *  - c853953658 "load-fragment: Rework config_parse_exec()" -- replaces
 *    the historical assert(path_is_absolute(path)) with an explicit
 *    validate-and-reject chain; parse_exec_line() follows that template.
 *  - a2a5291b3 / b2fadec60 "conf-parser: fix potentially bad memory
 *    accesses" -- an unterminated quote or trailing garbage after a
 *    closing quote was silently accepted; extract_first_word() below
 *    rejects both.
 *  - 8ea913b2e "conf-parser: fix invalid free" -- a strdup() result was
 *    checked via a stale nearby variable instead of the one just
 *    assigned. Every allocation check here tests its own lvalue.
 *  - 91ffff962 "conf-parser: free old section on error" -- section names
 *    are freed before being replaced, not leaked.
 *  - 9dd7ea9a7 "conf-parser: skip UTF-8 byte order mark" -- a BOM on the
 *    first line no longer breaks "[Section]" matching.
 *  - 9adbfeb38 + 0ef695858 -- a comment line ending in backslash must not
 *    start a continuation, and a blank/comment line must still be able to
 *    terminate one already in progress.
 *  - 4f29e0db1 "conf-parser: parse last line of file even if it's an
 *    unterminated continuation" -- flushed explicitly after the read loop.
 *  - 2d4fffb00 "conf-parser: ignore lines without '='" -- one malformed
 *    line is logged and skipped, not a whole-file -EINVAL.
 *  - e6dde451a "conf-parser: use fgets_with_tabs... unbounded read" --
 *    getline() below is inherently unbounded, so a long ExecStart= line
 *    is never silently truncated the way a fixed LINE_MAX buffer would.
 *
 * Not backported (see plans/29-pico-init.md for scope): the UTF-8
 * validity/escaping fixes (b5d742138, 78d17fa09, 9e6027783) -- no
 * quoted-strv directive in this MVP needs them; the mtime-tracking fixes
 * (9fd8d678b, da46a1bc3) -- unit_parse_file() has no mtime out-param in
 * the M0 header contract; the ';'-multi-command ExecStart fixes
 * (3851c51ad, 598c47c86) -- multi-command ExecStart= is out of MVP scope,
 * Type=simple takes exactly one command; specifier-expansion OOM-vs-syntax
 * distinction (487060c239) -- no specifier expansion (%i etc.) exists yet.
 */

#include "unit.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp, for the boolean spellings */

#include "manager.h"
#include "service.h"
#include "util.h"

typedef enum ConfigSection {
        SECTION_NONE,
        SECTION_UNIT,
        SECTION_SERVICE,
        SECTION_INSTALL,
        SECTION_UNKNOWN,
} ConfigSection;

typedef int (*ConfigParseFn)(Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue);

typedef struct ConfigItem {
        ConfigSection section;
        const char *lvalue;
        ConfigParseFn parse;
} ConfigItem;

/* --- small string helpers --- */

static char *strip(char *s) {
        char *end;

        while (*s == ' ' || *s == '\t')
                s++;

        end = s + strlen(s);
        while (end > s && (end[-1] == ' ' || end[-1] == '\t'))
                end--;
        *end = '\0';

        return s;
}

static bool line_is_blank_or_comment(const char *l) {
        l += strspn(l, " \t");
        return *l == '\0' || *l == '#' || *l == ';';
}

/* --- word splitting for ExecStart=/ExecStartPre= --- */

/*
 * Extracts one whitespace-separated word from *state, honoring a single
 * level of double-quoting so "a b" is one argument. *state is advanced
 * past the word. Returns 1 with *ret set (caller owns it), 0 at end of
 * string, -EINVAL on an unterminated quote or on trailing garbage right
 * after a closing quote (a2a5291b3/b2fadec60 -- both used to be silently
 * accepted).
 */
static int extract_first_word(const char **state, char **ret) {
        const char *p = *state;
        char *buf, *w;
        bool quoted = false;

        while (*p == ' ' || *p == '\t')
                p++;
        if (*p == '\0') {
                *state = p;
                return 0;
        }

        buf = malloc(strlen(p) + 1);
        if (!buf)
                return -ENOMEM;
        w = buf;

        for (;;) {
                if (*p == '\0') {
                        if (quoted) {
                                free(buf);
                                return -EINVAL; /* unterminated quote */
                        }
                        break;
                }
                if (*p == '"') {
                        if (quoted) {
                                /*
                                 * Closing a quote: the next character must be
                                 * unquoted whitespace or end-of-string, or
                                 * that's trailing garbage right after the
                                 * quote (foo="bar"baz). This is the actual
                                 * a2a5291b3/b2fadec60 check -- a prior version
                                 * of this function had the equivalent check
                                 * placed after the loop, where it could never
                                 * fire (the loop's own exit conditions mean
                                 * *p is always '\0'/' '/'\t' by the time it's
                                 * reached), so foo="bar"baz was silently
                                 * accepted as "barbaz". Found by review
                                 * before this ever shipped.
                                 */
                                if (p[1] != '\0' && p[1] != ' ' && p[1] != '\t') {
                                        free(buf);
                                        return -EINVAL;
                                }
                        }
                        quoted = !quoted;
                        p++;
                        continue;
                }
                if (*p == '\\' && p[1] != '\0') {
                        *w++ = p[1];
                        p += 2;
                        continue;
                }
                if (!quoted && (*p == ' ' || *p == '\t'))
                        break;
                *w++ = *p++;
        }
        *w = '\0';

        /*
         * No trailing-garbage check needed here: the loop above only ever
         * exits with *p == '\0' or (unquoted) *p being a space/tab -- the
         * real trailing-garbage rejection happens at the point a quote
         * closes, above, where the actual violating character is still
         * known.
         */

        *state = p;
        *ret = buf;
        return 1;
}

/*
 * Parses one ExecStart=/ExecStartPre= value into a NULL-terminated argv.
 * Supports the "-" modifier (ignore exit status) only when it's not
 * separated from the path by whitespace; that's the exact shape
 * ("ExecStart=- /bin/true") that hit assert(skip < l) upstream (35b1078e1)
 * -- reject it with a warning instead of indexing past it. Other
 * modifiers (@ + ! :) aren't supported in this MVP and cause the whole
 * directive to be rejected, same as c853953658's validate-and-reject
 * rework rather than the original assert-on-bad-input.
 */
static int parse_exec_line(const char *path, unsigned line, const char *rvalue, char ***ret_argv) {
        const char *p = rvalue;
        char **argv = NULL;
        char *word;
        int r;

        p += strspn(p, " \t");

        if (*p == '-' && p[1] != '\0' && p[1] != ' ' && p[1] != '\t') {
                p++; /* modifier glued to the path: accepted, exit status just isn't tracked yet */
        } else if (*p == '-') {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: ExecStart= modifier must not be "
                         "separated from the path by whitespace, ignoring",
                         path,
                         line);
                return -EINVAL;
        } else if (*p == '@' || *p == '+' || *p == '!' || *p == ':') {
                pico_log(PICO_LOG_DEBUG,
                         "%s:%u: unsupported ExecStart= modifier '%c', ignoring line",
                         path,
                         line,
                         *p);
                return -EINVAL;
        }

        r = extract_first_word(&p, &word);
        if (r <= 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: %s in ExecStart=, ignoring",
                         path,
                         line,
                         r < 0 ? "malformed quoting" : "empty command line");
                return r < 0 ? r : -EINVAL;
        }

        if (word[0] != '/') {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: ExecStart= path '%s' is not absolute, ignoring",
                         path,
                         line,
                         word);
                free(word);
                return -EINVAL;
        }
        if (word[strlen(word) - 1] == '/') {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: ExecStart= path '%s' is a directory, ignoring",
                         path,
                         line,
                         word);
                free(word);
                return -EINVAL;
        }

        r = pico_strv_extend(&argv, word);
        free(word);
        if (r < 0)
                return r;

        for (;;) {
                r = extract_first_word(&p, &word);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: malformed quoting in ExecStart=, ignoring",
                                 path,
                                 line);
                        argv = pico_strv_free(argv);
                        return r;
                }
                if (r == 0)
                        break;

                r = pico_strv_extend(&argv, word);
                free(word);
                if (r < 0) {
                        argv = pico_strv_free(argv);
                        return r;
                }
        }

        *ret_argv = argv;
        return 0;
}

/* --- [Unit] handlers --- */

static int config_parse_description(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        char *d;
        (void) path;
        (void) line;
        (void) lvalue;

        d = pico_strdup(rvalue);
        if (!d)
                return -ENOMEM;

        u->description = pico_mfree(u->description);
        u->description = d;
        return 0;
}

static int config_parse_unit_deps(Unit *u, const char *path, unsigned line, UnitDependency d, const char *rvalue) {
        char *names;
        char *saveptr = NULL;
        char *tok;

        /*
         * Heap, not a VLA: rvalue comes straight from unit_parse_file()'s
         * unbounded getline() (e6dde451a -- no LINE_MAX truncation is the
         * whole point), so a VLA sized by strlen(rvalue) turns one long
         * Requires= line into a stack overflow -- exactly the "malformed
         * unit file kills PID1" class this file exists to prevent (see the
         * 35b1078e1 note at the top of this file). Found by review before
         * this ever shipped, not a hypothetical.
         */
        names = pico_strdup(rvalue);
        if (!names)
                return -ENOMEM;

        for (tok = strtok_r(names, " \t", &saveptr); tok; tok = strtok_r(NULL, " \t", &saveptr)) {
                Unit *other;
                int r;

                /*
                 * unit_name_is_valid() subsumes the old suffix check and adds
                 * the one that actually matters: this token is concatenated
                 * into a search-path entry by unit_load(), so
                 * "Requires=../../tmp/evil.service" must be rejected before it
                 * ever becomes a path.
                 */
                if (!unit_name_is_valid(tok)) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: '%s' is not a valid unit name, ignoring",
                                 path,
                                 line,
                                 tok);
                        continue;
                }

                if (!u->manager) {
                        pico_log(PICO_LOG_DEBUG,
                                 "%s:%u: no manager attached, not resolving "
                                 "dependency on '%s'",
                                 path,
                                 line,
                                 tok);
                        continue;
                }

                r = manager_load_unit(u->manager, tok, &other);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: failed to resolve dependency on '%s': %s, "
                                 "ignoring",
                                 path,
                                 line,
                                 tok,
                                 strerror(-r));
                        continue;
                }

                /*
                 * A single bad dependency is non-fatal to the rest of the
                 * unit, the same way systemd itself logs-and-continues rather
                 * than aborting the whole load. The usual cause is a
                 * self-dependency or an out-of-memory grow, neither of which
                 * makes the other directives in the file wrong.
                 */
                r = unit_add_dependency(u, d, other);
                if (r < 0)
                        pico_log(PICO_LOG_DEBUG,
                                 "%s:%u: could not record %s dependency on '%s': %s",
                                 path,
                                 line,
                                 unit_dependency_to_string(d),
                                 tok,
                                 strerror(-r));
        }

        pico_mfree(names);
        return 0;
}

static int config_parse_requires(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        (void) lvalue;
        return config_parse_unit_deps(u, path, line, UNIT_REQUIRES, rvalue);
}

static int config_parse_wants(Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        (void) lvalue;
        return config_parse_unit_deps(u, path, line, UNIT_WANTS, rvalue);
}

static int config_parse_before(Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        (void) lvalue;
        return config_parse_unit_deps(u, path, line, UNIT_BEFORE, rvalue);
}

static int config_parse_after(Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        (void) lvalue;
        return config_parse_unit_deps(u, path, line, UNIT_AFTER, rvalue);
}

/* --- [Service] handlers --- */

/* Targets are a real unit type now, so a [Service] directive on one is a
 * misplaced-directive warning rather than an impossible case. */
static Service *unit_to_service(Unit *u, const char *path, unsigned line) {
        if (u->type != UNIT_SERVICE) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: [Service] directive on a %s unit, ignoring",
                         path,
                         line,
                         unit_type_to_string(u->type));
                return NULL;
        }
        return SERVICE(u);
}

static int config_parse_type(Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        (void) lvalue;

        if (!s)
                return 0;

        if (strcmp(rvalue, "simple") == 0)
                s->type = SERVICE_TYPE_SIMPLE;
        else if (strcmp(rvalue, "oneshot") == 0)
                s->type = SERVICE_TYPE_ONESHOT;
        else {
                /*
                 * Still a hard failure rather than a dropped directive:
                 * forking/dbus/notify/idle each change *when* a service counts
                 * as started, so silently running one as simple would report
                 * the unit up before it actually is, and everything ordered
                 * After= it would then start too early. Refusing is safer.
                 */
                pico_log(PICO_LOG_ERR,
                         "%s:%u: Type=%s is not supported (only 'simple' and 'oneshot' are), failing unit",
                         path,
                         line,
                         rvalue);
                return -EINVAL;
        }

        return 0;
}

/*
 * systemd's own boolean spellings (parse_boolean() in src/basic/parse-util.c):
 * 1/yes/y/true/t/on and 0/no/n/false/f/off, case-insensitively. Matching that
 * set exactly is part of the drop-in goal -- "RemainAfterExit=on" and "=true"
 * both appear in real unit files.
 */
static int parse_boolean_value(const char *v, bool *ret) {
        if (strcmp(v, "1") == 0 || strcasecmp(v, "yes") == 0 || strcasecmp(v, "y") == 0 ||
            strcasecmp(v, "true") == 0 || strcasecmp(v, "t") == 0 || strcasecmp(v, "on") == 0) {
                *ret = true;
                return 0;
        }

        if (strcmp(v, "0") == 0 || strcasecmp(v, "no") == 0 || strcasecmp(v, "n") == 0 ||
            strcasecmp(v, "false") == 0 || strcasecmp(v, "f") == 0 || strcasecmp(v, "off") == 0) {
                *ret = false;
                return 0;
        }

        return -EINVAL;
}

static int config_parse_remain_after_exit(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        bool b;
        (void) lvalue;

        if (!s)
                return 0;

        if (parse_boolean_value(rvalue, &b) < 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: invalid RemainAfterExit= value '%s', ignoring",
                         path,
                         line,
                         rvalue);
                return 0;
        }

        s->remain_after_exit = b;
        return 0;
}

static int config_parse_exec_start(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        char **argv = NULL;
        int r;
        (void) lvalue;

        if (!s)
                return 0;

        /* Same non-fatal-per-directive policy as every other handler in this
         * file (Restart=, RestartSec=, ...): parse_exec_line() already logged
         * why, so just leave exec_start as it was rather than failing the
         * whole unit over one bad directive. A unit that ends up with no
         * ExecStart= at all is a validation problem, not a parse error --
         * not yet enforced (no post-load validation pass exists), tracked in
         * plans/29-pico-init.md. */
        r = parse_exec_line(path, line, rvalue, &argv);
        if (r < 0)
                return 0;

        s->exec_start = pico_strv_free(s->exec_start);
        s->exec_start = argv;
        return 0;
}

static int config_parse_exec_start_pre(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        char **argv = NULL;
        int r;
        (void) lvalue;

        if (!s)
                return 0;

        r = parse_exec_line(path, line, rvalue, &argv);
        if (r < 0)
                return 0;

        if (s->exec_start_pre)
                pico_log(PICO_LOG_DEBUG,
                         "%s:%u: multiple ExecStartPre= not supported, replacing "
                         "previous value",
                         path,
                         line);

        s->exec_start_pre = pico_strv_free(s->exec_start_pre);
        s->exec_start_pre = argv;
        return 0;
}

static int config_parse_restart(Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        (void) lvalue;

        if (!s)
                return 0;

        if (strcmp(rvalue, "no") == 0)
                s->restart = SERVICE_RESTART_NO;
        else if (strcmp(rvalue, "on-failure") == 0)
                s->restart = SERVICE_RESTART_ON_FAILURE;
        else {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: Restart=%s not supported (only 'no'/'on-failure'), "
                         "defaulting to 'no'",
                         path,
                         line,
                         rvalue);
                s->restart = SERVICE_RESTART_NO;
        }

        return 0;
}

/*
 * Minimal time-span parser: a plain integer is seconds; a single
 * "<n><suffix>" with suffix one of us/ms/s/min/m/h is also accepted.
 * Compound spans ("1min 30s") aren't supported in this MVP. The overflow
 * check is an explicit bound comparison rather than the round-trip cast
 * idiom ((uint64_t)(size_t)v != v) that 31ef154f1 (2026-08-18, most
 * recent fix in the whole quarry history) replaced for being legally
 * elidable by an optimizer -- built correctly from day one instead of
 * porting the fragile idiom.
 */
static int parse_usec(const char *rvalue, usec_t *ret) {
        char *end;
        unsigned long long v;
        usec_t scale = USEC_PER_SEC;

        errno = 0;
        v = strtoull(rvalue, &end, 10);
        if (end == rvalue || errno == ERANGE)
                return -EINVAL;

        end += strspn(end, " \t");

        if (*end != '\0') {
                if (strcmp(end, "us") == 0)
                        scale = 1;
                else if (strcmp(end, "ms") == 0)
                        scale = USEC_PER_MSEC;
                else if (strcmp(end, "s") == 0)
                        scale = USEC_PER_SEC;
                else if (strcmp(end, "min") == 0 || strcmp(end, "m") == 0)
                        scale = USEC_PER_SEC * 60ULL;
                else if (strcmp(end, "h") == 0)
                        scale = USEC_PER_SEC * 3600ULL;
                else
                        return -EINVAL;
        }

        if (v != 0 && scale != 0 && v > USEC_INFINITY / scale)
                return -EOVERFLOW;

        *ret = (usec_t) v * scale;
        return 0;
}

static int config_parse_restart_sec(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        int r;
        (void) lvalue;

        if (!s)
                return 0;

        r = parse_usec(rvalue, &s->restart_usec);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid RestartSec= value '%s', ignoring", path, line, rvalue);
        return 0;
}

static int config_parse_timeout_start_sec(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        int r;
        (void) lvalue;

        if (!s)
                return 0;

        r = parse_usec(rvalue, &s->timeout_start_usec);
        if (r < 0)
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: invalid TimeoutStartSec= value '%s', ignoring",
                         path,
                         line,
                         rvalue);
        return 0;
}

static int config_parse_timeout_stop_sec(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        int r;
        (void) lvalue;

        if (!s)
                return 0;

        r = parse_usec(rvalue, &s->timeout_stop_usec);
        if (r < 0)
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: invalid TimeoutStopSec= value '%s', ignoring",
                         path,
                         line,
                         rvalue);
        return 0;
}

/* --- [Install] handlers --- */

/*
 * WantedBy=/RequiredBy= are stored as raw names, not resolved into edges here.
 * At parse time the named target may not be loaded yet, and -- more
 * importantly -- whether these are honoured at all depends on enablement (a
 * .wants/ symlink or a preset rule), which cannot be decided until every
 * fragment has been read. unit-enable.c turns them into real edges later, or
 * deliberately does not.
 */
static int config_parse_install_names(
                Unit *u, const char *path, unsigned line, const char *rvalue, char ***target) {
        char *saveptr = NULL;
        char *names;
        char *tok;

        (void) u;

        /* heap, not a VLA: rvalue comes from an unbounded getline(), the same
         * stack-overflow hazard config_parse_unit_deps() documents above */
        names = pico_strdup(rvalue);
        if (!names)
                return -ENOMEM;

        for (tok = strtok_r(names, " \t", &saveptr); tok; tok = strtok_r(NULL, " \t", &saveptr)) {
                if (!unit_name_is_valid(tok)) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: '%s' is not a valid unit name, ignoring",
                                 path,
                                 line,
                                 tok);
                        continue;
                }

                if (pico_strv_extend(target, tok) < 0) {
                        pico_mfree(names);
                        return -ENOMEM;
                }
        }

        pico_mfree(names);
        return 0;
}

static int config_parse_wanted_by(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        (void) lvalue;
        return config_parse_install_names(u, path, line, rvalue, &u->wanted_by);
}

static int config_parse_required_by(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        (void) lvalue;
        return config_parse_install_names(u, path, line, rvalue, &u->required_by);
}

static const ConfigItem config_items[] = {
        {    SECTION_UNIT,     "Description",       config_parse_description },
        {    SECTION_UNIT,        "Requires",          config_parse_requires },
        {    SECTION_UNIT,           "Wants",             config_parse_wants },
        {    SECTION_UNIT,          "Before",            config_parse_before },
        {    SECTION_UNIT,           "After",             config_parse_after },
        { SECTION_SERVICE,            "Type",              config_parse_type },
        { SECTION_SERVICE,       "ExecStart",        config_parse_exec_start },
        { SECTION_SERVICE,    "ExecStartPre",    config_parse_exec_start_pre },
        { SECTION_SERVICE,         "Restart",           config_parse_restart },
        { SECTION_SERVICE,      "RestartSec",       config_parse_restart_sec },
        { SECTION_SERVICE, "RemainAfterExit", config_parse_remain_after_exit },
        { SECTION_SERVICE, "TimeoutStartSec", config_parse_timeout_start_sec },
        { SECTION_SERVICE,  "TimeoutStopSec",  config_parse_timeout_stop_sec },
        { SECTION_INSTALL,        "WantedBy",         config_parse_wanted_by },
        { SECTION_INSTALL,      "RequiredBy",       config_parse_required_by },
};

static const char *section_name(ConfigSection s) {
        switch (s) {
        case SECTION_UNIT:
                return "Unit";
        case SECTION_SERVICE:
                return "Service";
        case SECTION_INSTALL:
                return "Install";
        default:
                return "?";
        }
}

/* Parses one complete logical line (continuations already joined). */
static int parse_line(Unit *u, const char *path, unsigned line, ConfigSection *section, char *l) {
        char *lvalue, *rvalue, *eq;
        size_t i;

        l = strip(l);
        if (line_is_blank_or_comment(l))
                return 0;

        if (l[0] == '[') {
                char *close = strchr(l, ']');
                if (!close) {
                        pico_log(PICO_LOG_WARNING, "%s:%u: '[' without closing ']', ignoring line", path, line);
                        return 0;
                }
                *close = '\0';

                if (strcmp(l + 1, "Unit") == 0)
                        *section = SECTION_UNIT;
                else if (strcmp(l + 1, "Service") == 0)
                        *section = SECTION_SERVICE;
                else if (strcmp(l + 1, "Install") == 0)
                        *section = SECTION_INSTALL;
                else {
                        pico_log(PICO_LOG_DEBUG,
                                 "%s:%u: unknown section [%s], ignoring its directives",
                                 path,
                                 line,
                                 l + 1);
                        *section = SECTION_UNKNOWN;
                }
                return 0;
        }

        if (*section == SECTION_NONE) {
                pico_log(PICO_LOG_WARNING, "%s:%u: assignment outside any section, ignoring", path, line);
                return 0;
        }

        /* 2d4fffb00: a line with no '=' used to fail the whole file; skip just this line. */
        eq = strchr(l, '=');
        if (!eq) {
                pico_log(PICO_LOG_WARNING, "%s:%u: no '=' found, ignoring line", path, line);
                return 0;
        }
        *eq = '\0';
        lvalue = strip(l);
        rvalue = strip(eq + 1);

        /* [Install] is no longer dropped wholesale: WantedBy=/RequiredBy= have
         * real backing fields and are in the table below. Everything else in
         * that section (Alias=, Also=, DefaultInstance=) still falls through
         * to the unknown-directive debug log at the bottom, which is the
         * graceful degradation the drop-in goal asks for. */

        if (*section == SECTION_UNKNOWN)
                return 0;

        for (i = 0; i < sizeof(config_items) / sizeof(config_items[0]); i++)
                if (config_items[i].section == *section && strcmp(config_items[i].lvalue, lvalue) == 0)
                        return config_items[i].parse(u, path, line, lvalue, rvalue);

        pico_log(PICO_LOG_DEBUG,
                 "%s:%u: unknown directive %s= in [%s], ignoring",
                 path,
                 line,
                 lvalue,
                 section_name(*section));
        return 0;
}

int unit_parse_file(Unit *u, const char *path) {
        FILE *f;
        char *rawline = NULL;
        size_t rawcap = 0;
        char *continuation = NULL;
        ConfigSection section = SECTION_NONE;
        unsigned line = 0;
        bool first_line = true;
        int r = 0;

        if (!u || !path)
                return -EINVAL;

        f = fopen(path, "re");
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

                /* 9dd7ea9a7: a UTF-8 BOM on the file's first line must not shift "[Section]" */
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
                        /* 0ef695858: a blank/comment line still ends an in-progress
                         * continuation instead of being folded into it. */
                        if (line_is_blank_or_comment(l)) {
                                r = parse_line(u, path, line, &section, continuation);
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
                } else if (line_is_blank_or_comment(l)) {
                        /* 9adbfeb38: a comment ending in backslash must not start a continuation */
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

                r = parse_line(u, path, line, &section, l);
                if (l == continuation)
                        continuation = pico_mfree(continuation);
                if (r < 0)
                        break;
        }

        /* 4f29e0db1: a file ending mid-continuation must still parse that last line */
        if (r == 0 && continuation)
                r = parse_line(u, path, line, &section, continuation);
        continuation = pico_mfree(continuation);

        free(rawline);
        fclose(f);
        return r;
}
