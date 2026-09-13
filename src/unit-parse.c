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
 * The line-level scanner (getline loop, sections, comments, continuations,
 * BOM, key/value split) now lives in conf-scan.c, shared with netd's
 * `.network` parser -- see conf-scan.h for why. This file reduces to the
 * handler table and unit-file semantics: unit_parse_file() below just drives
 * pico_conf_scan() with unit_conf_handler().
 *
 * Backported fixes from the 2011 baseline's real upstream history (see
 * plans/29-pico-init.md quarrying-discipline note); commit hashes below are
 * from github.com/systemd/systemd. Seven of the original eleven are scanner
 * properties and their citations moved to conf-scan.c with the code that
 * carries them (e6dde451a unbounded getline, 2d4fffb00 malformed-line-skip,
 * 9adbfeb38+0ef695858 the comment-backslash/blank-line-terminates pair,
 * 4f29e0db1 unterminated-continuation flush, 9dd7ea9a7 BOM skip, 8ea913b2e
 * invalid-free, 91ffff962 free-old-section-before-replacing). The three
 * remaining are unit-file value semantics and stay here:
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
 *  - 92c1622e14 / 36c16a7cdd (M3, service.c quarry) -- TimeoutStartSec=/
 *    TimeoutStopSec= and RestartSec= have opposite zero-semantics upstream
 *    (0 means "never time out" for the former, "restart immediately" for
 *    the latter). parse_usec() below also accepts the literal "infinity",
 *    and only the two Timeout*Sec= handlers translate a parsed 0 to
 *    USEC_INFINITY; config_parse_restart_sec() deliberately does not.
 *
 * Not backported (see plans/29-pico-init.md for scope): the UTF-8
 * validity/escaping fixes (b5d742138, 78d17fa09, 9e6027783) -- no
 * quoted-strv directive in this MVP needs them; the mtime-tracking fixes
 * (9fd8d678b, da46a1bc3) -- unit_parse_file() has no mtime out-param in
 * the M0 header contract; the ';'-multi-command ExecStart fixes
 * (3851c51ad, 598c47c86) -- multi-command ExecStart= is out of MVP scope,
 * Type=simple takes exactly one command.
 *
 * Specifier expansion (%i/%I/%n/%N/%p, G2): config_parse_unit_deps() and
 * config_parse_install_names() expand per-token through unit_name_printf()
 * (name-safe: no expansion here can introduce whitespace or a '/'), and
 * parse_exec_line()/config_parse_description() expand through
 * unit_full_printf() (adds %I, which unescapes and so can). Deliberately
 * NOT expanded: config_parse_condition_path() -- verified against the
 * quarry that v30 at this tag (load-fragment.c:1584-1620) does not run
 * specifier_printf() on a condition value either, so staying unexpanded
 * keeps this milestone at v30 fidelity rather than one that only looks
 * complete. See that function's own comment for the practical consequence.
 *
 * The stack-overflow-class bug the M1 review found (a VLA sized by an
 * unbounded, attacker-controlled line length, reproduced with a 30MB
 * Requires= line) was in config_parse_unit_deps() below, not the scanner --
 * conf-scan.c's own getline/realloc-based line handling never used a VLA
 * either. Its committed regression test lives in netd/test-netd-network.c,
 * exercising the same heap-not-VLA discipline through netd's own parser
 * (see that file for why: this project's test programs are not this file's
 * to add to at N0).
 */

#include "unit.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h> /* snprintf, for the degradation record's name=qualifier form */
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp, for the boolean spellings */

#include "conf-scan.h"
#include "manager.h"
#include "service.h"
#include "socket.h"
#include "util.h"

#include <sys/socket.h> /* AF_UNIX/AF_UNSPEC/SOCK_STREAM/SOCK_DGRAM, for ListenStream=/ListenDatagram= */
#include <sys/un.h>     /* sizeof(sun_path), for the ListenStream=/ListenDatagram= length check */

typedef enum ConfigSection {
        SECTION_UNIT,
        SECTION_SERVICE,
        SECTION_SOCKET,
        SECTION_INSTALL,
        SECTION_UNKNOWN,
} ConfigSection;

typedef int (*ConfigParseFn)(Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue);

typedef struct ConfigItem {
        ConfigSection section;
        const char *lvalue;
        ConfigParseFn parse;
} ConfigItem;

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
/*
 * Expand *word through the full table (%I included) and replace it in
 * place, freeing the raw word either way -- the caller has nothing left to
 * clean up on either return path.
 */
static int expand_word(Unit *u, char **word) {
        char *expanded = NULL;
        int r = unit_full_printf(u, *word, &expanded);

        free(*word);
        *word = r < 0 ? NULL : expanded;
        return r;
}

static int parse_exec_line(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue, char ***ret_argv) {
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
                char what[64];

                pico_log(PICO_LOG_DEBUG,
                         "%s:%u: unsupported %s= modifier '%c', ignoring line",
                         path,
                         line,
                         lvalue,
                         *p);
                snprintf(what, sizeof(what), "%s=%c", lvalue, *p);
                (void) unit_add_degradation(u, what);
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

        /*
         * Expanded here, after extract_first_word() and before the
         * absolute-path check below -- so the check judges the expanded
         * path, and so a %I that unescapes to something containing a space
         * (e.g. an instance "a\x20b") stays one argv element instead of
         * being split by a whole-rvalue expansion done before word-splitting
         * ever ran. v30 itself expands ExecStart= at spawn time instead
         * (unit_full_printf_strv() from service.c, already-tokenized argv
         * in hand by then) rather than here at parse time -- pico expands
         * earlier for the same per-word-not-per-line reason, just applied
         * sooner, since pico has no separate spawn-time expansion pass.
         */
        r = expand_word(u, &word);
        if (r < 0)
                return r;

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

                r = expand_word(u, &word);
                if (r < 0) {
                        argv = pico_strv_free(argv);
                        return r;
                }

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
        char *d = NULL;
        int r;
        (void) path;
        (void) line;
        (void) lvalue;

        /* Full table (%I included): a Description= is free text, never a
         * path or a name, so there is nothing here for an unescaped '/' to
         * corrupt. */
        r = unit_full_printf(u, rvalue, &d);
        if (r < 0)
                return r;

        u->description = pico_mfree(u->description);
        u->description = d;
        return 0;
}

static int config_parse_unit_deps(Unit *u, const char *path, unsigned line, UnitDependency d, const char *rvalue) {
        char *names;
        char *saveptr = NULL;
        char *tok;

        /*
         * Heap, not a VLA: rvalue comes straight from conf-scan.c's unbounded
         * getline() (e6dde451a -- no LINE_MAX truncation is the whole point),
         * so a VLA sized by strlen(rvalue) turns one long Requires= line into
         * a stack overflow -- exactly the "malformed unit file kills PID1"
         * class this file exists to prevent (see the 35b1078e1 note at the
         * top of this file). Found by review before this ever shipped, not a
         * hypothetical.
         */
        names = pico_strdup(rvalue);
        if (!names)
                return -ENOMEM;

        for (tok = strtok_r(names, " \t", &saveptr); tok; tok = strtok_r(NULL, " \t", &saveptr)) {
                Unit *other;
                char *expanded = NULL;
                int r;

                /*
                 * Per token, before validation, not on the whole rvalue:
                 * unit_name_printf()'s table (%n %N %p %i) cannot itself
                 * introduce whitespace, but expanding per-word here anyway is
                 * what keeps that true by construction rather than by an
                 * accident of which specifiers happen to exist today -- the
                 * same discipline parse_exec_line() needs for real, below.
                 */
                r = unit_name_printf(u, tok, &expanded);
                if (r < 0) {
                        pico_mfree(names);
                        return r;
                }

                /*
                 * unit_name_is_valid() subsumes the old suffix check and adds
                 * the one that actually matters: this token is concatenated
                 * into a search-path entry by unit_load(), so
                 * "Requires=../../tmp/evil.service" must be rejected before it
                 * ever becomes a path.
                 */
                if (!unit_name_is_valid(expanded)) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: '%s' is not a valid unit name, ignoring",
                                 path,
                                 line,
                                 expanded);
                        pico_mfree(expanded);
                        continue;
                }

                if (!u->manager) {
                        pico_log(PICO_LOG_DEBUG,
                                 "%s:%u: no manager attached, not resolving "
                                 "dependency on '%s'",
                                 path,
                                 line,
                                 expanded);
                        pico_mfree(expanded);
                        continue;
                }

                r = manager_load_unit(u->manager, expanded, &other);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: failed to resolve dependency on '%s': %s, "
                                 "ignoring",
                                 path,
                                 line,
                                 expanded,
                                 strerror(-r));
                        pico_mfree(expanded);
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
                                 expanded,
                                 strerror(-r));

                pico_mfree(expanded);
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

/*
 * One path per assignment, taken verbatim: Condition* values are single paths,
 * not whitespace-separated lists, and repeated assignments accumulate (all
 * must pass). An empty value resets the list, as upstream.
 *
 * Bad values are dropped with a warning rather than returned as an error: a
 * handler returning < 0 aborts the rest of the scan (conf-scan.c) and leaves
 * the unit UNIT_ERROR, so a real unit file carrying a '!'-negated condition
 * this MVP does not implement would drop out of the boot entirely over a
 * directive it does not need. Dropping is also exactly what these spellings
 * already did before this handler existed, so it is no regression -- but it
 * does mean a negated condition is ignored rather than honoured, which is the
 * named limitation of this minimal support.
 *
 * Deliberately not specifier-expanded (G2): verified at v30's own tag that
 * this directive (load-fragment.c:1584-1620) is not run through
 * specifier_printf() there either -- that only came later upstream. Staying
 * at v30 fidelity here is a real, named limitation: a generic
 * "serial-getty@.service" template cannot carry
 * "ConditionPathExists=/dev/%I". Not needed for the units this project
 * currently ships (SERIAL_CONSOLES-derived consoles always exist; the
 * ttyGS0 override keeps its literal condition), and test-unit-parse.c pins
 * this exact non-expanding behaviour so the choice stays visible rather than
 * silently regressed if a future commit's search-and-replace ever reaches
 * this function.
 */
static int config_parse_condition_path(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue, char ***target) {
        if (rvalue[0] == '\0') {
                *target = pico_strv_free(*target);
                return 0;
        }

        if (rvalue[0] == '!' || rvalue[0] == '|') {
                char what[64];

                pico_log(PICO_LOG_WARNING,
                         "%s:%u: %s=%s: negated and triggering conditions are not supported, ignoring",
                         path,
                         line,
                         lvalue,
                         rvalue);
                snprintf(what, sizeof(what), "%s=%c", lvalue, rvalue[0]);
                return unit_add_degradation(u, what);
        }

        if (rvalue[0] != '/') {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: %s= path '%s' is not absolute, ignoring",
                         path,
                         line,
                         lvalue,
                         rvalue);
                return 0;
        }

        return pico_strv_extend(target, rvalue);
}

static int config_parse_condition_path_exists(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_condition_path(u, path, line, lvalue, rvalue, &u->condition_path_exists);
}

static int config_parse_condition_path_is_directory(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_condition_path(u, path, line, lvalue, rvalue, &u->condition_path_is_directory);
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
        else if (strcmp(rvalue, "exec") == 0)
                s->type = SERVICE_TYPE_EXEC;
        else if (strcmp(rvalue, "notify") == 0)
                s->type = SERVICE_TYPE_NOTIFY;
        else if (strcmp(rvalue, "notify-reload") == 0) {
                /* Everything notify-reload adds over notify is a reload
                 * protocol, and neither ExecReload= nor a reload verb exists
                 * for it to differ on -- so the start semantics are exact,
                 * and the record is what keeps that visible. */
                s->type = SERVICE_TYPE_NOTIFY;
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: Type=notify-reload: no reload machinery, running as Type=notify",
                         path,
                         line);
                return unit_add_degradation(u, "Type=notify-reload");
        } else {
                /*
                 * Still a hard failure rather than a dropped directive:
                 * forking/dbus/idle each change *when* a service counts as
                 * started, so silently running one as simple would report
                 * the unit up before it actually is, and everything ordered
                 * After= it would then start too early. Refusing is safer.
                 */
                pico_log(PICO_LOG_ERR,
                         "%s:%u: Type=%s is not supported (simple, oneshot, exec, notify, notify-reload are), failing unit",
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

/*
 * User=/Group=: kept as written (a name or a numeric id) and resolved at
 * every spawn, in the parent (service-exec.c). Only the shape is checked
 * here: whether the account exists is a start-time question, and answering
 * it at load would make the unit tree's load order depend on the user
 * database. An empty value resets to unset, as in systemd.
 */
static int config_parse_user_group(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        char **field;
        const char *p;
        char *copy;

        if (!s)
                return 0;

        field = strcmp(lvalue, "User") == 0 ? &s->user : &s->group;

        if (!*rvalue) {
                *field = pico_mfree(*field);
                return 0;
        }

        for (p = rvalue; *p; p++)
                if ((unsigned char) *p <= ' ' || *p == 0x7f || *p == ':' || *p == '/') {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: invalid %s= value '%s', ignoring",
                                 path,
                                 line,
                                 lvalue,
                                 rvalue);
                        return 0;
                }

        copy = pico_strdup(rvalue);
        if (!copy)
                return -ENOMEM;

        pico_mfree(*field);
        *field = copy;
        return 0;
}

static int config_parse_exec_start(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        char **argv = NULL;
        int r;

        if (!s)
                return 0;

        /* Same non-fatal-per-directive policy as every other handler in this
         * file (Restart=, RestartSec=, ...): parse_exec_line() already logged
         * why, so just leave exec_start as it was rather than failing the
         * whole unit over one bad directive. A unit that ends up with no
         * ExecStart= at all is a validation problem, not a parse error --
         * not yet enforced (no post-load validation pass exists), tracked in
         * plans/29-pico-init.md. */
        r = parse_exec_line(u, path, line, lvalue, rvalue, &argv);
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

        if (!s)
                return 0;

        r = parse_exec_line(u, path, line, lvalue, rvalue, &argv);
        if (r < 0)
                return 0;

        if (s->exec_start_pre) {
                pico_log(PICO_LOG_DEBUG,
                         "%s:%u: multiple ExecStartPre= not supported, replacing "
                         "previous value",
                         path,
                         line);
                (void) unit_add_degradation(u, "ExecStartPre=multiple");
        }

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
 * "<n><suffix>" with suffix one of us/ms/s/min/m/h is also accepted, and so
 * is the literal spelling "infinity" (case-insensitive), which maps straight
 * to USEC_INFINITY. Compound spans ("1min 30s") aren't supported in this
 * MVP. The overflow check is an explicit bound comparison rather than the
 * round-trip cast idiom ((uint64_t)(size_t)v != v) that 31ef154f1
 * (2026-08-18, most recent fix in the whole quarry history) replaced for
 * being legally elidable by an optimizer -- built correctly from day one
 * instead of porting the fragile idiom.
 */
static int parse_usec(const char *rvalue, usec_t *ret) {
        char *end;
        unsigned long long v;
        usec_t scale = USEC_PER_SEC;

        if (strcasecmp(rvalue, "infinity") == 0) {
                *ret = USEC_INFINITY;
                return 0;
        }

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
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: invalid TimeoutStartSec= value '%s', ignoring",
                         path,
                         line,
                         rvalue);
                return 0;
        }

        /*
         * 92c1622e14/36c16a7cdd: TimeoutStartSec=0 means "never time out",
         * the opposite of RestartSec=0 ("restart immediately") -- do not
         * reuse this translation there.
         */
        if (s->timeout_start_usec == 0)
                s->timeout_start_usec = USEC_INFINITY;

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
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: invalid TimeoutStopSec= value '%s', ignoring",
                         path,
                         line,
                         rvalue);
                return 0;
        }

        /* 92c1622e14/36c16a7cdd: same zero-means-never translation as TimeoutStartSec= above */
        if (s->timeout_stop_usec == 0)
                s->timeout_stop_usec = USEC_INFINITY;

        return 0;
}

/* --- [Socket] handlers --- */

/* Targets/services are real unit types too, so a [Socket] directive on one
 * is a misplaced-directive warning rather than an impossible case, matching
 * unit_to_service()'s own shape above. */
static Socket *unit_to_socket(Unit *u, const char *path, unsigned line) {
        if (u->type != UNIT_SOCKET) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: [Socket] directive on a %s unit, ignoring",
                         path,
                         line,
                         unit_type_to_string(u->type));
                return NULL;
        }
        return SOCKET(u);
}

static void socket_port_append(Socket *s, SocketPort *p) {
        SocketPort **tail = &s->ports;

        while (*tail)
                tail = &(*tail)->next;

        *tail = p; /* tail-appended: fd order == declared Listen* order (H12) */
}

/*
 * "/path" -> AF_UNIX; a bare 1-65535 decimal -> a port, family resolved
 * later at bind time (629abfc23f -- see socket.c). Anything else is logged
 * and dropped, same non-fatal-per-directive policy as every other handler
 * in this file.
 */
static int config_parse_listen(Unit *u, const char *path, unsigned line, const char *rvalue, int type) {
        Socket *s = unit_to_socket(u, path, line);
        SocketPort *p;

        if (!s)
                return 0;

        p = calloc(1, sizeof(SocketPort));
        if (!p)
                return -ENOMEM;

        p->fd = -1;
        p->socket = s;
        p->type = type;

        if (rvalue[0] == '/') {
                if (strlen(rvalue) >= sizeof(((struct sockaddr_un *) 0)->sun_path)) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: socket path '%s' too long, ignoring",
                                 path,
                                 line,
                                 rvalue);
                        free(p);
                        return 0;
                }

                p->family = AF_UNIX;
                p->path = pico_strdup(rvalue);
                if (!p->path) {
                        free(p);
                        return -ENOMEM;
                }
        } else {
                char *end;
                unsigned long v;

                errno = 0;
                v = strtoul(rvalue, &end, 10);
                if (end == rvalue || *end != '\0' || errno == ERANGE || v == 0 || v > 65535) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: '%s' is neither an absolute path nor a port number, ignoring",
                                 path,
                                 line,
                                 rvalue);
                        free(p);
                        return 0;
                }

                p->family = AF_UNSPEC; /* resolved at bind time */
                p->port = (uint16_t) v;
        }

        socket_port_append(s, p);
        return 0;
}

static int config_parse_listen_stream(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        (void) lvalue;
        return config_parse_listen(u, path, line, rvalue, SOCK_STREAM);
}

static int config_parse_listen_datagram(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        (void) lvalue;
        return config_parse_listen(u, path, line, rvalue, SOCK_DGRAM);
}

static int config_parse_socket_service(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Socket *s = unit_to_socket(u, path, line);
        (void) lvalue;

        if (!s)
                return 0;

        if (!unit_name_is_valid(rvalue) || unit_type_from_name(rvalue) != UNIT_SERVICE) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: Service= value '%s' is not a valid service name, ignoring",
                         path,
                         line,
                         rvalue);
                return 0;
        }

        s->service_name = pico_mfree(s->service_name);
        s->service_name = pico_strdup(rvalue);
        return s->service_name ? 0 : -ENOMEM;
}

static int config_parse_socket_accept(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Socket *s = unit_to_socket(u, path, line);
        bool b;
        (void) lvalue;

        if (!s)
                return 0;

        if (parse_boolean_value(rvalue, &b) < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid Accept= value '%s', ignoring", path, line, rvalue);
                return 0;
        }

        s->accept = b;
        return 0;
}

static int config_parse_socket_mode(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Socket *s = unit_to_socket(u, path, line);
        char *end;
        unsigned long v;
        (void) lvalue;

        if (!s)
                return 0;

        errno = 0;
        v = strtoul(rvalue, &end, 8);
        if (end == rvalue || *end != '\0' || errno == ERANGE || v > 07777) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid SocketMode= value '%s', ignoring", path, line, rvalue);
                return 0;
        }

        s->socket_mode = (mode_t) v;
        return 0;
}

static int config_parse_socket_backlog(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Socket *s = unit_to_socket(u, path, line);
        char *end;
        long v;
        (void) lvalue;

        if (!s)
                return 0;

        errno = 0;
        v = strtol(rvalue, &end, 10);
        if (end == rvalue || *end != '\0' || errno == ERANGE || v <= 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid Backlog= value '%s', ignoring", path, line, rvalue);
                return 0;
        }

        s->backlog = (int) v;
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

        /* heap, not a VLA: rvalue comes from conf-scan.c's unbounded
         * getline(), the same stack-overflow hazard config_parse_unit_deps()
         * documents above */
        names = pico_strdup(rvalue);
        if (!names)
                return -ENOMEM;

        for (tok = strtok_r(names, " \t", &saveptr); tok; tok = strtok_r(NULL, " \t", &saveptr)) {
                char *expanded = NULL;
                int r;

                /* same name-safe, per-token expansion as config_parse_unit_deps() above */
                r = unit_name_printf(u, tok, &expanded);
                if (r < 0) {
                        pico_mfree(names);
                        return r;
                }

                if (!unit_name_is_valid(expanded)) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: '%s' is not a valid unit name, ignoring",
                                 path,
                                 line,
                                 expanded);
                        pico_mfree(expanded);
                        continue;
                }

                r = pico_strv_extend(target, expanded);
                pico_mfree(expanded);
                if (r < 0) {
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
        {    SECTION_UNIT,              "Description",                 config_parse_description },
        {    SECTION_UNIT,                 "Requires",                    config_parse_requires },
        {    SECTION_UNIT,                    "Wants",                       config_parse_wants },
        {    SECTION_UNIT,                   "Before",                      config_parse_before },
        {    SECTION_UNIT,                    "After",                       config_parse_after },
        {    SECTION_UNIT,      "ConditionPathExists",       config_parse_condition_path_exists },
        {    SECTION_UNIT, "ConditionPathIsDirectory", config_parse_condition_path_is_directory },
        { SECTION_SERVICE,                     "Type",                        config_parse_type },
        { SECTION_SERVICE,                "ExecStart",                  config_parse_exec_start },
        { SECTION_SERVICE,             "ExecStartPre",              config_parse_exec_start_pre },
        { SECTION_SERVICE,                  "Restart",                     config_parse_restart },
        { SECTION_SERVICE,               "RestartSec",                 config_parse_restart_sec },
        { SECTION_SERVICE,          "RemainAfterExit",           config_parse_remain_after_exit },
        { SECTION_SERVICE,          "TimeoutStartSec",           config_parse_timeout_start_sec },
        { SECTION_SERVICE,           "TimeoutStopSec",            config_parse_timeout_stop_sec },
        { SECTION_SERVICE,                     "User",                  config_parse_user_group },
        { SECTION_SERVICE,                    "Group",                  config_parse_user_group },
        {  SECTION_SOCKET,             "ListenStream",               config_parse_listen_stream },
        {  SECTION_SOCKET,           "ListenDatagram",             config_parse_listen_datagram },
        {  SECTION_SOCKET,                  "Service",              config_parse_socket_service },
        {  SECTION_SOCKET,                   "Accept",               config_parse_socket_accept },
        {  SECTION_SOCKET,               "SocketMode",                 config_parse_socket_mode },
        {  SECTION_SOCKET,                  "Backlog",              config_parse_socket_backlog },
        { SECTION_INSTALL,                 "WantedBy",                   config_parse_wanted_by },
        { SECTION_INSTALL,               "RequiredBy",                 config_parse_required_by },
};

/*
 * The conf-scan.h handler: dispatches one already-scanned assignment through
 * config_items[] and logs-and-drops anything not in it. `section` is NULL
 * for an assignment outside any [Section] header (conf-scan.c's contract);
 * everything else, known section or not, is decided here rather than by the
 * scanner -- an unrecognized [Section] simply never matches a config_items
 * row, so its directives fall through to the same debug-and-drop path a
 * recognized section's unknown directive would.
 */
static int unit_conf_handler(
                const char *path,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *userdata) {
        Unit *u = userdata;
        ConfigSection sec = SECTION_UNKNOWN;
        size_t i;

        if (!section) {
                pico_log(PICO_LOG_WARNING, "%s:%u: assignment outside any section, ignoring", path, line);
                return 0;
        }

        if (strcmp(section, "Unit") == 0)
                sec = SECTION_UNIT;
        else if (strcmp(section, "Service") == 0)
                sec = SECTION_SERVICE;
        else if (strcmp(section, "Socket") == 0)
                sec = SECTION_SOCKET;
        else if (strcmp(section, "Install") == 0)
                sec = SECTION_INSTALL;

        /* [Install] is no longer dropped wholesale: WantedBy=/RequiredBy= have
         * real backing fields and are in the table below. Everything else in
         * that section (Alias=, Also=, DefaultInstance=) still falls through
         * to the unknown-directive debug log below, which is the graceful
         * degradation the drop-in goal asks for. */

        for (i = 0; i < sizeof(config_items) / sizeof(config_items[0]); i++)
                if (config_items[i].section == sec && strcmp(config_items[i].lvalue, lvalue) == 0)
                        return config_items[i].parse(u, path, line, lvalue, rvalue);

        /* Still DEBUG per line -- the per-unit WARNING in unit_parse_file()
         * is what makes the drop visible; this line only keeps the file:line.
         * An empty name ("=value") is a malformed line, not a dropped
         * directive, so it is skipped rather than recorded. */
        pico_log(PICO_LOG_DEBUG, "%s:%u: unknown directive %s= in [%s], ignoring", path, line, lvalue, section);
        return *lvalue ? unit_add_degradation(u, lvalue) : 0;
}

int unit_parse_file(Unit *u, const char *path) {
        int r;

        if (!u || !path)
                return -EINVAL;

        r = pico_conf_scan(path, unit_conf_handler, u);

        /* One WARNING per unit, not one per directive: the record itself
         * carries the names, and a unit like iiotool's drops twenty. */
        if (r == 0 && u->n_degraded_directives > 0) {
                char *list = unit_degraded_directives_string(u);

                pico_log(PICO_LOG_WARNING,
                         "%s: %zu directive%s not implemented by pico-init dropped: %s",
                         u->id,
                         u->n_degraded_directives,
                         u->n_degraded_directives == 1 ? "" : "s",
                         list ? list : "(out of memory)");
                pico_mfree(list);
        }

        /*
         * B9/69339ae9f7/29500cf8c4/8688a389ca: load-time validation. Placed
         * here rather than in unit_load() (unit-load.c) because this is the
         * one function that already knows parsing succeeded and the fragment
         * is otherwise done with -- a unit that parses cleanly but never sets
         * ExecStart= is a validation problem, not a parse error, and must
         * still fail to load rather than silently becoming a service with
         * nothing to run.
         */
        if (r == 0 && u->type == UNIT_SERVICE)
                r = service_verify(SERVICE(u));
        else if (r == 0 && u->type == UNIT_SOCKET)
                /* Gated on r == 0 for the same reason as service_verify()
                 * above (75193d4128, see socket.c's header): this must never
                 * run against a stub or errored unit. */
                r = socket_verify_and_pair(SOCKET(u));

        return r;
}
