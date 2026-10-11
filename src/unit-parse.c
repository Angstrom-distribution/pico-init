/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * INI-style unit-file parser, quarried from systemd's ~2011-era
 * src/conf-parser.c + src/load-fragment.c (tag v30, commit 501c92c,
 * copyright 2010 Lennart Poettering, GPL-2.0-or-later). Only the directives
 * that service.h, socket.h and unit.h have fields for are implemented;
 * everything else is recognized as valid INI syntax and dropped at debug
 * level (and recorded as a degradation) rather than erroring, matching real
 * unit-file tolerance.
 *
 * The line-level scanner (getline loop, sections, comments, continuations,
 * BOM, key/value split) lives in conf-scan.c, shared with netd's `.network`
 * parser; see conf-scan.h. This file is the handler table and unit-file
 * semantics: unit_parse_file() drives pico_conf_scan() with
 * unit_conf_handler().
 *
 * Backported fixes (commit hashes from github.com/systemd/systemd). Seven
 * fixes are scanner properties and are cited in conf-scan.c with the code
 * that carries them (e6dde451a unbounded getline, 2d4fffb00
 * malformed-line-skip, 9adbfeb38+0ef695858 the comment-backslash/
 * blank-line-terminates pair, 4f29e0db1 unterminated-continuation flush,
 * 9dd7ea9a7 BOM skip, 8ea913b2e invalid-free, 91ffff962
 * free-old-section-before-replacing). The rest are unit-file value
 * semantics and stay here:
 *
 *  - 35b1078e1 "load-fragment: Don't assert() on invalid exec flags" --
 *    v30 hit assert(skip < l) on "ExecStart=- /bin/true" (a modifier
 *    separated from the path by whitespace) and aborted the manager. A
 *    malformed unit file must never be able to kill PID 1, so
 *    parse_exec_line() rejects that shape with a warning.
 *  - c853953658 "load-fragment: Rework config_parse_exec()" -- replaces
 *    the historical assert(path_is_absolute(path)) with an explicit
 *    validate-and-reject chain; parse_exec_line() follows that template.
 *  - a2a5291b3 / b2fadec60 "conf-parser: fix potentially bad memory
 *    accesses" -- an unterminated quote or trailing garbage after a
 *    closing quote was silently accepted; pico_extract_first_word() (util.c,
 *    shared with $VAR splitting at spawn time) rejects both.
 *  - 92c1622e14 / 36c16a7cdd -- TimeoutStartSec=/TimeoutStopSec= and
 *    RestartSec= have opposite zero-semantics upstream (0 means "never time
 *    out" for the former, "restart immediately" for the latter).
 *    parse_usec() also accepts the literal "infinity", and only the two
 *    Timeout*Sec= handlers translate a parsed 0 to USEC_INFINITY;
 *    config_parse_restart_sec() does not.
 *
 * Not backported: the UTF-8 validity/escaping fixes (b5d742138, 78d17fa09,
 * 9e6027783) -- no quoted-strv directive here needs them; the mtime-tracking
 * fixes (9fd8d678b, da46a1bc3) -- unit_parse_file() has no mtime out-param;
 * the ';'-multi-command ExecStart fixes (3851c51ad, 598c47c86) -- each
 * ExecStart= line is exactly one command.
 *
 * Specifier expansion (%i/%I/%n/%N/%p): config_parse_unit_deps() and
 * config_parse_install_names() expand per token through unit_name_printf()
 * (name-safe: no expansion can introduce whitespace or a '/'), and
 * parse_exec_line()/config_parse_description() expand through
 * unit_full_printf() (adds %I, which unescapes and so can). Not expanded:
 * config_parse_condition_path(), because v30 at this tag
 * (load-fragment.c:1584-1620) does not run specifier_printf() on a
 * condition value either; see that function's comment for the consequence.
 */

#include "unit.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h> /* snprintf, for the degradation record's name=qualifier form */
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp, for the boolean spellings */

#include "cgroups-v2.h"
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

/*
 * Parses one Exec*= value (ExecStart=, ExecStop=, ...) into a NULL-terminated argv.
 * Supports the "-" modifier (ignore exit status), stored via *ret_ignore for
 * the caller to keep on the command (v30 load-fragment.c:531-533 sets
 * ExecCommand.ignore the same way), only when it's not separated from the
 * path by whitespace; "ExecStart=- /bin/true" hit assert(skip < l) upstream
 * (35b1078e1) and is rejected with a warning. Other modifiers (@ + ! :) are
 * not supported and cause the whole directive to be rejected (c853953658's
 * validate-and-reject rework).
 */
static int
                parse_exec_line(Unit *u,
                                const char *path,
                                unsigned line,
                                const char *lvalue,
                                const char *rvalue,
                                char ***ret_argv,
                                bool *ret_ignore) {
        const char *p = rvalue;
        char **argv = NULL;
        char *word;
        int r;

        *ret_ignore = false;
        p += strspn(p, " \t");

        if (*p == '-' && p[1] != '\0' && p[1] != ' ' && p[1] != '\t') {
                p++; /* modifier glued to the path */
                *ret_ignore = true;
        } else if (*p == '-') {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: %s= modifier must not be "
                         "separated from the path by whitespace, ignoring",
                         path,
                         line,
                         lvalue);
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

        r = pico_extract_first_word(&p, &word);
        if (r <= 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: %s in %s=, ignoring",
                         path,
                         line,
                         r < 0 ? "malformed quoting" : "empty command line",
                         lvalue);
                return r < 0 ? r : -EINVAL;
        }

        /*
         * Expanded after pico_extract_first_word() and before the
         * absolute-path check, so the check judges the expanded path and a
         * %I that unescapes to something containing a space (e.g. an
         * instance "a\x20b") stays one argv element. v30 expands at spawn
         * time (unit_full_printf_strv() on the tokenized argv); this is the
         * same per-word expansion, done at parse time. $VAR expansion is the
         * spawn-time pass (service-exec.c) and runs on these already
         * %-expanded words, as in v30.
         */
        r = expand_word(u, &word);
        if (r < 0)
                return r;

        /*
         * c853953658's template, as modern systemd (since v239, 7c891d53b
         * "load-fragment: when parsing paths for Exec*=, be more liberal"):
         * a bare filename (no '/') is also accepted and resolved at exec time
         * (service-exec.c's find_in_default_path()). A relative path that
         * contains a '/' ("foo/bar") is rejected, as nothing can resolve it.
         * pico_exec_path_is_valid() is the shared test (also used by
         * service_verify()), including the trailing-'/' (directory) and
         * "."/".." cases.
         */
        if (!pico_exec_path_is_valid(word)) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: %s= path '%s' is neither an absolute path nor a plain "
                         "executable name, ignoring",
                         path,
                         line,
                         lvalue,
                         word);
                free(word);
                return -EINVAL;
        }

        r = pico_strv_extend(&argv, word);
        free(word);
        if (r < 0)
                return r;

        for (;;) {
                r = pico_extract_first_word(&p, &word);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: malformed quoting in %s=, ignoring",
                                 path,
                                 line,
                                 lvalue);
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

        /* Full table (%I included): a Description= is free text, so an
         * unescaped '/' corrupts nothing. */
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
         * Heap, not a VLA: rvalue comes from conf-scan.c's unbounded getline()
         * (e6dde451a), so a VLA sized by strlen(rvalue) would turn one long
         * Requires= line into a stack overflow (see the 35b1078e1 note at the
         * top of this file).
         */
        names = pico_strdup(rvalue);
        if (!names)
                return -ENOMEM;

        for (tok = strtok_r(names, " \t", &saveptr); tok; tok = strtok_r(NULL, " \t", &saveptr)) {
                Unit *other;
                char *expanded = NULL;
                int r;

                /*
                 * Per token, before validation: unit_name_printf()'s table
                 * (%n %N %p %i) cannot introduce whitespace, and expanding
                 * per word keeps that true if specifiers are added.
                 */
                r = unit_name_printf(u, tok, &expanded);
                if (r < 0) {
                        pico_mfree(names);
                        return r;
                }

                /*
                 * This token is concatenated into a search-path entry by
                 * unit_load(), so "Requires=../../tmp/evil.service" must be
                 * rejected before it becomes a path.
                 */
                if (!unit_name_is_valid(expanded)) {
                        /*
                         * A valid unit name of a type pico has no vtable for
                         * (.mount, .device, ...) is a compatibility gap, not a
                         * malformed directive: record it as a degradation
                         * (visible in picoctl show and pico-unit-lint).
                         */
                        if (unit_name_has_unsupported_type(expanded)) {
                                char what[UNIT_NAME_MAX + 32];

                                snprintf(what,
                                         sizeof(what),
                                         "%s=%s",
                                         unit_dependency_to_string(d),
                                         strrchr(expanded, '.'));
                                (void) unit_add_degradation(u, what);
                        }
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

                /* A single bad dependency (usually a self-dependency or OOM) is
                 * non-fatal to the rest of the unit, as in systemd. */
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

/*
 * Conflicts= records only the forward edge as written; unit_add_dependency()
 * adds the ConflictedBy= inverse on the peer. ConflictedBy= is not a
 * unit-file directive upstream either, so it has no config_items[] row.
 */
static int config_parse_conflicts(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        (void) lvalue;
        return config_parse_unit_deps(u, path, line, UNIT_CONFLICTS, rvalue);
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
 * must pass). An empty value resets the list, as upstream. A leading '!'
 * negates that one entry's result and is stripped before the path is stored;
 * the negation is recorded in the parallel *_negated array at the same
 * index, which unit_condition_test() consults.
 *
 * Triggering ('|') is dropped with a warning and a degradation rather than
 * returned as an error: a handler returning < 0 aborts the rest of the scan
 * (conf-scan.c) and leaves the unit UNIT_ERROR. The triggering condition is
 * therefore ignored, not honoured.
 *
 * Not specifier-expanded: v30 at this tag (load-fragment.c:1584-1620) does not
 * run specifier_printf() on this directive either (that came later
 * upstream), so a generic "serial-getty@.service" template cannot carry
 * "ConditionPathExists=/dev/%I". test-unit-parse.c pins this behaviour.
 */
static int config_parse_condition_path(
                Unit *u,
                const char *path,
                unsigned line,
                const char *lvalue,
                const char *rvalue,
                char ***target,
                bool **target_negated) {
        bool negated = false;
        size_t n;
        bool *new_negated;
        int r;

        if (rvalue[0] == '\0') {
                *target = pico_strv_free(*target);
                *target_negated = pico_mfree(*target_negated);
                return 0;
        }

        if (rvalue[0] == '|') {
                char what[64];

                pico_log(PICO_LOG_WARNING,
                         "%s:%u: %s=%s: triggering conditions are not supported, ignoring",
                         path,
                         line,
                         lvalue,
                         rvalue);
                snprintf(what, sizeof(what), "%s=%c", lvalue, rvalue[0]);
                return unit_add_degradation(u, what);
        }

        if (rvalue[0] == '!') {
                negated = true;
                rvalue++;
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

        n = pico_strv_length(*target);

        r = pico_strv_extend(target, rvalue);
        if (r < 0)
                return r;

        new_negated = realloc(*target_negated, (n + 1) * sizeof(bool));
        if (!new_negated)
                return -ENOMEM;

        new_negated[n] = negated;
        *target_negated = new_negated;

        return 0;
}

static int config_parse_condition_path_exists(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_condition_path(
                        u, path, line, lvalue, rvalue, &u->condition_path_exists, &u->condition_path_exists_negated);
}

static int config_parse_condition_path_is_directory(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_condition_path(
                        u,
                        path,
                        line,
                        lvalue,
                        rvalue,
                        &u->condition_path_is_directory,
                        &u->condition_path_is_directory_negated);
}

/* --- [Service] handlers --- */

/* A [Service] directive on a non-service unit is a misplaced-directive
 * warning. */
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
        else if (strcmp(rvalue, "forking") == 0)
                s->type = SERVICE_TYPE_FORKING;
        else if (strcmp(rvalue, "notify-reload") == 0) {
                /* notify-reload only adds a reload protocol over notify, and
                 * there is no reload verb for it to differ on; the degradation
                 * record keeps that visible. */
                s->type = SERVICE_TYPE_NOTIFY;
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: Type=notify-reload: no reload machinery, running as Type=notify",
                         path,
                         line);
                return unit_add_degradation(u, "Type=notify-reload");
        } else if (strcmp(rvalue, "dbus") == 0) {
                /*
                 * Readiness ("the name appeared on the system bus") cannot be
                 * observed: pico-init runs no bus. Running as simple is how
                 * avahi-daemon/bluetooth behaved before Type=dbus existed;
                 * refusing the unit would keep them from starting. BusName=
                 * falls through to the generic unknown-directive degradation.
                 */
                s->type = SERVICE_TYPE_SIMPLE;
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: Type=dbus: no system bus, running as Type=simple (BusName= readiness never "
                         "waited for)",
                         path,
                         line);
                return unit_add_degradation(u, "Type=dbus");
        } else if (strcmp(rvalue, "idle") == 0) {
                /* Real idle is simple with the start delayed until the job
                 * queue drains; the delay is not implemented. */
                s->type = SERVICE_TYPE_SIMPLE;
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: Type=idle: start-delay not implemented, running as Type=simple",
                         path,
                         line);
                return unit_add_degradation(u, "Type=idle");
        } else {
                /*
                 * A hard failure rather than a dropped directive: any other type
                 * changes *when* a service counts as started, so running it as
                 * simple would report the unit up too early and start
                 * everything ordered After= it too early.
                 */
                pico_log(PICO_LOG_ERR,
                         "%s:%u: Type=%s is not supported (simple, oneshot, exec, notify, notify-reload, forking, "
                         "dbus, idle are), failing unit",
                         path,
                         line,
                         rvalue);
                return -EINVAL;
        }

        return 0;
}

/*
 * StandardInput=socket (e.g. dropbear@.service) and tty/tty-force/tty-fail
 * (getty units, weston.service) are supported; see service.h's
 * ServiceStandardInput comment. A recognised value keeps "StandardInput" out
 * of the degraded-directives list that socket.c's socket_instance_refused()
 * checks; a tty-stdin Accept=yes instance is accepted and gets its connection
 * via LISTEN_FDS, as upstream. Any other value (null, file:, data, ...)
 * degrades.
 */
static int config_parse_standard_input(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        (void) lvalue;

        if (!s)
                return 0;

        if (strcmp(rvalue, "socket") == 0) {
                s->standard_input = SERVICE_STANDARD_INPUT_SOCKET;
                return 0;
        }
        if (strcmp(rvalue, "tty") == 0) {
                s->standard_input = SERVICE_STANDARD_INPUT_TTY;
                return 0;
        }
        if (strcmp(rvalue, "tty-force") == 0) {
                s->standard_input = SERVICE_STANDARD_INPUT_TTY_FORCE;
                return 0;
        }
        if (strcmp(rvalue, "tty-fail") == 0) {
                s->standard_input = SERVICE_STANDARD_INPUT_TTY_FAIL;
                return 0;
        }

        return unit_add_degradation(u, "StandardInput");
}

/*
 * StandardOutput= / StandardError=: inherit, journal (and the syslog and
 * +console spellings, which this treats as journal) and null; see
 * service.h's ServiceStdioOutput. Anything else is recorded as dropped.
 */
static int config_parse_standard_output(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        ServiceStdioOutput v;
        (void) path;
        (void) line;

        if (!s)
                return 0;

        if (strcmp(rvalue, "inherit") == 0)
                v = SERVICE_STDIO_OUTPUT_INHERIT;
        else if (strcmp(rvalue, "journal") == 0 || strcmp(rvalue, "journal+console") == 0 ||
                 strcmp(rvalue, "syslog") == 0 || strcmp(rvalue, "syslog+console") == 0)
                v = SERVICE_STDIO_OUTPUT_JOURNAL;
        else if (strcmp(rvalue, "null") == 0)
                v = SERVICE_STDIO_OUTPUT_NULL;
        else
                return unit_add_degradation(u, lvalue);

        if (strcmp(lvalue, "StandardError") == 0)
                s->standard_error = v;
        else
                s->standard_output = v;
        return 0;
}

/*
 * TTYPath=: full specifier table, since getty's TTYPath=/dev/%I needs %I's
 * unescaping. Unlike PIDFile=, a relative value is not anchored anywhere:
 * upstream's config_parse_unit_path_printf() logs and ignores it, so this
 * does the same and records the drop. An empty value resets to the
 * /dev/console default. Only consulted when StandardInput= is tty*.
 */
static int config_parse_tty_path(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        char *expanded = NULL;
        int r;
        (void) lvalue;

        if (!s)
                return 0;

        if (!*rvalue) {
                s->tty_path = pico_mfree(s->tty_path);
                return 0;
        }

        r = unit_full_printf(u, rvalue, &expanded);
        if (r < 0)
                return r;

        if (expanded[0] != '/') {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: TTYPath=%s is not an absolute path, ignoring",
                         path,
                         line,
                         expanded);
                pico_mfree(expanded);
                return unit_add_degradation(u, "TTYPath");
        }

        pico_mfree(s->tty_path);
        s->tty_path = expanded;
        return 0;
}

/*
 * systemd's own boolean spellings (parse_boolean() in src/basic/parse-util.c):
 * 1/yes/y/true/t/on and 0/no/n/false/f/off, case-insensitively; real unit
 * files use "RemainAfterExit=on" and "=true" alike.
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
 * PIDFile=: the full specifier table (a path, so %I's unescaped '/' is
 * wanted), and a relative value is taken under /run/ as systemd has done
 * since v237. Only the shape is checked here; the file is read after the
 * forking parent exits (service.c), never at load. An empty value resets.
 */
static int config_parse_pid_file(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        char *expanded = NULL;
        char *full;
        int r;
        (void) lvalue;

        if (!s)
                return 0;

        if (!*rvalue) {
                s->pid_file = pico_mfree(s->pid_file);
                return 0;
        }

        r = unit_full_printf(u, rvalue, &expanded);
        if (r < 0)
                return r;

        if (expanded[0] == '/')
                full = expanded;
        else {
                size_t len = strlen(expanded) + sizeof("/run/");

                full = malloc(len);
                if (!full) {
                        pico_mfree(expanded);
                        return -ENOMEM;
                }
                snprintf(full, len, "/run/%s", expanded);
                pico_mfree(expanded);
        }

        pico_mfree(s->pid_file);
        s->pid_file = full;
        return 0;
}

/*
 * Delegate= takes a boolean or a list of controller names. pico-init always
 * leaves a unit's cgroup subtree to the unit, so a list reads as "yes" and the
 * names are not used; what the flag adds is ownership of the cgroup for a
 * User= service. An empty assignment resets it, as in systemd.
 */
static int config_parse_delegate(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        const char *p;
        unsigned mask = 0;
        bool b;
        (void) lvalue;

        if (!s)
                return 0;

        /* As modern systemd: an empty assignment delegates with no controllers
         * (systemd-udevd.service relies on it), "yes" names every controller
         * it can delegate, "no" undoes either. */
        if (rvalue[0] == '\0') {
                s->delegate = true;
                s->delegate_controllers = 0;
                return 0;
        }

        if (parse_boolean_value(rvalue, &b) == 0) {
                s->delegate = b;
                s->delegate_controllers = b ? SERVICE_DELEGATE_ALL : 0;
                return 0;
        }

        for (p = rvalue; *p; p++)
                if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' ||
                      *p == ' ')) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: invalid Delegate= value '%s', ignoring",
                                 path,
                                 line,
                                 rvalue);
                        return 0;
                }

        /* Controllers pico-init has no name for (bpf-*, ...) are skipped. */
        for (p = rvalue; *p;) {
                char word[16];
                size_t n = strcspn(p, " ");

                if (n > 0 && n < sizeof(word)) {
                        memcpy(word, p, n);
                        word[n] = '\0';
                        mask |= service_delegate_controller_from_string(word);
                }
                p += n;
                p += strspn(p, " ");
        }

        s->delegate = true;
        s->delegate_controllers = mask;
        return 0;
}

static int config_parse_delegate_subgroup(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        char *copy;
        (void) lvalue;

        if (!s)
                return 0;

        if (rvalue[0] == '\0') {
                s->delegate_subgroup = pico_mfree(s->delegate_subgroup);
                return 0;
        }

        if (!cgroup_v2_subgroup_name_valid(rvalue)) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: invalid DelegateSubgroup= value '%s', ignoring",
                         path,
                         line,
                         rvalue);
                return 0;
        }

        copy = pico_strdup(rvalue);
        if (!copy)
                return -ENOMEM;

        free(s->delegate_subgroup);
        s->delegate_subgroup = copy;
        return 0;
}

static int config_parse_guess_main_pid(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        bool b;
        (void) lvalue;

        if (!s)
                return 0;

        if (parse_boolean_value(rvalue, &b) < 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: invalid GuessMainPID= value '%s', ignoring",
                         path,
                         line,
                         rvalue);
                return 0;
        }

        s->guess_main_pid = b;
        return 0;
}

/*
 * Shape-only check shared by User=/Group= and SupplementaryGroups=: no
 * control character, no ':' (/etc/passwd's field separator) and no '/'.
 * Whether the account or group exists is a start-time question (NSS, or the
 * user database not being available yet); upstream's valid_user_group_name()
 * in config_parse_user_group_strv_compat() is also a syntax check only.
 */
static bool user_group_token_is_valid(const char *p) {
        for (; *p; p++)
                if ((unsigned char) *p <= ' ' || *p == 0x7f || *p == ':' || *p == '/')
                        return false;

        return true;
}

/*
 * User=/Group=: kept as written (a name or a numeric id) and resolved at
 * every spawn, in the parent (service-exec.c). An empty value resets to
 * unset, as in systemd.
 */
static int config_parse_user_group(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        char **field;
        char *copy;

        if (!s)
                return 0;

        field = strcmp(lvalue, "User") == 0 ? &s->user : &s->group;

        if (!*rvalue) {
                *field = pico_mfree(*field);
                return 0;
        }

        if (!user_group_token_is_valid(rvalue)) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
                return 0;
        }

        copy = pico_strdup(rvalue);
        if (!copy)
                return -ENOMEM;

        pico_mfree(*field);
        *field = copy;
        return 0;
}

/*
 * SupplementaryGroups=: a whitespace-separated list of names/numeric gids,
 * %-expanded per word like Environment= above, each checked with the same
 * shape rule as User=/Group=. A bad token is skipped with a warning rather
 * than rejecting the whole line (as Environment= does; upstream rejects the
 * directive). Accumulates across repeated lines, as upstream; resolution to
 * a gid_t, combined with User=/Group=, happens at spawn time in
 * exec_creds_resolve() (service-exec.c). An empty rvalue resets the list.
 */
static int config_parse_supplementary_groups(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        const char *p = rvalue;
        char *word;
        int r;

        (void) lvalue;

        if (!s)
                return 0;

        if (rvalue[0] == '\0') {
                s->supplementary_groups = pico_strv_free(s->supplementary_groups);
                return 0;
        }

        for (;;) {
                r = pico_extract_first_word(&p, &word);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: malformed quoting in SupplementaryGroups=, ignoring",
                                 path,
                                 line);
                        return 0;
                }
                if (r == 0)
                        break;

                r = expand_word(u, &word);
                if (r < 0)
                        return r;

                if (!user_group_token_is_valid(word)) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: invalid SupplementaryGroups= entry '%s', ignoring",
                                 path,
                                 line,
                                 word);
                        free(word);
                        continue;
                }

                r = pico_strv_extend(&s->supplementary_groups, word);
                free(word);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int config_parse_exec_start(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        char **argv = NULL;
        bool ignore = false;
        int r;

        if (!s)
                return 0;

        /* Non-fatal per directive, like every other handler here:
         * parse_exec_line() already logged why, so leave exec_start as it was.
         * A unit with no ExecStart= at all is caught by service_verify(). */
        r = parse_exec_line(u, path, line, lvalue, rvalue, &argv, &ignore);
        if (r < 0)
                return 0;

        if (s->exec_start) {
                pico_log(PICO_LOG_DEBUG,
                         "%s:%u: multiple ExecStart= not supported, replacing "
                         "previous value",
                         path,
                         line);
                (void) unit_add_degradation(u, "ExecStart=multiple");
        }

        s->exec_start = pico_strv_free(s->exec_start);
        s->exec_start = argv;
        s->exec_start_ignore = ignore;
        return 0;
}

/* Upstream's list semantics, unlike ExecStart= above: every ExecStop= line
 * appends, and an empty one resets whatever came before it. */
static int config_parse_exec_stop(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        ServiceExecCommand *cmds;
        char **argv = NULL;
        bool ignore = false;
        int r;

        if (!s)
                return 0;

        if (rvalue[strspn(rvalue, " \t")] == '\0') {
                service_exec_stop_clear(s);
                return 0;
        }

        r = parse_exec_line(u, path, line, lvalue, rvalue, &argv, &ignore);
        if (r < 0)
                return 0;

        cmds = realloc(s->exec_stop, (s->n_exec_stop + 1) * sizeof(*cmds));
        if (!cmds) {
                pico_strv_free(argv);
                return -ENOMEM;
        }

        cmds[s->n_exec_stop].argv = argv;
        cmds[s->n_exec_stop].ignore = ignore;
        s->exec_stop = cmds;
        s->n_exec_stop++;
        return 0;
}

/* ExecStop='s list semantics for any other command list: each line appends,
 * an empty value resets the list. */
static int
                parse_exec_list(Unit *u,
                                const char *path,
                                unsigned line,
                                const char *lvalue,
                                const char *rvalue,
                                ServiceExecCommand **list,
                                unsigned *n) {
        ServiceExecCommand *cmds;
        char **argv = NULL;
        bool ignore = false;
        int r;

        if (rvalue[strspn(rvalue, " \t")] == '\0') {
                service_exec_commands_free(list, n);
                return 0;
        }

        r = parse_exec_line(u, path, line, lvalue, rvalue, &argv, &ignore);
        if (r < 0)
                return 0;

        cmds = realloc(*list, (*n + 1) * sizeof(*cmds));
        if (!cmds) {
                pico_strv_free(argv);
                return -ENOMEM;
        }

        cmds[*n].argv = argv;
        cmds[*n].ignore = ignore;
        *list = cmds;
        (*n)++;
        return 0;
}

static int config_parse_exec_start_pre(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);

        if (!s)
                return 0;

        return parse_exec_list(u, path, line, lvalue, rvalue, &s->exec_start_pre, &s->n_exec_start_pre);
}

static int config_parse_exec_condition(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);

        if (!s)
                return 0;

        return parse_exec_list(u, path, line, lvalue, rvalue, &s->exec_condition, &s->n_exec_condition);
}

static int config_parse_exec_stop_post(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);

        if (!s)
                return 0;

        return parse_exec_list(u, path, line, lvalue, rvalue, &s->exec_stop_post, &s->n_exec_stop_post);
}

/* Stored for whatever later asks one unit to reload, and a degradation until
 * then: nothing in pico-init runs it, and picoctl show and pico-unit-lint
 * must keep saying so. */
static int config_parse_exec_reload(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        int r;

        if (!s)
                return 0;

        r = parse_exec_list(u, path, line, lvalue, rvalue, &s->exec_reload, &s->n_exec_reload);
        if (r < 0)
                return r;

        if (s->n_exec_reload > 0)
                (void) unit_add_degradation(u, "ExecReload");
        return 0;
}

/*
 * Environment=. Tokenized with the same pico_extract_first_word() ExecStart=
 * uses, so quoting is identical: Environment="FOO=a b" is one word. Each word
 * is then %-expanded individually through expand_word(), as in
 * parse_exec_line(). A word with no '=' or an empty name is warned about and
 * skipped (v30 stored it unchecked). An empty rvalue resets the list.
 */
static int config_parse_environment(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        const char *p = rvalue;
        char *word;
        int r;

        (void) lvalue;

        if (!s)
                return 0;

        if (rvalue[0] == '\0') {
                s->environment = pico_strv_free(s->environment);
                return 0;
        }

        for (;;) {
                r = pico_extract_first_word(&p, &word);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: malformed quoting in Environment=, ignoring",
                                 path,
                                 line);
                        return 0;
                }
                if (r == 0)
                        break;

                r = expand_word(u, &word);
                if (r < 0)
                        return r;

                if (!strchr(word, '=') || word[0] == '=') {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: Environment=%s is not a valid assignment, ignoring",
                                 path,
                                 line,
                                 word);
                        free(word);
                        continue;
                }

                r = pico_strv_extend(&s->environment, word);
                free(word);
                if (r < 0)
                        return r;
        }

        return 0;
}

/*
 * EnvironmentFile=. Unlike Environment=, the whole rvalue is one path:
 * %-expanded as a single value (v30 does the same), not tokenized. An
 * optional leading '-' (missing file is not an error) is kept in the stored
 * string so the spawn-time loader sees it; what follows it must be absolute.
 * Accumulates like Environment=, and an empty rvalue resets the list.
 */
static int config_parse_environment_file(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        char *expanded = NULL;
        const char *check;
        int r;

        (void) lvalue;

        if (!s)
                return 0;

        if (rvalue[0] == '\0') {
                s->environment_files = pico_strv_free(s->environment_files);
                return 0;
        }

        r = unit_full_printf(u, rvalue, &expanded);
        if (r < 0)
                return r;

        check = expanded;
        if (check[0] == '-')
                check++;

        if (check[0] != '/') {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: EnvironmentFile= path '%s' is not absolute, ignoring",
                         path,
                         line,
                         expanded);
                free(expanded);
                return 0;
        }

        r = pico_strv_extend(&s->environment_files, expanded);
        free(expanded);
        return r;
}

/*
 * All seven upstream Restart= values map exactly, so none records a
 * degradation. service_shall_restart() (service.c) decides what each one
 * restarts on. on-watchdog parses but can never fire, as there is no
 * per-service watchdog; WatchdogSec='s degradation is the visible marker, as
 * upstream treats on-watchdog on a unit without WatchdogSec=. Type=oneshot
 * with always or on-success is refused later by service_verify(), not here.
 */
static int config_parse_restart(Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Service *s = unit_to_service(u, path, line);
        ServiceRestart r;
        (void) lvalue;

        if (!s)
                return 0;

        for (r = 0; r < _SERVICE_RESTART_MAX; r++)
                if (strcmp(rvalue, service_restart_to_string(r)) == 0) {
                        s->restart = r;
                        return 0;
                }

        pico_log(PICO_LOG_WARNING, "%s:%u: Restart=%s not recognized, defaulting to 'no'", path, line, rvalue);
        s->restart = SERVICE_RESTART_NO;
        return 0;
}

/*
 * Minimal time-span parser: a plain integer is seconds; a single
 * "<n><suffix>" with suffix one of us/ms/s/min/m/h is also accepted, and so
 * is the literal spelling "infinity" (case-insensitive), which maps straight
 * to USEC_INFINITY. Compound spans ("1min 30s") are not supported. The
 * overflow check is an explicit bound comparison, not the round-trip cast
 * idiom ((uint64_t)(size_t)v != v), which an optimizer may legally elide.
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
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid RestartSec= value '%s', ignoring", path, line, rvalue);
                (void) unit_add_degradation(u, "RestartSec=");
        }
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
                (void) unit_add_degradation(u, "TimeoutStartSec=");
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
                (void) unit_add_degradation(u, "TimeoutStopSec=");
                return 0;
        }

        /* 92c1622e14/36c16a7cdd: same zero-means-never translation as TimeoutStartSec= above */
        if (s->timeout_stop_usec == 0)
                s->timeout_stop_usec = USEC_INFINITY;

        return 0;
}

/* --- [Socket] handlers --- */

/* A [Socket] directive on a non-socket unit is a misplaced-directive
 * warning, as in unit_to_service(). */
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

        *tail = p; /* tail-appended: fd order == declared Listen* order */
}

/*
 * "/path" -> AF_UNIX; a bare 1-65535 decimal -> a port, family resolved
 * later at bind time (629abfc23f -- see socket.c). Anything else is logged
 * and dropped (non-fatal per directive, like every other handler here).
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

/* Only consulted under Accept=yes. v30 refuses a unit with a zero value at
 * verify time; rejecting it here keeps the default instead. */
static int config_parse_socket_max_connections(
                Unit *u, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        Socket *s = unit_to_socket(u, path, line);
        char *end;
        long v;
        (void) lvalue;

        if (!s)
                return 0;

        errno = 0;
        v = strtol(rvalue, &end, 10);
        if (end == rvalue || *end != '\0' || errno == ERANGE || v <= 0 || (long) (unsigned) v != v) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: invalid MaxConnections= value '%s', ignoring",
                         path,
                         line,
                         rvalue);
                return 0;
        }

        s->max_connections = (unsigned) v;
        return 0;
}

/* --- [Install] handlers --- */

/*
 * WantedBy=/RequiredBy= are stored as raw names, not resolved into edges here:
 * the named target may not be loaded yet, and whether they are honoured
 * depends on enablement (a .wants/ symlink or a preset rule), which cannot be
 * decided until every fragment has been read. unit-enable.c turns them into
 * edges later, or does not.
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
        {    SECTION_UNIT,                "Conflicts",                   config_parse_conflicts },
        {    SECTION_UNIT,      "ConditionPathExists",       config_parse_condition_path_exists },
        {    SECTION_UNIT, "ConditionPathIsDirectory", config_parse_condition_path_is_directory },
        { SECTION_SERVICE,                     "Type",                        config_parse_type },
        { SECTION_SERVICE,            "StandardInput",              config_parse_standard_input },
        { SECTION_SERVICE,           "StandardOutput",             config_parse_standard_output },
        { SECTION_SERVICE,            "StandardError",             config_parse_standard_output },
        { SECTION_SERVICE,                  "TTYPath",                    config_parse_tty_path },
        { SECTION_SERVICE,                "ExecStart",                  config_parse_exec_start },
        { SECTION_SERVICE,             "ExecStartPre",              config_parse_exec_start_pre },
        { SECTION_SERVICE,                 "ExecStop",                   config_parse_exec_stop },
        { SECTION_SERVICE,             "ExecStopPost",              config_parse_exec_stop_post },
        { SECTION_SERVICE,            "ExecCondition",              config_parse_exec_condition },
        { SECTION_SERVICE,               "ExecReload",                 config_parse_exec_reload },
        { SECTION_SERVICE,              "Environment",                 config_parse_environment },
        { SECTION_SERVICE,          "EnvironmentFile",            config_parse_environment_file },
        { SECTION_SERVICE,                  "Restart",                     config_parse_restart },
        { SECTION_SERVICE,               "RestartSec",                 config_parse_restart_sec },
        { SECTION_SERVICE,          "RemainAfterExit",           config_parse_remain_after_exit },
        { SECTION_SERVICE,                 "Delegate",                    config_parse_delegate },
        { SECTION_SERVICE,         "DelegateSubgroup",           config_parse_delegate_subgroup },
        { SECTION_SERVICE,          "TimeoutStartSec",           config_parse_timeout_start_sec },
        { SECTION_SERVICE,           "TimeoutStopSec",            config_parse_timeout_stop_sec },
        { SECTION_SERVICE,                     "User",                  config_parse_user_group },
        { SECTION_SERVICE,                    "Group",                  config_parse_user_group },
        { SECTION_SERVICE,      "SupplementaryGroups",        config_parse_supplementary_groups },
        { SECTION_SERVICE,                  "PIDFile",                    config_parse_pid_file },
        { SECTION_SERVICE,             "GuessMainPID",              config_parse_guess_main_pid },
        {  SECTION_SOCKET,             "ListenStream",               config_parse_listen_stream },
        {  SECTION_SOCKET,           "ListenDatagram",             config_parse_listen_datagram },
        {  SECTION_SOCKET,                  "Service",              config_parse_socket_service },
        {  SECTION_SOCKET,                   "Accept",               config_parse_socket_accept },
        {  SECTION_SOCKET,               "SocketMode",                 config_parse_socket_mode },
        {  SECTION_SOCKET,                  "Backlog",              config_parse_socket_backlog },
        {  SECTION_SOCKET,           "MaxConnections",      config_parse_socket_max_connections },
        { SECTION_INSTALL,                 "WantedBy",                   config_parse_wanted_by },
        { SECTION_INSTALL,               "RequiredBy",                 config_parse_required_by },
};

/*
 * The conf-scan.h handler: dispatches one already-scanned assignment through
 * config_items[] and logs-and-drops anything not in it. `section` is NULL
 * for an assignment outside any [Section] header (conf-scan.c's contract).
 * An unrecognized [Section] never matches a config_items row, so its
 * directives take the same debug-and-drop path as an unknown directive in a
 * known section.
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

        /* In [Install] only WantedBy=/RequiredBy= are implemented; Alias=,
         * Also= and DefaultInstance= fall through to the unknown-directive
         * debug log below. */

        for (i = 0; i < sizeof(config_items) / sizeof(config_items[0]); i++)
                if (config_items[i].section == sec && strcmp(config_items[i].lvalue, lvalue) == 0)
                        return config_items[i].parse(u, path, line, lvalue, rvalue);

        /* DEBUG per line; the per-unit WARNING in unit_parse_file() makes the
         * drop visible and this line keeps the file:line. An empty name
         * ("=value") is a malformed line, not a dropped directive, so it is
         * not recorded. */
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
         * 69339ae9f7/29500cf8c4/8688a389ca: load-time validation, here because
         * this is where parsing is known to have succeeded. A unit that parses
         * cleanly but never sets ExecStart= must still fail to load rather
         * than become a service with nothing to run.
         */
        if (r == 0 && u->type == UNIT_SERVICE)
                r = service_verify(SERVICE(u));
        else if (r == 0 && u->type == UNIT_SOCKET)
                /* Gated on r == 0 like service_verify() above (75193d4128, see
                 * socket.c's header): never run against a stub or errored
                 * unit. */
                r = socket_verify_and_pair(SOCKET(u));

        return r;
}
