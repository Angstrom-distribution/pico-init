/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Fixture-driven test for unit-parse.c: real unit files on disk in, parsed
 * fields and tolerated errors out.
 *
 * This closes the last item on the §7 unit-test list. Two things had covered
 * parts of it and neither covered this. The line-level scanner moved into
 * conf-scan.c and is genuinely shared with netd's `.network` parser, so
 * test-netd-network.c's 30MB single-token line does exercise the unbounded
 * getline() path -- but it reaches it through netd's own
 * config_parse_match_name(), never through unit-parse.c. The VLA that actually
 * crashed was in config_parse_unit_deps() here, on the unit-file side of that
 * seam, and nothing committed had ever run a long line through it. And every
 * other PID1 test writes unit files only as a means to an end: they assert
 * about jobs, ordering, supervision and boot, so a directive silently parsed
 * into the wrong field would pass all of them as long as the unit loaded.
 *
 * So the rule here is that every assertion is about the parser's own output --
 * the fields on the Unit and the Service -- and about what it does with input
 * it should refuse.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "manager.h"
#include "service.h"
#include "test-util.h"
#include "unit.h"
#include "util.h"

static Manager *manager_for(const char *dir) {
        const char * const path[] = { dir, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT(manager_set_unit_path(m, path), 0);

        return m;
}

static const char *basename_of(const char *path) {
        const char *slash = strrchr(path, '/');

        return slash ? slash + 1 : path;
}

/* Load one fixture file and hand back the unit it produced. */
static Unit *load_one(Manager *m, const char *id) {
        Unit *u;

        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        u = manager_get_unit(m, id);
        ASSERT_TRUE(u != NULL);

        return u;
}

/*
 * The straightforward half: a service fragment using every directive the
 * parser actually has a field for, asserted field by field.
 *
 * The two zero-semantics cases are the point of doing it this way rather than
 * "it loaded, good enough". TimeoutStartSec=0 means never time out and
 * RestartSec=0 means restart immediately -- opposite meanings for the same
 * literal, which is a real upstream trap (92c1622e14/36c16a7cdd) and exactly
 * the kind of thing that is invisible until a unit behaves the other way round
 * on a board.
 */
static void test_service_fields(void) {
        Service *s;
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "a.service",
                                      "[Unit]\n"
                                      "Description=A test service\n"
                                      "\n"
                                      "[Service]\n"
                                      "Type=oneshot\n"
                                      "RemainAfterExit=yes\n"
                                      "ExecStartPre=/bin/true --pre\n"
                                      "ExecStart=/bin/echo hello world\n"
                                      "Restart=on-failure\n"
                                      "RestartSec=0\n"
                                      "TimeoutStartSec=0\n"
                                      "TimeoutStopSec=30\n"
                                      "\n"
                                      "[Install]\n"
                                      "WantedBy=multi-user.target\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "a.service");
        s = (Service *) u;

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->description, "A test service");
        ASSERT_TRUE(u->fragment_path != NULL);

        ASSERT_EQ_INT(s->type, SERVICE_TYPE_ONESHOT);
        ASSERT_TRUE(s->remain_after_exit);

        ASSERT_TRUE(s->exec_start_pre != NULL);
        ASSERT_STREQ(s->exec_start_pre[0], "/bin/true");
        ASSERT_STREQ(s->exec_start_pre[1], "--pre");
        ASSERT_TRUE(s->exec_start_pre[2] == NULL);

        ASSERT_TRUE(s->exec_start != NULL);
        ASSERT_STREQ(s->exec_start[0], "/bin/echo");
        ASSERT_STREQ(s->exec_start[1], "hello");
        ASSERT_STREQ(s->exec_start[2], "world");
        ASSERT_TRUE(s->exec_start[3] == NULL);

        ASSERT_EQ_INT(s->restart, SERVICE_RESTART_ON_FAILURE);

        /* RestartSec=0 is "immediately", so it stays 0 ... */
        ASSERT_TRUE(s->restart_usec == 0);
        /* ... while TimeoutStartSec=0 is "never", which is USEC_INFINITY. */
        ASSERT_TRUE(s->timeout_start_usec == USEC_INFINITY);
        ASSERT_TRUE(s->timeout_stop_usec == 30 * USEC_PER_SEC);

        /* [Install] is kept as raw names -- resolving it is unit-enable.c's
         * job, and at parse time the named target may not exist yet. */
        ASSERT_TRUE(u->wanted_by != NULL);
        ASSERT_STREQ(u->wanted_by[0], "multi-user.target");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Drop-in compatibility, which is a decided goal of this project rather than a
 * nicety: an unmodified upstream unit file is full of directives pico-init has
 * no field for, and every one of them must be accepted as valid syntax and
 * dropped, never error the unit out.
 */
static void test_unknown_directives_are_tolerated(void) {
        Service *s;
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "b.service",
                                      "[Unit]\n"
                                      "Description=B\n"
                                      "ConditionPathExists=/etc/nonexistent\n"
                                      "AssertPathIsDirectory=/var\n"
                                      "OnFailure=rescue.target\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"
                                      "PrivateTmp=yes\n"
                                      "ProtectSystem=strict\n"
                                      "NoNewPrivileges=yes\n"
                                      "CPUQuota=20%\n"
                                      "BusName=org.example.Thing\n"
                                      "\n"
                                      "[Slice]\n"
                                      "MemoryMax=64M\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "b.service");
        s = (Service *) u;

        /* Loaded, not errored -- including the entirely unknown [Slice]
         * section, which must be skipped as a section rather than making its
         * contents look like [Service] keys. */
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->description, "B");
        ASSERT_STREQ(s->exec_start[0], "/bin/true");

        /* Tolerated is not the same as silent: every drop is on the record,
         * in file order, the unknown [Slice] section's directive included. */
        ASSERT_EQ_INT(u->n_degraded_directives, 8);
        ASSERT_STREQ(u->degraded_directives[0], "AssertPathIsDirectory");
        ASSERT_STREQ(u->degraded_directives[1], "OnFailure");
        ASSERT_STREQ(u->degraded_directives[2], "PrivateTmp");
        ASSERT_STREQ(u->degraded_directives[3], "ProtectSystem");
        ASSERT_STREQ(u->degraded_directives[4], "NoNewPrivileges");
        ASSERT_STREQ(u->degraded_directives[5], "CPUQuota");
        ASSERT_STREQ(u->degraded_directives[6], "BusName");
        ASSERT_STREQ(u->degraded_directives[7], "MemoryMax");
        ASSERT_TRUE(u->degraded_directives[8] == NULL);
        ASSERT_EQ_INT(manager_count_degraded_units(m), 1);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The degradation record on a directive-rich real-world shape: the value-
 * level drops (a triggering condition, an ExecStart= modifier, a second
 * ExecStartPre=) are recorded under name=qualifier, repeats collapse, and a
 * unit pico-init honours in full carries no record at all.
 */
static void test_degradation_record(void) {
        Manager *m;
        char *dir;
        char *joined;
        Unit *u, *clean;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "rich.service",
                                      "[Unit]\n"
                                      "Description=Rich\n"
                                      "ConditionPathExists=|/etc/skip\n"
                                      "After=clean.service\n"
                                      "\n"
                                      "[Service]\n"
                                      "Type=simple\n"
                                      "EnvironmentFile=-/etc/default/rich\n"
                                      "Environment=A=1\n"
                                      "Environment=B=2\n"
                                      "ExecStartPre=/bin/true one\n"
                                      "ExecStartPre=/bin/true two\n"
                                      "ExecStart=@/usr/bin/richd richd\n"
                                      "ExecStart=/usr/bin/richd\n"
                                      "ExecStop=/usr/bin/richd --stop\n"
                                      "ExecReload=/bin/kill -HUP $MAINPID\n"
                                      "PIDFile=/run/richd.pid\n"
                                      "User=rich\n"
                                      "Group=rich\n"
                                      "\n"
                                      "[Install]\n"
                                      "WantedBy=multi-user.target\n"
                                      "Alias=r.service\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "clean.service",
                                      "[Unit]\n"
                                      "Description=Clean\n"
                                      "ConditionPathExists=/etc\n"
                                      "\n"
                                      "[Service]\n"
                                      "Type=oneshot\n"
                                      "ExecStartPre=/bin/true\n"
                                      "ExecStart=/bin/true\n"
                                      "\n"
                                      "[Install]\n"
                                      "WantedBy=multi-user.target\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "rich.service");
        clean = manager_get_unit(m, "clean.service");
        ASSERT_TRUE(clean != NULL);

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(((Service *) u)->exec_start[0], "/usr/bin/richd");

        /* User=/Group= are honoured, not dropped: parsed verbatim here,
         * resolved to ids at spawn (test-service.c proves the drop). */
        ASSERT_STREQ(((Service *) u)->user, "rich");
        ASSERT_STREQ(((Service *) u)->group, "rich");

        /* PIDFile= likewise: stored for Type=forking, never a drop. */
        ASSERT_STREQ(((Service *) u)->pid_file, "/run/richd.pid");

        /* EnvironmentFile=/Environment= are parsed and stored now (E1), not
         * degraded -- see test_environment_directives() for their own
         * dedicated coverage. */
        ASSERT_STREQ(((Service *) u)->environment_files[0], "-/etc/default/rich");
        ASSERT_TRUE(((Service *) u)->environment_files[1] == NULL);
        ASSERT_STREQ(((Service *) u)->environment[0], "A=1");
        ASSERT_STREQ(((Service *) u)->environment[1], "B=2");
        ASSERT_TRUE(((Service *) u)->environment[2] == NULL);

        ASSERT_EQ_INT(u->n_degraded_directives, 6);
        ASSERT_STREQ(u->degraded_directives[0], "ConditionPathExists=|");
        ASSERT_STREQ(u->degraded_directives[1], "ExecStartPre=multiple");
        ASSERT_STREQ(u->degraded_directives[2], "ExecStart=@");
        ASSERT_STREQ(u->degraded_directives[3], "ExecStop");
        ASSERT_STREQ(u->degraded_directives[4], "ExecReload");
        ASSERT_STREQ(u->degraded_directives[5], "Alias");
        ASSERT_TRUE(u->degraded_directives[6] == NULL);

        joined = unit_degraded_directives_string(u);
        ASSERT_STREQ(joined,
                     "ConditionPathExists=| ExecStartPre=multiple "
                     "ExecStart=@ ExecStop ExecReload Alias");
        free(joined);

        /* a second identical drop is not a second entry */
        ASSERT_EQ_INT(unit_add_degradation(u, "Alias"), 0);
        ASSERT_EQ_INT(u->n_degraded_directives, 6);

        ASSERT_EQ_INT(clean->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(clean->n_degraded_directives, 0);
        ASSERT_TRUE(clean->degraded_directives == NULL);
        joined = unit_degraded_directives_string(clean);
        ASSERT_STREQ(joined, "");
        free(joined);

        /* the boot summary counts units, not directives, and logs once */
        ASSERT_EQ_INT(manager_count_degraded_units(m), 1);
        ASSERT_TRUE(!m->degradation_summary_logged);
        manager_log_degradation_summary(m);
        ASSERT_TRUE(m->degradation_summary_logged);
        manager_log_degradation_summary(m);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * E0: a second, independently-valid ExecStart= line still replaces the
 * first (no command list exists to run both), but that replacement is now
 * visible in the degradation record -- config_parse_exec_start() mirrors
 * config_parse_exec_start_pre()'s existing "multiple ... not supported"
 * pattern instead of silently dropping the first value with no trace.
 */
static void test_repeated_exec_start_is_recorded(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "two.service",
                                      "[Service]\n"
                                      "ExecStart=/bin/true one\n"
                                      "ExecStart=/bin/true two\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "two.service");

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(((Service *) u)->exec_start[0], "/bin/true");
        ASSERT_STREQ(((Service *) u)->exec_start[1], "two");
        ASSERT_TRUE(((Service *) u)->exec_start[2] == NULL);

        ASSERT_EQ_INT(u->n_degraded_directives, 1);
        ASSERT_STREQ(u->degraded_directives[0], "ExecStart=multiple");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * E1: Environment=/EnvironmentFile= are parsed and stored, not degraded.
 * Quoting matches ExecStart= (pico_extract_first_word()), each word is
 * %-expanded individually, an empty rvalue resets the accumulated list, and
 * EnvironmentFile='s optional leading '-' is kept verbatim.
 */
static void test_environment_directives(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        /* quoting, a % specifier inside a value, and the '-' prefix */
        ASSERT_EQ_INT(test_write_file(dir,
                                      "env.service",
                                      "[Service]\n"
                                      "Environment=\"FOO=bar baz\" QUX=1\n"
                                      "Environment=INST=%n\n"
                                      "EnvironmentFile=/etc/default/a\n"
                                      "EnvironmentFile=-/etc/default/b\n"
                                      "ExecStart=/bin/true\n"),
                      0);

        /* reset-on-empty-rvalue: the accumulated list from the first two
         * lines of each pair is dropped by the empty third line */
        ASSERT_EQ_INT(test_write_file(dir,
                                      "env-reset.service",
                                      "[Service]\n"
                                      "Environment=A=1\n"
                                      "Environment=B=2\n"
                                      "Environment=\n"
                                      "EnvironmentFile=/etc/default/x\n"
                                      "EnvironmentFile=\n"
                                      "ExecStart=/bin/true\n"),
                      0);

        /* a word with no '=' or an empty name is warned and skipped, not
         * stored, and never fails the unit; same for a non-absolute path
         * with or without the '-' modifier */
        ASSERT_EQ_INT(test_write_file(dir,
                                      "env-bad.service",
                                      "[Service]\n"
                                      "Environment=NOEQUALS QUX=1 =EMPTYNAME\n"
                                      "EnvironmentFile=relative/path\n"
                                      "EnvironmentFile=-relative/path2\n"
                                      "ExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);

        u = load_one(m, "env.service");
        s = (Service *) u;
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(s->environment[0], "FOO=bar baz");
        ASSERT_STREQ(s->environment[1], "QUX=1");
        ASSERT_STREQ(s->environment[2], "INST=env.service");
        ASSERT_TRUE(s->environment[3] == NULL);
        ASSERT_STREQ(s->environment_files[0], "/etc/default/a");
        ASSERT_STREQ(s->environment_files[1], "-/etc/default/b");
        ASSERT_TRUE(s->environment_files[2] == NULL);
        ASSERT_EQ_INT(u->n_degraded_directives, 0);

        u = load_one(m, "env-reset.service");
        s = (Service *) u;
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_TRUE(s->environment == NULL);
        ASSERT_TRUE(s->environment_files == NULL);

        u = load_one(m, "env-bad.service");
        s = (Service *) u;
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(s->environment[0], "QUX=1");
        ASSERT_TRUE(s->environment[1] == NULL);
        ASSERT_TRUE(s->environment_files == NULL);
        ASSERT_EQ_INT(u->n_degraded_directives, 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A malformed line must cost exactly that line (2d4fffb00). The whole-file
 * failure this replaced is the worse behaviour by a distance: one typo in one
 * directive would take out a unit that is otherwise entirely valid, on a board
 * whose only diagnostic channel is a serial console.
 */
static void test_malformed_line_skips_only_that_line(void) {
        Service *s;
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "c.service",
                                      "[Unit]\n"
                                      "Description=C\n"
                                      "this line has no equals sign at all\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"
                                      "=value-with-no-key\n"
                                      "Restart=on-failure\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "c.service");
        s = (Service *) u;

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);

        /* Everything on both sides of both bad lines survived. */
        ASSERT_STREQ(u->description, "C");
        ASSERT_STREQ(s->exec_start[0], "/bin/true");
        ASSERT_EQ_INT(s->restart, SERVICE_RESTART_ON_FAILURE);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Scanner-level syntax reached through the unit parser: a UTF-8 BOM, both
 * comment characters, a line continuation, and a comment line that itself ends
 * in a backslash.
 *
 * That last one is the trap and the reason this case exists (9adbfeb38 /
 * 0ef695858): if a comment's trailing backslash is honoured as a continuation,
 * it swallows the real directive on the next line -- so the file parses
 * cleanly and one setting silently vanishes.
 */
static void test_bom_comments_and_continuations(void) {
        Service *s;
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "d.service",
                                      "\xef\xbb\xbf" /* UTF-8 BOM */
                                      "[Unit]\n"
                                      "# a hash comment \\\n"
                                      "Description=D\n"
                                      "; a semicolon comment\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/echo one \\\n"
                                      "    two \\\n"
                                      "    three\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "d.service");
        s = (Service *) u;

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);

        /* Not eaten by the comment's backslash. */
        ASSERT_STREQ(u->description, "D");

        ASSERT_STREQ(s->exec_start[0], "/bin/echo");
        ASSERT_STREQ(s->exec_start[1], "one");
        ASSERT_STREQ(s->exec_start[2], "two");
        ASSERT_STREQ(s->exec_start[3], "three");
        ASSERT_TRUE(s->exec_start[4] == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Quoting, and the trailing-garbage case the M1 review caught.
 *
 * `"bar"baz` was silently accepted and glued into `barbaz`, despite a comment
 * in the code claiming it was rejected -- a dead check. Asserting the
 * rejection is what keeps that from regressing back into a value nobody wrote.
 */
static void test_quoting_and_trailing_garbage(void) {
        Service *s;
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "e.service",
                                      "[Service]\n"
                                      "ExecStart=/bin/echo \"hello world\" plain\n"),
                      0);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "f.service",
                                      "[Unit]\n"
                                      "Description=F\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/echo \"bar\"baz\n"),
                      0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        /* A quoted argument is one argument, quotes removed. */
        u = manager_get_unit(m, "e.service");
        ASSERT_TRUE(u != NULL);
        s = (Service *) u;
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(s->exec_start[0], "/bin/echo");
        ASSERT_STREQ(s->exec_start[1], "hello world");
        ASSERT_STREQ(s->exec_start[2], "plain");
        ASSERT_TRUE(s->exec_start[3] == NULL);

        /*
         * Garbage after a closing quote is refused rather than glued together
         * into a value nobody wrote. Two rules meet here and the order matters:
         * the malformed ExecStart= line skips itself, exactly like any other
         * malformed directive -- and then the unit is left with no valid
         * ExecStart= at all, which a Service cannot load without. So the file
         * parses to the end (Description= is still read) and the unit resolves
         * to UNIT_ERROR rather than to a service that would be started with a
         * command line the file did not contain.
         */
        u = manager_get_unit(m, "f.service");
        ASSERT_TRUE(u != NULL);
        s = (Service *) u;
        ASSERT_EQ_INT(u->load_state, UNIT_ERROR);
        ASSERT_STREQ(u->description, "F");
        ASSERT_TRUE(s->exec_start == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A dependency token is a filename before it is anything else, so it must be
 * validated before it is ever concatenated into a search-path entry.
 * "Requires=../../tmp/evil.service" walking out of the unit directory is the
 * shape of the bug; unit files are root-owned config, so this is not a
 * privilege boundary, but one directory separator is the whole exploit.
 */
static void test_invalid_dependency_names_are_rejected(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "g.service",
                                      "[Unit]\n"
                                      "Description=G\n"
                                      "Requires=../../tmp/evil.service /absolute.service .hidden.service\n"
                                      "After=no-suffix h.service\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "h.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);
        u = load_one(m, "g.service");

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->description, "G");

        /* Not one of the three Requires= tokens is a valid unit name. */
        ASSERT_EQ_INT(u->n_dependencies[UNIT_REQUIRES], 0);

        /* The valid token on a line with an invalid one still lands: a bad
         * token skips itself, not the rest of the line. */
        ASSERT_EQ_INT(u->n_dependencies[UNIT_AFTER], 1);
        ASSERT_TRUE(unit_has_dependency(u, UNIT_AFTER, manager_get_unit(m, "h.service")));

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The reproduction this file exists for: a 30MB Requires= line.
 *
 * config_parse_unit_deps() originally sized a VLA by strlen(rvalue), and
 * rvalue comes straight out of conf-scan.c's deliberately unbounded getline()
 * -- so a single long line in a unit file overflowed PID 1's stack. The M1
 * review found it before it shipped and reproduced it by hand with exactly
 * this input; the fix was a heap buffer. It stayed a hand-run check until now,
 * which meant the one hazard in this parser with a known crashing input had no
 * committed regression at all.
 *
 * Two tokens, not one, and that is deliberate: a single 30MB token exercises
 * the allocation but never the tokenizer, and it is the strtok_r walk over a
 * heap copy that the VLA fix actually changed. The trailing short token also
 * proves the loop still terminates correctly after the enormous one.
 *
 * One thing this test looked like it had found and had not, recorded so the
 * next reader does not chase it either: the rejected 30MB token is echoed into
 * a "not a valid unit name" warning, which reads like PID 1 writing 30MB to
 * /dev/kmsg over one bad line. It does not. pico_log_internal() formats
 * through a fixed 1024-byte buffer, so the whole run emits under 3 KiB and the
 * longest line is 1022 bytes -- measured, not assumed. There is no unbounded
 * logging defect here to fix.
 */
static void test_huge_requires_line_does_not_crash(void) {
        const size_t huge_len = 30 * 1024 * 1024;
        char path[PATH_MAX];
        char chunk[65536];
        size_t remaining;
        Manager *m;
        char *dir;
        Unit *u;
        FILE *f;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        snprintf(path, sizeof(path), "%s/huge.service", dir);

        f = fopen(path, "we");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fputs("[Unit]\nDescription=Huge\nRequires=", f) >= 0);

        memset(chunk, 'a', sizeof(chunk));
        remaining = huge_len;
        while (remaining > 0) {
                size_t n = remaining < sizeof(chunk) ? remaining : sizeof(chunk);

                ASSERT_TRUE(fwrite(chunk, 1, n, f) == n);
                remaining -= n;
        }

        /* a second, ordinary token after the enormous one */
        ASSERT_TRUE(fputs(" real.service\n\n[Service]\nExecStart=/bin/true\n", f) >= 0);
        ASSERT_TRUE(fclose(f) == 0);

        ASSERT_EQ_INT(test_write_file(dir, "real.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);
        u = load_one(m, "huge.service");

        /* Reaching here at all is the assertion: before the fix this was a
         * stack overflow inside PID 1's own parser. */
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->description, "Huge");

        /* The 30MB token is not a valid unit name (length alone rules it out),
         * so it is dropped -- and the ordinary token after it is not. */
        ASSERT_EQ_INT(u->n_dependencies[UNIT_REQUIRES], 1);
        ASSERT_TRUE(unit_has_dependency(u, UNIT_REQUIRES, manager_get_unit(m, "real.service")));

        /* and the file kept parsing past the monster line */
        ASSERT_STREQ(((Service *) u)->exec_start[0], "/bin/true");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * ConditionPathExists=/ConditionPathIsDirectory= accumulate across repeated
 * assignments, and the two directives keep genuinely separate lists rather
 * than sharing one. A '!'-negated entry is stored with the '!' stripped from
 * the path and a matching true recorded at the same index in the parallel
 * *_negated array; a plain entry records false there.
 */
static void test_conditions_are_parsed(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "cond.service",
                                      "[Unit]\n"
                                      "Description=Cond\n"
                                      "ConditionPathExists=/a/one\n"
                                      "ConditionPathIsDirectory=/a/dir\n"
                                      "ConditionPathExists=!/a/two\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "cond.service");

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);

        ASSERT_EQ_INT((int) pico_strv_length(u->condition_path_exists), 2);
        ASSERT_STREQ(u->condition_path_exists[0], "/a/one");
        ASSERT_TRUE(!u->condition_path_exists_negated[0]);
        ASSERT_STREQ(u->condition_path_exists[1], "/a/two");
        ASSERT_TRUE(u->condition_path_exists_negated[1]);

        ASSERT_EQ_INT((int) pico_strv_length(u->condition_path_is_directory), 1);
        ASSERT_STREQ(u->condition_path_is_directory[0], "/a/dir");
        ASSERT_TRUE(!u->condition_path_is_directory_negated[0]);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The two spellings this MVP does not implement -- triggering, relative --
 * are dropped with a warning rather than failing the unit, and an empty
 * value resets whatever the same directive had already accumulated,
 * including its negation flags.
 */
static void test_unsupported_condition_values_are_dropped(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "bad.service",
                                      "[Unit]\n"
                                      "Description=Bad\n"
                                      "ConditionPathExists=|/a/trigger\n"
                                      "ConditionPathExists=relative/path\n"
                                      "ConditionPathIsDirectory=!/a/dir\n"
                                      "ConditionPathIsDirectory=\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "bad.service");

        /* A handler returning < 0 would abort the rest of the scan and leave
         * the unit UNIT_ERROR -- this is the assertion that matters. */
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);

        ASSERT_TRUE(u->condition_path_exists == NULL);
        ASSERT_TRUE(u->condition_path_exists_negated == NULL);
        /* the trailing empty value reset the list (and its negation flags)
         * the negated line above had filled */
        ASSERT_TRUE(u->condition_path_is_directory == NULL);
        ASSERT_TRUE(u->condition_path_is_directory_negated == NULL);

        ASSERT_STREQ(((Service *) u)->exec_start[0], "/bin/true");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * G2: specifier expansion through the real handler chain, not the engine's
 * own synthetic table (test-specifier.c already covers that). Everything
 * below this point is new; everything above is untouched by G2 -- see the
 * two test_conditions_are_parsed()/test_unsupported_condition_values_are_
 * dropped() cases above for the regression that matters most: neither
 * function nor test needed a single edit for this milestone to land.
 */

/*
 * The name-safe table (%n %N %p %i) in a dependency directive, expanded per
 * token before validation. Two companion units so the resolved edges are
 * to real, loaded targets rather than merely-created UNIT_ERROR stubs.
 */
static void test_name_safe_expansion_in_deps(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "foo@a.service",
                                      "[Unit]\n"
                                      "After=other-%i.service\n"
                                      "Requires=%p-common.service\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "other-a.service", "[Service]\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "foo-common.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);
        u = load_one(m, "foo@a.service");

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_TRUE(unit_has_dependency(u, UNIT_AFTER, manager_get_unit(m, "other-a.service")));
        ASSERT_TRUE(unit_has_dependency(u, UNIT_REQUIRES, manager_get_unit(m, "foo-common.service")));

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* Same table, [Install] side: WantedBy=/RequiredBy= are stored as raw
 * strings, so this proves expansion runs there too, not just on the
 * edge-resolving directives. */
static void test_name_safe_expansion_in_install(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "foo@a.service",
                                      "[Service]\nExecStart=/bin/true\n\n[Install]\nWantedBy=%p.target\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "foo@a.service");

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_TRUE(u->wanted_by != NULL);
        ASSERT_STREQ(u->wanted_by[0], "foo.target");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Proves the two tables are genuinely different, not one table used twice:
 * %I unescapes and so can introduce a '/', which is exactly why it is not
 * in the name-safe table. "x-%I.service" is expanded through that table,
 * finds no 'I' entry, and passes through literally -- then fails
 * unit_name_is_valid() on the '%' and is dropped, same as any other
 * malformed dependency token.
 */
static void test_name_safe_table_has_no_percent_I(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "foo@a.service",
                                      "[Unit]\nRequires=x-%I.service\n\n[Service]\nExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "foo@a.service");

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(u->n_dependencies[UNIT_REQUIRES], 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The full table in ExecStart=, and three things at once: %I really
 * unescapes (not an alias of raw %i), %i is preserved raw, and per-word
 * expansion keeps an unescaped instance containing a space as ONE argv
 * element rather than letting it re-tokenize the command line.
 */
static void test_full_expansion_in_exec(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "foo@a\\x20b.service",
                                      "[Service]\nExecStart=/bin/echo %i %I %n %N %p\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "foo@a\\x20b.service");
        s = (Service *) u;

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(s->exec_start[0], "/bin/echo");
        ASSERT_STREQ(s->exec_start[1], "a\\x20b");             /* %i: raw, unescaped instance */
        ASSERT_STREQ(s->exec_start[2], "a b");                 /* %I: actually unescaped */
        ASSERT_STREQ(s->exec_start[3], "foo@a\\x20b.service"); /* %n: full id */
        ASSERT_STREQ(s->exec_start[4], "foo@a\\x20b");         /* %N: id without suffix */
        ASSERT_STREQ(s->exec_start[5], "foo");                 /* %p: prefix */
        ASSERT_TRUE(s->exec_start[6] == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_description_expansion(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "serial-getty@ttyGS0.service",
                                      "[Unit]\nDescription=Serial getty on %I\n\n[Service]\nExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "serial-getty@ttyGS0.service");

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->description, "Serial getty on ttyGS0");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * v30's specifier_string() does assert(data) -- an abort waiting to happen
 * the moment a plain, non-instanced unit's ExecStart= carries a bare %i or
 * %I. This reaches that exact path through the real handler chain, not
 * specifier.c's own direct test of pico_specifier_string().
 */
static void test_specifiers_on_non_instanced_unit(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "plain.service", "[Service]\nExecStart=/bin/echo [%i][%I]\n"), 0);

        m = manager_for(dir);
        u = load_one(m, "plain.service");
        s = (Service *) u;

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(s->exec_start[0], "/bin/echo");
        ASSERT_STREQ(s->exec_start[1], "[][]");
        ASSERT_TRUE(s->exec_start[2] == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* The drop-in-tolerance property, through the real handler chain: a
 * specifier neither table implements passes through untouched, and "%%"
 * still collapses to a literal '%'. */
static void test_unknown_specifier_tolerated(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "plain.service",
                                      "[Unit]\nDescription=100%% done\n\n[Service]\nExecStart=/bin/echo %t %c\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "plain.service");
        s = (Service *) u;

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->description, "100% done");
        ASSERT_STREQ(s->exec_start[0], "/bin/echo");
        ASSERT_STREQ(s->exec_start[1], "%t");
        ASSERT_STREQ(s->exec_start[2], "%c");
        ASSERT_TRUE(s->exec_start[3] == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Pins the v30-fidelity scope boundary named in this file's own header:
 * verified against the quarry that v30 does not run specifier_printf() over
 * a Condition* value either, so this stays unexpanded on purpose, not by
 * omission. Makes the choice visible in the suite instead of implicit.
 */
static void test_condition_values_are_not_expanded(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "foo@a.service",
                                      "[Unit]\nConditionPathExists=/dev/%i\n\n[Service]\nExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "foo@a.service");

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_TRUE(u->condition_path_exists != NULL);
        ASSERT_STREQ(u->condition_path_exists[0], "/dev/%i");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * G1/G3(b) unaffected, half two of two: a byte-for-byte copy of the real
 * shipped serial-getty@ttyGS0.service fixture (meta-angstrom's
 * recipes-core/init-systems/pico-init-units/), asserted field by field.
 * The file carries no '%' character at all (verified by grep over the whole
 * pico-init-units/ directory before this milestone started), so
 * introducing specifier expansion cannot have changed what it means.
 */
static void test_shipped_ttygs0_unit_is_unchanged(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "usb-multi-gadget.service", "[Service]\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "serial-getty@ttyGS0.service",
                                      "[Unit]\n"
                                      "Description=Serial getty on ttyGS0\n"
                                      "After=usb-multi-gadget.service\n"
                                      "ConditionPathExists=/dev/ttyGS0\n"
                                      "\n"
                                      "[Service]\n"
                                      "Type=simple\n"
                                      "ExecStart=/sbin/getty 115200 ttyGS0\n"
                                      "Restart=on-failure\n"
                                      "RestartSec=2\n"
                                      "\n"
                                      "[Install]\n"
                                      "WantedBy=default.target\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "serial-getty@ttyGS0.service");
        s = (Service *) u;

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->instance, "ttyGS0");
        ASSERT_STREQ(u->description, "Serial getty on ttyGS0");
        ASSERT_TRUE(u->condition_path_exists != NULL);
        ASSERT_STREQ(u->condition_path_exists[0], "/dev/ttyGS0");
        ASSERT_STREQ(s->exec_start[0], "/sbin/getty");
        ASSERT_STREQ(s->exec_start[1], "115200");
        ASSERT_STREQ(s->exec_start[2], "ttyGS0");
        ASSERT_TRUE(s->exec_start[3] == NULL);
        ASSERT_EQ_INT(s->restart, SERVICE_RESTART_ON_FAILURE);
        ASSERT_TRUE(s->restart_usec == 2 * USEC_PER_SEC);
        ASSERT_TRUE(u->wanted_by != NULL);
        ASSERT_STREQ(u->wanted_by[0], "default.target");
        ASSERT_TRUE(unit_has_dependency(u, UNIT_AFTER, manager_get_unit(m, "usb-multi-gadget.service")));
        ASSERT_STREQ(basename_of(u->fragment_path), "serial-getty@ttyGS0.service");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * G1/G3(b) unaffected, and G2's own precedence rule in the same breath: the
 * exact post-G3(a) on-disk layout (a real template alongside the literal
 * override), tested before G3(a) itself is even written. Every assertion
 * from test_shipped_ttygs0_unit_is_unchanged() must hold identically.
 */
static void test_shipped_ttygs0_unit_wins_over_template(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "usb-multi-gadget.service", "[Service]\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "serial-getty@ttyGS0.service",
                                      "[Unit]\n"
                                      "Description=Serial getty on ttyGS0\n"
                                      "After=usb-multi-gadget.service\n"
                                      "ConditionPathExists=/dev/ttyGS0\n"
                                      "\n"
                                      "[Service]\n"
                                      "Type=simple\n"
                                      "ExecStart=/sbin/getty 115200 ttyGS0\n"
                                      "Restart=on-failure\n"
                                      "RestartSec=2\n"
                                      "\n"
                                      "[Install]\n"
                                      "WantedBy=default.target\n"),
                      0);
        /* the generic template: deliberately different ExecStart=, no
         * After=/ConditionPathExists= -- if this ever won, every assertion
         * below would fail loudly rather than silently degrade. */
        ASSERT_EQ_INT(test_write_file(dir, "serial-getty@.service", "[Service]\nExecStart=/bin/false %I\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "serial-getty@ttyGS0.service");
        s = (Service *) u;

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->instance, "ttyGS0");
        ASSERT_STREQ(u->description, "Serial getty on ttyGS0");
        ASSERT_TRUE(u->condition_path_exists != NULL);
        ASSERT_STREQ(u->condition_path_exists[0], "/dev/ttyGS0");
        ASSERT_STREQ(s->exec_start[0], "/sbin/getty");
        ASSERT_STREQ(s->exec_start[1], "115200");
        ASSERT_STREQ(s->exec_start[2], "ttyGS0");
        ASSERT_TRUE(s->exec_start[3] == NULL);
        ASSERT_EQ_INT(s->restart, SERVICE_RESTART_ON_FAILURE);
        ASSERT_TRUE(s->restart_usec == 2 * USEC_PER_SEC);
        ASSERT_TRUE(u->wanted_by != NULL);
        ASSERT_STREQ(u->wanted_by[0], "default.target");
        ASSERT_TRUE(unit_has_dependency(u, UNIT_AFTER, manager_get_unit(m, "usb-multi-gadget.service")));
        ASSERT_STREQ(basename_of(u->fragment_path), "serial-getty@ttyGS0.service");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Type=: exec and notify load as themselves, notify-reload as notify with
 * the fallback on the record, and a type pico-init has no answer for at all
 * (forking, until it lands) is still a load failure rather than a silent
 * simple -- the ordering argument in config_parse_type() unchanged.
 */
static void test_type_values(void) {
        Manager *m;
        char *dir;
        Unit *u;
        char *degraded;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "exec.service", "[Service]\nType=exec\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "notify.service", "[Service]\nType=notify\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "reload.service",
                                      "[Service]\nType=notify-reload\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "forking.service", "[Service]\nType=forking\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "bogus.service", "[Service]\nType=frobnicate\nExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);

        u = load_one(m, "exec.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(((Service *) u)->type, SERVICE_TYPE_EXEC);
        ASSERT_EQ_INT(u->n_degraded_directives, 0);

        u = load_one(m, "notify.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(((Service *) u)->type, SERVICE_TYPE_NOTIFY);
        ASSERT_EQ_INT(u->n_degraded_directives, 0);

        u = load_one(m, "reload.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(((Service *) u)->type, SERVICE_TYPE_NOTIFY);
        degraded = unit_degraded_directives_string(u);
        ASSERT_STREQ(degraded, "Type=notify-reload");
        free(degraded);

        u = load_one(m, "forking.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(((Service *) u)->type, SERVICE_TYPE_FORKING);
        ASSERT_EQ_INT(u->n_degraded_directives, 0);

        u = load_one(m, "bogus.service");
        ASSERT_EQ_INT(u->load_state, UNIT_ERROR);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Type=forking's own directives: PIDFile= takes the full specifier table
 * and a relative path lands under /run/ (systemd since v237); an empty
 * value resets it. GuessMainPID= defaults to yes.
 */
static void test_forking_directives(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "pf-abs.service",
                                      "[Service]\nType=forking\nPIDFile=/run/%n.pid\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "pf-rel.service",
                                      "[Service]\nType=forking\nPIDFile=pf/%p.pid\nGuessMainPID=no\n"
                                      "ExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "pf-reset.service",
                                      "[Service]\nType=forking\nPIDFile=/run/x.pid\nPIDFile=\n"
                                      "GuessMainPID=bogus\nExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);

        u = load_one(m, "pf-abs.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        s = (Service *) u;
        ASSERT_STREQ(s->pid_file, "/run/pf-abs.service.pid");
        ASSERT_EQ_INT(s->guess_main_pid, true);

        u = load_one(m, "pf-rel.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        s = (Service *) u;
        ASSERT_STREQ(s->pid_file, "/run/pf/pf-rel.pid");
        ASSERT_EQ_INT(s->guess_main_pid, false);

        u = load_one(m, "pf-reset.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        s = (Service *) u;
        ASSERT_TRUE(s->pid_file == NULL);
        ASSERT_EQ_INT(s->guess_main_pid, true); /* an invalid value is ignored, not applied */
        ASSERT_EQ_INT(u->n_degraded_directives, 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_service_fields();
        test_unknown_directives_are_tolerated();
        test_degradation_record();
        test_repeated_exec_start_is_recorded();
        test_environment_directives();
        test_malformed_line_skips_only_that_line();
        test_bom_comments_and_continuations();
        test_quoting_and_trailing_garbage();
        test_invalid_dependency_names_are_rejected();
        test_huge_requires_line_does_not_crash();
        test_conditions_are_parsed();
        test_unsupported_condition_values_are_dropped();

        test_name_safe_expansion_in_deps();
        test_name_safe_expansion_in_install();
        test_name_safe_table_has_no_percent_I();
        test_full_expansion_in_exec();
        test_description_expansion();
        test_specifiers_on_non_instanced_unit();
        test_unknown_specifier_tolerated();
        test_condition_values_are_not_expanded();
        test_shipped_ttygs0_unit_is_unchanged();
        test_shipped_ttygs0_unit_wins_over_template();
        test_type_values();
        test_forking_directives();

        printf("test-unit-parse: all checks passed\n");
        return 0;
}
