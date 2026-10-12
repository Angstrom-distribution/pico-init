/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Fixture-driven test for unit-parse.c: real unit files on disk in, parsed
 * fields and tolerated errors out.
 *
 * The line-level scanner lives in conf-scan.c and is shared with netd's
 * `.network` parser, but test-netd-network.c reaches it through netd's own
 * handlers, never through unit-parse.c. And every other PID1 test writes unit
 * files only as a means to an end: they assert about jobs, ordering,
 * supervision and boot, so a directive silently parsed into the wrong field
 * would pass all of them as long as the unit loaded.
 *
 * So the rule here is that every assertion is about the parser's own output --
 * the fields on the Unit and the Service -- and about what it does with input
 * it should refuse.
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
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

        ASSERT_EQ_INT(s->n_exec_start_pre, 1);
        ASSERT_STREQ(s->exec_start_pre[0].argv[0], "/bin/true");
        ASSERT_STREQ(s->exec_start_pre[0].argv[1], "--pre");
        ASSERT_TRUE(s->exec_start_pre[0].argv[2] == NULL);

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
 * level drops (a triggering condition, an ExecStart= modifier) are recorded under name=qualifier, repeats
 * collapse, and a unit pico-init honours in full carries no record at all.
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

        /* EnvironmentFile=/Environment= are parsed and stored, not
         * degraded -- see test_environment_directives() for their own
         * dedicated coverage. */
        ASSERT_STREQ(((Service *) u)->environment_files[0], "-/etc/default/rich");
        ASSERT_TRUE(((Service *) u)->environment_files[1] == NULL);
        ASSERT_STREQ(((Service *) u)->environment[0], "A=1");
        ASSERT_STREQ(((Service *) u)->environment[1], "B=2");
        ASSERT_TRUE(((Service *) u)->environment[2] == NULL);

        /* ExecStop= is implemented, not dropped (test_exec_stop_lines()). */
        ASSERT_EQ_INT(((Service *) u)->n_exec_stop, 1);
        ASSERT_STREQ(((Service *) u)->exec_stop[0].argv[1], "--stop");

        /* Both ExecStartPre= lines are kept, in order, not degraded. */
        ASSERT_EQ_INT(((Service *) u)->n_exec_start_pre, 2);
        ASSERT_STREQ(((Service *) u)->exec_start_pre[0].argv[1], "one");
        ASSERT_STREQ(((Service *) u)->exec_start_pre[1].argv[1], "two");

        ASSERT_EQ_INT(u->n_degraded_directives, 4);
        ASSERT_STREQ(u->degraded_directives[0], "ConditionPathExists=|");
        ASSERT_STREQ(u->degraded_directives[1], "ExecStart=@");
        ASSERT_STREQ(u->degraded_directives[2], "ExecReload");
        ASSERT_STREQ(u->degraded_directives[3], "Alias");
        ASSERT_TRUE(u->degraded_directives[4] == NULL);

        joined = unit_degraded_directives_string(u);
        ASSERT_STREQ(joined,
                     "ConditionPathExists=| "
                     "ExecStart=@ ExecReload Alias");
        free(joined);

        /* a second identical drop is not a second entry */
        ASSERT_EQ_INT(unit_add_degradation(u, "Alias"), 0);
        ASSERT_EQ_INT(u->n_degraded_directives, 4);

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
 * units-degradation-record-holes: a Requires= on a unit type pico has no
 * vtable for, and an unparseable TimeoutStartSec=, were each dropped with
 * only a WARNING -- invisible to picoctl show/pico-unit-lint, which read the
 * degradation record, not the log. Restart=always sits in the same unit
 * file as a sanity check that a fully-implemented value parses straight
 * through instead of degrading.
 */
static void test_degradation_record_covers_deps_and_timeouts(void) {
        Manager *m;
        char *dir;
        char *joined;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "holes.service",
                                      "[Unit]\n"
                                      "Requires=foo.mount\n"
                                      "\n"
                                      "[Service]\n"
                                      "Type=simple\n"
                                      "ExecStart=/bin/true\n"
                                      "Restart=always\n"
                                      "TimeoutStartSec=1min 30s\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "holes.service");

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);

        /* Restart=always is one of the seven fully-implemented values; it
         * parses straight through, not an approximation. */
        ASSERT_EQ_INT(((Service *) u)->restart, SERVICE_RESTART_ALWAYS);
        /* An unparseable value leaves the default (90s) untouched. */
        ASSERT_TRUE(((Service *) u)->timeout_start_usec == 90 * USEC_PER_SEC);

        joined = unit_degraded_directives_string(u);
        ASSERT_STREQ(joined, "Requires=.mount TimeoutStartSec=");
        free(joined);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A second, independently-valid ExecStart= line replaces the first, and
 * the replacement is visible in the degradation record --
 * config_parse_exec_start() mirrors config_parse_exec_start_pre()'s
 * "multiple ... not supported" pattern.
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
 * Environment=/EnvironmentFile= are parsed and stored, not degraded.
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
 * units-conf-comment-ends-continuation: a comment line inside a backslash
 * continuation must be skipped entirely (9adbfeb38a's own test case, kept
 * exact: "1\\\n#hogehoge\\\n2\\\n3\n" => "1 2 3"), not flush what has been
 * accumulated so far and lose the rest of the command line. A genuinely
 * blank line must still end the continuation (0ef69585d8).
 */
static void test_comment_inside_continuation_is_skipped(void) {
        Service *s;
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "e.service",
                                      "[Service]\n"
                                      "ExecStart=/bin/echo one \\\n"
                                      "# a comment in the middle \\\n"
                                      "    two \\\n"
                                      "    three\n"
                                      "ExecStartPre=/bin/true a \\\n"
                                      "\n"
                                      "b\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "e.service");
        s = (Service *) u;

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);

        /* The comment line contributed nothing, and did not cut the
         * continuation short: all three words survive. */
        ASSERT_STREQ(s->exec_start[0], "/bin/echo");
        ASSERT_STREQ(s->exec_start[1], "one");
        ASSERT_STREQ(s->exec_start[2], "two");
        ASSERT_STREQ(s->exec_start[3], "three");
        ASSERT_TRUE(s->exec_start[4] == NULL);

        /* A genuinely blank line still ends a continuation: ExecStartPre=
         * stops at "a", and the bare "b" on its own line is a malformed
         * line (no '='), not part of the command. */
        ASSERT_EQ_INT(s->n_exec_start_pre, 1);
        ASSERT_STREQ(s->exec_start_pre[0].argv[0], "/bin/true");
        ASSERT_STREQ(s->exec_start_pre[0].argv[1], "a");
        ASSERT_TRUE(s->exec_start_pre[0].argv[2] == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Quoting, and trailing garbage after a quoted word.
 *
 * `"bar"baz` must be rejected, not glued into `barbaz`, a value nobody wrote.
 */
/*
 * StandardOutput=/StandardError=: journal (and its syslog/+console spellings)
 * and null are honoured, inherit is the default, and a value pico-init has no
 * meaning for (kmsg, file:...) is recorded as dropped without touching the
 * default.
 */
static void test_standard_output_and_error(void) {
        Manager *m;
        Service *s;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "j.service",
                                      "[Service]\n"
                                      "StandardInput=tty\n"
                                      "StandardOutput=journal\n"
                                      "StandardError=journal\n"
                                      "ExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "n.service",
                                      "[Service]\n"
                                      "StandardOutput=null\n"
                                      "StandardError=syslog+console\n"
                                      "ExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "k.service",
                                      "[Service]\n"
                                      "StandardOutput=kmsg\n"
                                      "StandardError=file:/tmp/x\n"
                                      "ExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "d.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        s = (Service *) manager_get_unit(m, "j.service");
        ASSERT_TRUE(s != NULL);
        ASSERT_EQ_INT(s->standard_output, SERVICE_STDIO_OUTPUT_JOURNAL);
        ASSERT_EQ_INT(s->standard_error, SERVICE_STDIO_OUTPUT_JOURNAL);
        ASSERT_EQ_INT(UNIT(s)->n_degraded_directives, 0);

        s = (Service *) manager_get_unit(m, "n.service");
        ASSERT_TRUE(s != NULL);
        ASSERT_EQ_INT(s->standard_output, SERVICE_STDIO_OUTPUT_NULL);
        ASSERT_EQ_INT(s->standard_error, SERVICE_STDIO_OUTPUT_JOURNAL);
        ASSERT_EQ_INT(UNIT(s)->n_degraded_directives, 0);

        u = manager_get_unit(m, "k.service");
        ASSERT_TRUE(u != NULL);
        s = (Service *) u;
        ASSERT_EQ_INT(s->standard_output, SERVICE_STDIO_OUTPUT_INHERIT);
        ASSERT_EQ_INT(s->standard_error, SERVICE_STDIO_OUTPUT_INHERIT);
        ASSERT_EQ_INT(u->n_degraded_directives, 2);
        ASSERT_STREQ(u->degraded_directives[0], "StandardOutput");
        ASSERT_STREQ(u->degraded_directives[1], "StandardError");

        s = (Service *) manager_get_unit(m, "d.service");
        ASSERT_TRUE(s != NULL);
        ASSERT_EQ_INT(s->standard_output, SERVICE_STDIO_OUTPUT_INHERIT);
        ASSERT_EQ_INT(s->standard_error, SERVICE_STDIO_OUTPUT_INHERIT);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_exec_start_pre_list_and_reset(void) {
        Manager *m;
        Service *s;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "pre.service",
                                      "[Service]\n"
                                      "ExecStartPre=/bin/one\n"
                                      "ExecStartPre=-/bin/two arg\n"
                                      "ExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "reset.service",
                                      "[Service]\n"
                                      "ExecStartPre=/bin/one\n"
                                      "ExecStartPre=\n"
                                      "ExecStartPre=/bin/three\n"
                                      "ExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        u = manager_get_unit(m, "pre.service");
        ASSERT_TRUE(u != NULL);
        s = (Service *) u;
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(s->n_exec_start_pre, 2);
        ASSERT_STREQ(s->exec_start_pre[0].argv[0], "/bin/one");
        ASSERT_EQ_INT(s->exec_start_pre[0].ignore, false);
        ASSERT_STREQ(s->exec_start_pre[1].argv[0], "/bin/two");
        ASSERT_STREQ(s->exec_start_pre[1].argv[1], "arg");
        ASSERT_EQ_INT(s->exec_start_pre[1].ignore, true);
        ASSERT_EQ_INT(u->n_degraded_directives, 0);

        /* An empty ExecStartPre= forgets everything before it, as upstream. */
        u = manager_get_unit(m, "reset.service");
        ASSERT_TRUE(u != NULL);
        s = (Service *) u;
        ASSERT_EQ_INT(s->n_exec_start_pre, 1);
        ASSERT_STREQ(s->exec_start_pre[0].argv[0], "/bin/three");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_quoting_and_glued_quotes(void) {
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

        /* Single quotes group like double ones; the other quote is literal inside. */
        ASSERT_EQ_INT(test_write_file(dir,
                                      "g.service",
                                      "[Service]\n"
                                      "ExecStart=/bin/sh -c 'for i in 1 2; do echo \"x y\"; done' \"it's\"\n"),
                      0);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "h.service",
                                      "[Unit]\n"
                                      "Description=H\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/echo 'bar'baz\n"),
                      0);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "i.service",
                                      "[Unit]\n"
                                      "Description=I\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/echo 'open\n"),
                      0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        u = manager_get_unit(m, "g.service");
        ASSERT_TRUE(u != NULL);
        s = (Service *) u;
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(s->exec_start[0], "/bin/sh");
        ASSERT_STREQ(s->exec_start[1], "-c");
        ASSERT_STREQ(s->exec_start[2], "for i in 1 2; do echo \"x y\"; done");
        ASSERT_STREQ(s->exec_start[3], "it's");
        ASSERT_TRUE(s->exec_start[4] == NULL);

        /* Text glued to a closing quote continues the word. */
        u = manager_get_unit(m, "h.service");
        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(((Service *) u)->exec_start[1], "barbaz");
        u = manager_get_unit(m, "i.service");
        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->load_state, UNIT_ERROR);

        /* A quoted argument is one argument, quotes removed. */
        u = manager_get_unit(m, "e.service");
        ASSERT_TRUE(u != NULL);
        s = (Service *) u;
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(s->exec_start[0], "/bin/echo");
        ASSERT_STREQ(s->exec_start[1], "hello world");
        ASSERT_STREQ(s->exec_start[2], "plain");
        ASSERT_TRUE(s->exec_start[3] == NULL);

        u = manager_get_unit(m, "f.service");
        ASSERT_TRUE(u != NULL);
        s = (Service *) u;
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(u->description, "F");
        ASSERT_STREQ(s->exec_start[1], "barbaz");
        ASSERT_TRUE(s->exec_start[2] == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Exec*= and Environment= decode C escapes (printf's \n, \x41, \101) and keep
 * an unknown one as written, so a sed expression's \. survives. Quotes may be
 * glued to the text around them.
 */
static void test_exec_c_escapes(void) {
        Service *s;
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "esc.service",
                                      "[Service]\n"
                                      "ExecStart=/bin/sh -c \"printf a\\nb\" 's/\\./_/' \\x41\\101\\s\\\\ \"${DIR}\"/sub\n"
                                      "Environment=\"TABBED=a\\tb\" KEEP=\\q\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "esc.service");
        s = (Service *) u;
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_STREQ(s->exec_start[1], "-c");
        ASSERT_STREQ(s->exec_start[2], "printf a\nb");
        ASSERT_STREQ(s->exec_start[3], "s/\\./_/");
        ASSERT_STREQ(s->exec_start[4], "AA \\");
        ASSERT_STREQ(s->exec_start[5], "${DIR}/sub");
        ASSERT_TRUE(s->exec_start[6] == NULL);
        ASSERT_STREQ(s->environment[0], "TABBED=a\tb");
        ASSERT_STREQ(s->environment[1], "KEEP=\\q");

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
 * A 30MB Requires= line.
 *
 * rvalue comes straight out of conf-scan.c's unbounded getline(), so
 * config_parse_unit_deps() must not size a stack buffer (VLA) by
 * strlen(rvalue): one long line would overflow PID 1's stack.
 *
 * Two tokens, not one: a single 30MB token exercises the allocation but never
 * the tokenizer's strtok_r walk over the heap copy. The trailing short token
 * proves the loop still terminates after the enormous one.
 *
 * The rejected 30MB token is echoed into a "not a valid unit name" warning,
 * but pico_log_internal() formats through a fixed 1024-byte buffer, so the
 * log output stays bounded.
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
 * The two spellings this parser does not implement -- triggering, relative --
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
 * Specifier expansion through the real handler chain, not the engine's
 * own synthetic table (test-specifier.c already covers that).
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
 * Upstream v30 does not run specifier_printf() over a Condition* value
 * either, so it stays unexpanded on purpose; this pins that choice.
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
 * A byte-for-byte copy of a shipped serial-getty@ttyGS0.service unit,
 * asserted field by field. It carries no '%' character at all, so
 * specifier expansion cannot change what it means.
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
 * Precedence: a real template alongside the literal override. Every
 * assertion from test_shipped_ttygs0_unit_is_unchanged() must hold identically.
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
        /* the generic template: different ExecStart=, no
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
 * Type=dbus and Type=idle degrade to simple, permanently -- not the hard
 * refusal every other unrecognized Type= still gets.
 */
static void test_type_dbus_and_idle_degrade_to_simple(void) {
        Manager *m;
        char *dir;
        Unit *u;
        char *degraded;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "dbus.service",
                                      "[Service]\nType=dbus\nBusName=org.example.Thing\n"
                                      "ExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "idle.service", "[Service]\nType=idle\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);

        u = load_one(m, "dbus.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(((Service *) u)->type, SERVICE_TYPE_SIMPLE);
        degraded = unit_degraded_directives_string(u);
        ASSERT_TRUE(strstr(degraded, "Type=dbus") != NULL);
        free(degraded);

        u = load_one(m, "idle.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(((Service *) u)->type, SERVICE_TYPE_SIMPLE);
        degraded = unit_degraded_directives_string(u);
        ASSERT_STREQ(degraded, "Type=idle");
        free(degraded);

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

/*
 * units-exec-dash-prefix-ignored: the '-' modifier glued to the path was
 * parsed and then thrown away -- nothing carried it onto the Service, so a
 * failing "-" command still failed the unit (service.c).
 */
static void test_exec_dash_prefix_sets_ignore(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "dash.service",
                                      "[Service]\nExecStartPre=-/bin/false\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "nodash.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);

        u = load_one(m, "dash.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        s = (Service *) u;
        ASSERT_EQ_INT(s->exec_start_pre[0].ignore, true);
        ASSERT_EQ_INT(s->exec_start_ignore, false);
        ASSERT_STREQ(s->exec_start_pre[0].argv[0], "/bin/false");

        u = load_one(m, "nodash.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        s = (Service *) u;
        ASSERT_EQ_INT(s->exec_start_ignore, false);
        ASSERT_EQ_INT(s->n_exec_start_pre, 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Delegate= is a boolean or a list of controller names. As in modern systemd a
 * list delegates exactly those controllers, "yes" all of them, an empty
 * assignment delegates none, and "no" undoes any of it; junk is ignored with
 * the field left alone, and the unit is not recorded as having dropped the
 * directive.
 */
static void test_delegate(void) {
        static const struct {
                const char *value;
                bool want;
                unsigned mask;
        } cases[] = {
                {             "yes",true,                                                   SERVICE_DELEGATE_ALL                                    },
                {              "no", false,                                                                      0 },
                {               "1",  true,                                                   SERVICE_DELEGATE_ALL },
                {             "off", false,                                                                      0 },
                {      "cpu memory",  true,                         SERVICE_DELEGATE_CPU | SERVICE_DELEGATE_MEMORY },
                { "pids memory cpu",
                 true, SERVICE_DELEGATE_CPU | SERVICE_DELEGATE_MEMORY | SERVICE_DELEGATE_PIDS                     },
                {             "cpu",  true,                                                   SERVICE_DELEGATE_CPU },
                { "cpu bpf-devices",  true,                                                   SERVICE_DELEGATE_CPU },
                {                "",  true,                                                                      0 },
        };
        Manager *m;
        char *dir;
        size_t i;
        Unit *u;
        Service *s;
        char buf[64];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                char name[32], body[96];

                snprintf(name, sizeof(name), "d%zu.service", i);
                snprintf(body, sizeof(body), "[Service]\nExecStart=/bin/true\nDelegate=%s\n", cases[i].value);
                ASSERT_EQ_INT(test_write_file(dir, name, body), 0);
        }
        /* "no" after "yes" clears both; invalid after yes keeps yes; absent is false */
        ASSERT_EQ_INT(test_write_file(dir,
                                      "reset.service",
                                      "[Service]\nExecStart=/bin/true\nDelegate=yes\nDelegate=no\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "junk.service",
                                      "[Service]\nExecStart=/bin/true\nDelegate=yes\nDelegate=cpu;rm\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "absent.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);

        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                char name[32];

                snprintf(name, sizeof(name), "d%zu.service", i);
                u = load_one(m, name);
                ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
                s = (Service *) u;
                ASSERT_EQ_INT(s->delegate, cases[i].want);
                ASSERT_EQ_INT((int) s->delegate_controllers, (int) cases[i].mask);
                ASSERT_EQ_INT(u->n_degraded_directives, 0);
        }

        s = (Service *) load_one(m, "reset.service");
        ASSERT_EQ_INT(s->delegate, false);
        ASSERT_EQ_INT((int) s->delegate_controllers, 0);
        s = (Service *) load_one(m, "junk.service");
        ASSERT_EQ_INT(s->delegate, true);
        ASSERT_EQ_INT((int) s->delegate_controllers, (int) SERVICE_DELEGATE_ALL);
        s = (Service *) load_one(m, "absent.service");
        ASSERT_EQ_INT(s->delegate, false);

        /* the printed form: systemd's controller order whatever the unit's */
        service_delegate_controllers_to_string(SERVICE_DELEGATE_ALL, buf, sizeof(buf));
        ASSERT_STREQ(buf, "cpu cpuset io memory pids");
        service_delegate_controllers_to_string(SERVICE_DELEGATE_PIDS | SERVICE_DELEGATE_CPU, buf, sizeof(buf));
        ASSERT_STREQ(buf, "cpu pids");
        service_delegate_controllers_to_string(0, buf, sizeof(buf));
        ASSERT_STREQ(buf, "");
        service_delegate_controllers_to_string(SERVICE_DELEGATE_ALL, buf, 8);
        ASSERT_STREQ(buf, "cpu");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * DelegateSubgroup= takes one cgroup path component; a bad name is ignored
 * with a warning and the earlier value stays, an empty one clears it.
 */
static void test_delegate_subgroup(void) {
        Manager *m;
        char *dir;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "sub.service",
                                      "[Service]\nExecStart=/bin/true\nDelegate=yes\nDelegateSubgroup=main\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "bad.service",
                                      "[Service]\nExecStart=/bin/true\nDelegateSubgroup=main\nDelegateSubgroup=a/b\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "clear.service",
                                      "[Service]\nExecStart=/bin/true\nDelegateSubgroup=main\nDelegateSubgroup=\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "none.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);

        s = (Service *) load_one(m, "sub.service");
        ASSERT_TRUE(s->delegate_subgroup != NULL);
        ASSERT_STREQ(s->delegate_subgroup, "main");
        ASSERT_EQ_INT(UNIT(s)->n_degraded_directives, 0);
        s = (Service *) load_one(m, "bad.service");
        ASSERT_STREQ(s->delegate_subgroup, "main");
        s = (Service *) load_one(m, "clear.service");
        ASSERT_TRUE(s->delegate_subgroup == NULL);
        s = (Service *) load_one(m, "none.service");
        ASSERT_TRUE(s->delegate_subgroup == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * KillMode=, KillSignal=, SendSIGHUP= and SendSIGKILL=: values as systemd
 * reads them, an unknown value ignored with the earlier one kept, an empty
 * assignment back to the default, and no degradation recorded.
 */
static void test_kill_settings(void) {
        Manager *m;
        char *dir;
        Service *s;
        size_t i;
        static const struct {
                const char *value;
                KillMode want;
        } modes[] = {
                { "control-group", KILL_CONTROL_GROUP },
                {         "mixed",         KILL_MIXED },
                {       "process",       KILL_PROCESS },
                {          "none",          KILL_NONE },
        };

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
                char name[32], body[96];

                snprintf(name, sizeof(name), "k%zu.service", i);
                snprintf(body, sizeof(body), "[Service]\nExecStart=/bin/true\nKillMode=%s\n", modes[i].value);
                ASSERT_EQ_INT(test_write_file(dir, name, body), 0);
        }
        ASSERT_EQ_INT(test_write_file(dir,
                                      "sig.service",
                                      "[Service]\nExecStart=/bin/true\nKillSignal=SIGUSR1\nSendSIGHUP=yes\nSendSIGKILL=no\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "num.service", "[Service]\nExecStart=/bin/true\nKillSignal=2\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "bad.service",
                                      "[Service]\nExecStart=/bin/true\nKillMode=process\nKillMode=bogus\nKillSignal=SIGNOPE\nSendSIGHUP=maybe\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "reset.service",
                                      "[Service]\nExecStart=/bin/true\nKillMode=none\nKillMode=\nKillSignal=SIGUSR1\nKillSignal=\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "plain.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);

        for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
                char name[32];

                snprintf(name, sizeof(name), "k%zu.service", i);
                s = (Service *) load_one(m, name);
                ASSERT_EQ_INT(s->kill_mode, modes[i].want);
                ASSERT_EQ_INT(UNIT(s)->n_degraded_directives, 0);
        }
        s = (Service *) load_one(m, "sig.service");
        ASSERT_EQ_INT(s->kill_signal, SIGUSR1);
        ASSERT_EQ_INT(s->send_sighup, true);
        ASSERT_EQ_INT(s->send_sigkill, false);
        s = (Service *) load_one(m, "num.service");
        ASSERT_EQ_INT(s->kill_signal, SIGINT);
        s = (Service *) load_one(m, "bad.service");
        ASSERT_EQ_INT(s->kill_mode, KILL_PROCESS);
        ASSERT_EQ_INT(s->kill_signal, SIGTERM);
        ASSERT_EQ_INT(s->send_sighup, false);
        s = (Service *) load_one(m, "reset.service");
        ASSERT_EQ_INT(s->kill_mode, KILL_CONTROL_GROUP);
        ASSERT_EQ_INT(s->kill_signal, SIGTERM);
        s = (Service *) load_one(m, "plain.service");
        ASSERT_EQ_INT(s->kill_mode, KILL_CONTROL_GROUP);
        ASSERT_EQ_INT(s->kill_signal, SIGTERM);
        ASSERT_EQ_INT(s->send_sigkill, true);
        ASSERT_EQ_INT(s->send_sighup, false);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * ExecStop= goes through ExecStart='s own parse_exec_line(), so the prefix
 * rules are the same ones: '-' glued to the path is kept per line, '-'
 * separated from it by whitespace is refused, and the modifiers pico-init
 * does not implement (@ + ! !!) refuse the line and are recorded under
 * ExecStop='s own name. Unlike ExecStart=, every accepted line appends, and
 * an empty ExecStop= resets the list.
 */
static void test_exec_stop_lines(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "stops.service",
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"
                                      "ExecStop=-/bin/false one\n"
                                      "ExecStop=@/bin/true at\n"
                                      "ExecStop=- /bin/true spaced\n"
                                      "ExecStop=+/bin/true plus\n"
                                      "ExecStop=!!/bin/true bangbang\n"
                                      "ExecStop=bin/true relative\n"
                                      "ExecStop=/bin/true two\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "reset.service",
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"
                                      "ExecStop=/bin/true dropped\n"
                                      "ExecStop=\n"
                                      "ExecStop=/bin/true kept\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "nostop.service", "[Service]\nExecStart=/bin/true\n"), 0);

        m = manager_for(dir);

        u = load_one(m, "stops.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        s = (Service *) u;
        ASSERT_EQ_INT(s->n_exec_stop, 2);
        ASSERT_STREQ(s->exec_stop[0].argv[0], "/bin/false");
        ASSERT_STREQ(s->exec_stop[0].argv[1], "one");
        ASSERT_TRUE(s->exec_stop[0].argv[2] == NULL);
        ASSERT_EQ_INT(s->exec_stop[0].ignore, true);
        ASSERT_STREQ(s->exec_stop[1].argv[0], "/bin/true");
        ASSERT_STREQ(s->exec_stop[1].argv[1], "two");
        ASSERT_EQ_INT(s->exec_stop[1].ignore, false);

        /* "- /bin/true" and the relative path are refused with a warning,
         * not recorded: they are malformed, not unimplemented. */
        ASSERT_EQ_INT(u->n_degraded_directives, 3);
        ASSERT_STREQ(u->degraded_directives[0], "ExecStop=@");
        ASSERT_STREQ(u->degraded_directives[1], "ExecStop=+");
        ASSERT_STREQ(u->degraded_directives[2], "ExecStop=!");

        u = load_one(m, "reset.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        s = (Service *) u;
        ASSERT_EQ_INT(s->n_exec_stop, 1);
        ASSERT_STREQ(s->exec_stop[0].argv[1], "kept");
        ASSERT_EQ_INT(u->n_degraded_directives, 0);

        u = load_one(m, "nostop.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        s = (Service *) u;
        ASSERT_EQ_INT(s->n_exec_stop, 0);
        ASSERT_TRUE(s->exec_stop == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * ExecCondition=, ExecStopPost= and ExecReload= share ExecStop='s list
 * semantics: each line appends with its own '-' flag, an empty value
 * resets, a malformed line is refused alone. The first two are honoured and
 * leave no degradation; ExecReload= is stored but, with nothing to run it,
 * is recorded exactly once however many lines it has.
 */
static void test_exec_condition_stop_post_reload_lines(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;
        char *joined;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "lists.service",
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"
                                      "ExecCondition=/bin/true dropped\n"
                                      "ExecCondition=\n"
                                      "ExecCondition=-/bin/false one\n"
                                      "ExecCondition=/bin/true two\n"
                                      "ExecStopPost=/bin/true first\n"
                                      "ExecStopPost=bin/true relative\n"
                                      "ExecStopPost=-/bin/false second\n"
                                      "ExecReload=/bin/kill -HUP $MAINPID\n"
                                      "ExecReload=/bin/true again\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "reload-reset.service",
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"
                                      "ExecStopPost=/bin/true gone\n"
                                      "ExecStopPost=\n"
                                      "ExecReload=\n"),
                      0);

        m = manager_for(dir);

        u = load_one(m, "lists.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        s = (Service *) u;

        ASSERT_EQ_INT(s->n_exec_condition, 2);
        ASSERT_STREQ(s->exec_condition[0].argv[0], "/bin/false");
        ASSERT_STREQ(s->exec_condition[0].argv[1], "one");
        ASSERT_EQ_INT(s->exec_condition[0].ignore, true);
        ASSERT_STREQ(s->exec_condition[1].argv[1], "two");
        ASSERT_EQ_INT(s->exec_condition[1].ignore, false);

        ASSERT_EQ_INT(s->n_exec_stop_post, 2);
        ASSERT_STREQ(s->exec_stop_post[0].argv[1], "first");
        ASSERT_EQ_INT(s->exec_stop_post[0].ignore, false);
        ASSERT_STREQ(s->exec_stop_post[1].argv[0], "/bin/false");
        ASSERT_EQ_INT(s->exec_stop_post[1].ignore, true);

        ASSERT_EQ_INT(s->n_exec_reload, 2);
        ASSERT_STREQ(s->exec_reload[0].argv[0], "/bin/kill");
        ASSERT_STREQ(s->exec_reload[0].argv[2], "$MAINPID"); /* expanded at spawn, not here */
        ASSERT_STREQ(s->exec_reload[1].argv[1], "again");

        joined = unit_degraded_directives_string(u);
        ASSERT_STREQ(joined, "ExecReload");
        free(joined);

        u = load_one(m, "reload-reset.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        s = (Service *) u;
        ASSERT_EQ_INT(s->n_exec_stop_post, 0);
        ASSERT_TRUE(s->exec_stop_post == NULL);
        ASSERT_EQ_INT(s->n_exec_reload, 0);
        ASSERT_EQ_INT(s->n_exec_condition, 0);
        ASSERT_EQ_INT(u->n_degraded_directives, 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * systemd since v239 (7c891d53b "load-fragment: when parsing paths for
 * Exec*=, be more liberal"): a bare (slash-free) executable name is valid in
 * ExecStart= and friends, resolved against the search path at exec time
 * (service-exec.c's find_in_default_path()) rather than rejected here. The
 * real-world motivation is oe-core's own seatd.service, which ships exactly
 * this shape (see test_shipped_seatd_and_picowl_units_load() below).
 */
static void test_bare_exec_name_is_accepted(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "bare.service", "[Service]\nExecStart=seatd -g seat\n"), 0);

        m = manager_for(dir);
        u = load_one(m, "bare.service");
        s = (Service *) u;

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_TRUE(s->exec_start != NULL);
        ASSERT_STREQ(s->exec_start[0], "seatd"); /* kept bare -- not resolved at parse time */
        ASSERT_STREQ(s->exec_start[1], "-g");
        ASSERT_STREQ(s->exec_start[2], "seat");
        ASSERT_TRUE(s->exec_start[3] == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The other half of the same rule: a RELATIVE path that still contains a
 * '/' ("foo/bar") is neither absolute nor a bare filename, so it stays
 * rejected -- nothing (not this parser, not the exec-time lookup) has
 * anything to resolve it against. With no other ExecStart= line, the unit
 * ends up with none at all, which service_verify() refuses exactly as
 * test_b9 in test-service.c proves for a unit that never set ExecStart=.
 */
static void test_relative_exec_path_with_slash_is_rejected(void) {
        Manager *m;
        char *dir;
        Unit *u;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir, "relative.service", "[Service]\nExecStart=foo/bar\n"), 0);

        m = manager_for(dir);
        u = load_one(m, "relative.service");

        ASSERT_EQ_INT(u->load_state, UNIT_ERROR); /* refused, not silently loaded with no ExecStart= */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * SupplementaryGroups=: names and numeric gids in the same directive,
 * accumulating across repeated lines (upstream's own
 * config_parse_user_group_strv_compat() semantics), and a bad token (here,
 * one with an embedded '/') skipped with a warning rather than rejecting the
 * whole line -- this file's own Environment= precedent, not upstream's
 * reject-the-directive one (see config_parse_supplementary_groups()'s own
 * comment in unit-parse.c for why). Actually resolving/applying the list is
 * service-exec.c's job (test_supplementary_groups_applied() in
 * test-service.c); this is parse-time only.
 */
static void test_supplementary_groups_parsed(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "suppgroups.service",
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"
                                      "SupplementaryGroups=video 1000\n"
                                      "SupplementaryGroups=daemon not/valid\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "suppgroups.service");
        s = (Service *) u;

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        ASSERT_TRUE(s->supplementary_groups != NULL);
        ASSERT_STREQ(s->supplementary_groups[0], "video");
        ASSERT_STREQ(s->supplementary_groups[1], "1000");
        ASSERT_STREQ(s->supplementary_groups[2], "daemon"); /* accumulated from the second line */
        ASSERT_TRUE(s->supplementary_groups[3] == NULL);    /* "not/valid" skipped, not stored */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The stock oe-core seatd.service and a picowl.service as shipped
 * (directive lines only, verbatim). Both
 * carry a long run of directives pico-init has no field for at all
 * (ProtectHome=, CapabilityBoundingSet=, DeviceAllow=, ...): the point of
 * this test is that none of that stops either unit from loading with a
 * valid ExecStart=, which service_verify() would otherwise refuse (see
 * test_b9_service_verify_refuses_no_execstart() in test-service.c).
 */
static void test_shipped_seatd_and_picowl_units_load(void) {
        Manager *m;
        char *dir;
        Unit *u;
        Service *s;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        ASSERT_EQ_INT(test_write_file(dir,
                                      "seatd.service",
                                      "[Unit]\n"
                                      "Description=Seat management daemon\n"
                                      "Documentation=man:seatd(1)\n"
                                      "\n"
                                      "[Service]\n"
                                      "Type=simple\n"
                                      "ExecStart=seatd -g seat\n"
                                      "Restart=always\n"
                                      "RestartSec=1\n"
                                      "ProtectHome=true\n"
                                      "ProtectSystem=strict\n"
                                      "ProtectKernelTunables=true\n"
                                      "ProtectControlGroups=true\n"
                                      "PrivateTmp=true\n"
                                      "ProtectProc=invisible\n"
                                      "ProcSubset=pid\n"
                                      "UMask=0077\n"
                                      "NoNewPrivileges=true\n"
                                      "RestrictSUIDSGID=true\n"
                                      "PrivateNetwork=true\n"
                                      "IPAddressDeny=any\n"
                                      "SystemCallFilter=@system-service\n"
                                      "SystemCallFilter=~@resources\n"
                                      "SystemCallErrorNumber=EPERM\n"
                                      "SystemCallArchitectures=native\n"
                                      "ProtectKernelLogs=true\n"
                                      "ProtectKernelModules=true\n"
                                      "LockPersonality=true\n"
                                      "RestrictNamespaces=true\n"
                                      "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_CHOWN CAP_SYS_TTY_CONFIG CAP_DAC_OVERRIDE\n"
                                      "RestrictAddressFamilies=AF_UNIX\n"
                                      "RestrictRealtime=true\n"
                                      "MemoryDenyWriteExecute=true\n"
                                      "ProtectClock=true\n"
                                      "ProtectHostname=true\n"
                                      "DevicePolicy=strict\n"
                                      "DeviceAllow=char-/dev/console rw\n"
                                      "DeviceAllow=char-drm rw\n"
                                      "DeviceAllow=char-input rw\n"
                                      "DeviceAllow=char-tty rw\n"
                                      "DeviceAllow=/dev/null rw\n"
                                      "\n"
                                      "[Install]\n"
                                      "WantedBy=multi-user.target\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "picowl.service",
                                      "[Unit]\n"
                                      "Description=picowl Wayland compositor\n"
                                      "After=systemd-user-sessions.service seatd.service\n"
                                      "Wants=seatd.service\n"
                                      "Conflicts=getty@tty1.service\n"
                                      "After=getty@tty1.service\n"
                                      "\n"
                                      "[Service]\n"
                                      "Type=simple\n"
                                      "Environment=XDG_RUNTIME_DIR=/run/picowl\n"
                                      "ExecStartPre=/bin/mkdir -p -m 0700 /run/picowl\n"
                                      "ExecStart=/usr/bin/picowl\n"
                                      "Restart=on-failure\n"
                                      "RestartSec=3\n"
                                      "SupplementaryGroups=video\n"
                                      "TTYPath=/dev/tty1\n"
                                      "StandardInput=tty\n"
                                      "\n"
                                      "[Install]\n"
                                      "WantedBy=graphical.target\n"),
                      0);

        m = manager_for(dir);

        u = load_one(m, "seatd.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        s = (Service *) u;
        ASSERT_TRUE(s->exec_start != NULL);
        ASSERT_STREQ(s->exec_start[0], "seatd");
        ASSERT_STREQ(s->exec_start[1], "-g");
        ASSERT_STREQ(s->exec_start[2], "seat");

        u = load_one(m, "picowl.service");
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);
        s = (Service *) u;
        ASSERT_TRUE(s->exec_start != NULL);
        ASSERT_STREQ(s->exec_start[0], "/usr/bin/picowl");
        ASSERT_TRUE(s->supplementary_groups != NULL);
        ASSERT_STREQ(s->supplementary_groups[0], "video");
        ASSERT_TRUE(s->user == NULL); /* picowl's real shape: no User=/Group= at all */
        ASSERT_TRUE(s->group == NULL);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_service_fields();
        test_unknown_directives_are_tolerated();
        test_degradation_record();
        test_degradation_record_covers_deps_and_timeouts();
        test_repeated_exec_start_is_recorded();
        test_environment_directives();
        test_malformed_line_skips_only_that_line();
        test_bom_comments_and_continuations();
        test_comment_inside_continuation_is_skipped();
        test_quoting_and_glued_quotes();
        test_exec_c_escapes();
        test_exec_start_pre_list_and_reset();
        test_standard_output_and_error();
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
        test_type_dbus_and_idle_degrade_to_simple();
        test_forking_directives();
        test_exec_dash_prefix_sets_ignore();
        test_delegate();
        test_delegate_subgroup();
        test_kill_settings();
        test_exec_stop_lines();
        test_exec_condition_stop_post_reload_lines();
        test_bare_exec_name_is_accepted();
        test_relative_exec_path_with_slash_is_rejected();
        test_supplementary_groups_parsed();
        test_shipped_seatd_and_picowl_units_load();

        printf("test-unit-parse: all checks passed\n");
        return 0;
}
