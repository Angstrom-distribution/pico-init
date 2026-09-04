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
 * than sharing one.
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
                                      "ConditionPathExists=/a/two\n"
                                      "\n"
                                      "[Service]\n"
                                      "ExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);
        u = load_one(m, "cond.service");

        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);

        ASSERT_EQ_INT((int) pico_strv_length(u->condition_path_exists), 2);
        ASSERT_STREQ(u->condition_path_exists[0], "/a/one");
        ASSERT_STREQ(u->condition_path_exists[1], "/a/two");

        ASSERT_EQ_INT((int) pico_strv_length(u->condition_path_is_directory), 1);
        ASSERT_STREQ(u->condition_path_is_directory[0], "/a/dir");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The three spellings this MVP does not implement -- negated, triggering,
 * relative -- are dropped with a warning rather than failing the unit, and an
 * empty value resets whatever the same directive had already accumulated.
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
                                      "ConditionPathExists=!/a/neg\n"
                                      "ConditionPathExists=|/a/trigger\n"
                                      "ConditionPathExists=relative/path\n"
                                      "ConditionPathIsDirectory=/a/dir\n"
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
        /* the trailing empty value reset the list the line above had filled */
        ASSERT_TRUE(u->condition_path_is_directory == NULL);

        ASSERT_STREQ(((Service *) u)->exec_start[0], "/bin/true");

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_service_fields();
        test_unknown_directives_are_tolerated();
        test_malformed_line_skips_only_that_line();
        test_bom_comments_and_continuations();
        test_quoting_and_trailing_garbage();
        test_invalid_dependency_names_are_rejected();
        test_huge_requires_line_does_not_crash();
        test_conditions_are_parsed();
        test_unsupported_condition_values_are_dropped();

        printf("test-unit-parse: all checks passed\n");
        return 0;
}
