/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Colour tests for netctl's `status`/`status <iface>`/`list` output.
 *
 * The rendering lives in netctl.c's own static functions (status_one(),
 * status_all(), cmd_list(), and their colour helpers operational_color()/
 * setup_color()/online_color()/field_label_color()) -- file-local statics
 * with no header, and netctl.c is its own standalone executable with no
 * netctl-core library the way test-picoctl.c's own header already explains
 * for picoctl. So, like that file (and test-tmpfiles-create.c), this runs
 * the REAL built `netctl` binary as a subprocess -- found via /proc/self/exe,
 * since both land in the same meson build root -- rather than linking any
 * of netctl.c's own code into this test.
 *
 * Fixture is the loopback interface, "lo": every test namespace has one, so
 * no root/network setup is needed. Its real operational/setup words aren't
 * assumed (environments differ); each test reads them back from a
 * colours-disabled run first, then checks that a colours-forced run wraps
 * exactly the expected escape bytes around that same real value -- an
 * independent oracle reproduction of netctl.c's own colour rules (the same
 * upstream spec its own operational_color()/setup_color()/online_color()
 * mirror), not a call into netctl.c's code under test.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../test-util.h"

/* --- running the real netctl binary as a subprocess, as test-picoctl.c does --- */

static int sibling_binary_path(const char *name, char *out, size_t out_size) {
        char self[PATH_MAX];
        ssize_t n;
        char *slash;

        n = readlink("/proc/self/exe", self, sizeof(self) - 1);
        if (n < 0)
                return -errno;
        self[n] = '\0';

        slash = strrchr(self, '/');
        if (!slash)
                return -ENOENT;
        *slash = '\0';

        n = snprintf(out, out_size, "%s/%s", self, name);
        if (n < 0 || (size_t) n >= out_size)
                return -ENAMETOOLONG;
        return 0;
}

struct run_result {
        char out[16384];
        int exit_code;
};

/* Fork/exec `path` with `args`, *stdout only* captured into res->out --
 * same split as test-picoctl.c's run_binary() and for the same reason: a
 * failing assertion's stderr context stays visible under `meson test -v`
 * instead of getting mixed into the golden-output comparison. */
static int run_binary(const char *path, char * const args[], struct run_result *res) {
        int pipefd[2];
        pid_t pid;
        int status;
        size_t total = 0;

        res->out[0] = '\0';
        res->exit_code = -1;

        if (pipe(pipefd) < 0)
                return -errno;

        pid = fork();
        if (pid < 0) {
                close(pipefd[0]);
                close(pipefd[1]);
                return -errno;
        }

        if (pid == 0) {
                close(pipefd[0]);
                dup2(pipefd[1], STDOUT_FILENO);
                close(pipefd[1]);
                execv(path, args);
                _exit(127);
        }

        close(pipefd[1]);
        for (;;) {
                char buf[1024];
                ssize_t r = read(pipefd[0], buf, sizeof(buf));

                if (r <= 0)
                        break;
                if (total + (size_t) r < sizeof(res->out) - 1) {
                        memcpy(res->out + total, buf, (size_t) r);
                        total += (size_t) r;
                }
        }
        res->out[total] = '\0';
        close(pipefd[0]);

        if (waitpid(pid, &status, 0) < 0)
                return -errno;

        res->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        return 0;
}

/* --- the independent oracle: same spec netctl.c's own colour helpers mirror --- */

/* Quarried the same way as netctl.c's own helpers and pico-color.c, from
 * systemd main as of commit 4c63532c28094aeba6dccc5afb9690e02fd98d66
 * (2026-10-04): src/basic/ansi-color.h's ANSI_* literals, and
 * src/shared/format-table.c's table_data_color() default for an
 * uncoloured TABLE_FIELD cell (ANSI_BRIGHT_BLUE). Kept as literal escape
 * bytes here rather than pico-color.h's accessors on purpose: the point of
 * this file is to check netctl's actual bytes against the spec
 * independently, not against pico-color.c's own implementation of it.
 */
#define T_ANSI_NORMAL "\x1B[0m"
#define T_ANSI_HIGHLIGHT_GREEN "\x1B[0;1;32m"
#define T_ANSI_HIGHLIGHT_YELLOW "\x1B[0;1;38:5:185m"
#define T_ANSI_HIGHLIGHT_RED "\x1B[0;1;31m"
#define T_ANSI_BRIGHT_BLUE "\x1B[0;94m"
#define T_LABEL_WIDTH 28 /* mirrors netctl.c's own LABEL_WIDTH */

static void oracle_operational_color(const char *ifname, const char *state, const char **on, const char **off) {
        if (strcmp(state, "routable") == 0 || strcmp(state, "enslaved") == 0 ||
            (ifname && strcmp(ifname, "lo") == 0 && strcmp(state, "carrier") == 0)) {
                *on = T_ANSI_HIGHLIGHT_GREEN;
                *off = T_ANSI_NORMAL;
        } else if (strcmp(state, "degraded") == 0) {
                *on = T_ANSI_HIGHLIGHT_YELLOW;
                *off = T_ANSI_NORMAL;
        } else {
                *on = "";
                *off = "";
        }
}

static void oracle_setup_color(const char *state, const char **on, const char **off) {
        if (strcmp(state, "configured") == 0) {
                *on = T_ANSI_HIGHLIGHT_GREEN;
                *off = T_ANSI_NORMAL;
        } else if (strcmp(state, "configuring") == 0) {
                *on = T_ANSI_HIGHLIGHT_YELLOW;
                *off = T_ANSI_NORMAL;
        } else if (strcmp(state, "failed") == 0 || strcmp(state, "linger") == 0) {
                *on = T_ANSI_HIGHLIGHT_RED;
                *off = T_ANSI_NORMAL;
        } else {
                *on = "";
                *off = "";
        }
}

static void oracle_online_color(const char *state, const char **on, const char **off) {
        if (strcmp(state, "online") == 0) {
                *on = T_ANSI_HIGHLIGHT_GREEN;
                *off = T_ANSI_NORMAL;
        } else if (strcmp(state, "partial") == 0) {
                *on = T_ANSI_HIGHLIGHT_YELLOW;
                *off = T_ANSI_NORMAL;
        } else {
                *on = "";
                *off = "";
        }
}

/* --- hand-rolled, bounded parsing of netctl's own plain (colourless) output --- */

/* `list`'s row for `ifname`: finds " <ifname> " (unique enough -- no TYPE
 * value is ever literally an interface name), then reads the TYPE column
 * past it, then OPERATIONAL into `op`, then SETUP (rest of the line) into
 * `setup`. Bounded copies throughout, no snprintf of an unbounded source. */
static bool find_list_row(
                const char *output, const char *ifname, char *op, size_t opsz, char *setup, size_t setupsz) {
        char needle[40];
        const char *p;
        size_t i;

        snprintf(needle, sizeof needle, " %s ", ifname);
        p = strstr(output, needle);
        if (!p)
                return false;
        p += strlen(needle);

        while (*p == ' ')
                p++;
        while (*p && *p != ' ') /* TYPE column */
                p++;
        while (*p == ' ')
                p++;

        i = 0;
        while (*p && *p != ' ' && i + 1 < opsz)
                op[i++] = *p++;
        op[i] = '\0';

        while (*p == ' ')
                p++;
        i = 0;
        while (*p && *p != '\n' && i + 1 < setupsz)
                setup[i++] = *p++;
        setup[i] = '\0';

        return op[0] != '\0' && setup[0] != '\0';
}

/* Per-link status's "State: <op> (<setup>)" row. */
static bool parse_state_with_setup(const char *output, char *op, size_t opsz, char *setup, size_t setupsz) {
        const char *p = strstr(output, "State:");
        size_t i;

        if (!p)
                return false;
        p += strlen("State:");
        while (*p == ' ')
                p++;

        i = 0;
        while (*p && *p != ' ' && i + 1 < opsz)
                op[i++] = *p++;
        op[i] = '\0';

        while (*p == ' ')
                p++;
        if (*p != '(')
                return false;
        p++;

        i = 0;
        while (*p && *p != ')' && i + 1 < setupsz)
                setup[i++] = *p++;
        setup[i] = '\0';

        return op[0] != '\0' && setup[0] != '\0';
}

/* System-wide status's "State: <op>" row (no parenthesised setup state). */
static bool parse_state_only(const char *output, char *op, size_t opsz) {
        const char *p = strstr(output, "State:");
        size_t i;

        if (!p)
                return false;
        p += strlen("State:");
        while (*p == ' ')
                p++;

        i = 0;
        while (*p && *p != '\n' && i + 1 < opsz)
                op[i++] = *p++;
        op[i] = '\0';

        return op[0] != '\0';
}

static void assert_contains(const char *haystack, const char *needle, const char *what) {
        if (!strstr(haystack, needle)) {
                fprintf(stderr, "%s: expected coloured fragment not found in netctl's own output\n", what);
                exit(1);
        }
}

/* --- the tests --- */

/* With colours off (the default here: stdout is a pipe, never a tty), every
 * command's output must stay exactly what it was before this change -- no
 * ESC byte anywhere. Existing golden-output expectations elsewhere rely on
 * this. */
static void test_colors_disabled_no_escapes(const char *netctl_path) {
        struct run_result res;
        char *args_list[] = { (char *) netctl_path, "list", NULL };
        char *args_status[] = { (char *) netctl_path, "status", NULL };
        char *args_status_lo[] = { (char *) netctl_path, "status", "lo", NULL };

        unsetenv("SYSTEMD_COLORS");

        ASSERT_EQ_INT(run_binary(netctl_path, args_list, &res), 0);
        ASSERT_TRUE(strchr(res.out, '\x1B') == NULL);

        ASSERT_EQ_INT(run_binary(netctl_path, args_status, &res), 0);
        ASSERT_TRUE(strchr(res.out, '\x1B') == NULL);

        ASSERT_EQ_INT(run_binary(netctl_path, args_status_lo, &res), 0);
        ASSERT_TRUE(strchr(res.out, '\x1B') == NULL);
}

/* `netctl list`'s OPERATIONAL and SETUP columns, coloured. */
static void test_list_colors(const char *netctl_path) {
        struct run_result plain, colored;
        char *args[] = { (char *) netctl_path, "list", NULL };
        char op[32], setup[32];
        char op_padded[48], expect_op[80], expect_setup[64];
        const char *on_op, *off_op, *on_setup, *off_setup;

        unsetenv("SYSTEMD_COLORS");
        ASSERT_EQ_INT(run_binary(netctl_path, args, &plain), 0);
        ASSERT_TRUE(find_list_row(plain.out, "lo", op, sizeof op, setup, sizeof setup));

        oracle_operational_color("lo", op, &on_op, &off_op);
        oracle_setup_color(setup, &on_setup, &off_setup);

        setenv("SYSTEMD_COLORS", "true", 1);
        ASSERT_EQ_INT(run_binary(netctl_path, args, &colored), 0);
        unsetenv("SYSTEMD_COLORS");

        /* OPERATIONAL is left-justified to 11 columns (netctl.c's own
         * "%-11s") before the colour wraps around it -- the escape bytes
         * add no visible width, so padding happens first, same as netctl.c
         * itself relies on. */
        snprintf(op_padded, sizeof op_padded, "%-11s", op);
        snprintf(expect_op, sizeof expect_op, "%s%s%s", on_op, op_padded, off_op);
        assert_contains(colored.out, expect_op, "list: OPERATIONAL column");

        /* SETUP is the last column: no padding. */
        snprintf(expect_setup, sizeof expect_setup, "%s%s%s", on_setup, setup, off_setup);
        assert_contains(colored.out, expect_setup, "list: SETUP column");
}

/* `netctl status lo`: bullet, State row (both halves), Online state row,
 * and the "State"/"Online state" field labels' own colour. */
static void test_status_one_colors(const char *netctl_path) {
        struct run_result plain, colored;
        char *args[] = { (char *) netctl_path, "status", "lo", NULL };
        char op[32], setup[32];
        char expect_bullet[32], expect_state[160], expect_label_state[80], expect_online_row[160];
        const char *on_op, *off_op, *on_setup, *off_setup, *on_online, *off_online;

        unsetenv("SYSTEMD_COLORS");
        ASSERT_EQ_INT(run_binary(netctl_path, args, &plain), 0);
        ASSERT_TRUE(parse_state_with_setup(plain.out, op, sizeof op, setup, sizeof setup));

        oracle_operational_color("lo", op, &on_op, &off_op);
        oracle_setup_color(setup, &on_setup, &off_setup);
        oracle_online_color("unknown", &on_online, &off_online);

        setenv("SYSTEMD_COLORS", "true", 1);
        ASSERT_EQ_INT(run_binary(netctl_path, args, &colored), 0);
        unsetenv("SYSTEMD_COLORS");

        /* Bullet: coloured the same as State's operational half. */
        snprintf(expect_bullet, sizeof expect_bullet, "%s\xe2\x97\x8f%s", on_op, off_op);
        assert_contains(colored.out, expect_bullet, "status lo: bullet");

        /* State row's value: "<op> (<setup>)", each half in its own colour. */
        snprintf(expect_state, sizeof expect_state, "%s%s%s (%s%s%s)", on_op, op, off_op, on_setup, setup, off_setup);
        assert_contains(colored.out, expect_state, "status lo: State value");

        /* "State" field label itself: bright blue, padding-included, exactly
         * as real networkctl's vertical table colours every TABLE_FIELD
         * cell with no colour of its own. */
        snprintf(expect_label_state,
                 sizeof expect_label_state,
                 "%s%*s:%s",
                 T_ANSI_BRIGHT_BLUE,
                 T_LABEL_WIDTH,
                 "State",
                 T_ANSI_NORMAL);
        assert_contains(colored.out, expect_label_state, "status lo: \"State\" label colour");

        /* Online state is always "unknown" here (netd has no online-state
         * concept) -- online_state_to_color() leaves that plain, so only
         * the label is coloured, never the value. */
        snprintf(expect_online_row,
                 sizeof expect_online_row,
                 "%s%*s:%s %s%s%s",
                 T_ANSI_BRIGHT_BLUE,
                 T_LABEL_WIDTH,
                 "Online state",
                 T_ANSI_NORMAL,
                 on_online,
                 "unknown",
                 off_online);
        assert_contains(colored.out, expect_online_row, "status lo: \"Online state\" row");
}

/* `netctl status` (system-wide): same bullet/State/Online-state rules,
 * applied to the aggregate state rather than one link's. */
static void test_status_all_colors(const char *netctl_path) {
        struct run_result plain, colored;
        char *args[] = { (char *) netctl_path, "status", NULL };
        char op[32];
        char expect_bullet[32], expect_state[64], expect_online_row[160];
        const char *on_op, *off_op, *on_online, *off_online;

        unsetenv("SYSTEMD_COLORS");
        ASSERT_EQ_INT(run_binary(netctl_path, args, &plain), 0);
        ASSERT_TRUE(parse_state_only(plain.out, op, sizeof op));

        /* System-wide status passes no particular ifname (operational_state_to_color(NULL, ...)
         * upstream), so the "lo" special case never applies here. */
        oracle_operational_color(NULL, op, &on_op, &off_op);
        oracle_online_color("unknown", &on_online, &off_online);

        setenv("SYSTEMD_COLORS", "true", 1);
        ASSERT_EQ_INT(run_binary(netctl_path, args, &colored), 0);
        unsetenv("SYSTEMD_COLORS");

        snprintf(expect_bullet, sizeof expect_bullet, "%s\xe2\x97\x8f%s", on_op, off_op);
        assert_contains(colored.out, expect_bullet, "status: bullet");

        snprintf(expect_state, sizeof expect_state, "%s%s%s", on_op, op, off_op);
        assert_contains(colored.out, expect_state, "status: State value");

        snprintf(expect_online_row,
                 sizeof expect_online_row,
                 "%s%*s:%s %s%s%s",
                 T_ANSI_BRIGHT_BLUE,
                 T_LABEL_WIDTH,
                 "Online state",
                 T_ANSI_NORMAL,
                 on_online,
                 "unknown",
                 off_online);
        assert_contains(colored.out, expect_online_row, "status: \"Online state\" row");
}

int main(void) {
        char netctl_path[PATH_MAX];

        ASSERT_EQ_INT(sibling_binary_path("netctl", netctl_path, sizeof(netctl_path)), 0);

        test_colors_disabled_no_escapes(netctl_path);
        test_list_colors(netctl_path);
        test_status_one_colors(netctl_path);
        test_status_all_colors(netctl_path);

        return 0;
}
