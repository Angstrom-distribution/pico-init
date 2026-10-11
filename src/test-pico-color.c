/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-color.c's env-matrix: every rule pico_colors_enabled() mirrors from
 * systemd's get_color_mode_impl() (see pico-color.h), each exercised in
 * isolation.
 *
 * Each case forks: the cache is global per-process state, and the decision
 * depends on isatty(STDOUT_FILENO), which only a real fd change can flip, so
 * a fresh child with its own redirected stdout is the only way to
 * cover both the tty and non-tty sides of the TERM/NO_COLOR checks. A
 * child's stdout is either /dev/null (guaranteed non-tty) or one end of a
 * freshly opened pty (guaranteed a tty, without needing to become its
 * session's controlling terminal -- isatty() only cares that the fd is a
 * terminal device, not that the process is attached to it as one).
 */

#define _GNU_SOURCE /* ptsname_r() */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "pico-color.h"
#include "test-util.h"

typedef struct {
        const char *name;
        const char *systemd_colors; /* NULL = unset */
        const char *no_color;       /* NULL = unset */
        const char *term;           /* NULL = unset */
        bool tty;
        bool expect_enabled;
} ColorCase;

static const ColorCase cases[] = {
        /* Auto-detect, no $SYSTEMD_COLORS override. */
        {                           "non-tty stdout, sane TERM",    NULL, NULL, "xterm", false, false },
        {                           "tty, sane TERM -> enabled",    NULL, NULL, "xterm",  true,  true },
        {                                      "tty, TERM=dumb",    NULL, NULL,  "dumb",  true, false },
        {                                     "tty, TERM unset",    NULL, NULL,    NULL,  true, false },
        {                        "tty, sane TERM, NO_COLOR set",    NULL,  "1", "xterm",  true, false },

        /* $SYSTEMD_COLORS as a boolean: forces the decision, skipping every
         * other check, in both directions and both cases of each spelling. */
        {            "SYSTEMD_COLORS=false beats tty+sane TERM", "false", NULL, "xterm",  true, false },
        {                "SYSTEMD_COLORS=0 beats tty+sane TERM",     "0", NULL, "xterm",  true, false },
        {                   "SYSTEMD_COLORS=true beats non-tty",  "true", NULL, "xterm", false,  true },
        { "SYSTEMD_COLORS=YES (case-insensitive) beats non-tty",   "YES", NULL, "xterm", false,  true },
        {              "SYSTEMD_COLORS=true beats NO_COLOR too",  "true",  "1", "xterm", false,  true },

        /* $SYSTEMD_COLORS as a depth: pico-init has no depth, so any
         * recognized one just forces colour on, same as a boolean true. */
        {                     "SYSTEMD_COLORS=16 beats non-tty",    "16", NULL,    NULL, false,  true },
        {                    "SYSTEMD_COLORS=256 beats non-tty",   "256", NULL,    NULL, false,  true },
        {                  "SYSTEMD_COLORS=24bit beats non-tty", "24bit", NULL,    NULL, false,  true },

        /* An unrecognized $SYSTEMD_COLORS value (including upstream's own
         * "auto-*" modes, not reproduced here) is neither a boolean nor a
         * depth, so it falls through to auto-detection rather than forcing
         * anything -- proven both ways, non-tty and tty. */
        {        "SYSTEMD_COLORS=bogus falls through (non-tty)", "bogus", NULL, "xterm", false, false },
        {            "SYSTEMD_COLORS=bogus falls through (tty)", "bogus", NULL, "xterm",  true,  true },
};

static int open_pty_slave(int *master_out) {
        int master, slave;
        char name[64];

        master = posix_openpt(O_RDWR | O_NOCTTY);
        ASSERT_TRUE(master >= 0);
        ASSERT_EQ_INT(grantpt(master), 0);
        ASSERT_EQ_INT(unlockpt(master), 0);
        ASSERT_EQ_INT(ptsname_r(master, name, sizeof(name)), 0);

        slave = open(name, O_RDWR | O_NOCTTY);
        ASSERT_TRUE(slave >= 0);

        *master_out = master;
        return slave;
}

static void run_case(const ColorCase *c) {
        int fd, master = -1, status;
        pid_t pid;

        fd = c->tty ? open_pty_slave(&master) : open("/dev/null", O_WRONLY);
        ASSERT_TRUE(fd >= 0);

        pid = fork();
        ASSERT_TRUE(pid >= 0);

        if (pid == 0) {
                if (master >= 0)
                        close(master);

                dup2(fd, STDOUT_FILENO);
                close(fd);

                /* Fresh slate: a forked child keeps the parent's cache
                 * (if the parent ever computed one) and environment, and
                 * this test wants neither to leak between cases. */
                pico_colors_reset_cache();
                unsetenv("SYSTEMD_COLORS");
                unsetenv("NO_COLOR");
                unsetenv("TERM");
                if (c->systemd_colors)
                        setenv("SYSTEMD_COLORS", c->systemd_colors, 1);
                if (c->no_color)
                        setenv("NO_COLOR", c->no_color, 1);
                if (c->term)
                        setenv("TERM", c->term, 1);

                _exit(pico_colors_enabled() ? 0 : 1);
        }

        close(fd);
        ASSERT_EQ_INT(waitpid(pid, &status, 0), pid);
        if (master >= 0)
                close(master);

        ASSERT_TRUE(WIFEXITED(status));
        if (WEXITSTATUS(status) != (c->expect_enabled ? 0 : 1)) {
                fprintf(stderr,
                        "test-pico-color: case \"%s\": expected enabled=%d, got exit %d\n",
                        c->name,
                        c->expect_enabled,
                        WEXITSTATUS(status));
                exit(1);
        }
}

/*
 * The accessors themselves, forced both ways via $SYSTEMD_COLORS (sidesteps
 * needing a real/no tty in THIS process) and checked against the literal
 * upstream byte sequences -- not just the on/off boolean.
 */
static void test_accessors_follow_enabled_state(void) {
        setenv("SYSTEMD_COLORS", "true", 1);
        pico_colors_reset_cache();
        ASSERT_TRUE(pico_colors_enabled());
        ASSERT_STREQ(pico_ansi_normal(), "\x1B[0m");
        ASSERT_STREQ(pico_ansi_highlight(), "\x1B[0;1;39m");
        ASSERT_STREQ(pico_ansi_highlight_red(), "\x1B[0;1;31m");
        ASSERT_STREQ(pico_ansi_highlight_green(), "\x1B[0;1;32m");
        ASSERT_STREQ(pico_ansi_highlight_yellow(), "\x1B[0;1;38:5:185m");
        ASSERT_STREQ(pico_ansi_highlight_cyan(), "\x1B[0;1;36m");
        ASSERT_STREQ(pico_ansi_green(), "\x1B[0;32m");
        ASSERT_STREQ(pico_ansi_blue(), "\x1B[0;34m");
        ASSERT_STREQ(pico_ansi_grey(), "\x1B[0;38:5:245m");
        ASSERT_STREQ(pico_ansi_underline(), "\x1B[0;4m");

        setenv("SYSTEMD_COLORS", "false", 1);
        pico_colors_reset_cache();
        ASSERT_TRUE(!pico_colors_enabled());
        ASSERT_EQ_INT(strlen(pico_ansi_normal()), 0);
        ASSERT_EQ_INT(strlen(pico_ansi_highlight_red()), 0);
        ASSERT_EQ_INT(strlen(pico_ansi_highlight_yellow()), 0);
        ASSERT_EQ_INT(strlen(pico_ansi_grey()), 0);
        ASSERT_EQ_INT(strlen(pico_ansi_underline()), 0);

        unsetenv("SYSTEMD_COLORS");
        pico_colors_reset_cache();
}

int main(void) {
        test_accessors_follow_enabled_state();

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
                run_case(&cases[i]);

        printf("test-pico-color: %zu env-matrix cases, colour on/off rules verified\n",
               sizeof(cases) / sizeof(cases[0]));
        return 0;
}
