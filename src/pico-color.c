/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * See pico-color.h for the rules this mirrors and the two
 * simplifications. ANSI_* literal values below are copied byte-for-byte
 * from systemd's src/basic/ansi-color.h, main as of commit
 * 4c63532c28094aeba6dccc5afb9690e02fd98d66 (2026-10-04).
 */

#include "pico-color.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define PICO_ANSI_NORMAL "\x1B[0m"
#define PICO_ANSI_HIGHLIGHT "\x1B[0;1;39m"
#define PICO_ANSI_HIGHLIGHT_RED "\x1B[0;1;31m"
#define PICO_ANSI_HIGHLIGHT_GREEN "\x1B[0;1;32m"
#define PICO_ANSI_HIGHLIGHT_YELLOW "\x1B[0;1;38:5:185m" /* upstream ANSI_HIGHLIGHT_KHAKI3 */
#define PICO_ANSI_HIGHLIGHT_CYAN "\x1B[0;1;36m"
#define PICO_ANSI_GREEN "\x1B[0;32m"
#define PICO_ANSI_BLUE "\x1B[0;34m"
#define PICO_ANSI_GREY "\x1B[0;38:5:245m"
#define PICO_ANSI_UNDERLINE "\x1B[0;4m"

/* -1 = not yet computed, 0/1 after. Mirrors upstream's cached_color_mode. */
static int cached_enabled = -1;

/*
 * Upstream's parse_boolean() (src/basic/parse-util.c): case-insensitive,
 * exactly these tokens either way, nothing else. Returns 1, 0, or -1 (not a
 * boolean -- caller falls through to the depth/auto-detect checks).
 */
static int parse_bool_like(const char *v) {
        static const char * const truthy[] = { "1", "yes", "y", "true", "t", "on" };
        static const char * const falsy[] = { "0", "no", "n", "false", "f", "off" };

        for (size_t i = 0; i < sizeof(truthy) / sizeof(truthy[0]); i++)
                if (strcasecmp(v, truthy[i]) == 0)
                        return 1;
        for (size_t i = 0; i < sizeof(falsy) / sizeof(falsy[0]); i++)
                if (strcasecmp(v, falsy[i]) == 0)
                        return 0;

        return -1;
}

static bool compute_colors_enabled(void) {
        const char *e = getenv("SYSTEMD_COLORS");

        if (e) {
                int b = parse_bool_like(e);

                if (b == 1)
                        return true; /* forced on: skips NO_COLOR/tty/TERM entirely */
                if (b == 0)
                        return false; /* forced off, same priority */

                /* A depth value forces colour on too -- pico-init has no
                 * depth of its own, any recognized one just means "on". */
                if (strcmp(e, "16") == 0 || strcmp(e, "256") == 0 || strcmp(e, "24bit") == 0)
                        return true;

                /* Anything else (including upstream's own "auto-16"/
                 * "auto-256"/"auto-24bit" modes) falls through below,
                 * matching upstream's handling of an unparsed value. */
        }

        if (getenv("NO_COLOR"))
                return false;

        if (!isatty(STDOUT_FILENO))
                return false;

        const char *term = getenv("TERM");
        if (!term || strcmp(term, "dumb") == 0)
                return false;

        return true;
}

bool pico_colors_enabled(void) {
        if (cached_enabled < 0)
                cached_enabled = compute_colors_enabled() ? 1 : 0;

        return cached_enabled;
}

void pico_colors_reset_cache(void) {
        cached_enabled = -1;
}

#define DEFINE_PICO_ANSI_FUNC(name, SEQ)                 \
        const char *pico_ansi_##name(void) {             \
                return pico_colors_enabled() ? SEQ : ""; \
        }

DEFINE_PICO_ANSI_FUNC(normal, PICO_ANSI_NORMAL)
DEFINE_PICO_ANSI_FUNC(highlight, PICO_ANSI_HIGHLIGHT)
DEFINE_PICO_ANSI_FUNC(highlight_red, PICO_ANSI_HIGHLIGHT_RED)
DEFINE_PICO_ANSI_FUNC(highlight_green, PICO_ANSI_HIGHLIGHT_GREEN)
DEFINE_PICO_ANSI_FUNC(highlight_yellow, PICO_ANSI_HIGHLIGHT_YELLOW)
DEFINE_PICO_ANSI_FUNC(highlight_cyan, PICO_ANSI_HIGHLIGHT_CYAN)
DEFINE_PICO_ANSI_FUNC(green, PICO_ANSI_GREEN)
DEFINE_PICO_ANSI_FUNC(blue, PICO_ANSI_BLUE)
DEFINE_PICO_ANSI_FUNC(grey, PICO_ANSI_GREY)
DEFINE_PICO_ANSI_FUNC(underline, PICO_ANSI_UNDERLINE)
