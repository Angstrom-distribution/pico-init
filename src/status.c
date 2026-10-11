/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The console status channel. See status.h for why this is not pico_log().
 */

#include "status.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "os-release.h"
#include "util.h"

/* Disabled until status_enable(); see status.h for why that is opt-in. */
static int status_fd = -1;
static bool status_color = false;

/* Test seam; see status_set_test_sink() in status.h. NULL (the default)
 * means disabled, and status_write() below never looks at the other two. */
static char *test_sink_buf = NULL;
static size_t test_sink_size = 0;

/*
 * Colour unless the console says it is a dumb terminal, as systemd's
 * dev_console_colors_enabled() (src/basic/terminal-util.c): an unset TERM is
 * colourable, only the literal "dumb" is not.
 *
 * Its earlier $SYSTEMD_COLORS and $NO_COLOR checks are not carried over: PID 1
 * inherits almost no environment and has no kernel-command-line parser to
 * read one from. A terminfo probe is unnecessary: the console is a kernel VT
 * or a serial line, and both take SGR.
 */
static bool console_colors_enabled(void) {
        const char *term = getenv("TERM");

        return !term || strcmp(term, "dumb") != 0;
}

void status_enable(void) {
        int fd;

        if (status_fd >= 0)
                return;

        fd = open("/dev/console", O_WRONLY | O_NOCTTY | O_CLOEXEC);
        status_fd = fd >= 0 ? fd : STDOUT_FILENO;
        status_color = console_colors_enabled();
}

void status_set_test_sink(char *buf, size_t size, bool color) {
        test_sink_buf = buf;
        test_sink_size = size;
        status_color = color;

        if (buf && size > 0)
                buf[0] = '\0';
}

/* One write() per line, as in pico_log_internal(), so a line-oriented
 * destination does not have to reassemble a record. */
static void status_write(const char *buf, size_t n) {
        if (n == 0)
                return;

        if (test_sink_buf) {
                size_t have = strlen(test_sink_buf);

                /* Drop the line rather than append a partial one. */
                if (have + n < test_sink_size)
                        /* n + 1: status_format_line() always NUL-terminates at buf[n]. */
                        memcpy(test_sink_buf + have, buf, n + 1);
                return;
        }

        if (status_fd < 0)
                return;

        /* Not `(void) write(...)`: a void cast does not suppress
         * warn_unused_result -- see pico_log_internal(). */
        if (write(status_fd, buf, n) < 0) {
                /* Nothing useful to do here: this is the console. */
        }
}

size_t status_format_line(char *buf, size_t size, const char *word, const char *color, const char *text) {
        int n;

        if (!buf || size < 2) {
                if (buf && size > 0)
                        buf[0] = '\0';
                return 0;
        }

        if (word)
                n = snprintf(buf, size, "[%s%s%s] %s\n", color ? color : "", word, color ? ANSI_NORMAL : "", text);
        else
                n = snprintf(buf, size, "%s\n", text);

        if (n < 0) {
                buf[0] = '\0';
                return 0;
        }

        /* Truncated: keep the trailing newline so the next line does not
         * continue on the same console row. */
        if ((size_t) n >= size) {
                buf[size - 2] = '\n';
                return size - 1;
        }

        return (size_t) n;
}

void status_printf(const char *word, const char *color, const char *format, ...) {
        char text[512], line[1024];
        va_list ap;
        size_t n;

        if (status_fd < 0 && !test_sink_buf)
                return;

        va_start(ap, format);
        (void) vsnprintf(text, sizeof(text), format, ap);
        va_end(ap);

        n = status_format_line(line, sizeof(line), word, status_color ? color : NULL, text);
        status_write(line, n);
}

/*
 * ANSI_COLOR= is spliced straight into an SGR sequence, so only the bytes
 * that can legally appear in one are accepted; anything else between ESC[
 * and m could reprogram the terminal.
 */
static bool ansi_color_is_valid(const char *s) {
        return s && s[0] != '\0' && s[strspn(s, "0123456789;")] == '\0';
}

size_t status_welcome_line(char *buf, size_t size, const char *path, bool color) {
        char *pretty = NULL, *name = NULL, *ansi_color = NULL;
        const char *label, *sgr;
        char text[512];

        if (!path)
                path = OS_RELEASE_PATH;

        /*
         * PRETTY_NAME, then NAME, then "Linux" (systemd's
         * os_release_pretty_name() fallback chain), so a missing file, key or
         * empty value does not produce "Welcome to !". NAME is only read when
         * needed.
         */
        (void) os_release_get(path, "PRETTY_NAME", &pretty);
        if (!pretty || pretty[0] == '\0')
                (void) os_release_get(path, "NAME", &name);

        if (pretty && pretty[0] != '\0')
                label = pretty;
        else if (name && name[0] != '\0')
                label = name;
        else
                label = "Linux";

        /*
         * Byte for byte systemd's greeting (os_release_status(),
         * src/core/main.c):
         *
         *   "\n" ANSI_HIGHLIGHT "Welcome to " ANSI_NORMAL "%s" ANSI_NORMAL
         *   ANSI_HIGHLIGHT "!" ANSI_NORMAL "\n"
         *
         * with the name itself wrapped in whatever SGR parameters os-release
         * names in ANSI_COLOR=, defaulting to "1" (bold) when it names none.
         * The blank line either side is upstream's too.
         */
        if (color) {
                (void) os_release_get(path, "ANSI_COLOR", &ansi_color);
                sgr = ansi_color_is_valid(ansi_color) ? ansi_color : "1";

                (void) snprintf(text,
                                sizeof(text),
                                "\n" ANSI_HIGHLIGHT "Welcome to " ANSI_NORMAL
                                "\x1B[%sm%s" ANSI_NORMAL ANSI_HIGHLIGHT "!" ANSI_NORMAL "\n",
                                sgr,
                                label);
        } else
                (void) snprintf(text, sizeof(text), "\nWelcome to %s!\n", label);

        pretty = pico_mfree(pretty);
        name = pico_mfree(name);
        ansi_color = pico_mfree(ansi_color);

        return status_format_line(buf, size, NULL, NULL, text);
}

void status_welcome(const char *path) {
        char line[1024];
        size_t n;

        if (status_fd < 0 && !test_sink_buf)
                return;

        n = status_welcome_line(line, sizeof(line), path, status_color);
        status_write(line, n);
}
