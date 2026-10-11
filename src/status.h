/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Boot status output: the console PID 1 greets on and reports per-unit
 * progress to. A second output channel, separate from pico_log(), as in
 * systemd: the greeting and "[  OK  ] Started foo." lines are status_printf()
 * writes to /dev/console (src/core/show-status.c), while the version banner
 * is a log record (src/core/main.c).
 *
 *  - Greeting and per-unit progress come here. They are a running report on a
 *    console someone is watching, not diagnostics: a "pico-init[info]: "
 *    prefix would be noise, ANSI colour does not belong in the kernel ring,
 *    and mirroring them to /dev/kmsg would make picolog replay a second copy
 *    of every line the console already showed.
 *  - Anything to look up afterwards -- the identity line, warnings, a failed
 *    job -- stays on pico_log().
 *
 * Neither replaces the other: job.c logs a finished job and also prints its
 * status line, as upstream does.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "version.h"

/*
 * What PID 1 announces itself as, mirroring systemd's PROJECT_VERSION/
 * GIT_VERSION pair: the release number and the git description of the tree.
 * PICO_INIT_VERSION comes from meson's project() version, via a -D;
 * PICO_INIT_GIT_VERSION from vcs_tag(). Both in meson.build.
 */
#define PICO_INIT_VERSION_STRING PICO_INIT_VERSION " (" PICO_INIT_GIT_VERSION ")"

/* SGR sequences, byte for byte from systemd's src/basic/ansi-color.h. */
#define ANSI_NORMAL "\x1B[0m"
#define ANSI_GREEN "\x1B[0;32m"
#define ANSI_HIGHLIGHT "\x1B[0;1;39m"
#define ANSI_HIGHLIGHT_RED "\x1B[0;1;31m"

/*
 * systemd's ANSI_HIGHLIGHT_YELLOW is the 256-colour ANSI_HIGHLIGHT_KHAKI3
 * ("\x1B[0;1;38:5:185m"), which is only safe alongside the ColorMode
 * negotiation (src/basic/ansi-color.h) that falls back to
 * ANSI_HIGHLIGHT_YELLOW_FALLBACK, the value used here, on terminals without
 * 256 colours. console_colors_enabled() has no such negotiation, so the
 * 16-colour fallback is used unconditionally; serial consoles may not render
 * the 256-colour form.
 */
#define ANSI_HIGHLIGHT_YELLOW "\x1B[0;1;33m"

/*
 * The status word for a job that succeeded, verbatim from systemd's
 * job_done_messages[JOB_DONE] (src/core/job.c): six columns, "OK" centred,
 * so every bracket down the left edge has the same width.
 */
#define STATUS_WORD_OK "  OK  "

/*
 * And its colour: plain green, the default of systemd's 'ok-color' build
 * option (meson_options.txt), not the bold ANSI_HIGHLIGHT_GREEN.
 */
#define STATUS_COLOR_OK ANSI_GREEN

/*
 * The remaining three words systemd's job_done_messages[] (src/core/job.c)
 * actually prints to the console, same six columns, same colours.
 * JOB_CANCELED has no word there and gets none here; JobResult has no
 * counterpart for JOB_SKIPPED/JOB_COLLECTED/JOB_INVALID/etc.
 */
#define STATUS_WORD_FAILED "FAILED"
#define STATUS_COLOR_FAILED ANSI_HIGHLIGHT_RED

#define STATUS_WORD_TIMEOUT " TIME "
#define STATUS_COLOR_TIMEOUT ANSI_HIGHLIGHT_RED

#define STATUS_WORD_DEPENDENCY "DEPEND"
#define STATUS_COLOR_DEPENDENCY ANSI_HIGHLIGHT_YELLOW

/*
 * Start writing to /dev/console. Opt-in, like pico_log_to_kmsg(): this code
 * is linked into every test binary and into picoctl, which must not write to
 * the machine's console. Until PID 1 calls this, every function below is a
 * no-op.
 *
 * Falls back to stdout when /dev/console will not open; for an init that is
 * the same device (the kernel opens /dev/console as fd 0/1/2 for PID 1).
 */
void status_enable(void);

/*
 * Test seam: tests must not call status_enable() (it opens the real console)
 * but need the bytes job_finish_full() hands to status_printf(). This
 * redirects status_write() into `buf` (size `size`), with `color` standing in
 * for what console_colors_enabled() would decide, so both renderings are
 * reachable. Each call appends, so the lines of several status_printf() calls
 * land in `buf` in order.
 *
 * status_set_test_sink(NULL, 0, false) turns it off. Until a test calls this,
 * it is inert and status_fd stays -1.
 */
void status_set_test_sink(char *buf, size_t size, bool color);

/*
 * Print one status line: "[<word>] <message>", or just "<message>" when
 * `word` is NULL. `color` is dropped when the console is not colourable, so
 * callers always pass the colour they would like and never test for it.
 */
void status_printf(const char *word, const char *color, const char *format, ...)
                __attribute__((format(printf, 3, 4)));

/*
 * Compose one status line into `buf` exactly as it goes to the console,
 * returning its length. Split out of status_printf() so test-status.c can
 * assert the byte-level shape, bracket padding and escape sequences included.
 * Always NUL-terminates and, unless `buf` is too small to hold anything,
 * ends in a newline.
 */
size_t status_format_line(char *buf, size_t size, const char *word, const char *color, const char *text);

/* Greet the console with the distribution name from `path` (NULL for
 * OS_RELEASE_PATH). */
void status_welcome(const char *path);

/* As above, composed into `buf` rather than written, for the reason
 * status_format_line() gives. `color` is explicit here so a test can assert
 * both renderings without a console. */
size_t status_welcome_line(char *buf, size_t size, const char *path, bool color);
