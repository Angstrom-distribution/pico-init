/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Boot status output: the console PID 1 greets on and reports per-unit
 * progress to. A second output channel, deliberately not pico_log().
 *
 * WHY A SECOND CHANNEL, when util.c already has one. Because upstream has
 * two, and the reasons carry over unchanged. systemd's greeting and its
 * "[  OK  ] Started foo." lines are not log records at all: they are
 * status_printf() writes to /dev/console (src/core/show-status.c), while the
 * version banner emitted a few lines away from the greeting IS a log record
 * (log_info("systemd " GIT_VERSION " running in %ssystem mode (%s)"),
 * src/core/main.c). This project splits it the same way:
 *
 *  - Greeting and per-unit progress come here. They are not diagnostics but a
 *    running report on a console someone is watching. A "pico-init[info]: "
 *    prefix on every one is noise, ANSI colour has no business in the kernel
 *    ring, and mirroring them to /dev/kmsg would make picolog replay a second
 *    copy of every line the console already showed, interleaved with the real
 *    log records it exists to carry.
 *  - Anything someone would go looking for afterwards -- the identity line,
 *    warnings, a failed job -- stays on pico_log(), which is where the level,
 *    the prefix and the kmsg mirror are the point rather than the cost.
 *
 * Neither channel replaces the other: job.c logs a finished job AND prints
 * its status line, exactly as upstream does, because the two have different
 * readers.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "version.h"

/*
 * What PID 1 announces itself as. Two halves on purpose, mirroring systemd's
 * own PROJECT_VERSION/GIT_VERSION pair: the number is what the source claims
 * to be, the git description is what the tree actually was. On a device built
 * from a moving branch the second half is the only one that identifies
 * anything. PICO_INIT_VERSION comes from meson's project() version, via a -D;
 * PICO_INIT_GIT_VERSION from vcs_tag(). Both in meson.build.
 */
#define PICO_INIT_VERSION_STRING PICO_INIT_VERSION " (" PICO_INIT_GIT_VERSION ")"

/* SGR sequences, byte for byte from systemd's src/basic/ansi-color.h. */
#define ANSI_NORMAL "\x1B[0m"
#define ANSI_GREEN "\x1B[0;32m"
#define ANSI_HIGHLIGHT "\x1B[0;1;39m"
#define ANSI_HIGHLIGHT_RED "\x1B[0;1;31m"

/*
 * systemd's real ANSI_HIGHLIGHT_YELLOW is a 256-colour sequence
 * (ANSI_HIGHLIGHT_KHAKI3, "\x1B[0;1;38:5:185m") substituted in because the
 * plain 16-colour bold yellow "is currently not displayed well by some
 * terminals" -- but that substitution is only safe alongside the ColorMode
 * negotiation (src/basic/ansi-color.h) that falls back to
 * ANSI_HIGHLIGHT_YELLOW_FALLBACK, byte for byte the value used here, on a
 * terminal that cannot do 256 colours. console_colors_enabled() below has no
 * such negotiation -- on or off is the whole of it -- so sending the
 * 256-colour form unconditionally would risk exactly the broken-escape
 * output upstream's own fallback exists to avoid, on the serial consoles
 * this project's boot messages mostly go to. The fallback is therefore the
 * only one of the two that is correct here.
 */
#define ANSI_HIGHLIGHT_YELLOW "\x1B[0;1;33m"

/*
 * The status word for a job that succeeded, verbatim from systemd's
 * job_done_messages[JOB_DONE] (src/core/job.c): six columns, "OK" centred.
 * The padding is not decoration -- it is what keeps every bracket down the
 * left edge of a boot the same width, so it is only right if it is exactly
 * this.
 */
#define STATUS_WORD_OK "  OK  "

/*
 * And its colour. systemd's ANSI_OK_COLOR is a build option ('ok-color' in
 * meson_options.txt) whose default is 'green' -- plain green, not the bold
 * ANSI_HIGHLIGHT_GREEN -- so that is what a distro which does not override it
 * ships, and what this matches.
 */
#define STATUS_COLOR_OK ANSI_GREEN

/*
 * The remaining three words systemd's job_done_messages[] (src/core/job.c)
 * actually prints to the console, same six columns, same table's colours.
 * JOB_CANCELED has no word there and gets none here either; this project's
 * JobResult has no counterpart for JOB_SKIPPED/JOB_COLLECTED/JOB_INVALID/etc,
 * so there is nothing to suppress for them beyond simply not printing.
 */
#define STATUS_WORD_FAILED "FAILED"
#define STATUS_COLOR_FAILED ANSI_HIGHLIGHT_RED

#define STATUS_WORD_TIMEOUT " TIME "
#define STATUS_COLOR_TIMEOUT ANSI_HIGHLIGHT_RED

#define STATUS_WORD_DEPENDENCY "DEPEND"
#define STATUS_COLOR_DEPENDENCY ANSI_HIGHLIGHT_YELLOW

/*
 * Start writing to /dev/console. Opt-in, exactly like pico_log_to_kmsg() and
 * for the same reason: this code is linked into every test binary and into
 * picoctl, and none of them has any business writing to the machine's
 * console. Until PID 1 calls this, every function below is a no-op.
 *
 * Falls back to stdout when /dev/console will not open, which for an init is
 * the same device: the kernel opens /dev/console as fd 0/1/2 for the process
 * it execs as PID 1.
 */
void status_enable(void);

/*
 * Test seam. A test binary must not call status_enable() -- that opens the
 * real console, exactly the thing it is not allowed to do -- but job.c's own
 * tests need to see the bytes job_finish_full() hands to status_printf() for
 * each JobResult, and status_printf() only composes a line, it does not
 * return one. This redirects status_write() into `buf` (size `size`)
 * instead of a console fd, with `color` standing in for what
 * console_colors_enabled() would otherwise decide, so both renderings are
 * reachable from a test. Each call appends, so the lines from more than one
 * status_printf() (a failed start's word line plus its hint line) land in
 * `buf` in order, exactly as a real console would show them.
 *
 * status_set_test_sink(NULL, 0, false) turns it back off. Until a test calls
 * this, it is inert and status_fd stays -1: no path through status_printf()
 * or status_welcome() touches a real fd any differently than before this
 * existed.
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
 * returning its length. Split out of status_printf() so the byte-level shape
 * -- bracket padding and escape sequences included -- can be asserted in
 * test-status.c, which has no console to write to. Always NUL-terminates and,
 * unless `buf` is too small to hold anything at all, always ends in a newline.
 */
size_t status_format_line(char *buf, size_t size, const char *word, const char *color, const char *text);

/* Greet the console with the distribution name from `path` (NULL for
 * OS_RELEASE_PATH). */
void status_welcome(const char *path);

/* As above, composed into `buf` rather than written, for the reason
 * status_format_line() gives. `color` is explicit here so a test can assert
 * both renderings without a console. */
size_t status_welcome_line(char *buf, size_t size, const char *path, bool color);
