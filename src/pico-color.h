/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * ANSI colour output shared by netctl/picoctl/picolog (networkctl/systemctl/
 * journalctl's on-device equivalents), mirroring real systemd's own rules:
 * the on/off decision (colors_enabled()/get_color_mode() in
 * src/basic/ansi-color.c) and the escape sequences themselves (the ANSI_*
 * #defines in src/basic/ansi-color.h), taken from systemd main as of commit
 * 4c63532c28094aeba6dccc5afb9690e02fd98d66 (2026-10-04).
 *
 * Two simplifications versus upstream, because pico-init's three tools are
 * plain one-shot CLIs with no pager and no colour-depth concept (just on/off):
 *
 *   - upstream's on_tty() checks both stdout AND stderr (defensive against a
 *     pager/shell piping just one of them); this checks stdout only.
 *   - upstream's 256-colour accessors (ansi_highlight_yellow(), ansi_grey())
 *     pick between a 16-colour FALLBACK sequence and a 256-colour sequence
 *     by way of get_color_mode()'s COLOR_16/COLOR_256/COLOR_24BIT depth.
 *     Since pico-init has no depth concept, pico_ansi_highlight_yellow() and
 *     pico_ansi_grey() always emit the plain (256-colour) ANSI_* literal,
 *     with no 16-colour fallback prefix.
 *
 * underline_enabled()'s extra exception (upstream turns underline off when
 * $TERM is exactly "linux", even with colours otherwise on, because the
 * Linux console cannot render it) is not mirrored either: pico_ansi_underline()
 * follows pico_colors_enabled() only.
 */

#pragma once

#include <stdbool.h>

/*
 * True when ANSI colour escapes should be written to stdout. Cached after
 * the first call, same idea as upstream's cached_color_mode -- see
 * pico_colors_reset_cache(). Mirrors get_color_mode_impl()'s decision tree:
 *
 *   1. $SYSTEMD_COLORS, parsed as a boolean (case-insensitive 1/yes/y/true/
 *      t/on vs. 0/no/n/false/f/off, upstream's parse_boolean()): true forces
 *      colour on unconditionally -- even piped, even with $NO_COLOR set, an
 *      explicit request wins. false forces it off, same priority.
 *   2. $SYSTEMD_COLORS set to "16", "256" or "24bit" (a depth, not a
 *      boolean): forces colour on. Upstream picks a palette width here;
 *      pico-init only has on/off, so any recognized depth means on.
 *   3. Otherwise (unset, or an unrecognized value such as "auto-16" --
 *      upstream's own AUTO_* modes, not reproduced here -- falls through to
 *      auto-detection, same as upstream's unparsed-value behaviour):
 *        - $NO_COLOR set (any value, even empty) -> off.
 *        - stdout is not a terminal -> off.
 *        - $TERM unset or exactly "dumb" -> off.
 *        - else -> on.
 */
bool pico_colors_enabled(void);

/*
 * Test-only: clears the cache so a change to the environment (or to which
 * fd stdout points at) takes effect on the next pico_colors_enabled() call.
 * None of netctl/picoctl/picolog's own code calls this -- a real process's
 * environment and stdout don't change under it mid-run.
 */
void pico_colors_reset_cache(void);

/*
 * ANSI escape accessors: the literal byte sequence of upstream's same-named
 * ANSI_* #define when pico_colors_enabled() is true, "" when it is false --
 * so a call site never has to branch on colour itself, just like upstream's
 * own ansi_*() wrappers.
 *
 * Limited to the colours netctl/picoctl/picolog's upstream counterparts
 * actually print with (networkctl-util.c's operational/online/setup state
 * colouring, systemctl-show.c's active/enabled/tainted/socket-limit fields,
 * logs-show.c's priority/cursor/timestamp highlighting) -- not upstream's
 * full ANSI_* palette.
 */
const char *pico_ansi_normal(void);           /* ANSI_NORMAL */
const char *pico_ansi_highlight(void);        /* ANSI_HIGHLIGHT */
const char *pico_ansi_highlight_red(void);    /* ANSI_HIGHLIGHT_RED */
const char *pico_ansi_highlight_green(void);  /* ANSI_HIGHLIGHT_GREEN */
const char *pico_ansi_highlight_yellow(void); /* ANSI_HIGHLIGHT_YELLOW (== ANSI_HIGHLIGHT_KHAKI3) */
const char *pico_ansi_highlight_cyan(void);   /* ANSI_HIGHLIGHT_CYAN */
const char *pico_ansi_green(void);            /* ANSI_GREEN */
const char *pico_ansi_blue(void);             /* ANSI_BLUE */
const char *pico_ansi_grey(void);             /* ANSI_GREY */
const char *pico_ansi_underline(void);        /* ANSI_UNDERLINE */
