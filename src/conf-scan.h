/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The INI line scanner, shared by every config parser in this project.
 *
 * netd's `.network` parser needs exactly the same line-level
 * behaviour as unit files, and a second copy would stop inheriting upstream
 * fixes: unbounded getline() so a long line is never truncated, a malformed
 * line skipping just that line instead of failing the whole file, the
 * comment-line-ending-in-backslash and blank-line-terminates-continuation
 * pair, and the flush of an unterminated final continuation.
 *
 * The scanner knows about sections, comments, continuations, the UTF-8 BOM
 * and the key/value split. It knows nothing about what any key means -- that
 * is the caller's handler, which is the whole seam.
 */

#pragma once

/*
 * Called once per successfully scanned assignment. `section` is NULL for an
 * assignment appearing before any [Section] header. `key` and `value` are
 * NUL-terminated and valid only for the duration of the call -- a handler
 * that wants to keep either must copy it.
 *
 * Return 0 to continue, or -errno to abort the whole file. Returning an error
 * for an unrecognized key is a policy choice this project does
 * not make: both unit files and .network files accept unknown directives as
 * valid syntax and drop them at debug level.
 */
typedef int (*pico_conf_handler_t)(
                const char *filename,
                unsigned line,
                const char *section,
                const char *key,
                const char *value,
                void *userdata);

/*
 * Called once per accepted [Section] header, before its assignments. A header
 * that is refused (no closing bracket, control characters) is not reported.
 * `section` is the name without the brackets, valid only for the call. Return
 * 0 to continue, or -errno to abort the whole file.
 */
typedef int (*pico_conf_section_handler_t)(
                const char *filename, unsigned line, const char *section, void *userdata);

/*
 * Scan `filename`, invoking `handler` per assignment. Returns 0 on success or
 * -errno. A malformed line is logged and skipped rather than failing the file,
 * so a partially broken config still yields everything it got right.
 */
int pico_conf_scan(const char *filename, pico_conf_handler_t handler, void *userdata);

/*
 * As pico_conf_scan(), and `section_handler` (may be NULL) is also called for
 * each accepted header, so a caller can tell a repeated section from one
 * longer section.
 */
int pico_conf_scan_full(
                const char *filename,
                pico_conf_handler_t handler,
                pico_conf_section_handler_t section_handler,
                void *userdata);
