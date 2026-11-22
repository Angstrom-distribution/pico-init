/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * [Unit] Condition*= checks: ConditionPathExists=, ConditionPathIsDirectory=,
 * ConditionDirectoryNotEmpty= and ConditionKernelCommandLine=.
 *
 * The list semantics are systemd's condition_test_list() in
 * src/shared/condition.c (v262): every non-triggering condition must hold,
 * and when the list has triggering ('|') conditions at least one of them
 * must hold too. A leading '!' negates one condition's result and follows
 * the '|' ("|!x"). An empty list is true.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef enum ConditionType {
        CONDITION_PATH_EXISTS,
        CONDITION_PATH_IS_DIRECTORY,
        CONDITION_DIRECTORY_NOT_EMPTY,
        CONDITION_KERNEL_COMMAND_LINE,
        _CONDITION_TYPE_MAX,
        _CONDITION_TYPE_INVALID = -1,
} ConditionType;

typedef struct Condition {
        ConditionType type;
        char *parameter; /* owned; a path, or the command line word for KERNEL_COMMAND_LINE */
        bool negate;     /* leading '!' */
        bool trigger;    /* leading '|' */
} Condition;

/* The kernel command line file. Tests point it at a fixture. */
extern const char *pico_condition_cmdline_path;

/* "ConditionPathExists" and so on, without the '='. */
const char *condition_type_to_string(ConditionType t);

/* The type for a directive name without the '=', or _CONDITION_TYPE_INVALID. */
ConditionType condition_type_from_string(const char *name);

/* True for the types whose parameter must be an absolute path. */
bool condition_type_is_path(ConditionType t);

/* Append a condition to *list (*n entries), copying parameter. 0 or -ENOMEM. */
int condition_add(Condition **list, size_t *n, ConditionType type, const char *parameter, bool trigger, bool negate);

/* Free the parameters and the array; returns NULL. */
Condition *condition_free_list(Condition *list, size_t n);

/*
 * Whether `parameter` is on the kernel command line `cmdline`, as systemd
 * does for ConditionKernelCommandLine=: a parameter without '=' is true for
 * a word that is that key, with or without a value; one with '=' only for
 * a word that is exactly it. The text is split like /proc/cmdline in systemd
 * (white space, single and double quotes grouping, quotes removed). '-' and
 * '_' are not treated alike here. Backslash escapes inside a word are
 * decoded, where systemd keeps them, and an unterminated quote drops the rest
 * of the line, where systemd takes the rest as one word.
 */
bool condition_cmdline_has(const char *cmdline, const char *parameter);

/*
 * True when path is a directory with at least one entry that is not hidden
 * or a backup file (a name starting with '.', ending in '~', or ending in
 * a known package-manager or backup suffix, and lost+found, aquota.user and
 * aquota.group), as systemd's dir_is_empty(.., ignore_hidden_or_backup=true).
 * A missing path or one that is not a directory is false; a directory that
 * cannot be read counts as not empty, as in systemd.
 */
bool condition_directory_not_empty(const char *path);

/* One condition's result, with its negation applied. */
bool condition_test(const Condition *c);

/*
 * The whole list. When it is false, *failed (may be NULL) is the first
 * non-triggering condition that did not hold, or the first triggering
 * condition when none of the triggering ones held.
 */
bool condition_test_list(const Condition *list, size_t n, const Condition **failed);
