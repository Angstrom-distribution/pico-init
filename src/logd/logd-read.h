/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The ring reader. Deliberately its own file rather than living inside picolog.c: picoctl's per-unit log
 * tail (plan §1.7, C1) reuses exactly this reader out of the shared static library, so it must not be locked
 * inside a CLI's translation unit.
 *
 * Scaffolding: milestone J3 owns this file and lands the real body. It is
 * registered in the build now so that milestone adds code to a file that
 * already exists and is already compiled, rather than editing meson.build
 * while another milestone is also editing it.
 */

#pragma once

/*
 * Placeholder so this file declares something and its translation unit is not
 * empty under -Wpedantic. Milestone J3 replaces it with the real surface;
 * nothing calls it, and it returns -ENOSYS rather than succeeding so a stray
 * caller fails loudly instead of silently doing nothing.
 */
int logd_read_not_implemented(void);
