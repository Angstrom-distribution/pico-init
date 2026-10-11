/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * compat.h is macros/inline only, so this TU exists solely to give a
 * symbol-presence test something to find.
 */

#include "compat.h"

int compat_noop(void) {
        return 0;
}
