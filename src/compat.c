/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * M0 placeholder: compat.h itself is macros/inline only, so this TU exists
 * solely to give the M0 symbol-presence test something to find.
 */

#include "compat.h"

int compat_noop(void) {
        return 0;
}
