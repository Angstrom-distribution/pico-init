/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The variable parts of the early boot lines that systemd prints in the
 * same words: the architecture and the watchdog timeout.
 */

#pragma once

#include <stddef.h>

#include "util.h"

/*
 * The name systemd prints in "Detected architecture <name>." for a uname(2)
 * machine string (arm, arm64, x86-64, ...; systemd's
 * src/basic/architecture.c). A machine this table does not know is returned
 * as given, so the line still says something true. Never NULL for a non-NULL
 * argument; NULL returns "unknown".
 */
const char *pico_architecture_name(const char *machine);

/*
 * t as systemd's FORMAT_TIMESPAN(t, 0) writes it, at whole-second
 * resolution: "30s", "15min 30s", "1h", "0", "infinity". The result is cut
 * off to fit size, which must be at least 1. Returns buf.
 */
char *pico_format_timespan(char *buf, size_t size, usec_t t);
