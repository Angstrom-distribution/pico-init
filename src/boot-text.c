/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "boot-text.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The machine strings uname(2) reports whose systemd name is not the string itself. */
static const struct {
        const char *machine;
        const char *name;
} architecture_names[] = {
        {    "aarch64",    "arm64" },
        { "aarch64_be", "arm64-be" },
        {     "x86_64",   "x86-64" },
        {       "i386",      "x86" },
        {       "i486",      "x86" },
        {       "i586",      "x86" },
        {       "i686",      "x86" },
        {      "arceb",   "arc-be" },
        {    "crisv32",     "cris" },
        {    "ppc64le", "ppc64-le" },
        {      "ppcle",   "ppc-le" },
        {        "sh2",       "sh" },
        {       "sh2a",       "sh" },
        {        "sh3",       "sh" },
        {        "sh4",       "sh" },
        {       "sh4a",       "sh" },
        {        "sh5",     "sh64" },
};

const char *pico_architecture_name(const char *machine) {
        size_t i, len;

        if (!machine)
                return "unknown";

        /* armv4l .. armv8l, armv5tel, armv7ml: little endian unless the name ends in 'b'. */
        len = strlen(machine);
        if (strncmp(machine, "arm", 3) == 0 && len > 3 && machine[3] == 'v')
                return machine[len - 1] == 'b' ? "arm-be" : "arm";

        for (i = 0; i < sizeof(architecture_names) / sizeof(architecture_names[0]); i++)
                if (strcmp(machine, architecture_names[i].machine) == 0)
                        return architecture_names[i].name;

        if (strcmp(machine, "riscv") == 0)
                return sizeof(void *) == 8 ? "riscv64" : "riscv32";

        return machine;
}

char *pico_format_timespan(char *buf, size_t size, usec_t t) {
        static const struct {
                const char *suffix;
                uint64_t sec;
        } units[] = {
                {     "y", 31557600 },
                { "month",  2629800 },
                {     "w",   604800 },
                {     "d",    86400 },
                {     "h",     3600 },
                {   "min",       60 },
                {     "s",        1 },
        };
        uint64_t sec;
        size_t i, used = 0;

        if (size == 0)
                return buf;
        buf[0] = '\0';

        if (t == USEC_INFINITY) {
                snprintf(buf, size, "infinity");
                return buf;
        }

        sec = t / USEC_PER_SEC;
        for (i = 0; i < sizeof(units) / sizeof(units[0]) && sec > 0 && used + 1 < size; i++) {
                int n;

                if (sec < units[i].sec)
                        continue;

                n = snprintf(buf + used,
                             size - used,
                             "%s%llu%s",
                             used > 0 ? " " : "",
                             (unsigned long long) (sec / units[i].sec),
                             units[i].suffix);
                if (n < 0)
                        break;
                used = used + (size_t) n < size ? used + (size_t) n : size - 1;
                sec %= units[i].sec;
        }

        if (used == 0)
                snprintf(buf, size, "0");

        return buf;
}
