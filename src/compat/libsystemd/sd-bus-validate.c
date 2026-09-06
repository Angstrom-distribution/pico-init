/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Naming validators for sd-bus.h. These are the one corner of the sd-bus
 * family that needs no bus at all -- pure string checks against the D-Bus
 * specification's grammar (message-protocol-names) -- so unlike
 * everything else under sd-bus-*.c they can be, and are, genuinely real.
 */

#include "sd-bus.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#define DBUS_NAME_MAX 255

static int is_name_char(char c, bool allow_hyphen) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
                        (allow_hyphen && c == '-');
}

static int is_digit(char c) {
        return c >= '0' && c <= '9';
}

/*
 * Shared walk for interface and bus/service names: both are '.'-separated
 * element lists with the same "first char of an element is never a digit"
 * rule, differing only in the character set (hyphen) and in whether an
 * element may start with a digit (a unique name's numeric suffix element
 * may). unique_ok lets the unique-name spelling (leading ':') skip the
 * first-char-not-digit check on every element after the first.
 */
static int dotted_name_is_valid(
                const char *p, size_t len, bool allow_hyphen, bool unique_ok, bool require_two_elements) {
        size_t n_elements = 0;
        size_t i = 0;

        /* A trailing '.' has no element after it to catch in the loop
         * below -- consuming it as "skip the separator" lands i exactly on
         * len, ending the loop one iteration early instead of surfacing an
         * empty final element. Checked once, up front, instead. */
        if (len > 0 && p[len - 1] == '.')
                return 0;

        while (i < len) {
                size_t start = i;

                while (i < len && p[i] != '.') {
                        if (!is_name_char(p[i], allow_hyphen))
                                return 0;
                        i++;
                }

                if (i == start) /* empty element ("..", leading/trailing '.') */
                        return 0;
                if (!unique_ok && is_digit(p[start]))
                        return 0;

                n_elements++;

                if (i < len) /* skip the '.' */
                        i++;
        }

        if (require_two_elements && n_elements < 2)
                return 0;

        return 1;
}

int sd_bus_interface_name_is_valid(const char *p) {
        size_t len;

        if (!p)
                return -EINVAL;

        len = strlen(p);
        if (len == 0 || len > DBUS_NAME_MAX)
                return 0;

        return dotted_name_is_valid(
                        p,
                        len,
                        /* allow_hyphen= */ false,
                        /* unique_ok= */ false,
                        /* require_two_elements= */ true);
}

int sd_bus_service_name_is_valid(const char *p) {
        size_t len;

        if (!p)
                return -EINVAL;

        len = strlen(p);
        if (len == 0 || len > DBUS_NAME_MAX)
                return 0;

        if (p[0] == ':') {
                /* Unique name: ":" followed by a '.'-separated element list
                 * whose elements may start with a digit. A bare ":" (no
                 * elements at all) is not a name anyone could have meant. */
                if (len < 2)
                        return 0;
                return dotted_name_is_valid(
                                p + 1,
                                len - 1,
                                /* allow_hyphen= */ true,
                                /* unique_ok= */ true,
                                /* require_two_elements= */ false);
        }

        return dotted_name_is_valid(
                        p,
                        len,
                        /* allow_hyphen= */ true,
                        /* unique_ok= */ false,
                        /* require_two_elements= */ true);
}

int sd_bus_member_name_is_valid(const char *p) {
        size_t len, i;

        if (!p)
                return -EINVAL;

        len = strlen(p);
        if (len == 0 || len > DBUS_NAME_MAX)
                return 0;

        if (is_digit(p[0]))
                return 0;

        for (i = 0; i < len; i++)
                if (!is_name_char(p[i], /* allow_hyphen= */ false))
                        return 0;

        return 1;
}

int sd_bus_object_path_is_valid(const char *p) {
        size_t len, i;

        if (!p)
                return -EINVAL;

        len = strlen(p);
        if (len == 0 || p[0] != '/')
                return 0;

        if (len == 1) /* "/" alone: the root path, no elements */
                return 1;

        if (p[len - 1] == '/') /* no trailing slash beyond the bare root */
                return 0;

        i = 1;
        while (i < len) {
                size_t start = i;

                while (i < len && p[i] != '/') {
                        if (!is_name_char(p[i], /* allow_hyphen= */ false))
                                return 0;
                        i++;
                }

                if (i == start) /* "//" -- an empty element */
                        return 0;

                if (i < len)
                        i++;
        }

        return 1;
}
