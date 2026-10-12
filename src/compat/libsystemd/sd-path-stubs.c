/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_path_lookup() and sd_path_lookup_strv() are not implemented: every
 * lookup fails with -EOPNOTSUPP, the error upstream gives a type it does
 * not know, so callers already handle it. A NULL output parameter is
 * -EINVAL, as upstream.
 *
 * Upstream's answers come from systemd's build-time directory layout, its
 * unit and generator search, NSS for the home directory and a parse of
 * xdg-user-dirs. pico-init has no one mechanism behind these and would
 * have to invent the values.
 */

#include "sd-path.h"

#include <errno.h>

int sd_path_lookup(uint64_t type, const char *suffix, char **ret) {
        (void) type;
        (void) suffix;
        return ret ? -EOPNOTSUPP : -EINVAL;
}

int sd_path_lookup_strv(uint64_t type, const char *suffix, char ***ret) {
        (void) type;
        (void) suffix;
        return ret ? -EOPNOTSUPP : -EINVAL;
}
