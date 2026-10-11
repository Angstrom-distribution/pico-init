/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * No hwdb.bin reader exists in this build. devd (src/devd/devd-match.c,
 * devd-rules.c) matches on sysfs attributes and its own rules file instead
 * of a modalias-keyed hardware database, so sd_hwdb_new() failing is the
 * same "no hwdb.bin" answer real libsystemd gives (sd-hwdb.c:384-415, HEAD
 * ded83144) on a system that has not built one.
 */

#include "sd-hwdb.h"

#include <errno.h>
#include <stddef.h>

int sd_hwdb_new(sd_hwdb **ret) {
        if (!ret)
                return -EINVAL;
        return -ENOENT;
}

/* Unlike sd_hwdb_new(), `path` may exist; there is no
 * hwdb.bin reader in this build to open it with. -ENOENT would wrongly
 * claim the file is missing, so report -EOPNOTSUPP. */
int sd_hwdb_new_from_path(const char *path, sd_hwdb **ret) {
        if (!path || !ret)
                return -EINVAL;
        return -EOPNOTSUPP;
}

int sd_hwdb_get(sd_hwdb *hwdb, const char *modalias, const char *key, const char **ret) {
        (void) hwdb;
        (void) modalias;
        (void) key;
        (void) ret;
        return -EINVAL;
}

int sd_hwdb_seek(sd_hwdb *hwdb, const char *modalias) {
        (void) hwdb;
        (void) modalias;
        return -EINVAL;
}

int sd_hwdb_enumerate(sd_hwdb *hwdb, const char **ret_key, const char **ret_value) {
        (void) hwdb;
        (void) ret_key;
        (void) ret_value;
        return -EINVAL;
}

sd_hwdb *sd_hwdb_ref(sd_hwdb *hwdb) {
        (void) hwdb;
        return NULL;
}

sd_hwdb *sd_hwdb_unref(sd_hwdb *hwdb) {
        (void) hwdb;
        return NULL;
}
