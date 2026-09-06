/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * No hwdb.bin reader exists in this build. Real udev's hardware database
 * exists to attach static vendor/model properties (USB IDs, keyboard
 * layouts, PCI class strings, ...) to a uevent by modalias lookup; pico's
 * devd (src/devd/devd-match.c, devd-rules.c) matches purely on sysfs
 * attributes and its own rules file instead, so nothing in this build ever
 * needed a hwdb to begin with -- sd_hwdb_new() failing is not a missing
 * feature, it is the truthful "no hwdb.bin anywhere" real libsystemd
 * itself reports (sd-hwdb.c:384-415, HEAD ded83144) on any system that
 * hasn't built one, which describes every pico image, permanently.
 */

#include "sd-hwdb.h"

#include <errno.h>
#include <stddef.h>

int sd_hwdb_new(sd_hwdb **ret) {
        if (!ret)
                return -EINVAL;
        return -ENOENT;
}

/* Unlike sd_hwdb_new(), `path` may genuinely exist -- there is simply no
 * trie/hwdb.bin reader in this library build to open it with. -ENOENT
 * would claim the file is missing, which could be a lie; -EOPNOTSUPP
 * states the true condition instead. */
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
