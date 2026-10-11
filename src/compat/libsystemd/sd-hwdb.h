/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-init's own implementation of the sd-hwdb.h ABI surface, matching
 * systemd's src/systemd/sd-hwdb.h in function names and signatures. No
 * hwdb.bin reader exists in this build, so every function fails; see
 * sd-hwdb.c.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sd_hwdb sd_hwdb;

sd_hwdb *sd_hwdb_ref(sd_hwdb *hwdb);
sd_hwdb *sd_hwdb_unref(sd_hwdb *hwdb);

int sd_hwdb_new(sd_hwdb **ret);
int sd_hwdb_new_from_path(const char *path, sd_hwdb **ret);

int sd_hwdb_get(sd_hwdb *hwdb, const char *modalias, const char *key, const char **ret);

int sd_hwdb_seek(sd_hwdb *hwdb, const char *modalias);
int sd_hwdb_enumerate(sd_hwdb *hwdb, const char **ret_key, const char **ret_value);

/* the inverse condition avoids ambiguity of dangling 'else' after the macro */
#define SD_HWDB_FOREACH_PROPERTY(hwdb, modalias, key, value) \
        if (sd_hwdb_seek(hwdb, modalias) < 0) {              \
        } else                                               \
                while (sd_hwdb_enumerate(hwdb, &(key), &(value)) > 0)

static inline void sd_hwdb_unrefp(sd_hwdb **p) {
        if (*p)
                sd_hwdb_unref(*p);
}

#ifdef __cplusplus
}
#endif
