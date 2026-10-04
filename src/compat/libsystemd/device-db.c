/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The udev database overlay: /run/udev/data/<device-id>, read once per
 * device and laid over the uevent properties.
 *
 * devd writes these entries, and today only for input devices -- the
 * ID_INPUT* classification of devd-input-id.c. Overlaying them here, inside
 * device_ensure_properties(), is what puts ID_INPUT_TOUCHSCREEN in front of
 * every consumer that reads properties through sd_device: libudev is a thin
 * layer over this one, so Xorg's config/udev and libinput get it with no
 * change of their own, and so does the enumerator's property matching.
 *
 * Written from scratch against the format alone (devd-udev-db.h describes
 * it), not from upstream's LGPL-2.1-or-later reader -- the same policy
 * sd-device.h states for this whole layer. The behaviour it reproduces is
 * upstream's at systemd 041e70d7: records end at '\n' or '\r', an
 * unterminated last record is dropped, E: replaces the uevent's value (and an
 * empty value removes the key), I: becomes USEC_INITIALIZED, V: is the
 * format version, and a missing file is not an error (sd-device.c:1835).
 * Two departures, both stated: any other read error is also "no database"
 * rather than an error, because a property lookup on this layer has never
 * failed because of a database and nothing here should start; and S:/L:/G:/
 * Q:/W: are skipped, because devd writes none of them -- devlinks still come
 * from device-devlink.c's /dev scan and the tag family stays empty.
 *
 * A monitor-received device is never overlaid. That is upstream's sealed-
 * device rule (device-private.c:963: a sealed device does not load the
 * database unless forced): the event carries the properties udevd attached,
 * and the file on disk may already describe a later state.
 */

#include "sd-device.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "device-internal.h"

#define UDEV_DB_ROOT_DEFAULT "/run/udev/data"

/* Real entries are a few hundred bytes; this bounds what a corrupt or hostile
 * file can make every property lookup allocate. Anything past it is cut,
 * which the "unterminated last record is dropped" rule then handles. */
#define UDEV_DB_SIZE_MAX (64U * 1024U)

static char udev_db_root_buf[PATH_MAX] = UDEV_DB_ROOT_DEFAULT;

const char *device_udev_db_root(void) {
        return udev_db_root_buf;
}

void device_set_udev_db_root_for_tests(const char *root) {
        if (!root)
                root = UDEV_DB_ROOT_DEFAULT;

        (void) snprintf(udev_db_root_buf, sizeof(udev_db_root_buf), "%s", root);
}

/* Full decimal parses, the way the writer prints them: digits only. */
static bool parse_u64(const char *s, uint64_t *ret) {
        unsigned long long v;
        char *end;

        if (s[0] < '0' || s[0] > '9')
                return false;

        errno = 0;
        v = strtoull(s, &end, 10);
        if (errno != 0 || *end != '\0')
                return false;

        *ret = (uint64_t) v;
        return true;
}

static bool parse_unsigned(const char *s, unsigned *ret) {
        uint64_t v;

        if (!parse_u64(s, &v) || v > UINT_MAX)
                return false;

        *ret = (unsigned) v;
        return true;
}

/* One record, already NUL-terminated at its line end. Only -ENOMEM is an
 * error; everything malformed is skipped. */
static int apply_record(sd_device *d, char *rec, size_t len) {
        char *value, *eq;

        if (len < 2 || rec[1] != ':')
                return 0;

        value = rec + 2;

        switch (rec[0]) {

        case 'E':
                eq = strchr(value, '=');
                if (!eq || eq == value)
                        return 0;

                *eq = '\0';
                return device_set_property(d, value, eq + 1);

        case 'I': {
                uint64_t usec;

                if (!parse_u64(value, &usec))
                        return 0;

                d->usec_initialized = usec;
                return device_set_property(d, "USEC_INITIALIZED", value);
        }

        case 'V':
                (void) parse_unsigned(value, &d->database_version);
                return 0;

        default:
                /* S: L: G: Q: W:, and anything newer -- see the top comment. */
                return 0;
        }
}

int device_read_db(sd_device *d) {
        char id[256], path[PATH_MAX];
        size_t len = 0, start = 0;
        char *buf;
        int fd, r = 0;

        if (d->db_loaded || d->from_monitor || d->no_uevent_file)
                return 0;

        /* Before the read, not after: one attempt per device, whatever it
         * finds, which keeps a failed read from being retried on every
         * lookup and a recursive call from ever getting this far. */
        d->db_loaded = true;

        if (device_format_id(d, id, sizeof(id)) < 0)
                return 0;

        /* The id is a filename; one that could name something else is not
         * one this layer will open. */
        if (id[0] == '.' || strchr(id, '/'))
                return 0;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", device_udev_db_root(), id) >= sizeof(path))
                return 0;

        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (fd < 0)
                return 0; /* ENOENT is upstream's "no database"; anything else is ours */

        buf = malloc(UDEV_DB_SIZE_MAX + 1);
        if (!buf) {
                (void) close(fd);
                return -ENOMEM;
        }

        while (len < UDEV_DB_SIZE_MAX) {
                ssize_t k = read(fd, buf + len, UDEV_DB_SIZE_MAX - len);

                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        len = 0; /* unreadable: no database, not half of one */
                        break;
                }

                if (k == 0)
                        break;

                len += (size_t) k;
        }

        (void) close(fd);
        buf[len] = '\0';

        for (size_t i = 0; i < len && r >= 0; i++) {
                if (buf[i] != '\n' && buf[i] != '\r')
                        continue;

                buf[i] = '\0';
                r = apply_record(d, buf + start, i - start);
                start = i + 1;
        }

        free(buf);
        return r < 0 ? r : 0;
}
