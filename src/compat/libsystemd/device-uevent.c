/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The property table (uevent file or monitor env, plus synthesized keys)
 * and every getter that reads out of it: DEVTYPE, MAJOR/MINOR, IFINDEX,
 * DEVNAME, DISKSEQ. ACTION/SEQNUM/SYNTH_UUID are set directly by the
 * monitor/trigger paths rather than read back out of the table -- see
 * device-internal.h's struct comment -- but are added to the table too, so
 * sd_device_get_property_first()/_next() shows them.
 */

#include "sd-device.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device-internal.h"

static const char * const action_table[_SD_DEVICE_ACTION_MAX] = {
        [SD_DEVICE_ADD] = "add",   [SD_DEVICE_REMOVE] = "remove", [SD_DEVICE_CHANGE] = "change",
        [SD_DEVICE_MOVE] = "move", [SD_DEVICE_ONLINE] = "online", [SD_DEVICE_OFFLINE] = "offline",
        [SD_DEVICE_BIND] = "bind", [SD_DEVICE_UNBIND] = "unbind",
};

const char *device_action_to_string(sd_device_action_t a) {
        if (a < 0 || a >= _SD_DEVICE_ACTION_MAX)
                return NULL;

        return action_table[a];
}

sd_device_action_t device_action_from_string(const char *s) {
        int i;

        if (!s)
                return _SD_DEVICE_ACTION_INVALID;

        for (i = 0; i < _SD_DEVICE_ACTION_MAX; i++)
                if (strcmp(s, action_table[i]) == 0)
                        return (sd_device_action_t) i;

        return _SD_DEVICE_ACTION_INVALID;
}

/* RFC 4122 36-char form, e.g. "12345678-90ab-cdef-1234-567890abcdef". */
void device_id128_to_uuid_string(sd_id128_t id, char s[37]) {
        snprintf(s,
                 37,
                 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 id.bytes[0],
                 id.bytes[1],
                 id.bytes[2],
                 id.bytes[3],
                 id.bytes[4],
                 id.bytes[5],
                 id.bytes[6],
                 id.bytes[7],
                 id.bytes[8],
                 id.bytes[9],
                 id.bytes[10],
                 id.bytes[11],
                 id.bytes[12],
                 id.bytes[13],
                 id.bytes[14],
                 id.bytes[15]);
}

static int hex2(const char *s, uint8_t *ret) {
        int hi, lo;

        if (!isxdigit((unsigned char) s[0]) || !isxdigit((unsigned char) s[1]))
                return -EINVAL;

        hi = s[0] <= '9' ? s[0] - '0' : (s[0] | 0x20) - 'a' + 10;
        lo = s[1] <= '9' ? s[1] - '0' : (s[1] | 0x20) - 'a' + 10;
        *ret = (uint8_t) ((hi << 4) | lo);
        return 0;
}

int device_id128_from_uuid_string(const char *s, sd_id128_t *ret) {
        static const bool dash_at[36] = { [8] = true, [13] = true, [18] = true, [23] = true };
        sd_id128_t id;
        size_t si = 0, bi = 0;

        if (!s || strlen(s) != 36)
                return -EINVAL;

        while (si < 36) {
                if (dash_at[si]) {
                        if (s[si] != '-')
                                return -EINVAL;
                        si++;
                        continue;
                }

                if (bi >= 16 || hex2(s + si, &id.bytes[bi]) < 0)
                        return -EINVAL;
                bi++;
                si += 2;
        }

        if (bi != 16)
                return -EINVAL;

        *ret = id;
        return 0;
}

int device_add_property(sd_device *d, const char *key, const char *value) {
        DeviceProperty *n;
        size_t i;

        for (i = 0; i < d->n_properties; i++)
                if (strcmp(d->properties[i].key, key) == 0)
                        return 0; /* first write wins */

        n = realloc(d->properties, (d->n_properties + 1) * sizeof(*n));
        if (!n)
                return -ENOMEM;
        d->properties = n;

        d->properties[d->n_properties].key = strdup(key);
        d->properties[d->n_properties].value = strdup(value);
        if (!d->properties[d->n_properties].key || !d->properties[d->n_properties].value) {
                free(d->properties[d->n_properties].key);
                free(d->properties[d->n_properties].value);
                return -ENOMEM;
        }

        d->n_properties++;
        return 0;
}

int device_set_monitor_properties(sd_device *d, const char * const *keys, const char * const *values, size_t n) {
        size_t i;
        int r;

        for (i = 0; i < n; i++) {
                r = device_add_property(d, keys[i], values[i]);
                if (r < 0)
                        return r;
        }

        d->from_monitor = true;
        return 0;
}

const char *device_get_property_raw(sd_device *d, const char *key) {
        size_t i;

        for (i = 0; i < d->n_properties; i++)
                if (strcmp(d->properties[i].key, key) == 0)
                        return d->properties[i].value;

        return NULL;
}

/* KEY=VALUE lines, exactly the shape both a /sys/.../uevent file and this
 * shim's monitor env use. A line with no '=' or an empty line is skipped:
 * "make sense of what's there" rather than treat a stray blank line as a
 * malformed file. */
static int read_uevent_file(sd_device *d) {
        char path[PATH_MAX];
        FILE *f;
        char line[1024];

        if ((size_t) snprintf(path, sizeof(path), "%s/uevent", d->syspath) >= sizeof(path))
                return -ENAMETOOLONG;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        while (fgets(line, sizeof(line), f)) {
                char *nl = strchr(line, '\n'), *eq;

                if (nl)
                        *nl = '\0';
                if (line[0] == '\0')
                        continue;

                eq = strchr(line, '=');
                if (!eq)
                        continue;
                *eq = '\0';

                (void) device_add_property(d, line, eq + 1);
        }

        fclose(f);
        return 0;
}

int device_ensure_properties(sd_device *d) {
        char buf[32];
        const char *s;
        int r;

        if (d->properties_built)
                return d->properties_errno;

        if (!d->no_uevent_file && !d->from_monitor) {
                r = read_uevent_file(d);
                if (r < 0 && r != -ENOENT) {
                        d->properties_errno = r;
                        d->properties_built = true;
                        return r;
                }
        }
        /* no_uevent_file: nothing to read (subsystem pseudo-device).
         * from_monitor: device_set_monitor_properties() already populated
         * the base table at construction time. */

        (void) device_add_property(d, "DEVPATH", d->devpath);

        if (sd_device_get_subsystem(d, &s) >= 0)
                (void) device_add_property(d, "SUBSYSTEM", s);

        if (sd_device_get_driver(d, &s) >= 0)
                (void) device_add_property(d, "DRIVER", s);

        if (d->action != _SD_DEVICE_ACTION_INVALID)
                (void) device_add_property(d, "ACTION", device_action_to_string(d->action));

        if (d->has_seqnum) {
                snprintf(buf, sizeof(buf), "%" PRIu64, d->seqnum);
                (void) device_add_property(d, "SEQNUM", buf);
        }

        if (d->has_synth_uuid) {
                char uuid[37];

                device_id128_to_uuid_string(d->synth_uuid, uuid);
                (void) device_add_property(d, "SYNTH_UUID", uuid);
        }

        d->properties_errno = 0;
        d->properties_built = true;
        return 0;
}

int sd_device_get_devtype(sd_device *device, const char **ret) {
        const char *v;
        int r;

        if (!device)
                return -EINVAL;

        r = device_ensure_properties(device);
        if (r < 0)
                return r;

        v = device_get_property_raw(device, "DEVTYPE");
        if (!v)
                return -ENOENT;

        if (ret)
                *ret = v;
        return 0;
}

int sd_device_get_devnum(sd_device *device, dev_t *ret) {
        const char *maj, *min;
        char *end;
        unsigned long majv, minv;
        int r;

        if (!device || !ret)
                return -EINVAL;

        r = device_ensure_properties(device);
        if (r < 0)
                return r;

        maj = device_get_property_raw(device, "MAJOR");
        min = device_get_property_raw(device, "MINOR");
        if (!maj || !min)
                return -ENOENT;

        majv = strtoul(maj, &end, 10);
        if (*end != '\0')
                return -EINVAL;
        minv = strtoul(min, &end, 10);
        if (*end != '\0')
                return -EINVAL;

        *ret = makedev((unsigned) majv, (unsigned) minv);
        return 0;
}

int sd_device_get_ifindex(sd_device *device, int *ret) {
        const char *v;
        char *end;
        long val;
        int r;

        if (!device || !ret)
                return -EINVAL;

        r = device_ensure_properties(device);
        if (r < 0)
                return r;

        v = device_get_property_raw(device, "IFINDEX");
        if (!v)
                return -ENOENT;

        val = strtol(v, &end, 10);
        if (*end != '\0' || val <= 0 || val > INT_MAX)
                return -EINVAL;

        *ret = (int) val;
        return 0;
}

int sd_device_get_diskseq(sd_device *device, uint64_t *ret) {
        const char *v;
        char *end;
        unsigned long long val;
        int r;

        if (!device || !ret)
                return -EINVAL;

        r = device_ensure_properties(device);
        if (r < 0)
                return r;

        v = device_get_property_raw(device, "DISKSEQ");
        if (!v)
                return -ENOENT;

        val = strtoull(v, &end, 10);
        if (*end != '\0')
                return -EINVAL;

        *ret = val;
        return 0;
}

int sd_device_get_devname(sd_device *device, const char **ret) {
        const char *raw;
        int r;

        if (!device)
                return -EINVAL;

        r = device_ensure_properties(device);
        if (r < 0)
                return r;

        raw = device_get_property_raw(device, "DEVNAME");
        if (!raw)
                return -ENOENT;

        if (!device->devname_resolved) {
                if (raw[0] == '/')
                        device->devname = strdup(raw);
                else {
                        char buf[PATH_MAX];

                        if ((size_t) snprintf(buf, sizeof(buf), "/dev/%s", raw) >= sizeof(buf))
                                device->devname = NULL;
                        else
                                device->devname = strdup(buf);
                }
                device->devname_resolved = true;
        }

        if (!device->devname)
                return -ENOMEM;

        if (ret)
                *ret = device->devname;
        return 0;
}

int sd_device_get_action(sd_device *device, sd_device_action_t *ret) {
        if (!device)
                return -EINVAL;

        if (device->action == _SD_DEVICE_ACTION_INVALID)
                return -ENOENT;

        if (ret)
                *ret = device->action;
        return 0;
}

int sd_device_get_seqnum(sd_device *device, uint64_t *ret) {
        if (!device)
                return -EINVAL;

        if (!device->has_seqnum)
                return -ENOENT;

        if (ret)
                *ret = device->seqnum;
        return 0;
}

int sd_device_get_trigger_uuid(sd_device *device, sd_id128_t *ret) {
        if (!device)
                return -EINVAL;

        if (!device->has_synth_uuid)
                return -ENOENT;

        if (ret)
                *ret = device->synth_uuid;
        return 0;
}
