/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Property iteration and lookup, plus the tag family. Pico has no tag
 * mechanism at all: devd has no TAG+=, and the udev database entries it does
 * write (device-db.c) carry no G:/Q: records, so the tag set is genuinely
 * empty rather than stubbed -- see sd-device.h's design note; these are the
 * correct answers, not placeholders.
 */

#include "sd-device.h"

#include <errno.h>

#include "device-internal.h"

const char *sd_device_get_property_first(sd_device *device, const char **value) {
        int r;

        if (!device)
                return NULL;

        r = device_ensure_properties(device);
        if (r < 0 || device->n_properties == 0)
                return NULL;

        device->property_iter = 1;
        if (value)
                *value = device->properties[0].value;
        return device->properties[0].key;
}

const char *sd_device_get_property_next(sd_device *device, const char **value) {
        if (!device || device->property_iter >= device->n_properties)
                return NULL;

        if (value)
                *value = device->properties[device->property_iter].value;
        return device->properties[device->property_iter++].key;
}

int sd_device_get_property_value(sd_device *device, const char *key, const char **ret) {
        const char *v;
        int r;

        if (!device || !key)
                return -EINVAL;

        r = device_ensure_properties(device);
        if (r < 0)
                return r;

        v = device_get_property_raw(device, key);
        if (!v)
                return -ENOENT;

        if (ret)
                *ret = v;
        return 0;
}

const char *sd_device_get_tag_first(sd_device *device) {
        (void) device;
        return NULL;
}

const char *sd_device_get_tag_next(sd_device *device) {
        (void) device;
        return NULL;
}

const char *sd_device_get_current_tag_first(sd_device *device) {
        (void) device;
        return NULL;
}

const char *sd_device_get_current_tag_next(sd_device *device) {
        (void) device;
        return NULL;
}

int sd_device_has_tag(sd_device *device, const char *tag) {
        if (!device || !tag)
                return -EINVAL;

        return 0; /* the tag set is genuinely empty */
}

int sd_device_has_current_tag(sd_device *device, const char *tag) {
        if (!device || !tag)
                return -EINVAL;

        return 0;
}
