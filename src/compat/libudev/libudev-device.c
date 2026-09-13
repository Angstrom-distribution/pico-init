/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * udev_device over sd_device, the same one-object-wraps-the-other shape
 * upstream's libudev-device.c has. The libudev error convention differs
 * from sd-device's (NULL/0 plus errno instead of a negative return), and
 * "no such value" answers (-ENOENT from a getter) are the documented
 * NULL/0 result rather than an error.
 *
 * udev_device_new_from_environment() is the one constructor with no
 * public sd-device counterpart: the process environment is kept as a
 * property overlay on the wrapper itself, consulted before the sysfs
 * snapshot, which is what an IMPORT=/RUN+= helper started with
 * DEVPATH=/ACTION= in its environment expects to see.
 */

#include "libudev.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libudev-internal.h"

extern char **environ;

struct udev_device {
        struct udev *udev;
        unsigned n_ref;
        sd_device *device;

        struct udev_device *parent;
        bool parent_set;

        struct udev_list *properties, *tags, *current_tags, *devlinks, *sysattrs;
        bool properties_read, tags_read, current_tags_read, devlinks_read, sysattrs_read;

        struct udev_list *env; /* new_from_environment() overlay, else NULL */
};

static const char * const action_names[_SD_DEVICE_ACTION_MAX] = {
        [SD_DEVICE_ADD] = "add",       [SD_DEVICE_REMOVE] = "remove", [SD_DEVICE_CHANGE] = "change",
        [SD_DEVICE_MOVE] = "move",     [SD_DEVICE_ONLINE] = "online", [SD_DEVICE_OFFLINE] = "offline",
        [SD_DEVICE_BIND] = "bind",     [SD_DEVICE_UNBIND] = "unbind",
};

static void *fail_errno(int r) {
        errno = -r;
        return NULL;
}

struct udev_device *libudev_device_new(struct udev *udev, sd_device *device) {
        struct udev_device *d;

        if (!device)
                return fail_errno(-EINVAL);

        d = calloc(1, sizeof(*d));
        if (!d)
                return fail_errno(-ENOMEM);

        d->properties = libudev_list_new(true);
        d->tags = libudev_list_new(true);
        d->current_tags = libudev_list_new(true);
        d->devlinks = libudev_list_new(true);
        d->sysattrs = libudev_list_new(true);
        if (!d->properties || !d->tags || !d->current_tags || !d->devlinks || !d->sysattrs) {
                libudev_list_free(d->properties);
                libudev_list_free(d->tags);
                libudev_list_free(d->current_tags);
                libudev_list_free(d->devlinks);
                libudev_list_free(d->sysattrs);
                free(d);
                return fail_errno(-ENOMEM);
        }

        d->n_ref = 1;
        d->udev = udev;
        d->device = sd_device_ref(device);
        return d;
}

sd_device *libudev_device_get_sd_device(struct udev_device *udev_device) {
        return udev_device ? udev_device->device : NULL;
}

static struct udev_device *wrap_new(struct udev *udev, sd_device *device, int r) {
        struct udev_device *d;

        if (r < 0)
                return fail_errno(r);

        d = libudev_device_new(udev, device);
        sd_device_unref(device);
        return d;
}

struct udev_device *udev_device_new_from_syspath(struct udev *udev, const char *syspath) {
        sd_device *device = NULL;
        int r;

        r = sd_device_new_from_syspath(&device, syspath);
        return wrap_new(udev, device, r);
}

struct udev_device *udev_device_new_from_devnum(struct udev *udev, char type, dev_t devnum) {
        sd_device *device = NULL;
        int r;

        r = sd_device_new_from_devnum(&device, type, devnum);
        return wrap_new(udev, device, r);
}

struct udev_device *udev_device_new_from_subsystem_sysname(struct udev *udev, const char *subsystem, const char *sysname) {
        sd_device *device = NULL;
        int r;

        r = sd_device_new_from_subsystem_sysname(&device, subsystem, sysname);
        return wrap_new(udev, device, r);
}

struct udev_device *udev_device_new_from_device_id(struct udev *udev, const char *id) {
        sd_device *device = NULL;
        int r;

        r = sd_device_new_from_device_id(&device, id);
        return wrap_new(udev, device, r);
}

struct udev_device *udev_device_new_from_environment(struct udev *udev) {
        const char *devpath = getenv("DEVPATH");
        char syspath[PATH_MAX];
        sd_device *device = NULL;
        struct udev_device *d;
        char **e;
        int r;

        if (!devpath || devpath[0] != '/')
                return fail_errno(-EINVAL);
        if ((size_t) snprintf(syspath, sizeof(syspath), "/sys%s", devpath) >= sizeof(syspath))
                return fail_errno(-ENAMETOOLONG);

        r = sd_device_new_from_syspath(&device, syspath);
        if (r < 0)
                return fail_errno(r);

        d = libudev_device_new(udev, device);
        sd_device_unref(device);
        if (!d)
                return NULL;

        d->env = libudev_list_new(true);
        if (!d->env) {
                udev_device_unref(d);
                return fail_errno(-ENOMEM);
        }
        for (e = environ; e && *e; e++) {
                const char *eq = strchr(*e, '=');
                char key[256];
                size_t klen;

                if (!eq || eq == *e)
                        continue;
                klen = (size_t) (eq - *e);
                if (klen >= sizeof(key))
                        continue;
                memcpy(key, *e, klen);
                key[klen] = '\0';
                if (!libudev_list_add(d->env, key, eq + 1)) {
                        udev_device_unref(d);
                        return fail_errno(-ENOMEM);
                }
        }

        return d;
}

struct udev_device *udev_device_ref(struct udev_device *udev_device) {
        if (!udev_device)
                return NULL;
        udev_device->n_ref++;
        return udev_device;
}

struct udev_device *udev_device_unref(struct udev_device *udev_device) {
        if (!udev_device)
                return NULL;
        if (--udev_device->n_ref > 0)
                return NULL;

        sd_device_unref(udev_device->device);
        udev_device_unref(udev_device->parent);
        libudev_list_free(udev_device->properties);
        libudev_list_free(udev_device->tags);
        libudev_list_free(udev_device->current_tags);
        libudev_list_free(udev_device->devlinks);
        libudev_list_free(udev_device->sysattrs);
        libudev_list_free(udev_device->env);
        free(udev_device);
        return NULL;
}

struct udev *udev_device_get_udev(struct udev_device *udev_device) {
        if (!udev_device)
                return fail_errno(-EINVAL);
        return udev_device->udev;
}

/* --- parent chain --- */

struct udev_device *udev_device_get_parent(struct udev_device *udev_device) {
        if (!udev_device)
                return fail_errno(-EINVAL);

        if (!udev_device->parent_set) {
                sd_device *parent;
                int r;

                udev_device->parent_set = true;
                r = sd_device_get_parent(udev_device->device, &parent);
                if (r < 0)
                        return fail_errno(r);
                udev_device->parent = libudev_device_new(udev_device->udev, parent);
        }

        if (!udev_device->parent)
                errno = ENOENT;
        return udev_device->parent;
}

struct udev_device *udev_device_get_parent_with_subsystem_devtype(
                struct udev_device *udev_device, const char *subsystem, const char *devtype) {
        sd_device *parent;
        const char *want;
        int r;

        if (!udev_device)
                return fail_errno(-EINVAL);

        r = sd_device_get_parent_with_subsystem_devtype(udev_device->device, subsystem, devtype, &parent);
        if (r < 0)
                return fail_errno(r);
        r = sd_device_get_syspath(parent, &want);
        if (r < 0)
                return fail_errno(r);

        /* Hand back the wrapper on our own parent chain for that syspath,
         * so its lifetime is the child's like every other parent result. */
        while ((udev_device = udev_device_get_parent(udev_device))) {
                const char *have;

                if (sd_device_get_syspath(udev_device->device, &have) >= 0 && strcmp(have, want) == 0)
                        return udev_device;
        }

        return fail_errno(-ENOENT);
}

/* --- scalar getters --- */

static const char *string_getter(int r, const char *value, bool enoent_is_null) {
        if (r == -ENOENT && enoent_is_null)
                return NULL;
        if (r < 0)
                return fail_errno(r);
        return value;
}

const char *udev_device_get_devpath(struct udev_device *udev_device) {
        const char *v = NULL;

        if (!udev_device)
                return fail_errno(-EINVAL);
        return string_getter(sd_device_get_devpath(udev_device->device, &v), v, false);
}

const char *udev_device_get_syspath(struct udev_device *udev_device) {
        const char *v = NULL;

        if (!udev_device)
                return fail_errno(-EINVAL);
        return string_getter(sd_device_get_syspath(udev_device->device, &v), v, false);
}

const char *udev_device_get_sysname(struct udev_device *udev_device) {
        const char *v = NULL;

        if (!udev_device)
                return fail_errno(-EINVAL);
        return string_getter(sd_device_get_sysname(udev_device->device, &v), v, false);
}

const char *udev_device_get_sysnum(struct udev_device *udev_device) {
        const char *v = NULL;

        if (!udev_device)
                return fail_errno(-EINVAL);
        return string_getter(sd_device_get_sysnum(udev_device->device, &v), v, true);
}

const char *udev_device_get_subsystem(struct udev_device *udev_device) {
        const char *v = NULL;

        if (!udev_device)
                return fail_errno(-EINVAL);
        return string_getter(sd_device_get_subsystem(udev_device->device, &v), v, false);
}

const char *udev_device_get_devtype(struct udev_device *udev_device) {
        const char *v = NULL;

        if (!udev_device)
                return fail_errno(-EINVAL);
        return string_getter(sd_device_get_devtype(udev_device->device, &v), v, true);
}

const char *udev_device_get_driver(struct udev_device *udev_device) {
        const char *v = NULL;

        if (!udev_device)
                return fail_errno(-EINVAL);
        return string_getter(sd_device_get_driver(udev_device->device, &v), v, false);
}

const char *udev_device_get_devnode(struct udev_device *udev_device) {
        const char *v = NULL;

        if (!udev_device)
                return fail_errno(-EINVAL);
        return string_getter(sd_device_get_devname(udev_device->device, &v), v, false);
}

dev_t udev_device_get_devnum(struct udev_device *udev_device) {
        dev_t devnum;
        int r;

        if (!udev_device) {
                errno = EINVAL;
                return makedev(0, 0);
        }

        r = sd_device_get_devnum(udev_device->device, &devnum);
        if (r == -ENOENT)
                return makedev(0, 0);
        if (r < 0) {
                errno = -r;
                return makedev(0, 0);
        }
        return devnum;
}

const char *udev_device_get_action(struct udev_device *udev_device) {
        sd_device_action_t action;

        if (!udev_device)
                return fail_errno(-EINVAL);

        if (udev_device->env) {
                const char *v = libudev_list_lookup(udev_device->env, "ACTION");

                if (v)
                        return v;
        }

        if (sd_device_get_action(udev_device->device, &action) < 0)
                return NULL;
        if (action < 0 || action >= _SD_DEVICE_ACTION_MAX)
                return NULL;
        return action_names[action];
}

unsigned long long int udev_device_get_seqnum(struct udev_device *udev_device) {
        uint64_t seqnum;

        if (!udev_device) {
                errno = EINVAL;
                return 0;
        }

        if (udev_device->env) {
                const char *v = libudev_list_lookup(udev_device->env, "SEQNUM");

                if (v)
                        return strtoull(v, NULL, 10);
        }

        if (sd_device_get_seqnum(udev_device->device, &seqnum) < 0)
                return 0;
        return seqnum;
}

int udev_device_get_is_initialized(struct udev_device *udev_device) {
        int r;

        if (!udev_device)
                return -EINVAL;

        r = sd_device_get_is_initialized(udev_device->device);
        if (r < 0) {
                errno = -r;
                return 0;
        }
        return r;
}

unsigned long long int udev_device_get_usec_since_initialized(struct udev_device *udev_device) {
        uint64_t usec;
        int r;

        if (!udev_device)
                return 0;

        r = sd_device_get_usec_since_initialized(udev_device->device, &usec);
        if (r < 0) {
                errno = -r;
                return 0;
        }
        return usec;
}

/* --- properties --- */

const char *udev_device_get_property_value(struct udev_device *udev_device, const char *key) {
        const char *v = NULL;

        if (!udev_device || !key)
                return fail_errno(-EINVAL);

        if (udev_device->env) {
                v = libudev_list_lookup(udev_device->env, key);
                if (v)
                        return v;
        }

        return string_getter(sd_device_get_property_value(udev_device->device, key, &v), v, false);
}

struct udev_list_entry *udev_device_get_properties_list_entry(struct udev_device *udev_device) {
        if (!udev_device)
                return fail_errno(-EINVAL);

        if (!udev_device->properties_read) {
                const char *key, *value;

                libudev_list_clear(udev_device->properties);

                for (key = sd_device_get_property_first(udev_device->device, &value); key;
                     key = sd_device_get_property_next(udev_device->device, &value))
                        if (!libudev_list_add(udev_device->properties, key, value))
                                return fail_errno(-ENOMEM);

                /* The environment overlay wins over the sysfs snapshot, so
                 * it is merged last into a replace-on-duplicate list. */
                if (udev_device->env) {
                        struct udev_list_entry *e;

                        for (e = libudev_list_first(udev_device->env); e; e = udev_list_entry_get_next(e))
                                if (!libudev_list_add(udev_device->properties,
                                                      udev_list_entry_get_name(e),
                                                      udev_list_entry_get_value(e)))
                                        return fail_errno(-ENOMEM);
                }

                udev_device->properties_read = true;
        }

        return libudev_list_first(udev_device->properties);
}

/* --- tags: the set is genuinely empty (no tag mechanism exists here) --- */

struct udev_list_entry *udev_device_get_tags_list_entry(struct udev_device *udev_device) {
        if (!udev_device)
                return fail_errno(-EINVAL);

        if (!udev_device->tags_read) {
                const char *tag;

                libudev_list_clear(udev_device->tags);
                for (tag = sd_device_get_tag_first(udev_device->device); tag;
                     tag = sd_device_get_tag_next(udev_device->device))
                        if (!libudev_list_add(udev_device->tags, tag, NULL))
                                return fail_errno(-ENOMEM);
                udev_device->tags_read = true;
        }

        return libudev_list_first(udev_device->tags);
}

struct udev_list_entry *udev_device_get_current_tags_list_entry(struct udev_device *udev_device) {
        if (!udev_device)
                return fail_errno(-EINVAL);

        if (!udev_device->current_tags_read) {
                const char *tag;

                libudev_list_clear(udev_device->current_tags);
                for (tag = sd_device_get_current_tag_first(udev_device->device); tag;
                     tag = sd_device_get_current_tag_next(udev_device->device))
                        if (!libudev_list_add(udev_device->current_tags, tag, NULL))
                                return fail_errno(-ENOMEM);
                udev_device->current_tags_read = true;
        }

        return libudev_list_first(udev_device->current_tags);
}

int udev_device_has_tag(struct udev_device *udev_device, const char *tag) {
        if (!udev_device)
                return 0;
        return sd_device_has_tag(udev_device->device, tag) > 0;
}

int udev_device_has_current_tag(struct udev_device *udev_device, const char *tag) {
        if (!udev_device)
                return 0;
        return sd_device_has_current_tag(udev_device->device, tag) > 0;
}

/* --- devlinks and sysattrs --- */

struct udev_list_entry *udev_device_get_devlinks_list_entry(struct udev_device *udev_device) {
        if (!udev_device)
                return fail_errno(-EINVAL);

        if (!udev_device->devlinks_read) {
                const char *link;

                libudev_list_clear(udev_device->devlinks);
                for (link = sd_device_get_devlink_first(udev_device->device); link;
                     link = sd_device_get_devlink_next(udev_device->device))
                        if (!libudev_list_add(udev_device->devlinks, link, NULL))
                                return fail_errno(-ENOMEM);
                udev_device->devlinks_read = true;
        }

        return libudev_list_first(udev_device->devlinks);
}

struct udev_list_entry *udev_device_get_sysattr_list_entry(struct udev_device *udev_device) {
        if (!udev_device)
                return fail_errno(-EINVAL);

        if (!udev_device->sysattrs_read) {
                const char *name;

                libudev_list_clear(udev_device->sysattrs);
                for (name = sd_device_get_sysattr_first(udev_device->device); name;
                     name = sd_device_get_sysattr_next(udev_device->device))
                        if (!libudev_list_add(udev_device->sysattrs, name, NULL))
                                return fail_errno(-ENOMEM);
                udev_device->sysattrs_read = true;
        }

        return libudev_list_first(udev_device->sysattrs);
}

const char *udev_device_get_sysattr_value(struct udev_device *udev_device, const char *sysattr) {
        const char *v = NULL;

        if (!udev_device || !sysattr)
                return fail_errno(-EINVAL);
        return string_getter(sd_device_get_sysattr_value(udev_device->device, sysattr, &v), v, false);
}

int udev_device_set_sysattr_value(struct udev_device *udev_device, const char *sysattr, const char *value) {
        if (!udev_device)
                return -EINVAL;
        return sd_device_set_sysattr_value(udev_device->device, sysattr, value);
}
