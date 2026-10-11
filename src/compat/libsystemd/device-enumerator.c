/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_device_enumerator: the match-list accessors, and the two scans
 * (get_device_first/next over real devices, get_subsystem_first/next over
 * the bus/class/module pseudo-devices).
 *
 * Both scans rescan on every _first call; /sys on an embedded board is
 * small, and this avoids any cache invalidation.
 */

#include "sd-device.h"

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device-internal.h"

/* --- construction / refcounting --- */

int sd_device_enumerator_new(sd_device_enumerator **ret) {
        sd_device_enumerator *e;

        if (!ret)
                return -EINVAL;

        e = calloc(1, sizeof(*e));
        if (!e)
                return -ENOMEM;

        e->n_ref = 1;
        *ret = e;
        return 0;
}

sd_device_enumerator *sd_device_enumerator_ref(sd_device_enumerator *enumerator) {
        if (!enumerator)
                return NULL;

        enumerator->n_ref++;
        return enumerator;
}

static void strv_free_n(char **v, size_t n) {
        size_t i;

        for (i = 0; i < n; i++)
                free(v[i]);
        free(v);
}

static void devices_clear(sd_device_enumerator *e) {
        size_t i;

        for (i = 0; i < e->n_devices; i++)
                sd_device_unref(e->devices[i]);
        free(e->devices);
        e->devices = NULL;
        e->n_devices = 0;
        e->scanned = false;
}

sd_device_enumerator *sd_device_enumerator_unref(sd_device_enumerator *enumerator) {
        size_t i;

        if (!enumerator)
                return NULL;

        if (--enumerator->n_ref > 0)
                return NULL;

        strv_free_n(enumerator->match_subsystem, enumerator->n_match_subsystem);
        strv_free_n(enumerator->nomatch_subsystem, enumerator->n_nomatch_subsystem);

        for (i = 0; i < enumerator->n_sysattr_matches; i++) {
                free(enumerator->sysattr_matches[i].sysattr);
                free(enumerator->sysattr_matches[i].value);
        }
        free(enumerator->sysattr_matches);

        for (i = 0; i < enumerator->n_property_matches; i++) {
                free(enumerator->property_matches[i].key);
                free(enumerator->property_matches[i].value);
        }
        free(enumerator->property_matches);

        for (i = 0; i < enumerator->n_property_required; i++) {
                free(enumerator->property_required[i].key);
                free(enumerator->property_required[i].value);
        }
        free(enumerator->property_required);

        strv_free_n(enumerator->match_sysname, enumerator->n_match_sysname);
        strv_free_n(enumerator->nomatch_sysname, enumerator->n_nomatch_sysname);
        strv_free_n(enumerator->match_tag, enumerator->n_match_tag);
        strv_free_n(enumerator->match_parent, enumerator->n_match_parent);

        devices_clear(enumerator);
        free(enumerator);
        return NULL;
}

/* --- match accessors --- */

static int strv_append(char ***v, size_t *n, const char *s) {
        char **nv;
        size_t i;

        for (i = 0; i < *n; i++)
                if (strcmp((*v)[i], s) == 0)
                        return 0; /* idempotent */

        nv = realloc(*v, (*n + 1) * sizeof(*nv));
        if (!nv)
                return -ENOMEM;
        *v = nv;

        (*v)[*n] = strdup(s);
        if (!(*v)[*n])
                return -ENOMEM;
        (*n)++;
        return 0;
}

int sd_device_enumerator_add_match_subsystem(sd_device_enumerator *enumerator, const char *subsystem, int match) {
        int r;

        if (!enumerator || !subsystem)
                return -EINVAL;

        r = match ? strv_append(&enumerator->match_subsystem, &enumerator->n_match_subsystem, subsystem) :
                    strv_append(&enumerator->nomatch_subsystem, &enumerator->n_nomatch_subsystem, subsystem);
        if (r < 0)
                return r;

        devices_clear(enumerator);
        return 0;
}

int sd_device_enumerator_add_match_sysattr(
                sd_device_enumerator *enumerator, const char *sysattr, const char *value, int match) {
        void *n;

        if (!enumerator || !sysattr)
                return -EINVAL;

        n = realloc(enumerator->sysattr_matches,
                    (enumerator->n_sysattr_matches + 1) * sizeof(*enumerator->sysattr_matches));
        if (!n)
                return -ENOMEM;
        enumerator->sysattr_matches = n;

        enumerator->sysattr_matches[enumerator->n_sysattr_matches].sysattr = strdup(sysattr);
        enumerator->sysattr_matches[enumerator->n_sysattr_matches].value = value ? strdup(value) : NULL;
        enumerator->sysattr_matches[enumerator->n_sysattr_matches].match = match != 0;
        if (!enumerator->sysattr_matches[enumerator->n_sysattr_matches].sysattr)
                return -ENOMEM;
        enumerator->n_sysattr_matches++;

        devices_clear(enumerator);
        return 0;
}

static int property_append(DeviceEnumeratorProperty **list, size_t *n, const char *key, const char *value) {
        void *nl = realloc(*list, (*n + 1) * sizeof(**list));

        if (!nl)
                return -ENOMEM;
        *list = nl;

        (*list)[*n].key = strdup(key);
        (*list)[*n].value = value ? strdup(value) : NULL;
        if (!(*list)[*n].key)
                return -ENOMEM;
        (*n)++;
        return 0;
}

int sd_device_enumerator_add_match_property(
                sd_device_enumerator *enumerator, const char *property, const char *value) {
        int r;

        if (!enumerator || !property)
                return -EINVAL;

        r = property_append(&enumerator->property_matches, &enumerator->n_property_matches, property, value);
        if (r < 0)
                return r;

        devices_clear(enumerator);
        return 0;
}

int sd_device_enumerator_add_match_property_required(
                sd_device_enumerator *enumerator, const char *property, const char *value) {
        int r;

        if (!enumerator || !property)
                return -EINVAL;

        r = property_append(&enumerator->property_required, &enumerator->n_property_required, property, value);
        if (r < 0)
                return r;

        devices_clear(enumerator);
        return 0;
}

int sd_device_enumerator_add_match_sysname(sd_device_enumerator *enumerator, const char *sysname) {
        int r;

        if (!enumerator || !sysname)
                return -EINVAL;

        r = strv_append(&enumerator->match_sysname, &enumerator->n_match_sysname, sysname);
        if (r < 0)
                return r;

        devices_clear(enumerator);
        return 0;
}

int sd_device_enumerator_add_nomatch_sysname(sd_device_enumerator *enumerator, const char *sysname) {
        int r;

        if (!enumerator || !sysname)
                return -EINVAL;

        r = strv_append(&enumerator->nomatch_sysname, &enumerator->n_nomatch_sysname, sysname);
        if (r < 0)
                return r;

        devices_clear(enumerator);
        return 0;
}

int sd_device_enumerator_add_match_tag(sd_device_enumerator *enumerator, const char *tag) {
        int r;

        if (!enumerator || !tag)
                return -EINVAL;

        /* The tag set is always empty (sd-device.h's design note), so any
         * tag filter yields an empty enumeration -- a fact about this
         * system, not a bug in this filter. */
        r = strv_append(&enumerator->match_tag, &enumerator->n_match_tag, tag);
        if (r < 0)
                return r;

        devices_clear(enumerator);
        return 0;
}

int sd_device_enumerator_add_match_parent(sd_device_enumerator *enumerator, sd_device *parent) {
        const char *syspath;
        int r;

        if (!enumerator || !parent)
                return -EINVAL;

        r = sd_device_get_syspath(parent, &syspath);
        if (r < 0)
                return r;

        r = strv_append(&enumerator->match_parent, &enumerator->n_match_parent, syspath);
        if (r < 0)
                return r;

        devices_clear(enumerator);
        return 0;
}

int sd_device_enumerator_allow_uninitialized(sd_device_enumerator *enumerator) {
        if (!enumerator)
                return -EINVAL;

        /* Every pico device already reports initialized, so this changes
         * nothing observable -- see sd_device_get_is_initialized(). */
        enumerator->allow_uninitialized = true;
        return 0;
}

int sd_device_enumerator_add_all_parents(sd_device_enumerator *enumerator) {
        if (!enumerator)
                return -EINVAL;

        enumerator->all_parents = true;
        devices_clear(enumerator);
        return 0;
}

/* --- filtering --- */

static bool strv_contains(char * const *v, size_t n, const char *s) {
        size_t i;

        for (i = 0; i < n; i++)
                if (strcmp(v[i], s) == 0)
                        return true;
        return false;
}

static bool strv_glob_contains(char * const *v, size_t n, const char *s) {
        size_t i;

        for (i = 0; i < n; i++)
                if (fnmatch(v[i], s, 0) == 0)
                        return true;
        return false;
}

static bool property_glob_matches(sd_device *dev, const char *key_pat, const char *value_pat) {
        const char *key, *value;

        for (key = sd_device_get_property_first(dev, &value); key;
             key = sd_device_get_property_next(dev, &value))
                if (fnmatch(key_pat, key, 0) == 0 && (!value_pat || fnmatch(value_pat, value, 0) == 0))
                        return true;

        return false;
}

static bool device_passes_filters(sd_device_enumerator *e, sd_device *dev) {
        const char *sysname, *subsystem;
        size_t i;

        if (sd_device_get_sysname(dev, &sysname) < 0)
                return false;

        if (e->n_match_sysname > 0 && !strv_glob_contains(e->match_sysname, e->n_match_sysname, sysname))
                return false;
        if (strv_glob_contains(e->nomatch_sysname, e->n_nomatch_sysname, sysname))
                return false;

        if (e->n_match_subsystem > 0 || e->n_nomatch_subsystem > 0) {
                if (sd_device_get_subsystem(dev, &subsystem) < 0)
                        subsystem = NULL;

                if (e->n_match_subsystem > 0 &&
                    (!subsystem || !strv_contains(e->match_subsystem, e->n_match_subsystem, subsystem)))
                        return false;
                if (subsystem && strv_contains(e->nomatch_subsystem, e->n_nomatch_subsystem, subsystem))
                        return false;
        }

        if (e->n_match_tag > 0)
                return false; /* the tag set is always empty */

        if (e->n_match_parent > 0) {
                const char *syspath;
                bool under_any = false;

                if (sd_device_get_syspath(dev, &syspath) < 0)
                        return false;

                for (i = 0; i < e->n_match_parent; i++) {
                        size_t plen = strlen(e->match_parent[i]);

                        if (strcmp(syspath, e->match_parent[i]) == 0 ||
                            (strncmp(syspath, e->match_parent[i], plen) == 0 && syspath[plen] == '/')) {
                                under_any = true;
                                break;
                        }
                }
                if (!under_any)
                        return false;
        }

        for (i = 0; i < e->n_sysattr_matches; i++) {
                const char *v;
                int r = sd_device_get_sysattr_value(dev, e->sysattr_matches[i].sysattr, &v);
                bool has = r >= 0;
                bool value_matches = has &&
                                (!e->sysattr_matches[i].value ||
                                 fnmatch(e->sysattr_matches[i].value, v, 0) == 0);

                if (e->sysattr_matches[i].match) {
                        if (!value_matches)
                                return false;
                } else {
                        if (value_matches)
                                return false;
                }
        }

        if (e->n_property_matches > 0) {
                bool any = false;

                for (i = 0; i < e->n_property_matches; i++)
                        if (property_glob_matches(
                                            dev, e->property_matches[i].key, e->property_matches[i].value)) {
                                any = true;
                                break;
                        }
                if (!any)
                        return false;
        }

        for (i = 0; i < e->n_property_required; i++)
                if (!property_glob_matches(dev, e->property_required[i].key, e->property_required[i].value))
                        return false;

        return true;
}

/* --- device scan --- */

static int candidates_add(char ***list, size_t *n, const char *syspath) {
        char **nv;
        size_t i;

        for (i = 0; i < *n; i++)
                if (strcmp((*list)[i], syspath) == 0)
                        return 0;

        nv = realloc(*list, (*n + 1) * sizeof(*nv));
        if (!nv)
                return -ENOMEM;
        *list = nv;

        (*list)[*n] = strdup(syspath);
        if (!(*list)[*n])
                return -ENOMEM;
        (*n)++;
        return 0;
}

static void scan_symlink_dir(const char *dir, char ***candidates, size_t *n_candidates) {
        DIR *dh = opendir(dir);
        struct dirent *de;

        if (!dh)
                return;

        while ((de = readdir(dh))) {
                char linkpath[PATH_MAX], resolved[PATH_MAX];

                if (de->d_name[0] == '.')
                        continue;
                if ((size_t) snprintf(linkpath, sizeof(linkpath), "%s/%s", dir, de->d_name) >= sizeof(linkpath))
                        continue;
                if (realpath(linkpath, resolved))
                        (void) candidates_add(candidates, n_candidates, resolved);
        }

        closedir(dh);
}

static void collect_device_candidates(const char *root, char ***candidates, size_t *n_candidates) {
        char busdir[PATH_MAX], classdir[PATH_MAX];
        DIR *bd, *cd;
        struct dirent *be, *ce;

        (void) snprintf(busdir, sizeof(busdir), "%s/bus", root);
        bd = opendir(busdir);
        if (bd) {
                while ((be = readdir(bd))) {
                        char devdir[PATH_MAX];

                        if (be->d_name[0] == '.')
                                continue;
                        if ((size_t) snprintf(devdir, sizeof(devdir), "%s/%s/devices", busdir, be->d_name) >=
                            sizeof(devdir))
                                continue;
                        scan_symlink_dir(devdir, candidates, n_candidates);
                }
                closedir(bd);
        }

        (void) snprintf(classdir, sizeof(classdir), "%s/class", root);
        cd = opendir(classdir);
        if (cd) {
                while ((ce = readdir(cd))) {
                        char subdir[PATH_MAX];

                        if (ce->d_name[0] == '.')
                                continue;
                        if ((size_t) snprintf(subdir, sizeof(subdir), "%s/%s", classdir, ce->d_name) >=
                            sizeof(subdir))
                                continue;
                        scan_symlink_dir(subdir, candidates, n_candidates);
                }
                closedir(cd);
        }
}

static int devices_append(sd_device_enumerator *e, sd_device *dev) {
        sd_device **n = realloc(e->devices, (e->n_devices + 1) * sizeof(*n));

        if (!n)
                return -ENOMEM;
        e->devices = n;
        e->devices[e->n_devices++] = dev;
        return 0;
}

static bool devices_contains_syspath(sd_device_enumerator *e, const char *syspath) {
        size_t i;
        const char *s;

        for (i = 0; i < e->n_devices; i++)
                if (sd_device_get_syspath(e->devices[i], &s) >= 0 && strcmp(s, syspath) == 0)
                        return true;
        return false;
}

static int cmp_str(const void *a, const void *b) {
        return strcmp(*(char * const *) a, *(char * const *) b);
}

static void enumerator_scan_devices(sd_device_enumerator *e) {
        char **candidates = NULL;
        size_t n_candidates = 0, i;

        collect_device_candidates(device_sys_root(), &candidates, &n_candidates);
        if (n_candidates > 0)
                qsort(candidates, n_candidates, sizeof(*candidates), cmp_str);

        for (i = 0; i < n_candidates; i++) {
                sd_device *dev = NULL;

                if (device_new_from_syspath_internal(&dev, candidates[i], false) < 0)
                        continue; /* hot-unplug race: not there any more */

                if (device_passes_filters(e, dev))
                        (void) devices_append(e, dev);
                else
                        sd_device_unref(dev);
        }

        strv_free_n(candidates, n_candidates);

        if (e->all_parents) {
                size_t n_before = e->n_devices;

                for (i = 0; i < n_before; i++) {
                        sd_device *cur = e->devices[i];

                        for (;;) {
                                sd_device *parent;
                                const char *syspath;

                                if (sd_device_get_parent(cur, &parent) < 0)
                                        break;
                                cur = parent;

                                if (sd_device_get_syspath(cur, &syspath) < 0)
                                        break;
                                if (!devices_contains_syspath(e, syspath))
                                        (void) devices_append(e, sd_device_ref(cur));
                        }
                }
        }

        e->scanned = true;
        e->iter = 0;
}

sd_device *sd_device_enumerator_get_device_first(sd_device_enumerator *enumerator) {
        if (!enumerator)
                return NULL;

        devices_clear(enumerator);
        enumerator_scan_devices(enumerator);

        if (enumerator->n_devices == 0)
                return NULL;

        enumerator->iter = 1;
        return enumerator->devices[0];
}

sd_device *sd_device_enumerator_get_device_next(sd_device_enumerator *enumerator) {
        if (!enumerator || enumerator->iter >= enumerator->n_devices)
                return NULL;

        return enumerator->devices[enumerator->iter++];
}

/* --- subsystem pseudo-device scan --- */

static bool subsystem_passes_filters(sd_device_enumerator *e, const char *name) {
        if (e->n_match_subsystem > 0 && !strv_contains(e->match_subsystem, e->n_match_subsystem, name))
                return false;
        if (strv_contains(e->nomatch_subsystem, e->n_nomatch_subsystem, name))
                return false;
        if (e->n_match_sysname > 0 && !strv_glob_contains(e->match_sysname, e->n_match_sysname, name))
                return false;
        if (strv_glob_contains(e->nomatch_sysname, e->n_nomatch_sysname, name))
                return false;

        return true;
}

static void scan_pseudo_dir(sd_device_enumerator *e, const char *dir) {
        DIR *dh = opendir(dir);
        struct dirent *de;

        if (!dh)
                return;

        while ((de = readdir(dh))) {
                char path[PATH_MAX];
                sd_device *dev = NULL;

                if (de->d_name[0] == '.')
                        continue;
                if (!subsystem_passes_filters(e, de->d_name))
                        continue;
                if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) >= sizeof(path))
                        continue;

                if (device_new_from_syspath_internal(&dev, path, true) < 0)
                        continue;

                (void) devices_append(e, dev);
        }

        closedir(dh);
}

sd_device *sd_device_enumerator_get_subsystem_first(sd_device_enumerator *enumerator) {
        char path[PATH_MAX];
        const char *root;

        if (!enumerator)
                return NULL;

        devices_clear(enumerator);
        root = device_sys_root();

        (void) snprintf(path, sizeof(path), "%s/bus", root);
        scan_pseudo_dir(enumerator, path);
        (void) snprintf(path, sizeof(path), "%s/class", root);
        scan_pseudo_dir(enumerator, path);
        (void) snprintf(path, sizeof(path), "%s/module", root);
        scan_pseudo_dir(enumerator, path);

        enumerator->scanned = true;
        enumerator->iter = 0;

        if (enumerator->n_devices == 0)
                return NULL;

        enumerator->iter = 1;
        return enumerator->devices[0];
}

sd_device *sd_device_enumerator_get_subsystem_next(sd_device_enumerator *enumerator) {
        if (!enumerator || enumerator->iter >= enumerator->n_devices)
                return NULL;

        return enumerator->devices[enumerator->iter++];
}
