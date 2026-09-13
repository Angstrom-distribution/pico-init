/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * udev_list_entry: the linked-list view every udev_*_get_*_list_entry()
 * getter returns. Backed by an array of individually allocated entries so
 * an entry pointer stays stable while its list is not being rebuilt.
 */

#include "libudev.h"

#include <stdlib.h>
#include <string.h>

#include "libudev-internal.h"

struct udev_list_entry {
        struct udev_list *list;
        size_t index; /* position in list->entries, refreshed after every sort */
        char *name;
        char *value;
};

struct udev_list {
        struct udev_list_entry **entries;
        size_t n;
        bool unique;
        bool sorted;
};

struct udev_list *libudev_list_new(bool unique) {
        struct udev_list *l = calloc(1, sizeof(*l));

        if (!l)
                return NULL;
        l->unique = unique;
        return l;
}

static void entry_free(struct udev_list_entry *e) {
        if (!e)
                return;
        free(e->name);
        free(e->value);
        free(e);
}

void libudev_list_clear(struct udev_list *list) {
        size_t i;

        if (!list)
                return;
        for (i = 0; i < list->n; i++)
                entry_free(list->entries[i]);
        free(list->entries);
        list->entries = NULL;
        list->n = 0;
        list->sorted = false;
}

void libudev_list_free(struct udev_list *list) {
        if (!list)
                return;
        libudev_list_clear(list);
        free(list);
}

static struct udev_list_entry *find(struct udev_list *list, const char *name) {
        size_t i;

        for (i = 0; i < list->n; i++)
                if (strcmp(list->entries[i]->name, name) == 0)
                        return list->entries[i];
        return NULL;
}

struct udev_list_entry *libudev_list_add(struct udev_list *list, const char *name, const char *value) {
        struct udev_list_entry *e, **n;
        char *v = NULL;

        if (!list || !name)
                return NULL;

        if (value) {
                v = strdup(value);
                if (!v)
                        return NULL;
        }

        if (list->unique) {
                e = find(list, name);
                if (e) {
                        free(e->value);
                        e->value = v;
                        return e;
                }
        }

        e = calloc(1, sizeof(*e));
        if (!e) {
                free(v);
                return NULL;
        }
        e->name = strdup(name);
        if (!e->name) {
                free(v);
                free(e);
                return NULL;
        }
        e->value = v;
        e->list = list;

        n = realloc(list->entries, (list->n + 1) * sizeof(*n));
        if (!n) {
                entry_free(e);
                return NULL;
        }
        list->entries = n;
        e->index = list->n;
        list->entries[list->n++] = e;
        list->sorted = false;
        return e;
}

static int cmp_entry(const void *a, const void *b) {
        return strcmp((*(struct udev_list_entry * const *) a)->name, (*(struct udev_list_entry * const *) b)->name);
}

struct udev_list_entry *libudev_list_first(struct udev_list *list) {
        if (!list || list->n == 0)
                return NULL;

        if (list->unique && !list->sorted) {
                size_t i;

                qsort(list->entries, list->n, sizeof(*list->entries), cmp_entry);
                for (i = 0; i < list->n; i++)
                        list->entries[i]->index = i;
                list->sorted = true;
        }
        return list->entries[0];
}

size_t libudev_list_size(struct udev_list *list) {
        return list ? list->n : 0;
}

const char *libudev_list_lookup(struct udev_list *list, const char *name) {
        struct udev_list_entry *e;

        if (!list || !name)
                return NULL;
        e = find(list, name);
        return e ? e->value : NULL;
}

struct udev_list_entry *udev_list_entry_get_next(struct udev_list_entry *list_entry) {
        size_t i;

        if (!list_entry)
                return NULL;

        i = list_entry->index + 1;
        return i < list_entry->list->n ? list_entry->list->entries[i] : NULL;
}

struct udev_list_entry *udev_list_entry_get_by_name(struct udev_list_entry *list_entry, const char *name) {
        if (!list_entry || !name)
                return NULL;
        /* Same rule as upstream: only a unique (keyed) list is searchable by name. */
        if (!list_entry->list->unique)
                return NULL;
        return find(list_entry->list, name);
}

const char *udev_list_entry_get_name(struct udev_list_entry *list_entry) {
        return list_entry ? list_entry->name : NULL;
}

const char *udev_list_entry_get_value(struct udev_list_entry *list_entry) {
        return list_entry ? list_entry->value : NULL;
}
