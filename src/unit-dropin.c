/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Drop-in files (the .conf files of foo.service.d), found as systemd's
 * unit_file_find_dropin_paths() (src/shared/dropin.c) and conf_files_list_strv()
 * (src/basic/conf-files.c) find them.
 *
 * For a unit "foo-bar@x.service" the directories named, most specific first,
 * are the unit itself, its template, and the dash-truncated prefixes of both
 * ("foo-.service", "foo-@x.service", "foo-@.service"), each with ".d" appended;
 * the type-level "service.d" comes last. Every search-path entry is tried for
 * each name, in search-path order, and all the type-level ones follow all the
 * named ones. The files are the "*.conf" entries of those directories, hidden
 * files excluded. A file name seen in an earlier directory hides the same name
 * in a later one (so an empty file or a link to /dev/null in /etc cancels a
 * packaged drop-in), and the survivors are applied sorted by file name, not by
 * directory. A drop-in directory does not make a unit exist: for a service,
 * socket or target without a unit file systemd stops with ENOENT before it
 * reads drop-ins, and unit_load() does the same.
 *
 * Differences from systemd: a unit's other names (aliases) do not contribute
 * directories, only its own id does, and "foo-@x.service" is only built when
 * it is a valid unit name here.
 *
 * Cost on a small board: each search-path entry is listed once per load pass
 * (manager_dropin_pass_begin()) and only the names ending in ".d" are kept, so
 * finding the directories of a unit is a handful of binary searches and no
 * stat() calls; only directories that exist are opened. Outside a pass a
 * lookup builds and drops its own listing.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "manager.h"
#include "unit-name.h"
#include "unit.h"
#include "util.h"

/* Names are at most UNIT_NAME_MAX long and every prefix step drops a dash,
 * so a valid name cannot get near this; it bounds the recursion regardless. */
#define DROPIN_MAX_DEPTH 130

typedef struct DropinDirList {
        char **names; /* entries ending in ".d" that are not plain files, sorted */
        size_t n;
} DropinDirList;

struct pico_dropin_cache {
        DropinDirList *lists; /* parallel to Manager.unit_path */
        size_t n;
};

typedef struct DropinFile {
        char *name; /* borrowed from path */
        char *path; /* owned */
} DropinFile;

static int dropin_name_cmp(const void *a, const void *b) {
        return strcmp(*(char * const *) a, *(char * const *) b);
}

static int dropin_file_cmp(const void *a, const void *b) {
        return strcmp(((const DropinFile *) a)->name, ((const DropinFile *) b)->name);
}

static void dropin_cache_free(struct pico_dropin_cache *c) {
        size_t i, j;

        if (!c)
                return;

        for (i = 0; i < c->n; i++) {
                for (j = 0; j < c->lists[i].n; j++)
                        free(c->lists[i].names[j]);
                free(c->lists[i].names);
        }
        free(c->lists);
        free(c);
}

/* Best effort: a directory that cannot be listed or an allocation that fails
 * leaves that entry without drop-ins rather than failing the load. */
static void dropin_list_dir(const char *dir, DropinDirList *l) {
        struct dirent *de;
        DIR *d = opendir(dir);

        if (!d) {
                if (errno != ENOENT)
                        pico_log(PICO_LOG_WARNING, "drop-ins: cannot list '%s': %s", dir, strerror(errno));
                return;
        }

        while ((de = readdir(d))) {
                size_t len = strlen(de->d_name);
                char **grown;
                char *copy;

                if (len < 3 || strcmp(de->d_name + len - 2, ".d") != 0 || de->d_type == DT_REG)
                        continue;

                copy = pico_strdup(de->d_name);
                grown = copy ? realloc(l->names, (l->n + 1) * sizeof(char *)) : NULL;
                if (!grown) {
                        free(copy);
                        break;
                }
                l->names = grown;
                l->names[l->n++] = copy;
        }
        closedir(d);

        if (l->n > 1)
                qsort(l->names, l->n, sizeof(char *), dropin_name_cmp);
}

static struct pico_dropin_cache *dropin_cache_new(Manager *m) {
        struct pico_dropin_cache *c = calloc(1, sizeof(*c));
        size_t n = pico_strv_length(m->unit_path);

        if (!c)
                return NULL;

        c->lists = calloc(n ? n : 1, sizeof(DropinDirList));
        if (!c->lists) {
                free(c);
                return NULL;
        }
        c->n = n;

        for (size_t i = 0; i < n; i++)
                dropin_list_dir(m->unit_path[i], &c->lists[i]);

        return c;
}

static bool dropin_cache_has(const struct pico_dropin_cache *c, size_t i, const char *dirname) {
        const DropinDirList *l = &c->lists[i];

        return l->n > 0 && bsearch(&dirname, l->names, l->n, sizeof(char *), dropin_name_cmp) != NULL;
}

void manager_dropin_pass_begin(Manager *m) {
        if (m)
                m->dropin_pass_depth++;
}

void manager_dropin_pass_end(Manager *m) {
        if (!m || m->dropin_pass_depth == 0)
                return;

        if (--m->dropin_pass_depth == 0) {
                dropin_cache_free(m->dropin_cache);
                m->dropin_cache = NULL;
        }
}

void manager_dropin_cache_free(Manager *m) {
        if (!m)
                return;

        dropin_cache_free(m->dropin_cache);
        m->dropin_cache = NULL;
        m->dropin_pass_depth = 0;
}

/*
 * The names whose ".d" directories apply to `name`, most specific first, as
 * unit_file_expand_dropin_names() orders them. 0 or -errno.
 */
static int dropin_expand_names(const char *name, unsigned depth, char ***list) {
        char *prefix, *instance = NULL, *built = NULL;
        const char *suffix, *dash;
        bool chopped = false;
        size_t n;
        int r;

        if (depth > DROPIN_MAX_DEPTH)
                return -ELOOP;

        r = pico_strv_extend(list, name);
        if (r < 0)
                return r;

        if (unit_name_is_instance(name)) {
                char *tmpl = unit_name_template(name);

                if (!tmpl)
                        return -ENOMEM;
                r = dropin_expand_names(tmpl, depth + 1, list);
                free(tmpl);
                if (r < 0)
                        return r;
        }

        suffix = strrchr(name, '.');
        prefix = unit_name_to_prefix(name);
        if (!suffix || !prefix) {
                free(prefix);
                return 0;
        }

        for (;;) {
                dash = strrchr(prefix, '-');
                if (!dash || dash == prefix) { /* no dash, or a leading one */
                        free(prefix);
                        return 0;
                }

                n = (size_t) (dash - prefix);
                if (prefix[n + 1] != '\0' || chopped) {
                        prefix[n + 1] = '\0';
                        break;
                }

                /* A trailing dash is chopped once and the search repeated */
                prefix[n] = '\0';
                chopped = true;
        }

        r = unit_name_to_instance(name, &instance);
        if (r < 0) {
                free(prefix);
                return r;
        }

        n = strlen(prefix) + (instance ? strlen(instance) + 1 : 0) + strlen(suffix) + 1;
        built = malloc(n);
        if (!built) {
                free(prefix);
                free(instance);
                return -ENOMEM;
        }
        snprintf(built, n, "%s%s%s%s", prefix, instance ? "@" : "", instance ? instance : "", suffix);
        free(prefix);
        free(instance);

        if (!unit_name_is_valid(built)) {
                free(built);
                return 0;
        }

        r = dropin_expand_names(built, depth + 1, list);
        free(built);
        return r;
}

/* Append "<search dir>/<name>.d" for every name that has a directory there. */
static int dropin_add_dirs(Manager *m, const struct pico_dropin_cache *c, char * const *names, char ***dirs) {
        for (size_t i = 0; i < c->n && m->unit_path[i]; i++)
                for (char * const *name = names; *name; name++) {
                        char dirname[UNIT_NAME_MAX + 3];
                        char path[PATH_MAX];
                        int n, r;

                        n = snprintf(dirname, sizeof(dirname), "%s.d", *name);
                        if (n < 0 || (size_t) n >= sizeof(dirname) || !dropin_cache_has(c, i, dirname))
                                continue;

                        n = snprintf(path, sizeof(path), "%s/%s", m->unit_path[i], dirname);
                        if (n < 0 || (size_t) n >= sizeof(path)) {
                                pico_log(PICO_LOG_WARNING, "drop-ins: path of '%s' too long, skipping", dirname);
                                continue;
                        }

                        r = pico_strv_extend(dirs, path);
                        if (r < 0)
                                return r;
                }

        return 0;
}

static void dropin_files_free(DropinFile *files, size_t n) {
        for (size_t i = 0; i < n; i++)
                free(files[i].path);
        free(files);
}

/* Add the "*.conf" entries of `dir` whose name no earlier directory had. */
static int dropin_read_dir(const char *dir, DropinFile **files, size_t *n) {
        struct dirent *de;
        DIR *d = opendir(dir);

        if (!d) {
                if (errno != ENOENT)
                        pico_log(PICO_LOG_WARNING, "drop-ins: cannot list '%s': %s", dir, strerror(errno));
                return 0;
        }

        while ((de = readdir(d))) {
                size_t len = strlen(de->d_name), i;
                DropinFile *grown;
                char *path;
                int w;

                if (de->d_name[0] == '.' || len < 5 || strcmp(de->d_name + len - 5, ".conf") != 0)
                        continue;

                for (i = 0; i < *n; i++)
                        if (strcmp((*files)[i].name, de->d_name) == 0)
                                break;
                if (i < *n)
                        continue;

                w = snprintf(NULL, 0, "%s/%s", dir, de->d_name);
                if (w < 0 || w >= PATH_MAX) {
                        pico_log(PICO_LOG_WARNING, "drop-ins: '%s/%s' too long, skipping", dir, de->d_name);
                        continue;
                }

                path = malloc((size_t) w + 1);
                if (!path) {
                        closedir(d);
                        return -ENOMEM;
                }
                snprintf(path, (size_t) w + 1, "%s/%s", dir, de->d_name);

                grown = realloc(*files, (*n + 1) * sizeof(DropinFile));
                if (!grown) {
                        free(path);
                        closedir(d);
                        return -ENOMEM;
                }
                *files = grown;
                (*files)[*n].path = path;
                (*files)[*n].name = strrchr(path, '/') + 1;
                (*n)++;
        }

        closedir(d);
        return 0;
}

int unit_find_dropins(Manager *m, const char *id, char ***ret) {
        struct pico_dropin_cache *tmp = NULL, *c;
        char **names = NULL, **dirs = NULL, **paths = NULL;
        DropinFile *files = NULL;
        size_t n_files = 0;
        UnitType type;
        int r;

        if (!m || !id || !ret)
                return -EINVAL;

        *ret = NULL;

        if (!m->unit_path || !m->unit_path[0])
                return 0;

        if (m->dropin_pass_depth > 0) {
                if (!m->dropin_cache)
                        m->dropin_cache = dropin_cache_new(m);
                c = m->dropin_cache;
        } else
                c = tmp = dropin_cache_new(m);
        if (!c)
                return -ENOMEM;

        r = dropin_expand_names(id, 0, &names);
        if (r < 0)
                goto out;

        r = dropin_add_dirs(m, c, names, &dirs);
        if (r < 0)
                goto out;

        /* The type-level directory is the most generic, so it comes last and
         * loses a file-name collision with any named directory. */
        type = unit_type_from_name(id);
        if (type != _UNIT_TYPE_INVALID) {
                char type_name[16];
                char * const generic[] = { type_name, NULL };

                snprintf(type_name, sizeof(type_name), "%s", unit_type_to_string(type));
                r = dropin_add_dirs(m, c, generic, &dirs);
                if (r < 0)
                        goto out;
        }

        for (char * const *dir = dirs; dirs && *dir; dir++) {
                r = dropin_read_dir(*dir, &files, &n_files);
                if (r < 0)
                        goto out;
        }

        if (n_files > 1)
                qsort(files, n_files, sizeof(DropinFile), dropin_file_cmp);

        for (size_t i = 0; i < n_files; i++) {
                r = pico_strv_extend(&paths, files[i].path);
                if (r < 0)
                        goto out;
        }

        *ret = paths;
        paths = NULL;
        r = n_files > 0;

out:
        pico_strv_free(paths);
        dropin_files_free(files, n_files);
        pico_strv_free(dirs);
        pico_strv_free(names);
        dropin_cache_free(tmp);
        return r;
}
