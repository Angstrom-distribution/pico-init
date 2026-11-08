/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Listing drop-in directories, as systemd's conf_files_list_strv()
 * (src/basic/conf-files.c) does it for the ".conf" files of a set of
 * directories.
 */

#include "dropin-files.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

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

int pico_dropin_dirlist_add(PicoDropinDirList *l, const struct dirent *de, const char *suffix) {
        size_t len = strlen(de->d_name), slen = strlen(suffix);
        char **grown;
        char *copy;

        if (len <= slen || strcmp(de->d_name + len - slen, suffix) != 0 || de->d_type == DT_REG)
                return 0;

        copy = pico_strdup(de->d_name);
        grown = copy ? realloc(l->names, (l->n + 1) * sizeof(char *)) : NULL;
        if (!grown) {
                free(copy);
                return -ENOMEM;
        }
        l->names = grown;
        l->names[l->n++] = copy;
        return 0;
}

void pico_dropin_dirlist_sort(PicoDropinDirList *l) {
        if (l->n > 1)
                qsort(l->names, l->n, sizeof(char *), dropin_name_cmp);
}

bool pico_dropin_dirlist_has(const PicoDropinDirList *l, const char *name) {
        return l->n > 0 && bsearch(&name, l->names, l->n, sizeof(char *), dropin_name_cmp) != NULL;
}

void pico_dropin_dirlist_clear(PicoDropinDirList *l) {
        for (size_t i = 0; i < l->n; i++)
                free(l->names[i]);
        free(l->names);
        l->names = NULL;
        l->n = 0;
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

int pico_dropin_files(char * const *dirs, char ***ret) {
        char **paths = NULL;
        DropinFile *files = NULL;
        size_t n_files = 0;
        int r = 0;

        if (!ret)
                return -EINVAL;

        *ret = NULL;

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

out:
        pico_strv_free(paths);
        dropin_files_free(files, n_files);
        return r;
}
