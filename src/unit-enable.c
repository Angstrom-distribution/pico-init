/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Enablement: .wants/.requires symlink directories and preset application.
 * See unit-enable.h for why both are read at boot rather than at install time.
 */

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "manager.h"
#include "unit-enable.h"
#include "unit.h"
#include "util.h"

/* Scan one <dir>/<u->id>.wants or .requires directory, adding `dep` from u to
 * every validly-named entry and marking that entry enabled. A missing
 * directory is normal (an image may not ship one); report the first real
 * error but keep scanning so one bad entry does not hide the rest. */
static int scan_enable_dir(Unit *u, const char *dirpath, UnitDependency dep) {
        struct dirent *de;
        int ret = 0;
        DIR *d;

        d = opendir(dirpath);
        if (!d)
                return errno == ENOENT ? 0 : -errno;

        while ((de = readdir(d))) {
                Unit *other;
                int r;

                /* entries are symlink names, about to become dependency-name
                 * lookups; validate before use, same as everywhere else a
                 * unit name is taken from the filesystem */
                if (!unit_name_is_valid(de->d_name))
                        continue;

                r = unit_add_dependency_by_name(u, dep, de->d_name);
                if (r < 0) {
                        if (ret == 0)
                                ret = r;
                        continue;
                }

                /* the edge just landed, so the unit is guaranteed loaded */
                other = manager_get_unit(u->manager, de->d_name);
                if (other)
                        other->enabled = true;
        }

        closedir(d);
        return ret;
}

int unit_add_wants_requires_dirs(Unit *u) {
        char * const *dir;
        int ret = 0;

        if (!u || !u->manager)
                return -EINVAL;

        for (dir = u->manager->unit_path; dir && *dir; dir++) {
                char path[PATH_MAX];
                int n, r;

                n = snprintf(path, sizeof(path), "%s/%s.wants", *dir, u->id);
                if (n < 0 || (size_t) n >= sizeof(path)) {
                        if (ret == 0)
                                ret = -ENAMETOOLONG;
                } else {
                        r = scan_enable_dir(u, path, UNIT_WANTS);
                        if (r < 0 && ret == 0)
                                ret = r;
                }

                n = snprintf(path, sizeof(path), "%s/%s.requires", *dir, u->id);
                if (n < 0 || (size_t) n >= sizeof(path)) {
                        if (ret == 0)
                                ret = -ENAMETOOLONG;
                } else {
                        r = scan_enable_dir(u, path, UNIT_REQUIRES);
                        if (r < 0 && ret == 0)
                                ret = r;
                }
        }

        return ret;
}

int unit_install_enablement(Unit *u) {
        int ret = 0;
        size_t i;

        if (!u)
                return -EINVAL;

        /* WantedBy=multi-user.target on u means the *target* wants u, so the
         * edge runs from the named unit to u, not the other way round. */
        for (i = 0; u->wanted_by && u->wanted_by[i]; i++) {
                Unit *target = NULL;
                int r;

                r = manager_load_unit(u->manager, u->wanted_by[i], &target);
                if (r < 0 || !target) {
                        if (ret == 0)
                                ret = r < 0 ? r : -ENOENT;
                        continue;
                }

                r = unit_add_dependency(target, UNIT_WANTS, u);
                if (r < 0 && ret == 0)
                        ret = r;
        }

        for (i = 0; u->required_by && u->required_by[i]; i++) {
                Unit *target = NULL;
                int r;

                r = manager_load_unit(u->manager, u->required_by[i], &target);
                if (r < 0 || !target) {
                        if (ret == 0)
                                ret = r < 0 ? r : -ENOENT;
                        continue;
                }

                r = unit_add_dependency(target, UNIT_REQUIRES, u);
                if (r < 0 && ret == 0)
                        ret = r;
        }

        u->enabled = true;

        return ret;
}

/* One *.preset file resolved to the single directory that wins for it (the
 * earliest entry in m->preset_path that has a file of this basename). */
typedef struct PresetEntry {
        char *basename;
        char *path; /* dir/basename */
} PresetEntry;

static void preset_entries_free(PresetEntry *entries, size_t n) {
        size_t i;

        for (i = 0; i < n; i++) {
                free(entries[i].basename);
                free(entries[i].path);
        }
        free(entries);
}

static int preset_entry_cmp(const void *a, const void *b) {
        const PresetEntry *pa = a;
        const PresetEntry *pb = b;

        return strcmp(pa->basename, pb->basename);
}

static bool has_preset_suffix(const char *name) {
        static const char suffix[] = ".preset";
        size_t slen = sizeof(suffix) - 1;
        size_t len = strlen(name);

        return len > slen && strcmp(name + len - slen, suffix) == 0;
}

/*
 * Collect one PresetEntry per distinct *.preset basename across the whole
 * search path, in directory order -- so a basename already recorded from an
 * earlier (higher-priority) directory shadows the same name turning up in a
 * later one, matching /etc > /run > /usr/lib. The caller sorts the result by
 * basename to get the real cross-directory file order.
 */
static int collect_preset_entries(Manager *m, PresetEntry **ret, size_t *ret_n) {
        PresetEntry *entries = NULL;
        size_t n_alloc = 0;
        size_t n = 0;
        size_t i;
        int rc = 0;

        for (i = 0; m->preset_path && m->preset_path[i]; i++) {
                const char *dir = m->preset_path[i];
                struct dirent *de;
                DIR *d;

                d = opendir(dir);
                if (!d) {
                        if (errno == ENOENT)
                                continue;
                        rc = -errno;
                        goto fail;
                }

                while ((de = readdir(d))) {
                        char path[PATH_MAX];
                        bool shadowed = false;
                        size_t j;
                        int written;

                        if (!has_preset_suffix(de->d_name))
                                continue;

                        for (j = 0; j < n; j++)
                                if (strcmp(entries[j].basename, de->d_name) == 0) {
                                        shadowed = true;
                                        break;
                                }

                        if (shadowed)
                                continue;

                        written = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
                        if (written < 0 || (size_t) written >= sizeof(path))
                                continue; /* unusable path, drop this one file */

                        if (n == n_alloc) {
                                PresetEntry *grown;
                                size_t new_alloc = n_alloc ? n_alloc * 2 : 8;

                                grown = realloc(entries, new_alloc * sizeof(PresetEntry));
                                if (!grown) {
                                        rc = -ENOMEM;
                                        closedir(d);
                                        goto fail;
                                }
                                entries = grown;
                                n_alloc = new_alloc;
                        }

                        entries[n].basename = pico_strdup(de->d_name);
                        entries[n].path = pico_strdup(path);
                        if (!entries[n].basename || !entries[n].path) {
                                free(entries[n].basename);
                                free(entries[n].path);
                                rc = -ENOMEM;
                                closedir(d);
                                goto fail;
                        }
                        n++;
                }

                closedir(d);
        }

        qsort(entries, n, sizeof(PresetEntry), preset_entry_cmp);

        *ret = entries;
        *ret_n = n;
        return 0;

fail:
        preset_entries_free(entries, n);
        return rc;
}

/*
 * Scan one preset file for the first line matching unit_name. Returns 1 with
 * *decision set when a line matched, 0 when the file has no matching line
 * (the caller moves on to the next file), or -errno.
 */
static int preset_file_query(const char *path, const char *unit_name, int *decision) {
        char line[LINE_MAX];
        FILE *f;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        while (fgets(line, sizeof(line), f)) {
                char *nl = strchr(line, '\n');
                char *p = line;
                size_t len;
                int action;

                if (nl)
                        *nl = '\0';

                while (*p == ' ' || *p == '\t')
                        p++;

                if (*p == '\0' || *p == '#' || *p == ';')
                        continue;

                if (strncmp(p, "enable", 6) == 0 && (p[6] == ' ' || p[6] == '\t')) {
                        action = 1;
                        p += 6;
                } else if (strncmp(p, "disable", 7) == 0 && (p[7] == ' ' || p[7] == '\t')) {
                        action = 0;
                        p += 7;
                } else {
                        continue; /* not a directive this parser understands, ignore */
                }

                while (*p == ' ' || *p == '\t')
                        p++;

                len = strlen(p);
                while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t'))
                        p[--len] = '\0';

                if (len == 0)
                        continue; /* "enable" with no glob at all */

                /* shell-style wildcards, e.g. "foo-*.service"; this is also
                 * why a unit type pico-init has no vtable for (.timer,
                 * .path) still parses fine here -- it is just a glob that
                 * happens never to match a loaded unit's name */
                if (fnmatch(p, unit_name, 0) == 0) {
                        *decision = action;
                        fclose(f);
                        return 1;
                }
        }

        fclose(f);
        return 0;
}

int manager_preset_query(Manager *m, const char *unit_name) {
        PresetEntry *entries = NULL;
        size_t n = 0;
        size_t i;
        int rc;

        if (!m || !unit_name)
                return -EINVAL;

        rc = collect_preset_entries(m, &entries, &n);
        if (rc < 0)
                return rc;

        /* entries is sorted by basename, i.e. by filename across every
         * directory at once -- the lexicographically earliest filename with
         * a matching line wins, per systemd.preset(5) */
        for (i = 0; i < n; i++) {
                int decision = 0;
                int r = preset_file_query(entries[i].path, unit_name, &decision);

                if (r < 0) {
                        preset_entries_free(entries, n);
                        return r;
                }

                if (r == 1) {
                        preset_entries_free(entries, n);
                        return decision;
                }
        }

        preset_entries_free(entries, n);
        return -ENOENT; /* no rule matched */
}

int manager_apply_presets(Manager *m) {
        int n_enabled = 0;
        size_t i;

        if (!m)
                return -EINVAL;

        /*
         * Index freshly and re-read m->n_units every iteration:
         * unit_install_enablement() below resolves WantedBy=/RequiredBy=
         * targets through manager_load_unit(), which can append to m->units
         * and realloc it -- the same hazard manager_startup() documents for
         * its own .wants/.requires scan. A newly-loaded target unit ending up
         * at the tail of the table also gets its own turn through this same
         * loop, which is exactly right: it deserves a preset decision too.
         */
        for (i = 0; i < m->n_units; i++) {
                Unit *u = m->units[i];
                int r;

                if (u->enabled)
                        continue; /* a .wants/.requires symlink already decided this one */

                if (!u->wanted_by && !u->required_by)
                        continue; /* no [Install] data for a preset to act on */

                r = manager_preset_query(m, u->id);
                if (r < 0 && r != -ENOENT) {
                        pico_log(PICO_LOG_WARNING, "%s: preset query failed: %s", u->id, strerror(-r));
                        continue;
                }

                /*
                 * -ENOENT ("no rule matched") means ENABLE, not disable. This
                 * is upstream systemd's own default -- `systemctl preset`
                 * enables any unit no rule speaks for -- and it is what OE
                 * images already get from systemd-preset at rootfs build
                 * time, so matching it is what the drop-in-compatibility goal
                 * requires. An image that wants the opposite default ships a
                 * catch-all "disable *" rule, exactly as it would under real
                 * systemd.
                 */
                if (r == 1 || r == -ENOENT) {
                        int ir = unit_install_enablement(u);

                        if (ir < 0) {
                                pico_log(PICO_LOG_WARNING,
                                         "%s: applying preset enablement: %s",
                                         u->id,
                                         strerror(-ir));
                                continue;
                        }
                        n_enabled++;
                }
                /* r == 0: disable -- leave u->enabled false */
        }

        return n_enabled;
}
