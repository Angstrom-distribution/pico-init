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
#include <sys/stat.h>
#include <unistd.h>

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

static int scan_wants_requires_for(Unit *u, const char *name) {
        char * const *dir;
        int ret = 0;

        for (dir = u->manager->unit_path; dir && *dir; dir++) {
                char path[PATH_MAX];
                int n, r;

                n = snprintf(path, sizeof(path), "%s/%s.wants", *dir, name);
                if (n < 0 || (size_t) n >= sizeof(path)) {
                        if (ret == 0)
                                ret = -ENAMETOOLONG;
                } else {
                        r = scan_enable_dir(u, path, UNIT_WANTS);
                        if (r < 0 && ret == 0)
                                ret = r;
                }

                n = snprintf(path, sizeof(path), "%s/%s.requires", *dir, name);
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

/* Every name the unit answers to, not just its id: with default.target an
 * alias of multi-user.target, both default.target.wants/ and
 * multi-user.target.wants/ belong to the one unit (v30 walked u->names the
 * same way). By index, re-reading u->aliases each time: a scan can load a
 * unit, and a newly found alias of u would realloc the vector. */
int unit_add_wants_requires_dirs(Unit *u) {
        size_t i;
        int ret, r;

        if (!u || !u->manager)
                return -EINVAL;

        ret = scan_wants_requires_for(u, u->id);

        for (i = 0; u->aliases && u->aliases[i]; i++) {
                r = scan_wants_requires_for(u, u->aliases[i]);
                if (r < 0 && ret == 0)
                        ret = r;
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

/* Every directory component of `path` except its own basename, created if
 * missing -- install.c's mkdir_parents_label(). Shared by both
 * unit_enable_create_symlink() callers (boot time here, picoctl's enable
 * verb). */
static int mkdir_parents(const char *path) {
        char buf[PATH_MAX];
        size_t len = strlen(path);
        char *p;

        if (len == 0 || len >= sizeof(buf))
                return -ENAMETOOLONG;
        memcpy(buf, path, len + 1);

        for (p = buf + 1; *p; p++) {
                if (*p != '/')
                        continue;
                *p = '\0';
                if (mkdir(buf, 0755) < 0 && errno != EEXIST)
                        return -errno;
                *p = '/';
        }

        return 0;
}

int unit_enable_create_symlink(
                const char *etcdir,
                const char *target,
                const char *suffix,
                const char *unit_id,
                const char *link_target) {
        char linkpath[PATH_MAX];
        char destbuf[PATH_MAX];
        ssize_t rl;
        int n, r;

        if (!etcdir || !target || !suffix || !unit_id || !link_target)
                return -EINVAL;

        n = snprintf(linkpath, sizeof(linkpath), "%s/%s%s/%s", etcdir, target, suffix, unit_id);
        if (n < 0 || (size_t) n >= sizeof(linkpath))
                return -ENAMETOOLONG;

        r = mkdir_parents(linkpath);
        if (r < 0)
                return r;

        rl = readlink(linkpath, destbuf, sizeof(destbuf) - 1);
        if (rl >= 0) {
                destbuf[rl] = '\0';
                if (strcmp(destbuf, link_target) == 0)
                        return 0; /* already correct: idempotent, not an error */
                unlink(linkpath);
        } else if (errno != ENOENT)
                unlink(linkpath); /* something else there (e.g. a plain file); force it */

        if (symlink(link_target, linkpath) < 0)
                return -errno;

        return 1;
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

        /* Guarded rather than unconditional: with no preset files anywhere in
         * the search path `entries` is still NULL, and qsort(NULL, 0, ...) is
         * undefined behaviour even though glibc tolerates it -- UBSan reports
         * a null pointer passed to a parameter declared never-null. An image
         * with no preset files at all is a supported configuration, so this is
         * reachable rather than theoretical. */
        if (entries && n > 1)
                qsort(entries, n, sizeof(PresetEntry), preset_entry_cmp);

        *ret = entries;
        *ret_n = n;
        return 0;

fail:
        preset_entries_free(entries, n);
        return rc;
}

/* A preset verdict besides enable (1) and disable (0): the first matching rule
 * said to leave the unit as it is. */
#define PRESET_IGNORE 2

/*
 * Scan one preset file for the first line matching unit_name. Returns 1 with
 * *decision set (1, 0 or PRESET_IGNORE) when a line matched, 0 when the file
 * has no matching line (the caller moves on to the next file), or -errno.
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
                } else if (strncmp(p, "ignore", 6) == 0 && (p[6] == ' ' || p[6] == '\t')) {
                        action = PRESET_IGNORE;
                        p += 6;
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
                 * happens never to match a loaded unit's name. NOESCAPE: the
                 * backslash in an escaped unit name (a\x2db) is literal. */
                if (fnmatch(p, unit_name, FNM_NOESCAPE) == 0) {
                        *decision = action;
                        fclose(f);
                        return 1;
                }
        }

        fclose(f);
        return 0;
}

/*
 * Query an already-collected, already-sorted entry list for unit_name.
 * Returns 1 with *decision set when a rule matched, 0 when none of the
 * entries had a matching line, or -errno from the first unreadable file.
 * Split out of manager_preset_query() so manager_apply_presets() can collect
 * the entry list once and run every unit's query against that same list,
 * instead of re-collecting it (opendir/readdir/sort of every preset
 * directory) on every single unit.
 */
static int preset_entries_query(PresetEntry *entries, size_t n, const char *unit_name, int *decision) {
        size_t i;

        /* entries is sorted by basename, i.e. by filename across every
         * directory at once -- the lexicographically earliest filename with
         * a matching line wins, per systemd.preset(5) */
        for (i = 0; i < n; i++) {
                int r = preset_file_query(entries[i].path, unit_name, decision);

                if (r != 0)
                        return r; /* r < 0: read error; r == 1: matched */
        }

        return 0; /* no rule matched */
}

int manager_preset_query(Manager *m, const char *unit_name) {
        PresetEntry *entries = NULL;
        size_t n = 0;
        int decision = 0;
        int rc, r;

        if (!m || !unit_name)
                return -EINVAL;

        rc = collect_preset_entries(m, &entries, &n);
        if (rc < 0)
                return rc;

        r = preset_entries_query(entries, n, unit_name, &decision);
        preset_entries_free(entries, n);

        if (r < 0)
                return r;
        if (r == 1 && decision == PRESET_IGNORE)
                return -ECANCELED;
        return r == 1 ? decision : -ENOENT;
}

/*
 * Persist a preset-driven enable as real symlinks, one per WantedBy=/
 * RequiredBy= name, under m->unit_path[0] -- the first, highest-priority
 * search-path entry, exactly the directory manager.h's own PICO_UNIT_DIR
 * comment says .wants/.requires always get created under. A failure on one
 * name is logged and does not stop the rest; it also never undoes the
 * in-memory enablement unit_install_enablement() already made, since that
 * decision is correct for this boot regardless of whether it survives to
 * the next one.
 */
static void persist_preset_enablement(Manager *m, Unit *u) {
        const char *etcdir;
        size_t i;

        if (!m->unit_path || !m->unit_path[0])
                return;
        etcdir = m->unit_path[0];

        for (i = 0; u->wanted_by && u->wanted_by[i]; i++) {
                int r = unit_enable_create_symlink(etcdir, u->wanted_by[i], ".wants", u->id, u->fragment_path);

                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "%s: persisting preset enablement under %s.wants: %s",
                                 u->id,
                                 u->wanted_by[i],
                                 strerror(-r));
        }

        for (i = 0; u->required_by && u->required_by[i]; i++) {
                int r = unit_enable_create_symlink(
                                etcdir, u->required_by[i], ".requires", u->id, u->fragment_path);

                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "%s: persisting preset enablement under %s.requires: %s",
                                 u->id,
                                 u->required_by[i],
                                 strerror(-r));
        }
}

int manager_apply_presets(Manager *m) {
        PresetEntry *entries = NULL;
        size_t n = 0;
        int n_enabled = 0;
        size_t i;
        int collect_rc;

        if (!m)
                return -EINVAL;

        /*
         * Collected once, not per unit: the rule set is the same for every
         * unit. A collection failure (anything but a missing directory, which
         * collect_preset_entries() treats as empty) is logged once below and
         * every eligible unit is skipped.
         */
        collect_rc = collect_preset_entries(m, &entries, &n);
        if (collect_rc < 0)
                pico_log(PICO_LOG_WARNING, "collecting preset files: %s", strerror(-collect_rc));

        /*
         * Index freshly and re-read m->n_units every iteration:
         * unit_install_enablement() below resolves WantedBy=/RequiredBy=
         * targets through manager_load_unit(), which can append to m->units
         * and realloc it -- the same hazard manager_startup() documents for
         * its own .wants/.requires scan. A newly loaded target unit at the
         * tail of the table also gets its own turn through this loop.
         */
        for (i = 0; i < m->n_units; i++) {
                Unit *u = m->units[i];
                int decision = 0;
                int r;

                if (u->enabled)
                        continue; /* a .wants/.requires symlink already decided this one */

                if (!u->wanted_by && !u->required_by)
                        continue; /* no [Install] data for a preset to act on */

                if (collect_rc < 0) {
                        pico_log(PICO_LOG_WARNING, "%s: preset query failed: %s", u->id, strerror(-collect_rc));
                        continue;
                }

                r = preset_entries_query(entries, n, u->id, &decision);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING, "%s: preset query failed: %s", u->id, strerror(-r));
                        continue;
                }

                if (r == 1 && decision == PRESET_IGNORE)
                        continue; /* the rule says to leave this unit alone */

                /*
                 * No match (r == 0) means ENABLE, not disable: upstream's
                 * default (`systemctl preset` enables any unit no rule speaks
                 * for), which OE images already get at rootfs build time. An
                 * image that wants the opposite ships a catch-all "disable *"
                 * rule, as under real systemd.
                 */
                if (r == 0 || (r == 1 && decision == 1)) {
                        int ir = unit_install_enablement(u);

                        if (ir < 0) {
                                pico_log(PICO_LOG_WARNING,
                                         "%s: applying preset enablement: %s",
                                         u->id,
                                         strerror(-ir));
                                continue;
                        }
                        n_enabled++;
                        persist_preset_enablement(m, u);
                }
                /* r == 1 && decision == 0: disable -- leave u->enabled false */
        }

        preset_entries_free(entries, n);
        return n_enabled;
}
