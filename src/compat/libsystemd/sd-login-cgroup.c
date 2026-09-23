/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_pid_get_cgroup()/get_unit()/get_slice() and their pidfd/peer
 * siblings: the three sd-login.h queries this shim can answer for real,
 * because pico-init actually runs every supervised service inside a v2
 * cgroup at a fixed, known path -- system.slice/<unit>.service, the exact
 * layout real systemd itself uses (src/manager.h:47 PICO_CGROUP_ROOT,
 * src/service.c:255-268) -- so reading /proc/<pid>/cgroup answers these
 * honestly instead of faking them.
 *
 * get_unit()/get_slice() are both implemented in terms of get_cgroup(),
 * not a second /proc read: the cgroup path is the one piece of real data
 * here, and every other question is just parsing it further.
 *
 * Deliberately does NOT call this project's own unit_name_is_valid()
 * (unit.h/unit.c): that function pulls in unit.c's whole per-type vtable
 * table (service.c, socket.c, target.c) as a side effect of static
 * linking, which would make a one-string syntax check on a cgroup path
 * drag pico-init's entire unit engine into any consumer of this
 * standalone library. is_valid_service_component() below is a small,
 * deliberately duplicated copy of the same character-class and length
 * rule (unit.h:61 UNIT_NAME_MAX, unit.c's UNIT_NAME_VALID_CHARS), with
 * the ".service"/".slice" suffix check this call site actually needs
 * folded in instead of delegated to unit_type_from_name().
 */

#include "sd-login.h"

#include "sd-login-resolve.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_COMPONENT_MAX 255
#define UNIT_COMPONENT_VALID_CHARS "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ:-_.\\@"

static int is_valid_unit_component(const char *name, const char *suffix) {
        size_t len = strlen(name);
        size_t suffix_len = strlen(suffix);

        if (len == 0 || len > UNIT_COMPONENT_MAX)
                return 0;
        if (name[0] == '.')
                return 0;
        if (strspn(name, UNIT_COMPONENT_VALID_CHARS) != len)
                return 0;
        if (len <= suffix_len || strcmp(name + len - suffix_len, suffix) != 0)
                return 0;

        return 1;
}

/* The v2 unified entry is always "0::<path>" -- one hierarchy, no
 * controller-name list. Absent -> -ENODATA (this shim never runs on a v1
 * or hybrid hierarchy, but the file could in principle lack the line). */
static int extract_unified_cgroup(const char *content, char **ret) {
        const char *line = content;
        size_t len;
        char *path;

        for (;;) {
                if (strncmp(line, "0::", 3) == 0)
                        break;
                line = strchr(line, '\n');
                if (!line)
                        return -ENODATA;
                line++;
        }

        line += 3;
        len = strcspn(line, "\n");

        if (len == 0) {
                path = strdup("/");
                if (!path)
                        return -ENOMEM;
        } else {
                path = malloc(len + 1);
                if (!path)
                        return -ENOMEM;
                memcpy(path, line, len);
                path[len] = '\0';
        }

        /* ret is optional, matching sd_pid_get_cgroup()'s own upstream
         * `if (ret_cgroup) *ret_cgroup = TAKE_PTR(c);` idiom. */
        if (ret)
                *ret = path;
        else
                free(path);
        return 0;
}

int sd_pid_get_cgroup(pid_t pid, char **ret_cgroup) {
        pid_t rpid;
        char *content;
        int r = login_resolve_pid(pid, &rpid, &content);

        if (r < 0)
                return r;

        r = extract_unified_cgroup(content, ret_cgroup);
        free(content);
        return r;
}

int sd_pidfd_get_cgroup(int pidfd, char **ret_cgroup) {
        pid_t rpid;
        char *content;
        int r = login_resolve_pidfd(pidfd, &rpid, &content);

        if (r < 0)
                return r;

        r = extract_unified_cgroup(content, ret_cgroup);
        free(content);
        return r;
}

int sd_peer_get_cgroup(int fd, char **ret_cgroup) {
        pid_t rpid;
        char *content;
        int r = login_resolve_peer(fd, &rpid, &content);

        if (r < 0)
                return r;

        r = extract_unified_cgroup(content, ret_cgroup);
        free(content);
        return r;
}

/* Walks a cgroup path's elements, skipping any leading *.slice components,
 * and hands back the following element -- the point immediately after the
 * slice hierarchy, where a unit (service) or nothing at all lives. NULL if
 * the path runs out before a non-slice element appears. */
static const char *skip_slices(const char *path, size_t *ret_len) {
        const char *p = path;

        if (*p == '/')
                p++;

        while (*p) {
                size_t len = strcspn(p, "/");
                const char *next = p[len] ? p + len + 1 : NULL;

                if (!(len > 6 && strncmp(p + len - 6, ".slice", 6) == 0)) {
                        *ret_len = len;
                        return p;
                }

                if (!next)
                        return NULL;
                p = next;
        }

        return NULL;
}

static int extract_unit_component(const char *cgroup_path, char **ret) {
        size_t len;
        const char *comp = skip_slices(cgroup_path, &len);
        char *name;

        if (!comp)
                return -ENODATA;

        name = malloc(len + 1);
        if (!name)
                return -ENOMEM;
        memcpy(name, comp, len);
        name[len] = '\0';

        if (!is_valid_unit_component(name, ".service")) {
                free(name);
                return -ENODATA;
        }

        /* ret is optional, same idiom as extract_unified_cgroup() above. */
        if (ret)
                *ret = name;
        else
                free(name);
        return 0;
}

int sd_pid_get_unit(pid_t pid, char **ret_unit) {
        char *cg;
        int r = sd_pid_get_cgroup(pid, &cg);

        if (r < 0)
                return r;
        r = extract_unit_component(cg, ret_unit);
        free(cg);
        return r;
}

int sd_pidfd_get_unit(int pidfd, char **ret_unit) {
        char *cg;
        int r = sd_pidfd_get_cgroup(pidfd, &cg);

        if (r < 0)
                return r;
        r = extract_unit_component(cg, ret_unit);
        free(cg);
        return r;
}

int sd_peer_get_unit(int fd, char **ret_unit) {
        char *cg;
        int r = sd_peer_get_cgroup(fd, &cg);

        if (r < 0)
                return r;
        r = extract_unit_component(cg, ret_unit);
        free(cg);
        return r;
}

/* The last *.slice element in the path, or "-.slice" (upstream's
 * SPECIAL_ROOT_SLICE fallback for a path with no slice at all,
 * cgroup-util.c:1196) if there is none. */
static int extract_slice_component(const char *cgroup_path, char **ret) {
        const char *p = cgroup_path;
        const char *best = NULL;
        size_t best_len = 0;

        if (*p == '/')
                p++;

        while (*p) {
                size_t len = strcspn(p, "/");

                if (len > 6 && strncmp(p + len - 6, ".slice", 6) == 0) {
                        best = p;
                        best_len = len;
                } else
                        break; /* the slice hierarchy ends at the first non-slice element */

                p += len;
                if (*p == '/')
                        p++;
        }

        /* ret is optional throughout, same idiom as extract_unified_cgroup()
         * and extract_unit_component() above. */
        if (!best) {
                if (!ret)
                        return 0;
                *ret = strdup("-.slice");
                return *ret ? 0 : -ENOMEM;
        }

        {
                char *name = malloc(best_len + 1);

                if (!name)
                        return -ENOMEM;
                memcpy(name, best, best_len);
                name[best_len] = '\0';

                if (!is_valid_unit_component(name, ".slice")) {
                        free(name);
                        if (!ret)
                                return 0;
                        *ret = strdup("-.slice");
                        return *ret ? 0 : -ENOMEM;
                }

                if (ret)
                        *ret = name;
                else
                        free(name);
                return 0;
        }
}

int sd_pid_get_slice(pid_t pid, char **ret_slice) {
        char *cg;
        int r = sd_pid_get_cgroup(pid, &cg);

        if (r < 0)
                return r;
        r = extract_slice_component(cg, ret_slice);
        free(cg);
        return r;
}

int sd_pidfd_get_slice(int pidfd, char **ret_slice) {
        char *cg;
        int r = sd_pidfd_get_cgroup(pidfd, &cg);

        if (r < 0)
                return r;
        r = extract_slice_component(cg, ret_slice);
        free(cg);
        return r;
}

int sd_peer_get_slice(int fd, char **ret_slice) {
        char *cg;
        int r = sd_peer_get_cgroup(fd, &cg);

        if (r < 0)
                return r;
        r = extract_slice_component(cg, ret_slice);
        free(cg);
        return r;
}
