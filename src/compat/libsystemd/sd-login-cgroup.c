/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_pid_get_cgroup()/get_unit()/get_slice() and their pidfd/peer
 * siblings: the sd-login.h queries answerable without logind, because
 * pico-init runs every supervised service in a v2 cgroup at
 * system.slice/<unit>.service, the layout real systemd uses
 * (src/service.c). /proc/<pid>/cgroup therefore gives the real answer.
 *
 * get_unit()/get_slice() are implemented in terms of get_cgroup() rather
 * than a second /proc read.
 *
 * This file does not call unit_name_is_valid() (unit.c): that would link
 * unit.c's per-type vtables (service.c, socket.c, target.c) and with them
 * the whole unit engine into every consumer of this library.
 * is_valid_unit_component() below duplicates its character-class and length
 * rule (UNIT_NAME_MAX, UNIT_NAME_VALID_CHARS) and adds the suffix check.
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

/* The v2 unified entry is "0::<path>". Absent -> -ENODATA (v1 and hybrid
 * hierarchies are not supported). */
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

        /* ret is optional, as in upstream. */
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

        /* ret is optional. */
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

        /* ret is optional. */
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
