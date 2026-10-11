/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_network_get_dns()/_get_search_domains()/_get_route_domains()/_get_ntp():
 * the one real data source this family has, netd's own /etc/resolv.conf
 * (netd-resolv.h), read back under the provenance rule netd-resolv.c writes it
 * under.
 *
 * netd's headers (src/netd/netd.h, netd-resolv.h) are not included: they
 * pull in the whole Netd object, which a shared library must not depend on.
 * NETD_RESOLV_CONF and NETD_RESOLV_MAX_NAMESERVERS are mirrored below and
 * must be kept in sync with netd-resolv.h by hand.
 */

#include "sd-network.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network-internal.h"

/* netd-resolv.h: NETD_RESOLV_CONF */
#define RESOLV_CONF_PATH "/etc/resolv.conf"
/* netd-resolv.h: NETD_RESOLV_MAX_NAMESERVERS (glibc itself reads no more) */
#define RESOLV_MAX_NAMESERVERS 3

static char root_prefix[PATH_MAX] = "";

void network_set_root_for_tests(const char *prefix) {
        (void) snprintf(root_prefix, sizeof(root_prefix), "%s", prefix ? prefix : "");
}

int network_path(char *buf, size_t size, const char *abs_path) {
        int n = snprintf(buf, size, "%s%s", root_prefix, abs_path);

        if (n < 0)
                return -EIO;
        if ((size_t) n >= size)
                return -ENAMETOOLONG;
        return 0;
}

static int strv_append_owned(char ***v, size_t *n, char *s) {
        char **nv = realloc(*v, (*n + 2) * sizeof(*nv));

        if (!nv) {
                free(s);
                return -ENOMEM;
        }
        *v = nv;
        (*v)[*n] = s;
        (*v)[*n + 1] = NULL;
        (*n)++;
        return 0;
}

int network_resolv_read(char ***ret_lines) {
        char path[PATH_MAX], line[1024];
        FILE *f;
        char **lines = NULL;
        size_t n = 0;
        bool first = true;
        int r;

        r = network_path(path, sizeof(path), RESOLV_CONF_PATH);
        if (r < 0)
                return r;

        f = fopen(path, "re");
        if (!f)
                return errno == ENOENT ? -ENODATA : -errno;

        while (fgets(line, sizeof(line), f)) {
                char *nl = strchr(line, '\n');
                char *dup;

                if (nl)
                        *nl = '\0';

                if (first) {
                        first = false;
                        if (strcmp(line, NETD_RESOLV_SENTINEL) != 0) {
                                fclose(f);
                                return -ENODATA; /* not netd's file */
                        }
                        continue;
                }

                if (line[0] == '\0')
                        continue;

                dup = strdup(line);
                if (!dup || strv_append_owned(&lines, &n, dup) < 0) {
                        fclose(f);
                        for (size_t i = 0; i < n; i++)
                                free(lines[i]);
                        free(lines);
                        return -ENOMEM;
                }
        }

        fclose(f);

        if (first)
                return -ENODATA; /* empty file: no sentinel seen at all */

        *ret_lines = lines;
        return 0;
}

int sd_network_get_dns(char ***ret) {
        char **lines = NULL;
        char **out = NULL;
        size_t n_out = 0;
        int r;

        if (!ret)
                return -EINVAL;

        r = network_resolv_read(&lines);
        if (r < 0)
                return r;

        for (char **p = lines; p && *p && n_out < RESOLV_MAX_NAMESERVERS; p++) {
                if (strncmp(*p, "nameserver ", 11) == 0) {
                        char *dup = strdup(*p + 11);

                        if (!dup || strv_append_owned(&out, &n_out, dup) < 0) {
                                for (size_t i = 0; i < n_out; i++)
                                        free(out[i]);
                                free(out);
                                for (char **q = lines; q && *q; q++)
                                        free(*q);
                                free(lines);
                                return -ENOMEM;
                        }
                }
        }

        for (char **q = lines; q && *q; q++)
                free(*q);
        free(lines);

        *ret = out; /* NULL when none, per the header's own convention */
        return 0;
}

int sd_network_get_search_domains(char ***ret) {
        char **lines = NULL;
        char **out = NULL;
        size_t n_out = 0;
        int r;

        if (!ret)
                return -EINVAL;

        r = network_resolv_read(&lines);
        if (r < 0)
                return r;

        for (char **p = lines; p && *p; p++) {
                if (strncmp(*p, "search ", 7) == 0) {
                        /* netd writes at most one domain (netd-resolv.c),
                         * but resolv.conf's own "search" syntax allows a
                         * space-separated list, so split defensively rather
                         * than assume the writer's current behaviour. */
                        char *rest = strdup(*p + 7);
                        char *saveptr, *tok;

                        if (!rest) {
                                r = -ENOMEM;
                                break;
                        }

                        for (tok = strtok_r(rest, " \t", &saveptr); tok;
                             tok = strtok_r(NULL, " \t", &saveptr)) {
                                char *dup = strdup(tok);

                                if (!dup || strv_append_owned(&out, &n_out, dup) < 0) {
                                        r = -ENOMEM;
                                        break;
                                }
                        }
                        free(rest);
                        break; /* one "search" line is all netd ever writes */
                }
        }

        for (char **q = lines; q && *q; q++)
                free(*q);
        free(lines);

        if (r < 0) {
                for (size_t i = 0; i < n_out; i++)
                        free(out[i]);
                free(out);
                return r;
        }

        *ret = out;
        return 0;
}

int sd_network_get_route_domains(char ***ret) {
        if (!ret)
                return -EINVAL;

        /*
         * A resolved/networkd DNS-routing concept (Domains=~example.com):
         * netd has no resolver and no such directive to parse, so the
         * empty set is this system's true value, not a stub -- the header
         * explicitly blesses NULL for "none".
         */
        *ret = NULL;
        return 0;
}

int sd_network_get_ntp(char ***ret) {
        if (!ret)
                return -EINVAL;

        /*
         * The effective NTP server set (static NTP= merged with DHCP
         * option 42 under UseNTP= gating) lives only in netd's in-memory
         * NetdSntp and is written nowhere this library could read it.
         * -EOPNOTSUPP rather than -ENODATA, which callers would retry.
         */
        return -EOPNOTSUPP;
}
