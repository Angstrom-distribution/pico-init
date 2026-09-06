/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_network_monitor: an inotify watch on netd's lease directory
 * (netd.h's NETD_LEASE_DIR, "/run/netd/leases"), which netd rewrites
 * atomically (tmp + rename) on every lease change -- exactly the moments
 * a "leases" category monitor exists to report, since IN_MOVED_TO fires
 * on the rename that publishes each new lease file.
 *
 * netd only creates that directory on its first lease write, so a
 * monitor started before any link has ever gotten a lease has nothing to
 * watch yet. Rather than fail outright, this watches upward one level at
 * a time -- /run/netd, then /run -- and sd_network_monitor_flush()
 * re-arms downward toward the real target the moment a deeper directory
 * appears, bounded at two steps because that is the whole depth between
 * "/run" (which always exists) and the leases directory itself.
 *
 * "links" and NULL (NULL meaning links+leases together in real usage)
 * both fail with -EOPNOTSUPP rather than silently degrading to
 * leases-only: no links directory exists anywhere to watch, and a caller
 * that asked for link-change notification and got none back would sleep
 * on this monitor forever believing it was covered.
 */

#include "sd-network.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "network-internal.h"

#define LEASES_SUFFIX "/run/netd/leases" /* netd.h: NETD_LEASE_DIR */
#define NETD_DIR_SUFFIX "/run/netd"      /* netd.h: NETD_RUNTIME_DIR */
#define RUN_SUFFIX "/run"

#define WATCH_MASK (IN_CREATE | IN_MOVED_TO | IN_MODIFY | IN_DELETE | IN_MOVE_SELF | IN_DELETE_SELF)

struct sd_network_monitor {
        int fd; /* inotify, IN_NONBLOCK */
        int wd;
        int level; /* 0 = watching the leases dir itself (the target); 1 = /run/netd; 2 = /run */
};

static int try_watch(int fd, const char *suffix, int *ret_wd) {
        char path[PATH_MAX];
        int wd, r;

        r = network_path(path, sizeof(path), suffix);
        if (r < 0)
                return r;

        wd = inotify_add_watch(fd, path, WATCH_MASK);
        if (wd < 0)
                return -errno;

        *ret_wd = wd;
        return 0;
}

int sd_network_monitor_new(sd_network_monitor **ret, const char *category) {
        sd_network_monitor *m;
        int fd, wd = -1, r, level;

        if (!ret)
                return -EINVAL;

        if (category && strcmp(category, "leases") != 0 && strcmp(category, "links") != 0)
                return -EINVAL;

        if (!category || strcmp(category, "links") == 0)
                return -EOPNOTSUPP; /* no links directory exists anywhere to watch */

        fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        level = 0;
        r = try_watch(fd, LEASES_SUFFIX, &wd);
        if (r < 0) {
                level = 1;
                r = try_watch(fd, NETD_DIR_SUFFIX, &wd);
        }
        if (r < 0) {
                level = 2;
                r = try_watch(fd, RUN_SUFFIX, &wd);
        }
        if (r < 0) {
                close(fd);
                return r;
        }

        m = calloc(1, sizeof(*m));
        if (!m) {
                close(fd);
                return -ENOMEM;
        }
        m->fd = fd;
        m->wd = wd;
        m->level = level;

        *ret = m;
        return 0;
}

sd_network_monitor *sd_network_monitor_unref(sd_network_monitor *m) {
        if (!m)
                return NULL;

        close(m->fd);
        free(m);
        return NULL;
}

int sd_network_monitor_flush(sd_network_monitor *m) {
        char buf[4096];
        ssize_t n;

        if (!m)
                return -EINVAL;

        for (;;) {
                n = read(m->fd, buf, sizeof(buf));
                if (n < 0) {
                        if (errno == EAGAIN)
                                break;
                        return -errno;
                }
        }

        while (m->level > 0) {
                const char *suffix = m->level == 2 ? NETD_DIR_SUFFIX : LEASES_SUFFIX;
                int wd, r = try_watch(m->fd, suffix, &wd);

                if (r < 0)
                        break; /* still not there; stay at the current level */

                (void) inotify_rm_watch(m->fd, m->wd);
                m->wd = wd;
                m->level--;
        }

        return 0;
}

int sd_network_monitor_get_fd(sd_network_monitor *m) {
        if (!m)
                return -EINVAL;

        return m->fd;
}

int sd_network_monitor_get_events(sd_network_monitor *m) {
        if (!m)
                return -EINVAL;

        return POLLIN;
}

int sd_network_monitor_get_timeout(sd_network_monitor *m, uint64_t *ret_usec) {
        if (!m || !ret_usec)
                return -EINVAL;

        *ret_usec = UINT64_MAX;
        return 0;
}
