/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netd's daemon core: object lifecycle, the settable paths, and main().
 *
 * N0 scaffold. The Netd object, its fds and its paths are real -- they are no
 * harder to write than a stub would have been, and every other milestone
 * builds against them. The sequencing entry points (startup, reload,
 * loopback) return -ENOSYS until N1 lands the link layer.
 */

#include "netd.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../signal.h"
#include "../timer.h"
#include "../util.h"
#include "netd-link.h"
#include "netd-network.h"
#include "netd-resolv.h"
#include "netd-rtnl.h"
#include "netd-sntp.h"
#include "netd-time.h"

static const char * const default_network_path[] = {
        NETD_NETWORK_DIR,
        NETD_RUNTIME_NETWORK_DIR,
        NETD_PACKAGED_NETWORK_DIR,
        NULL,
};

/* Replace *field with an owned copy of `value`. 0 or -errno. */
static int set_string(char **field, const char *value) {
        char *copy;

        if (!field || !value)
                return -EINVAL;

        copy = pico_strdup(value);
        if (!copy)
                return -ENOMEM;

        free(*field);
        *field = copy;
        return 0;
}

int netd_new(Netd **ret) {
        Netd *n;
        int r;

        if (!ret)
                return -EINVAL;

        n = calloc(1, sizeof(*n));
        if (!n)
                return -ENOMEM;

        n->epoll_fd = -1;
        n->objective = NETD_RUNNING;

        r = netd_set_network_path(n, default_network_path);
        if (r < 0)
                goto fail;

        r = set_string(&n->runtime_dir, NETD_RUNTIME_DIR);
        if (r < 0)
                goto fail;

        r = set_string(&n->state_dir, NETD_STATE_DIR);
        if (r < 0)
                goto fail;

        r = set_string(&n->resolv_conf, NETD_RESOLV_CONF);
        if (r < 0)
                goto fail;

        r = set_string(&n->zoneinfo_dir, NETD_ZONEINFO_DIR);
        if (r < 0)
                goto fail;

        r = set_string(&n->localtime_path, NETD_LOCALTIME_PATH);
        if (r < 0)
                goto fail;

        r = pico_signal_new(&n->signal);
        if (r < 0)
                goto fail;

        r = pico_timer_new(&n->timer);
        if (r < 0)
                goto fail;

        r = netd_loop_setup(n);
        if (r < 0)
                goto fail;

        *ret = n;
        return 0;

fail:
        netd_free(n);
        return r;
}

Netd *netd_free(Netd *n) {
        if (!n)
                return NULL;

        /* Links first: each one deregisters its own epoll entries and removes
         * what it put in the kernel, and both need the rtnl socket and the
         * epoll fd to still be open. */
        while (n->n_links > 0)
                (void) link_free(n->links[n->n_links - 1]);
        free(n->links);

        n->sntp = netd_sntp_free(n->sntp);

        network_free_all(n);
        n->network_path = pico_strv_free(n->network_path);

        n->rtnl = netd_rtnl_free(n->rtnl);
        n->timer = pico_timer_free(n->timer);
        n->signal = pico_signal_free(n->signal);

        if (n->epoll_fd >= 0)
                (void) close(n->epoll_fd);

        free(n->runtime_dir);
        free(n->state_dir);
        free(n->resolv_conf);
        free(n->zoneinfo_dir);
        free(n->localtime_path);

        free(n);
        return NULL;
}

int netd_set_network_path(Netd *n, const char * const *path) {
        char **copy = NULL;
        int r;

        if (!n || !path)
                return -EINVAL;

        for (size_t i = 0; path[i]; i++) {
                r = pico_strv_extend(&copy, path[i]);
                if (r < 0) {
                        pico_strv_free(copy);
                        return r;
                }
        }

        pico_strv_free(n->network_path);
        n->network_path = copy;
        return 0;
}

int netd_set_runtime_dir(Netd *n, const char *dir) {
        return n ? set_string(&n->runtime_dir, dir) : -EINVAL;
}

int netd_set_state_dir(Netd *n, const char *dir) {
        return n ? set_string(&n->state_dir, dir) : -EINVAL;
}

int netd_set_resolv_conf(Netd *n, const char *path) {
        return n ? set_string(&n->resolv_conf, path) : -EINVAL;
}

int netd_set_zoneinfo_dir(Netd *n, const char *dir) {
        return n ? set_string(&n->zoneinfo_dir, dir) : -EINVAL;
}

int netd_set_localtime_path(Netd *n, const char *path) {
        return n ? set_string(&n->localtime_path, path) : -EINVAL;
}

int netd_runtime_path(Netd *n, const char *subdir, const char *name, bool mkdir_parent, char **ret) {
        char dir[PATH_MAX], path[PATH_MAX];
        char *copy;
        int len;

        if (!n || !n->runtime_dir || !ret)
                return -EINVAL;

        if (subdir)
                len = snprintf(dir, sizeof(dir), "%s/%s", n->runtime_dir, subdir);
        else
                len = snprintf(dir, sizeof(dir), "%s", n->runtime_dir);
        if (len < 0 || (size_t) len >= sizeof(dir))
                return -ENAMETOOLONG;

        if (mkdir_parent) {
                /* The runtime directory itself may be missing too, so create
                 * both levels rather than assuming a tmpfiles.d dropped one
                 * in: netd is the only thing that writes here. */
                if (subdir && mkdir(n->runtime_dir, 0755) < 0 && errno != EEXIST)
                        return -errno;

                if (mkdir(dir, 0755) < 0 && errno != EEXIST)
                        return -errno;
        }

        if (name)
                len = snprintf(path, sizeof(path), "%s/%s", dir, name);
        else
                len = snprintf(path, sizeof(path), "%s", dir);
        if (len < 0 || (size_t) len >= sizeof(path))
                return -ENAMETOOLONG;

        copy = pico_strdup(path);
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return 0;
}

int netd_startup(Netd *n) {
        if (!n)
                return -EINVAL;

        /* N1: clock floor, network_load_all(), netd_rtnl_new() + subscribe,
         * netd_rtnl_enumerate_links(), netd_bring_up_loopback(). */
        return -ENOSYS;
}

int netd_reload(Netd *n) {
        if (!n)
                return -EINVAL;

        return -ENOSYS;
}

int netd_bring_up_loopback(Netd *n) {
        if (!n)
                return -EINVAL;

        return -ENOSYS;
}

int main(int argc, char *argv[]) {
        Netd *n = NULL;
        int r;

        (void) argc;
        (void) argv;

        r = netd_new(&n);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "netd: failed to allocate: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        r = netd_startup(n);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "netd: startup failed: %s", strerror(-r));
                netd_free(n);
                return EXIT_FAILURE;
        }

        r = netd_loop_run(n);
        netd_free(n);

        if (r < 0) {
                pico_log(PICO_LOG_ERR, "netd: event loop failed: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
