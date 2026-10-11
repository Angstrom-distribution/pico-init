/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_network_monitor's inotify watch, including the two-level
 * upward re-arm: started against a scratch root where none of
 * run/netd/leases exists yet, it has to fall back to watching "run"
 * itself, then climb back down to the real leases directory as netd
 * would eventually create it, one flush() at a time.
 */

#include "sd-network.h"

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../../test-util.h"
#include "network-internal.h"

static bool poll_readable(int fd, int timeout_ms) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        return poll(&pfd, 1, timeout_ms) > 0 && (pfd.revents & POLLIN);
}

int main(void) {
        char *tmp = test_tmpdir_new();
        sd_network_monitor *m = NULL;
        uint64_t timeout;

        ASSERT_TRUE(tmp != NULL);
        network_set_root_for_tests(tmp);

        ASSERT_EQ_INT(sd_network_monitor_new(&m, "bogus"), -EINVAL);
        ASSERT_EQ_INT(sd_network_monitor_new(&m, "links"), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_network_monitor_new(&m, NULL), -EOPNOTSUPP);

        /* "run" always exists (test_tmpdir_new() only made the top dir),
         * netd/leases do not yet: this has to succeed by climbing up to
         * watching "run" itself. */
        ASSERT_EQ_INT(test_mkdir(tmp, "run"), 0);
        ASSERT_EQ_INT(sd_network_monitor_new(&m, "leases"), 0);

        ASSERT_TRUE(sd_network_monitor_get_fd(m) >= 0);
        ASSERT_EQ_INT(sd_network_monitor_get_events(m), POLLIN);
        ASSERT_EQ_INT(sd_network_monitor_get_timeout(m, &timeout), 0);
        ASSERT_EQ_INT((long long) timeout, (long long) UINT64_MAX);

        /* Creating "run/netd" is visible on the "run" watch; flush()
         * drains it and climbs one level down. */
        ASSERT_EQ_INT(test_mkdir(tmp, "run/netd"), 0);
        ASSERT_TRUE(poll_readable(sd_network_monitor_get_fd(m), 2000));
        ASSERT_EQ_INT(sd_network_monitor_flush(m), 0);

        /* Same again for "run/netd/leases" itself. */
        ASSERT_EQ_INT(test_mkdir(tmp, "run/netd/leases"), 0);
        ASSERT_TRUE(poll_readable(sd_network_monitor_get_fd(m), 2000));
        ASSERT_EQ_INT(sd_network_monitor_flush(m), 0);

        /* Now watching the real target: a lease file appearing must be
         * visible directly, with no further climbing needed. */
        ASSERT_EQ_INT(test_write_file(tmp, "run/netd/leases/1", "ADDRESS=192.0.2.9\n"), 0);
        ASSERT_TRUE(poll_readable(sd_network_monitor_get_fd(m), 2000));
        ASSERT_EQ_INT(sd_network_monitor_flush(m), 0);

        sd_network_monitor_unref(m);
        ASSERT_TRUE(sd_network_monitor_unref(NULL) == NULL);

        network_set_root_for_tests(NULL);
        test_rm_rf(tmp);
        free(tmp);

        printf("test-sd-network-monitor: OK\n");
        return 0;
}
