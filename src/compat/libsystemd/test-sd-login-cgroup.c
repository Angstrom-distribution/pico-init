/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Real /sys/fs/cgroup/system.slice/<x>.service directories and a real
 * forked-and-joined child process, the same "give it a real directory to
 * read, not a mock" approach test-timer-cgroup.c already uses for
 * cgroups-v2.c. sd_pid_get_cgroup()/get_unit()/get_slice() and their
 * pidfd/peer siblings are exercised against that one real child: pidfd
 * via a real pidfd_open() syscall, peer via a real AF_UNIX connect() the
 * child makes only after it has already joined the cgroup -- accept()
 * blocking on that connection is the test's whole synchronization point,
 * no separate readiness pipe needed.
 */

#include "sd-login.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../test-util.h"

#define CGROUP_ROOT "/sys/fs/cgroup"

static int pico_pidfd_open(pid_t pid) {
        return (int) syscall(SYS_pidfd_open, pid, 0);
}

int main(void) {
        char unit_name[64];
        char cgroup_path[PATH_MAX];
        char sock_path[PATH_MAX];
        char *tmpdir;
        pid_t child;
        int listen_fd, conn_fd, pidfd;
        struct sockaddr_un addr;
        char *ret;
        uid_t ruid;
        int status;
        int r;

        snprintf(unit_name, sizeof(unit_name), "pico-init-test-%lld.service", (long long) getpid());
        snprintf(cgroup_path, sizeof(cgroup_path), CGROUP_ROOT "/system.slice/%s", unit_name);

        r = mkdir(CGROUP_ROOT "/system.slice", 0755);
        if (r < 0 && errno != EEXIST) {
                fprintf(stderr, "mkdir system.slice failed (%s), skipping\n", strerror(errno));
                exit(77); /* meson: SKIP */
        }
        rmdir(cgroup_path); /* leftover from an aborted run */
        if (mkdir(cgroup_path, 0755) < 0) {
                fprintf(stderr, "mkdir cgroup leaf failed (%s), skipping\n", strerror(errno));
                exit(77);
        }

        tmpdir = test_tmpdir_new();
        ASSERT_TRUE(tmpdir != NULL);
        snprintf(sock_path, sizeof(sock_path), "%s/peer.sock", tmpdir);

        listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        ASSERT_TRUE(listen_fd >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
        ASSERT_EQ_INT(bind(listen_fd, (struct sockaddr *) &addr, sizeof(addr)), 0);
        ASSERT_EQ_INT(listen(listen_fd, 1), 0);

        child = fork();
        ASSERT_TRUE(child >= 0);
        if (child == 0) {
                char pidbuf[32];
                char procs_path[PATH_MAX];
                int fd, cfd;
                int n;

                n = snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);
                if (n < 0 || (size_t) n >= sizeof(procs_path))
                        _exit(1);
                fd = open(procs_path, O_WRONLY);
                if (fd < 0)
                        _exit(1);
                snprintf(pidbuf, sizeof(pidbuf), "%lld", (long long) getpid());
                if (write(fd, pidbuf, strlen(pidbuf)) < 0)
                        _exit(1);
                close(fd);

                cfd = socket(AF_UNIX, SOCK_STREAM, 0);
                if (cfd < 0)
                        _exit(1);
                if (connect(cfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
                        _exit(1);

                pause(); /* until the parent SIGTERMs us */
                _exit(0);
        }

        conn_fd = accept(listen_fd, NULL, NULL);
        ASSERT_TRUE(conn_fd >= 0); /* blocks until the child has joined the cgroup and connected */

        /* --- pid --- */
        {
                char expected_cgroup[PATH_MAX];

                snprintf(expected_cgroup, sizeof(expected_cgroup), "/system.slice/%s", unit_name);
                ret = NULL;
                ASSERT_EQ_INT(sd_pid_get_cgroup(child, &ret), 0);
                ASSERT_STREQ(ret, expected_cgroup);
                free(ret);
        }

        ret = NULL;
        ASSERT_EQ_INT(sd_pid_get_unit(child, &ret), 0);
        ASSERT_STREQ(ret, unit_name);
        free(ret);

        ret = NULL;
        ASSERT_EQ_INT(sd_pid_get_slice(child, &ret), 0);
        ASSERT_STREQ(ret, "system.slice");
        free(ret);

        /* --- pidfd --- */
        pidfd = pico_pidfd_open(child);
        ASSERT_TRUE(pidfd >= 0);

        ret = NULL;
        ASSERT_EQ_INT(sd_pidfd_get_unit(pidfd, &ret), 0);
        ASSERT_STREQ(ret, unit_name);
        free(ret);

        ret = NULL;
        ASSERT_EQ_INT(sd_pidfd_get_slice(pidfd, &ret), 0);
        ASSERT_STREQ(ret, "system.slice");
        free(ret);
        close(pidfd);

        /* --- peer --- */
        ret = NULL;
        ASSERT_EQ_INT(sd_peer_get_unit(conn_fd, &ret), 0);
        ASSERT_STREQ(ret, unit_name);
        free(ret);

        ret = NULL;
        ASSERT_EQ_INT(sd_peer_get_slice(conn_fd, &ret), 0);
        ASSERT_STREQ(ret, "system.slice");
        free(ret);

        /* --- own process: no unit, but real cgroup path answered --- */
        ret = NULL;
        ASSERT_EQ_INT(sd_pid_get_cgroup(0, &ret), 0);
        ASSERT_TRUE(ret != NULL && ret[0] == '/');
        free(ret);

        /* --- invalid / dead --- */
        ASSERT_EQ_INT(sd_pid_get_cgroup(-1, &ret), -EINVAL);
        ASSERT_EQ_INT(sd_pid_get_unit(-1, &ret), -EINVAL);
        ASSERT_EQ_INT(sd_pid_get_slice(-1, &ret), -EINVAL);
        ASSERT_EQ_INT(sd_pidfd_get_cgroup(-1, &ret), -EBADF);
        ASSERT_EQ_INT(sd_peer_get_cgroup(-1, &ret), -EBADF); /* getsockopt() itself fails */

        {
                pid_t dead = fork();
                ASSERT_TRUE(dead >= 0);
                if (dead == 0)
                        _exit(0);
                waitpid(dead, &status, 0);
                ASSERT_EQ_INT(sd_pid_get_cgroup(dead, &ret), -ESRCH);
                ASSERT_EQ_INT(sd_pid_get_unit(dead, &ret), -ESRCH);
        }

        /* --- sd-login.c's "process confirmed alive, no such metadata"
         * honest_failure family, sharing the same resolver --- */
        ASSERT_EQ_INT(sd_pid_get_session(child, &ret), -ENODATA);
        ASSERT_EQ_INT(sd_pid_get_owner_uid(child, &ruid), -ENODATA);

        kill(child, SIGTERM);
        waitpid(child, &status, 0);

        close(conn_fd);
        close(listen_fd);
        unlink(sock_path);
        rmdir(cgroup_path);
        test_rm_rf(tmpdir);
        free(tmpdir);

        printf("test-sd-login-cgroup: all checks passed\n");
        return 0;
}
