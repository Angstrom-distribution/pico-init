/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Runs against real kernel objects: a fifo, an AF_UNIX socket, fds
 * renumbered the way service-exec.c's shift_fds() leaves them, and a
 * receiving datagram socket for sd_notify(). The env-var-only protocols
 * (sd_listen_fds()'s LISTEN_PID/LISTEN_FDS, sd_watchdog_enabled()) are
 * driven by setting and clearing the process environment.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "../../test-util.h"
#include "sd-daemon.h"

/* Puts a fresh pipe's read end at exactly fd `target`, closing whatever was
 * there first: the layout sd_listen_fds() consumes (SD_LISTEN_FDS_START..+n-1). */
static void install_fd_at(int target) {
        int p[2];

        /* Close first, then pipe(): pipe() takes the lowest free fd, which is
         * then target. Calling pipe() first could allocate target as p[0], and
         * closing it afterwards would close the fd being installed. */
        close(target);
        ASSERT_TRUE(pipe(p) == 0);
        if (p[0] != target) {
                ASSERT_TRUE(dup2(p[0], target) == target);
                close(p[0]);
        }
        close(p[1]);
}

static void clear_listen_env(void) {
        unsetenv("LISTEN_PID");
        unsetenv("LISTEN_PIDFDID");
        unsetenv("LISTEN_FDS");
        unsetenv("LISTEN_FDNAMES");
}

static void test_listen_fds_absent(void) {
        clear_listen_env();
        ASSERT_EQ_INT(sd_listen_fds(0), 0);
}

static void test_listen_fds_wrong_pid(void) {
        clear_listen_env();
        setenv("LISTEN_PID", "1", 1); /* never us, in a container or not */
        setenv("LISTEN_FDS", "1", 1);
        ASSERT_EQ_INT(sd_listen_fds(0), 0);
        clear_listen_env();
}

static void test_listen_fds_garbage(void) {
        char pidbuf[32];

        clear_listen_env();
        snprintf(pidbuf, sizeof(pidbuf), "%d", (int) getpid());
        setenv("LISTEN_PID", pidbuf, 1);

        setenv("LISTEN_FDS", "", 1);
        ASSERT_EQ_INT(sd_listen_fds(0), -EINVAL);

        setenv("LISTEN_FDS", "3x", 1);
        ASSERT_EQ_INT(sd_listen_fds(0), -EINVAL);

        setenv("LISTEN_FDS", "0", 1);
        ASSERT_EQ_INT(sd_listen_fds(0), -EINVAL);

        setenv("LISTEN_FDS", "-1", 1);
        ASSERT_EQ_INT(sd_listen_fds(0), -EINVAL);

        clear_listen_env();
}

static void test_listen_fds_real(void) {
        char pidbuf[32];
        int r, flags;

        install_fd_at(3);
        install_fd_at(4);

        /* Mirrors service-exec.c's child_exec(): PID 1 clears FD_CLOEXEC
         * before execve(), leaving sd_listen_fds() to re-arm it. */
        flags = fcntl(3, F_GETFD);
        ASSERT_TRUE(fcntl(3, F_SETFD, flags & ~FD_CLOEXEC) == 0);
        flags = fcntl(4, F_GETFD);
        ASSERT_TRUE(fcntl(4, F_SETFD, flags & ~FD_CLOEXEC) == 0);

        clear_listen_env();
        snprintf(pidbuf, sizeof(pidbuf), "%d", (int) getpid());
        setenv("LISTEN_PID", pidbuf, 1);
        setenv("LISTEN_FDS", "2", 1);

        r = sd_listen_fds(0);
        ASSERT_EQ_INT(r, 2);

        flags = fcntl(3, F_GETFD);
        ASSERT_TRUE(flags >= 0 && (flags & FD_CLOEXEC));
        flags = fcntl(4, F_GETFD);
        ASSERT_TRUE(flags >= 0 && (flags & FD_CLOEXEC));

        /* Env vars still present -- unset_environment was 0 above. */
        ASSERT_TRUE(getenv("LISTEN_FDS") != NULL);

        r = sd_listen_fds(1); /* now really unset everything */
        ASSERT_EQ_INT(r, 2);
        ASSERT_TRUE(getenv("LISTEN_PID") == NULL);
        ASSERT_TRUE(getenv("LISTEN_FDS") == NULL);

        close(3);
        close(4);
}

static void test_listen_fds_with_names_unknown(void) {
        char pidbuf[32];
        char **names = NULL;
        int r;

        install_fd_at(3);
        install_fd_at(4);

        clear_listen_env();
        snprintf(pidbuf, sizeof(pidbuf), "%d", (int) getpid());
        setenv("LISTEN_PID", pidbuf, 1);
        setenv("LISTEN_FDS", "2", 1);

        /* service-exec.c never sets LISTEN_FDNAMES, so this is the path every
         * pico-init-started service takes. */
        r = sd_listen_fds_with_names(1, &names);
        ASSERT_EQ_INT(r, 2);
        ASSERT_TRUE(names != NULL);
        ASSERT_STREQ(names[0], "unknown");
        ASSERT_STREQ(names[1], "unknown");
        ASSERT_TRUE(names[2] == NULL);

        free(names[0]);
        free(names[1]);
        free(names);
        close(3);
        close(4);
}

static void test_listen_fds_with_names_explicit(void) {
        char pidbuf[32];
        char **names = NULL;
        int r;

        install_fd_at(3);
        install_fd_at(4);
        install_fd_at(5);

        clear_listen_env();
        snprintf(pidbuf, sizeof(pidbuf), "%d", (int) getpid());
        setenv("LISTEN_PID", pidbuf, 1);
        setenv("LISTEN_FDS", "3", 1);
        setenv("LISTEN_FDNAMES", "one::three", 1); /* middle field stays empty */

        r = sd_listen_fds_with_names(1, &names);
        ASSERT_EQ_INT(r, 3);
        ASSERT_STREQ(names[0], "one");
        ASSERT_STREQ(names[1], "");
        ASSERT_STREQ(names[2], "three");
        ASSERT_TRUE(names[3] == NULL);

        free(names[0]);
        free(names[1]);
        free(names[2]);
        free(names);
        close(3);
        close(4);
        close(5);
}

static void test_listen_fds_with_names_mismatch(void) {
        char pidbuf[32];
        char **names = NULL;

        install_fd_at(3);

        clear_listen_env();
        snprintf(pidbuf, sizeof(pidbuf), "%d", (int) getpid());
        setenv("LISTEN_PID", pidbuf, 1);
        setenv("LISTEN_FDS", "1", 1);
        setenv("LISTEN_FDNAMES", "one:two", 1); /* two names, one fd */

        ASSERT_EQ_INT(sd_listen_fds_with_names(1, &names), -EINVAL);
        ASSERT_TRUE(getenv("LISTEN_FDS") == NULL); /* unset even on -EINVAL */

        close(3);
}

static void test_is_fifo(void) {
        char *dir;
        char path[512];
        int fd;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(path, sizeof(path), "%s/fifo", dir);
        ASSERT_TRUE(mkfifo(path, 0600) == 0);

        fd = open(path, O_RDWR | O_NONBLOCK);
        ASSERT_TRUE(fd >= 0);

        ASSERT_EQ_INT(sd_is_fifo(fd, NULL), 1);
        ASSERT_EQ_INT(sd_is_fifo(fd, path), 1);
        ASSERT_EQ_INT(sd_is_fifo(fd, "/nonexistent/path"), 0);
        ASSERT_EQ_INT(sd_is_fifo(-1, NULL), -EBADF);

        close(fd);
        test_rm_rf(dir);
        free(dir);
}

static void test_is_socket_unix(void) {
        char *dir;
        char path[512];
        int fd;
        struct sockaddr_un sun;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(path, sizeof(path), "%s/sock", dir);

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        ASSERT_TRUE(fd >= 0);

        memset(&sun, 0, sizeof(sun));
        sun.sun_family = AF_UNIX;
        strncpy(sun.sun_path, path, sizeof(sun.sun_path) - 1);
        ASSERT_TRUE(bind(fd, (struct sockaddr *) &sun, sizeof(sun)) == 0);
        ASSERT_TRUE(listen(fd, 1) == 0);

        ASSERT_EQ_INT(sd_is_socket(fd, AF_UNIX, SOCK_STREAM, 1), 1);
        ASSERT_EQ_INT(sd_is_socket(fd, AF_INET, 0, -1), 0);
        ASSERT_EQ_INT(sd_is_socket(fd, 0, SOCK_DGRAM, -1), 0);
        ASSERT_EQ_INT(sd_is_socket_unix(fd, SOCK_STREAM, 1, path, 0), 1);
        ASSERT_EQ_INT(sd_is_socket_unix(fd, SOCK_STREAM, 1, "/wrong/path", 0), 0);
        ASSERT_EQ_INT(sd_is_socket_unix(fd, SOCK_DGRAM, 1, NULL, 0), 0);

        close(fd);
        unlink(path);
        test_rm_rf(dir);
        free(dir);
}

static void test_notify_roundtrip(void) {
        char *dir;
        char path[512];
        int recv_fd;
        struct sockaddr_un sun;
        socklen_t sun_len;
        char buf[64];
        ssize_t n;

        clear_listen_env();
        unsetenv("NOTIFY_SOCKET");
        ASSERT_EQ_INT(sd_notify(0, "READY=1"), 0); /* not running under any init */

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(path, sizeof(path), "%s/notify", dir);

        recv_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        ASSERT_TRUE(recv_fd >= 0);
        memset(&sun, 0, sizeof(sun));
        sun.sun_family = AF_UNIX;
        strncpy(sun.sun_path, path, sizeof(sun.sun_path) - 1);
        ASSERT_TRUE(bind(recv_fd, (struct sockaddr *) &sun, sizeof(sun)) == 0);

        setenv("NOTIFY_SOCKET", path, 1);
        ASSERT_EQ_INT(sd_notify(0, "READY=1"), 1);
        ASSERT_TRUE(getenv("NOTIFY_SOCKET") != NULL); /* unset_environment was 0 */

        sun_len = sizeof(sun);
        n = recvfrom(recv_fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *) &sun, &sun_len);
        ASSERT_TRUE(n > 0);
        buf[n] = '\0';
        ASSERT_STREQ(buf, "READY=1");

        ASSERT_EQ_INT(sd_notifyf(1, "STATUS=%d%%", 50), 1);
        ASSERT_TRUE(getenv("NOTIFY_SOCKET") == NULL); /* unset_environment was 1 */
        n = recvfrom(recv_fd, buf, sizeof(buf) - 1, 0, NULL, NULL);
        ASSERT_TRUE(n > 0);
        buf[n] = '\0';
        ASSERT_STREQ(buf, "STATUS=50%");

        close(recv_fd);
        unlink(path);
        test_rm_rf(dir);
        free(dir);
}

static void test_notify_bad_socket_value(void) {
        clear_listen_env();
        setenv("NOTIFY_SOCKET", "relative/not/absolute", 1);
        ASSERT_EQ_INT(sd_notify(1, "READY=1"), -EINVAL);
        ASSERT_TRUE(getenv("NOTIFY_SOCKET") == NULL);
}

static void test_pid_notify_with_fds_honest_failure(void) {
        int fds[1] = { 0 };

        unsetenv("NOTIFY_SOCKET");
        ASSERT_EQ_INT(sd_pid_notify_with_fds(0, 0, "READY=1", fds, 1), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_pid_notify_with_fds(0, 0, "READY=1", NULL, 1), -EINVAL);
        /* n_fds == 0 is real -- routes to the same "no init listening" 0. */
        ASSERT_EQ_INT(sd_pid_notify_with_fds(0, 0, "READY=1", NULL, 0), 0);
        ASSERT_EQ_INT(sd_pid_notifyf_with_fds(0, 0, fds, 1, "READY=1"), -EOPNOTSUPP);
}

static void test_watchdog_enabled(void) {
        uint64_t usec = 0;
        char pidbuf[32];

        unsetenv("WATCHDOG_USEC");
        unsetenv("WATCHDOG_PID");
        ASSERT_EQ_INT(sd_watchdog_enabled(0, &usec), 0);

        setenv("WATCHDOG_USEC", "0", 1);
        ASSERT_EQ_INT(sd_watchdog_enabled(0, &usec), -EINVAL);

        setenv("WATCHDOG_USEC", "5000000", 1);
        snprintf(pidbuf, sizeof(pidbuf), "%d", (int) getpid());
        setenv("WATCHDOG_PID", pidbuf, 1);
        ASSERT_EQ_INT(sd_watchdog_enabled(0, &usec), 1);
        ASSERT_EQ_INT((long long) usec, 5000000LL);
        ASSERT_TRUE(getenv("WATCHDOG_USEC") != NULL);

        setenv("WATCHDOG_PID", "1", 1); /* not us */
        ASSERT_EQ_INT(sd_watchdog_enabled(1, &usec), 0);
        ASSERT_TRUE(getenv("WATCHDOG_USEC") == NULL);
        ASSERT_TRUE(getenv("WATCHDOG_PID") == NULL);
}

static void test_booted(void) {
        int r = sd_booted();

        /* Not a pico-init boot: only checks for a legal value (0/1) and no
         * crash. */
        ASSERT_TRUE(r == 0 || r == 1);
}

int main(void) {
        test_listen_fds_absent();
        test_listen_fds_wrong_pid();
        test_listen_fds_garbage();
        test_listen_fds_real();
        test_listen_fds_with_names_unknown();
        test_listen_fds_with_names_explicit();
        test_listen_fds_with_names_mismatch();
        test_is_fifo();
        test_is_socket_unix();
        test_notify_roundtrip();
        test_notify_bad_socket_value();
        test_pid_notify_with_fds_honest_failure();
        test_watchdog_enabled();
        test_booted();

        printf("test-sd-daemon: all checks passed\n");
        return 0;
}
