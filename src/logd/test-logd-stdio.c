/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * logd's own stdout and stderr. Under PID 1 they are datagram sockets
 * connected to the socket logd reads, so a blocking write into a full queue
 * waits on logd itself. The test hands logd a stdout and stderr whose queue
 * is already full, and requires that startup reaches the event loop and that
 * SIGTERM ends it, within a bounded time.
 *
 * logd.c is included so its static helper can be called and main() can be run
 * in a forked child; main() is renamed out of the way.
 */

#define _GNU_SOURCE /* struct ucred, via logd-recv.h */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define main logd_main
#pragma GCC diagnostic ignored "-Wunused-function"
#include "logd.c"
#undef main

#include "../test-util.h"
#include "logd-read.h"

#define WAIT_MS 5000

/* Send until the queue refuses; the receiving end stays unread. */
static void fill_queue(int fd) {
        int n = 0;

        for (;;) {
                if (send(fd, "x", 1, MSG_DONTWAIT) < 0) {
                        ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
                        break;
                }
                ASSERT_TRUE(++n < 1000000);
        }
}

static void test_helper(void) {
        int full[2], idle[2], pipefd[2], saved1, saved2;
        ssize_t w;

        ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, full), 0);
        ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, idle), 0);
        ASSERT_EQ_INT(pipe(pipefd), 0);
        fill_queue(full[0]);

        saved1 = dup(STDOUT_FILENO);
        saved2 = dup(STDERR_FILENO);
        ASSERT_TRUE(saved1 >= 0 && saved2 >= 0);

        /* A full socket on fd 2 refuses the write instead of waiting; a pipe
         * on fd 1 is left alone. */
        ASSERT_TRUE(dup2(pipefd[1], STDOUT_FILENO) >= 0);
        ASSERT_TRUE(dup2(full[0], STDERR_FILENO) >= 0);
        logd_stdio_nonblock();

        alarm(WAIT_MS / 1000);
        w = write(STDERR_FILENO, "y", 1);
        alarm(0);
        ASSERT_EQ_INT((int) w, -1);
        ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
        ASSERT_TRUE((fcntl(STDERR_FILENO, F_GETFL) & O_NONBLOCK) != 0);
        ASSERT_TRUE((fcntl(STDOUT_FILENO, F_GETFL) & O_NONBLOCK) == 0);

        ASSERT_TRUE(dup2(saved1, STDOUT_FILENO) >= 0);
        ASSERT_TRUE(dup2(saved2, STDERR_FILENO) >= 0);
        close(saved1);
        close(saved2);
        close(full[0]);
        close(full[1]);
        close(idle[0]);
        close(idle[1]);
        close(pipefd[0]);
        close(pipefd[1]);
}

static bool ring_has_message(const char *dir, const char *msg) {
        LogdRing *ring = NULL;
        bool found = false;

        if (logd_ring_read(dir, &ring) < 0)
                return false;
        for (size_t i = 0; i < logd_ring_n_entries(ring); i++)
                if (logd_field_equals(logd_entry_field(logd_ring_entry(ring, i), "MESSAGE"), msg))
                        found = true;
        logd_ring_free(ring);
        return found;
}

static void sleep_ms(long ms) {
        struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };

        nanosleep(&ts, NULL);
}

static void move_high(int *fd) {
        int n = fcntl(*fd, F_DUPFD, 10);

        ASSERT_TRUE(n >= 10);
        close(*fd);
        *fd = n;
}

/* The child runs the real logd startup as a socket-activated service: fd 1
 * and 2 are the full queue, fd 3 and 4 the two input sockets. */
static void test_startup_with_full_stdout(void) {
        char *dir = test_tmpdir_new();
        char arg[4096];
        int full[2], in_stdout[2], in_syslog[2];
        int status = 0, i;
        bool ready = false, exited = false;
        pid_t pid;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, full), 0);
        ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, in_stdout), 0);
        ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, in_syslog), 0);
        fill_queue(full[0]);

        /* The child dup2()s onto 1..4; keep the originals out of that range. */
        move_high(&full[0]);
        move_high(&in_stdout[0]);
        move_high(&in_syslog[0]);

        snprintf(arg, sizeof(arg), "--runtime-dir=%s", dir);

        pid = fork();
        ASSERT_TRUE(pid >= 0);
        if (pid == 0) {
                char *args[] = { (char *) "logd", arg, NULL };
                char pidbuf[32];

                if (dup2(full[0], STDOUT_FILENO) < 0 || dup2(full[0], STDERR_FILENO) < 0 ||
                    dup2(in_stdout[0], 3) < 0 || dup2(in_syslog[0], 4) < 0)
                        _exit(120);
                snprintf(pidbuf, sizeof(pidbuf), "%d", (int) getpid());
                setenv("LISTEN_PID", pidbuf, 1);
                setenv("LISTEN_FDS", "2", 1);
                _exit(logd_main(2, args));
        }

        /* A datagram on the stdout input shows up in the ring only once the
         * event loop is running. */
        ASSERT_EQ_INT((int) send(in_stdout[1], "event-loop-reached\n", 19, 0), 19);
        for (i = 0; i < WAIT_MS / 50 && !ready; i++) {
                ready = ring_has_message(dir, "event-loop-reached");
                if (!ready)
                        sleep_ms(50);
        }

        if (ready) {
                ASSERT_EQ_INT(kill(pid, SIGTERM), 0);
                for (i = 0; i < WAIT_MS / 50 && !exited; i++) {
                        if (waitpid(pid, &status, WNOHANG) == pid)
                                exited = true;
                        else
                                sleep_ms(50);
                }
        }

        if (!exited) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
        }

        fprintf(stderr,
                "test-logd-stdio: event loop reached: %s, exited on SIGTERM: %s\n",
                ready ? "yes" : "no",
                exited ? "yes" : "no");
        ASSERT_TRUE(ready);
        ASSERT_TRUE(exited);
        ASSERT_TRUE(WIFEXITED(status));
        ASSERT_EQ_INT(WEXITSTATUS(status), 0);

        close(full[0]);
        close(full[1]);
        close(in_stdout[0]);
        close(in_stdout[1]);
        close(in_syslog[0]);
        close(in_syslog[1]);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        /* Backstop: a regression must not hang the suite. */
        alarm(60);

        test_helper();
        test_startup_with_full_stdout();

        printf("test-logd-stdio: all checks passed\n");
        return 0;
}
