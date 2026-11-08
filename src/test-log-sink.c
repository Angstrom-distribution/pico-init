/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * PID 1's log sink: pico_log() goes to logd's /dev/log socket while the
 * manager reports logd as running and to /dev/kmsg otherwise and whenever a
 * send fails. A datagram socket in a temporary directory stands in for
 * /dev/log and a regular file for /dev/kmsg. The manager's side of the gate
 * is covered by test-manager-log-sink.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "test-util.h"
#include "util.h"

static char sock_path[256];
static char kmsg_path[256];
static char err_path[256];

static int sock_bind(void) {
        struct sockaddr_un sa = { .sun_family = AF_UNIX };
        int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

        ASSERT_TRUE(fd >= 0);
        (void) unlink(sock_path);
        strcpy(sa.sun_path, sock_path);
        ASSERT_TRUE(bind(fd, (struct sockaddr *) &sa, sizeof(sa)) == 0);
        return fd;
}

/* Reads one datagram; "" when none is queued. */
static const char *sock_recv(int fd) {
        static char buf[2048];
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);

        if (n < 0) {
                ASSERT_TRUE(errno == EAGAIN);
                return "";
        }
        buf[n] = '\0';
        return buf;
}

/*
 * What was appended to a file since the last call. The sink's descriptor
 * keeps its own write offset on /dev/kmsg's stand-in, so the file is only
 * emptied when a sink is (re)started, which reopens it at offset 0.
 */
static long seen[2];

static const char *file_take(const char *path) {
        static char buf[4096];
        int slot = (strcmp(path, kmsg_path) == 0) ? 0 : 1;
        FILE *f = fopen(path, "r");
        size_t n;

        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fseek(f, seen[slot], SEEK_SET) == 0);
        n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        seen[slot] += (long) n;
        fclose(f);
        return buf;
}

/* The sink starts with logd not running; most cases mark it running. */
static void start_sink_not_running(const char *syslog_path, const char *kmsg) {
        ASSERT_TRUE(truncate(kmsg_path, 0) == 0);
        seen[0] = 0;
        pico_log_to_journal_or_kmsg_at(syslog_path, kmsg);
}

static void start_sink(const char *syslog_path, const char *kmsg) {
        start_sink_not_running(syslog_path, kmsg);
        pico_log_set_journal_running(true);
}

/*
 * A bound /dev/log accepts connections whether or not logd runs, because PID
 * 1 holds it. Until the manager says logd runs nothing may be sent there, or
 * it queues unread and socket-activates logd.
 */
static void test_kmsg_while_logd_is_not_running(void) {
        int fd = sock_bind();

        start_sink_not_running(sock_path, kmsg_path);
        pico_log(PICO_LOG_INFO, "early %d", 1);
        ASSERT_STREQ(file_take(kmsg_path), "<6>pico-init[info]: early 1\n");
        ASSERT_STREQ(sock_recv(fd), "");

        pico_log_set_journal_running(true);
        pico_log(PICO_LOG_INFO, "up");
        ASSERT_STREQ(sock_recv(fd), "<6>pico-init[info]: up");
        ASSERT_STREQ(file_take(kmsg_path), "");

        /* logd going down closes the gate again, with the socket still bound. */
        pico_log_set_journal_running(false);
        pico_log(PICO_LOG_INFO, "down");
        ASSERT_STREQ(file_take(kmsg_path), "<6>pico-init[info]: down\n");
        ASSERT_STREQ(sock_recv(fd), "");

        pico_log_set_journal_running(true);
        pico_log(PICO_LOG_INFO, "again");
        ASSERT_STREQ(sock_recv(fd), "<6>pico-init[info]: again");

        close(fd);
}

static void test_logd_while_running(void) {
        int fd = sock_bind();

        start_sink(sock_path, kmsg_path);
        pico_log(PICO_LOG_DEBUG, "a.service: activating -> active");
        pico_log(PICO_LOG_WARNING, "a.service: main process exited");

        ASSERT_STREQ(sock_recv(fd), "<7>pico-init[debug]: a.service: activating -> active");
        ASSERT_STREQ(sock_recv(fd), "<4>pico-init[warning]: a.service: main process exited");
        ASSERT_STREQ(file_take(kmsg_path), "");

        close(fd);
}

/* A socket that appears after the sink started is picked up once logd runs. */
static void test_switch_when_socket_appears(void) {
        int fd;

        (void) unlink(sock_path);
        start_sink(sock_path, kmsg_path);
        pico_log(PICO_LOG_INFO, "one");
        ASSERT_STREQ(file_take(kmsg_path), "<6>pico-init[info]: one\n");

        fd = sock_bind();
        pico_log(PICO_LOG_INFO, "two");
        ASSERT_STREQ(sock_recv(fd), "<6>pico-init[info]: two");
        ASSERT_STREQ(file_take(kmsg_path), "");

        close(fd);
}

/* A listener that goes away falls back to kmsg, and a new one is picked up again. */
static void test_fallback_and_reconnect(void) {
        int fd = sock_bind();

        start_sink(sock_path, kmsg_path);
        pico_log(PICO_LOG_INFO, "one");
        ASSERT_STREQ(sock_recv(fd), "<6>pico-init[info]: one");

        /* Stale socket file: connect() or send() is refused. */
        close(fd);
        pico_log(PICO_LOG_INFO, "two");
        ASSERT_STREQ(file_take(kmsg_path), "<6>pico-init[info]: two\n");
        pico_log(PICO_LOG_INFO, "three");
        ASSERT_STREQ(file_take(kmsg_path), "<6>pico-init[info]: three\n");

        /* Restarted socket unit: new inode at the same path. */
        fd = sock_bind();
        pico_log(PICO_LOG_INFO, "four");
        ASSERT_STREQ(sock_recv(fd), "<6>pico-init[info]: four");
        ASSERT_STREQ(file_take(kmsg_path), "");

        /* Removed under a connected sink. */
        close(fd);
        (void) unlink(sock_path);
        pico_log(PICO_LOG_INFO, "five");
        ASSERT_STREQ(file_take(kmsg_path), "<6>pico-init[info]: five\n");

        fd = sock_bind();
        pico_log(PICO_LOG_INFO, "six");
        ASSERT_STREQ(sock_recv(fd), "<6>pico-init[info]: six");
        close(fd);
}

/* logd stuck with a full queue: the record is not lost and the sink does not block. */
static void test_full_queue_falls_back(void) {
        int fd = sock_bind();
        int small = 4096;
        int i, sent_to_socket = 0;
        char line[200];

        ASSERT_TRUE(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) == 0);
        start_sink(sock_path, kmsg_path);

        memset(line, 'x', sizeof(line) - 1);
        line[sizeof(line) - 1] = '\0';
        for (i = 0; i < 2000; i++) {
                pico_log(PICO_LOG_INFO, "%s", line);
                if (file_take(kmsg_path)[0])
                        break;
                sent_to_socket++;
        }
        ASSERT_TRUE(i < 2000);
        ASSERT_TRUE(sent_to_socket > 0);

        /* Draining the queue makes logd reachable again on the same connection. */
        while (sock_recv(fd)[0])
                ;
        pico_log(PICO_LOG_INFO, "after");
        ASSERT_STREQ(sock_recv(fd), "<6>pico-init[info]: after");
        ASSERT_STREQ(file_take(kmsg_path), "");

        close(fd);
}

/* Without either destination, and before any opt-in, the record goes to stderr without the "<N>". */
static void test_stderr_when_nothing_is_available(void) {
        int saved, tmp;

        (void) unlink(sock_path);
        fflush(stderr);
        saved = dup(STDERR_FILENO);
        ASSERT_TRUE(saved >= 0);
        tmp = open(err_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        ASSERT_TRUE(tmp >= 0);
        ASSERT_TRUE(dup2(tmp, STDERR_FILENO) >= 0);
        close(tmp);

        start_sink(sock_path, NULL);
        pico_log(PICO_LOG_WARNING, "nowhere");

        ASSERT_TRUE(dup2(saved, STDERR_FILENO) >= 0);
        close(saved);
        ASSERT_STREQ(file_take(err_path), "pico-init[warning]: nowhere\n");
        ASSERT_STREQ(file_take(kmsg_path), "");
}

int main(void) {
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);
        snprintf(sock_path, sizeof(sock_path), "%s/log", dir);
        snprintf(kmsg_path, sizeof(kmsg_path), "%s/kmsg", dir);
        snprintf(err_path, sizeof(err_path), "%s/stderr", dir);
        ASSERT_EQ_INT(test_write_file(dir, "kmsg", ""), 0);
        ASSERT_EQ_INT(test_write_file(dir, "stderr", ""), 0);

        test_kmsg_while_logd_is_not_running();
        test_logd_while_running();
        test_switch_when_socket_appears();
        test_fallback_and_reconnect();
        test_full_queue_falls_back();
        test_stderr_when_nothing_is_available();

        test_rm_rf(dir);
        free(dir);
        printf("test-log-sink: all cases passed\n");
        return 0;
}
