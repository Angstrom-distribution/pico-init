/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * logd -- pico-init's log daemon (plan §3), main() and the event loop.
 *
 * logd is a supervised Type=simple service in its own cgroup, restarted on
 * failure -- the netd model, for the same reasons: PID 1 must never block on
 * log I/O, parsing attacker-influenceable client bytes stays out of PID 1,
 * and a logd crash must be cheap.
 *
 * The property that makes a crash cheap is fd ownership, not an fd store:
 * PID 1 binds and holds the datagram sockets via logd.socket, so they outlive
 * logd, datagrams queue in the receive buffer across a crash and restart, and
 * the respawned logd gets the same fds back through LISTEN_FDS and drains the
 * backlog. Every service's connected stdout fd stays valid throughout.
 *
 * FACTOR-OR-COPY DECISION (plan §3.2, recorded here as asked): netd's
 * generic, callback-tagged epoll wrapper (netd-loop.c's ~155-line pattern)
 * is neither factored into a shared library nor copied here. netd needed
 * genericity because its source count grows across milestones (rtnl,
 * timer, DHCP client/server sockets, SNTP...); logd's is fixed and small --
 * a signalfd plus the two datagram sockets today, /dev/kmsg the only
 * addition J2 brings -- closer in shape to PID 1's own three-hardcoded-arms
 * loop (manager-loop.c) than to netd's registry. The loop below is that:
 * a plain switch on which of a handful of known fds fired, reusing
 * signal.c from the shared static library (already linked here, same as
 * netd links timer.c/signal.c/util.c) rather than reimplementing
 * signalfd handling a third time.
 */

/* logd-recv.h declares struct ucred in its own signatures (via
 * <sys/socket.h>), which needs _GNU_SOURCE visible before that header is
 * first pulled in -- see logd-recv.c's identical comment. */
#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "../signal.h"
#include "../util.h"
#include "logd-recv.h"
#include "logd-write.h"
#include "logd.h"

#define LOGD_EPOLL_MAX_EVENTS 8

/* sd_listen_fds()'s own contract, which plan §1.6's socket activation
 * follows: passed fds start at 3. */
#define LOGD_LISTEN_FDS_START 3

/*
 * LISTEN_PID/LISTEN_FDS (plan §1.6): true with stdout_fd/syslog_fd (the
 * out-parameters) set to fd 3/4 (logd.socket's declared Listen* order --
 * stdout first, /dev/log second) if this process was socket-activated;
 * false (both left at -1) otherwise, which is not an error -- standalone
 * operation (no S3/J4 image wiring yet, or a developer running logd by
 * hand) binds its own sockets
 * instead, below.
 */
static bool get_listen_fds(int *stdout_fd, int *syslog_fd) {
        const char *pid_s = getenv("LISTEN_PID");
        const char *fds_s = getenv("LISTEN_FDS");
        char *endp;
        long pid, fds;

        *stdout_fd = -1;
        *syslog_fd = -1;

        if (!pid_s || !fds_s)
                return false;

        pid = strtol(pid_s, &endp, 10);
        if (endp == pid_s || *endp != '\0' || pid != (long) getpid())
                return false;

        fds = strtol(fds_s, &endp, 10);
        if (endp == fds_s || *endp != '\0' || fds < 2)
                return false;

        *stdout_fd = LOGD_LISTEN_FDS_START;
        *syslog_fd = LOGD_LISTEN_FDS_START + 1;
        return true;
}

int main(int argc, char *argv[]) {
        LogdWriter *writer = NULL;
        LogdRecv *recv_ctx = NULL;
        PicoSignal *sig = NULL;
        const char *runtime_dir_override = NULL;
        long max_bytes_override = -1;
        int stdout_fd, syslog_fd;
        int epoll_fd = -1;
        bool activated;
        int r;

        for (int i = 1; i < argc; i++) {
                if (strncmp(argv[i], "--runtime-dir=", 14) == 0)
                        runtime_dir_override = argv[i] + 14;
                else if (strncmp(argv[i], "--max-bytes=", 12) == 0)
                        max_bytes_override = strtol(argv[i] + 12, NULL, 10);
        }

        r = logd_writer_new(&writer);
        if (r < 0) {
                fprintf(stderr, "logd: writer init failed: %s\n", strerror(-r));
                return 1;
        }

        if (runtime_dir_override)
                (void) logd_writer_set_runtime_dir(writer, runtime_dir_override);
        if (max_bytes_override > 0)
                (void) logd_writer_set_max_bytes(writer, (size_t) max_bytes_override);

        r = logd_writer_open(writer);
        if (r < 0) {
                fprintf(stderr, "logd: failed to open the ring: %s\n", strerror(-r));
                logd_writer_free(writer);
                return 1;
        }

        r = logd_recv_new(writer, &recv_ctx);
        if (r < 0) {
                fprintf(stderr, "logd: recv init failed: %s\n", strerror(-r));
                logd_writer_free(writer);
                return 1;
        }

        activated = get_listen_fds(&stdout_fd, &syslog_fd);
        if (!activated) {
                /* --runtime-dir= relocates the stdout socket along with the
                 * ring itself, so standalone/test use never has to touch
                 * the real /run/logd -- /dev/log stays fixed regardless
                 * (glibc's syslog(3) has no override for it either). */
                char stdout_path_buf[4096];
                const char *stdout_path = LOGD_STDOUT_SOCKET_PATH;

                if (runtime_dir_override) {
                        int len = snprintf(
                                        stdout_path_buf,
                                        sizeof(stdout_path_buf),
                                        "%s/stdout",
                                        runtime_dir_override);

                        if (len > 0 && (size_t) len < sizeof(stdout_path_buf))
                                stdout_path = stdout_path_buf;
                }

                r = logd_recv_bind_socket(stdout_path, 0600, &stdout_fd);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING, "logd: failed to bind %s: %s", stdout_path, strerror(-r));
                        stdout_fd = -1;
                }

                r = logd_recv_bind_socket(LOGD_SYSLOG_SOCKET_PATH, 0666, &syslog_fd);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "logd: failed to bind %s: %s",
                                 LOGD_SYSLOG_SOCKET_PATH,
                                 strerror(-r));
                        syslog_fd = -1;
                }
        } else {
                /* Already bound and SO_PASSCRED'd by PID 1 in production,
                 * but set it again anyway -- harmless there, and it is what
                 * keeps a hand-fed fd correct under test too
                 * (logd-recv.h). */
                (void) logd_recv_ensure_passcred(stdout_fd);
                (void) logd_recv_ensure_passcred(syslog_fd);
        }

        if (stdout_fd < 0 && syslog_fd < 0) {
                fprintf(stderr, "logd: no input sockets available, nothing to do\n");
                logd_recv_free(recv_ctx);
                logd_writer_free(writer);
                return 1;
        }

        r = pico_signal_new(&sig);
        if (r < 0) {
                fprintf(stderr, "logd: signal setup failed: %s\n", strerror(-r));
                logd_recv_free(recv_ctx);
                logd_writer_free(writer);
                return 1;
        }

        epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (epoll_fd < 0) {
                fprintf(stderr, "logd: epoll_create1: %s\n", strerror(errno));
                pico_signal_free(sig);
                logd_recv_free(recv_ctx);
                logd_writer_free(writer);
                return 1;
        }

        {
                struct epoll_event ev;

                memset(&ev, 0, sizeof(ev));
                ev.events = EPOLLIN;

                if (stdout_fd >= 0) {
                        ev.data.fd = stdout_fd;
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, stdout_fd, &ev) < 0)
                                pico_log(PICO_LOG_WARNING,
                                         "logd: failed to register the stdout socket: %s",
                                         strerror(errno));
                }
                if (syslog_fd >= 0) {
                        ev.data.fd = syslog_fd;
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, syslog_fd, &ev) < 0)
                                pico_log(PICO_LOG_WARNING,
                                         "logd: failed to register /dev/log: %s",
                                         strerror(errno));
                }

                ev.data.fd = pico_signal_fd(sig);
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pico_signal_fd(sig), &ev) < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "logd: failed to register the signalfd: %s",
                                 strerror(errno));
        }

        pico_log(PICO_LOG_INFO,
                 "logd: startup: %s (stdout_fd=%d, syslog_fd=%d)",
                 activated ? "socket-activated" : "standalone",
                 stdout_fd,
                 syslog_fd);

        {
                bool running = true;

                while (running) {
                        struct epoll_event events[LOGD_EPOLL_MAX_EVENTS];
                        int k = epoll_wait(epoll_fd, events, LOGD_EPOLL_MAX_EVENTS, -1);

                        if (k < 0) {
                                if (errno == EINTR)
                                        continue;
                                pico_log(PICO_LOG_ERR, "logd: epoll_wait: %s", strerror(errno));
                                break;
                        }

                        for (int i = 0; i < k; i++) {
                                int fd = events[i].data.fd;

                                if (fd == stdout_fd)
                                        (void) logd_recv_drain_stdout(recv_ctx, fd);
                                else if (fd == syslog_fd)
                                        (void) logd_recv_drain_syslog(recv_ctx, fd);
                                else if (fd == pico_signal_fd(sig)) {
                                        int signo;

                                        while (pico_signal_read(sig, &signo) == 0)
                                                if (signo == SIGTERM || signo == SIGINT) {
                                                        pico_log(PICO_LOG_INFO,
                                                                 "logd: %s, shutting down",
                                                                 strsignal(signo));
                                                        running = false;
                                                }
                                }
                        }
                }
        }

        (void) close(epoll_fd);
        (void) pico_signal_free(sig);
        (void) logd_recv_free(recv_ctx);
        (void) logd_writer_free(writer);

        return 0;
}
