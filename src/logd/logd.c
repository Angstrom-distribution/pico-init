/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * logd -- pico-init's log daemon: main() and the event loop.
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
 * The event loop is a plain dispatch over a fixed set of fds (signalfd, the
 * two datagram sockets, /dev/kmsg), not netd's generic callback-tagged epoll
 * wrapper (netd-loop.c): the source set never grows.
 */

/* logd-recv.h declares struct ucred in its own signatures (via
 * <sys/socket.h>), which needs _GNU_SOURCE visible before that header is
 * first pulled in. */
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
#include "logd-kmsg.h"
#include "logd-recv.h"
#include "logd-write.h"
#include "logd.h"

#define LOGD_EPOLL_MAX_EVENTS 8

/* sd_listen_fds() contract: passed fds start at 3. */
#define LOGD_LISTEN_FDS_START 3

/*
 * LISTEN_PID/LISTEN_FDS: true with stdout_fd/syslog_fd (the out-parameters)
 * set to fd 3/4 (logd.socket's declared Listen* order -- stdout first,
 * /dev/log second) if this process was socket-activated; false (both left
 * at -1) otherwise, which is not an error -- standalone operation binds its
 * own sockets instead, below.
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

static void logd_usage(void) {
        puts("logd [OPTIONS...]\n"
             "\n"
             "Log daemon.\n"
             "\n"
             "  -h --help             Show this help\n"
             "     --version          Show version\n"
             "     --runtime-dir=DIR  Ring directory instead of /run/logd\n"
             "     --max-bytes=N      Ring cap in bytes instead of 2 MiB");
}

/*
 * systemd-journald v262 takes no options and one optional log namespace name.
 * Namespaces are not supported, so a non-empty one is refused rather than
 * served from the main ring. --help and --version are additions; upstream
 * would take them for a namespace.
 *
 * 0 to run, 1 when --help or --version was all there was to do, -EINVAL on a
 * bad command line.
 */
static int logd_parse_argv(int argc, char *argv[], const char **runtime_dir, long *max_bytes) {
        const char *ns = NULL;
        int n_args = 0;

        for (int i = 1; i < argc; i++) {
                if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
                        logd_usage();
                        return 1;
                } else if (strcmp(argv[i], "--version") == 0) {
                        puts("logd " PICO_INIT_VERSION);
                        return 1;
                } else if (strncmp(argv[i], "--runtime-dir=", 14) == 0)
                        *runtime_dir = argv[i] + 14;
                else if (strncmp(argv[i], "--max-bytes=", 12) == 0)
                        *max_bytes = strtol(argv[i] + 12, NULL, 10);
                else if (argv[i][0] == '-' && argv[i][1] != '\0') {
                        fprintf(stderr, "logd: unrecognized option '%s'\n", argv[i]);
                        return -EINVAL;
                } else {
                        ns = argv[i];
                        n_args++;
                }
        }

        if (n_args > 1) {
                fprintf(stderr, "logd: this program takes one or no arguments\n");
                return -EINVAL;
        }
        if (ns && *ns) {
                fprintf(stderr, "logd: log namespaces are not supported, refusing namespace '%s'\n", ns);
                return -EINVAL;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        LogdWriter *writer = NULL;
        LogdRecv *recv_ctx = NULL;
        LogdKmsg *kmsg_ctx = NULL;
        PicoSignal *sig = NULL;
        const char *runtime_dir_override = NULL;
        long max_bytes_override = -1;
        int stdout_fd, syslog_fd;
        int epoll_fd = -1;
        bool activated;
        int r;

        r = logd_parse_argv(argc, argv, &runtime_dir_override, &max_bytes_override);
        if (r < 0)
                return 1;
        if (r > 0)
                return 0;

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

        /* Best-effort and independent of the datagram sockets below: a
         * kernel with no /dev/kmsg, or a run with no CAP_SYSLOG, just means
         * no kernel transport this time, never a reason to refuse to start.
         * The first drain happens here, not in the epoll loop, and picks up
         * the whole ring from seq 0, including what the kernel logged
         * before logd existed. */
        r = logd_kmsg_new(&kmsg_ctx);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "logd: /dev/kmsg unavailable, no kernel transport this run: %s",
                         strerror(-r));
                kmsg_ctx = NULL;
        } else {
                int n = logd_kmsg_drain(kmsg_ctx, writer);

                if (n < 0)
                        pico_log(PICO_LOG_WARNING, "logd: initial /dev/kmsg drain failed: %s", strerror(-n));
                else
                        pico_log(PICO_LOG_INFO,
                                 "logd: backfilled %d kernel message%s from /dev/kmsg",
                                 n,
                                 n == 1 ? "" : "s");
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
                /* PID 1 already sets SO_PASSCRED; set it again for fds
                 * passed in by hand (logd-recv.h). */
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

                if (kmsg_ctx) {
                        ev.data.fd = logd_kmsg_fd(kmsg_ctx);
                        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) < 0)
                                pico_log(PICO_LOG_WARNING,
                                         "logd: failed to register /dev/kmsg: %s",
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
                                else if (kmsg_ctx && fd == logd_kmsg_fd(kmsg_ctx))
                                        (void) logd_kmsg_drain(kmsg_ctx, writer);
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
        (void) logd_kmsg_free(kmsg_ctx);
        (void) logd_recv_free(recv_ctx);
        (void) logd_writer_free(writer);

        return 0;
}
