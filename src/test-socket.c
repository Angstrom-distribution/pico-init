/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * S0-S2's acceptance tests (plan §1.6).
 *
 * This binary does double duty. Run with no arguments it is the test suite;
 * run with one of a handful of "--helper" flags it instead behaves as a
 * tiny socket-activation CONSUMER, re-execed as a unit's own ExecStart= via
 * /proc/self/exe. That is what lets S1's "a test client reimplementing
 * sd_listen_fds()'s checks accepts the queued connection end-to-end"
 * criterion use a REAL forked, REAL exec'd, REAL socket-syscall process
 * rather than a shell script -- accept()/recv() have no portable shell
 * spelling, and a second meson-registered binary is not available to S0-S2
 * (meson.build is coordinator-owned; see plans/29-pico-init.md's file
 * ownership table).
 *
 * The other real gap this file works around: socket_notify_service_dead()
 * is designed to be called from service.c (frozen, owned by the
 * coordinator) at the two points a service reaches a genuinely terminal
 * state -- service_enter_dead() and service_do_start()'s start-limit-
 * exceeded branch (see socket.c's header for exactly which two lines). That
 * wiring has not landed yet. drive_step() below simulates it by calling
 * socket_notify_service_dead() itself right after draining a SIGCHLD batch,
 * which is the same point service_enter_dead() would have. Every other
 * piece exercised here -- socket_dispatch_io(), manager_dispatch_signal(),
 * service_sigchld_event(), socket_collect_fds()/socket_notify_service_
 * starting() via the real service_spawn() -- is the real, already-wired
 * production code path, not a mock.
 */

/* struct ucred / SCM_CREDENTIALS / SO_PASSCRED are Linux/glibc extensions;
 * -std=gnu17 alone does not imply _GNU_SOURCE (see socket.c's own note). */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "job.h"
#include "manager.h"
#include "service.h"
#include "socket.h"
#include "test-util.h"
#include "timer.h"
#include "unit.h"
#include "util.h"

/* ======================================================================
 * Helper-process mode: re-exec'd as a unit's ExecStart=.
 * ====================================================================== */

static bool check_listen_env(FILE *f) {
        const char *pid_s = getenv("LISTEN_PID");
        const char *fds_s = getenv("LISTEN_FDS");
        char pidbuf[32];
        int flags;

        if (!pid_s || !fds_s) {
                fprintf(f, "FAIL missing LISTEN_PID/LISTEN_FDS\n");
                return false;
        }

        snprintf(pidbuf, sizeof(pidbuf), "%d", (int) getpid());
        if (strcmp(pid_s, pidbuf) != 0) {
                fprintf(f, "FAIL LISTEN_PID %s != %s\n", pid_s, pidbuf);
                return false;
        }

        if (strcmp(fds_s, "1") != 0) {
                fprintf(f, "FAIL LISTEN_FDS %s != 1\n", fds_s);
                return false;
        }

        /* fds start at 3: this is the fd we expect the passed socket at. */
        flags = fcntl(3, F_GETFD);
        if (flags < 0) {
                fprintf(f, "FAIL fd 3 not open: %s\n", strerror(errno));
                return false;
        }

        /* FD_CLOEXEC clear: if it were not, execve() itself would already
         * have closed fd 3 and the checks above would have failed differently. */
        if (flags & FD_CLOEXEC) {
                fprintf(f, "FAIL fd 3 still has FD_CLOEXEC\n");
                return false;
        }

        return true;
}

/* Accepts exactly one stream connection on fd 3 and echoes what it reads
 * into TEST_RESULT_PATH -- the "accepts the queued connection end-to-end"
 * proof for a ListenStream= unix socket. */
static int helper_accept_echo(void) {
        const char *result_path = getenv("TEST_RESULT_PATH");
        char buf[64];
        ssize_t n;
        int cfd;
        FILE *f;

        if (!result_path)
                return 90;
        f = fopen(result_path, "we");
        if (!f)
                return 91;

        if (!check_listen_env(f)) {
                fclose(f);
                return 1;
        }

        cfd = accept(3, NULL, NULL);
        if (cfd < 0) {
                fprintf(f, "FAIL accept: %s\n", strerror(errno));
                fclose(f);
                return 1;
        }

        n = read(cfd, buf, sizeof(buf) - 1);
        if (n <= 0) {
                fprintf(f, "FAIL read\n");
                close(cfd);
                fclose(f);
                return 1;
        }
        buf[n] = '\0';

        fprintf(f, "OK %s\n", buf);
        close(cfd);
        fclose(f);
        return 0;
}

/* recv()s exactly one datagram on fd 3 and echoes it -- the ListenDatagram=
 * equivalent of the above, and the "fds collected without a trigger" boot-
 * ordered test's exec target too. */
static int helper_recv_echo(void) {
        const char *result_path = getenv("TEST_RESULT_PATH");
        char buf[64];
        ssize_t n;
        FILE *f;

        if (!result_path)
                return 90;
        f = fopen(result_path, "we");
        if (!f)
                return 91;

        if (!check_listen_env(f)) {
                fclose(f);
                return 1;
        }

        n = recv(3, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
                fprintf(f, "FAIL recv\n");
                fclose(f);
                return 1;
        }
        buf[n] = '\0';

        fprintf(f, "OK %s\n", buf);
        fclose(f);
        return 0;
}

/* How many environ entries start with `prefix` -- a duplicate would be
 * invisible to getenv(), which only ever returns the first. */
static int count_env(const char *prefix) {
        char **e;
        int n = 0;

        for (e = environ; *e; e++)
                if (strncmp(*e, prefix, strlen(prefix)) == 0)
                        n++;

        return n;
}

/* --recv-echo plus the unit's own Environment=/EnvironmentFile= values, from
 * the same envp that carried LISTEN_FDS/LISTEN_PID. Written aside and renamed
 * into place, FAIL included: the test polls for the result file's existence,
 * not its contents. */
static int helper_recv_echo_env(void) {
        const char *result_path = getenv("TEST_RESULT_PATH");
        const char *a = getenv("PICO_ENV_A"), *b = getenv("PICO_ENV_B");
        char buf[64], tmp_path[PATH_MAX];
        int ret = 1;
        ssize_t n;
        FILE *f;

        if (!result_path)
                return 90;
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", result_path);
        f = fopen(tmp_path, "we");
        if (!f)
                return 91;

        if (!check_listen_env(f))
                goto finish;

        if (count_env("LISTEN_PID=") != 1 || count_env("LISTEN_FDS=") != 1 || count_env("PICO_ENV_B=") != 1) {
                fprintf(f, "FAIL duplicate environment entries\n");
                goto finish;
        }

        n = recv(3, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
                fprintf(f, "FAIL recv\n");
                goto finish;
        }
        buf[n] = '\0';

        fprintf(f, "OK %s A=%s B=%s\n", buf, a ? a : "(unset)", b ? b : "(unset)");
        ret = 0;

finish:
        fclose(f);
        return rename(tmp_path, result_path) < 0 ? 92 : ret;
}

/* --recv-echo plus its own argv after the mode flag -- the unit's ExecStart=
 * passes it $VAR-expanded, so this proves the expanded main command still
 * got LISTEN_FDS/LISTEN_PID and fd 3. Same write-aside-and-rename as above. */
static int helper_recv_echo_argv(int argc, char **argv) {
        const char *result_path = getenv("TEST_RESULT_PATH");
        char buf[64], tmp_path[PATH_MAX];
        int ret = 1, i;
        ssize_t n;
        FILE *f;

        if (!result_path)
                return 90;
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", result_path);
        f = fopen(tmp_path, "we");
        if (!f)
                return 91;

        if (!check_listen_env(f))
                goto finish;

        n = recv(3, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
                fprintf(f, "FAIL recv\n");
                goto finish;
        }
        buf[n] = '\0';

        fprintf(f, "OK %s argc=%d", buf, argc - 2);
        for (i = 2; i < argc; i++)
                fprintf(f, " [%s]", argv[i]);
        fputc('\n', f);
        ret = 0;

finish:
        fclose(f);
        return rename(tmp_path, result_path) < 0 ? 92 : ret;
}

/* Exits immediately without ever touching fd 3 -- the crash-without-
 * draining shape H4/the datagram-livelock test needs: a service that keeps
 * getting (re-)triggered but never consumes what triggered it. */
static int helper_instant_exit(void) {
        return 0;
}

static int run_as_helper(int argc, char **argv) {
        const char *mode = argv[1];

        if (strcmp(mode, "--accept-echo") == 0)
                return helper_accept_echo();
        if (strcmp(mode, "--recv-echo") == 0)
                return helper_recv_echo();
        if (strcmp(mode, "--recv-echo-env") == 0)
                return helper_recv_echo_env();
        if (strcmp(mode, "--recv-echo-argv") == 0)
                return helper_recv_echo_argv(argc, argv);
        if (strcmp(mode, "--instant-exit") == 0)
                return helper_instant_exit();

        fprintf(stderr, "test-socket: unknown helper mode '%s'\n", mode);
        return 99;
}

/* This binary's own absolute path, for use as an ExecStart= target -- the
 * only portable way for a spawned unit to re-exec "this same test binary,
 * in helper mode" without a second meson-registered executable. */
static char *self_exe_path(void) {
        char *buf = calloc(1, PATH_MAX);
        ssize_t n;

        if (!buf)
                return NULL;

        n = readlink("/proc/self/exe", buf, PATH_MAX - 1);
        if (n < 0) {
                free(buf);
                return NULL;
        }
        buf[n] = '\0';

        return buf;
}

/* ======================================================================
 * Test-suite mode.
 * ====================================================================== */

static char *g_self_exe;

static Manager *manager_for(const char *dir) {
        const char * const path[] = { dir, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_TRUE(m != NULL);
        ASSERT_EQ_INT(manager_set_unit_path(m, path), 0);

        return m;
}

/* --- S0: unit type, parser, pairing --- */

static void test_pairing_same_basename(void) {
        Manager *m;
        Unit *sock, *svc;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX];

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/foo.sock", dir);

        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenStream=%s\n", sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "foo.socket", content), 0);
        }
        ASSERT_EQ_INT(test_write_file(dir, "foo.service", "[Service]\nType=simple\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock = manager_get_unit(m, "foo.socket");
        svc = manager_get_unit(m, "foo.service");
        ASSERT_TRUE(sock != NULL && svc != NULL);
        ASSERT_EQ_INT(sock->type, UNIT_SOCKET);
        ASSERT_EQ_INT(sock->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(svc->load_state, UNIT_LOADED);
        ASSERT_TRUE(SOCKET(sock)->service == svc);

        /* the auto-Before=, and its inverse After= on the service side */
        ASSERT_TRUE(unit_has_dependency(sock, UNIT_BEFORE, svc));
        ASSERT_TRUE(unit_has_dependency(svc, UNIT_AFTER, sock));

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* journald-style pairing: differing basenames via an explicit Service=. */
static void test_pairing_explicit_service(void) {
        Manager *m;
        Unit *sock, *svc;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX];

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/log.sock", dir);

        {
                char content[PATH_MAX + 256];
                snprintf(content,
                         sizeof(content),
                         "[Socket]\nListenDatagram=%s\nService=logd.service\n",
                         sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "mylog.socket", content), 0);
        }
        ASSERT_EQ_INT(test_write_file(dir, "logd.service", "[Service]\nType=simple\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock = manager_get_unit(m, "mylog.socket");
        svc = manager_get_unit(m, "logd.service");
        ASSERT_TRUE(sock != NULL && svc != NULL);
        ASSERT_EQ_INT(sock->load_state, UNIT_LOADED);
        ASSERT_TRUE(SOCKET(sock)->service == svc);
        ASSERT_TRUE(unit_has_dependency(sock, UNIT_BEFORE, svc));
        ASSERT_TRUE(unit_has_dependency(svc, UNIT_AFTER, sock));

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_repeated_listen_lines(void) {
        Manager *m;
        Unit *sock;
        Socket *s;
        SocketPort *p;
        char *dir = test_tmpdir_new();
        char a[PATH_MAX], b[PATH_MAX];
        int n_ports = 0;

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(a, sizeof(a), "%s/a.sock", dir);
        snprintf(b, sizeof(b), "%s/b.sock", dir);

        {
                char content[2 * PATH_MAX + 256];
                snprintf(content,
                         sizeof(content),
                         "[Socket]\nListenStream=%s\nListenStream=9999\nListenDatagram=%s\n",
                         a,
                         b);
                ASSERT_EQ_INT(test_write_file(dir, "multi.socket", content), 0);
        }
        ASSERT_EQ_INT(test_write_file(dir, "multi.service", "[Service]\nType=simple\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock = manager_get_unit(m, "multi.socket");
        ASSERT_TRUE(sock != NULL);
        ASSERT_EQ_INT(sock->load_state, UNIT_LOADED);
        s = SOCKET(sock);

        /* declaration order preserved (H12) */
        ASSERT_TRUE(s->ports != NULL);
        ASSERT_EQ_INT(s->ports->type, SOCK_STREAM);
        ASSERT_STREQ(s->ports->path, a);
        ASSERT_TRUE(s->ports->next != NULL);
        ASSERT_EQ_INT(s->ports->next->type, SOCK_STREAM);
        ASSERT_TRUE(s->ports->next->path == NULL);
        ASSERT_EQ_INT(s->ports->next->port, 9999);
        ASSERT_TRUE(s->ports->next->next != NULL);
        ASSERT_EQ_INT(s->ports->next->next->type, SOCK_DGRAM);
        ASSERT_STREQ(s->ports->next->next->path, b);
        ASSERT_TRUE(s->ports->next->next->next == NULL);

        for (p = s->ports; p; p = p->next)
                n_ports++;
        ASSERT_EQ_INT(n_ports, 3);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* Directives this project does not parse (BindIPv6Only=, keepalive tuning,
 * Symlinks=, ...) must be logged-and-dropped, not fail the whole unit --
 * the same drop-in tolerance every other section already gets. */
static void test_ignored_directives_tolerated(void) {
        Manager *m;
        Unit *sock;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX];

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/ign.sock", dir);

        {
                char content[PATH_MAX + 256];
                snprintf(content,
                         sizeof(content),
                         "[Socket]\nListenStream=%s\nBindIPv6Only=default\nKeepAlive=yes\nSymlinks=/run/foo\n"
                         "ReceiveBuffer=1M\n",
                         sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "ign.socket", content), 0);
        }
        ASSERT_EQ_INT(test_write_file(dir, "ign.service", "[Service]\nType=simple\nExecStart=/bin/true\n"), 0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock = manager_get_unit(m, "ign.socket");
        ASSERT_TRUE(sock != NULL);
        ASSERT_EQ_INT(sock->load_state, UNIT_LOADED);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_accept_yes_fails_loudly(void) {
        Manager *m;
        Unit *sock;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX];

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/acc.sock", dir);

        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenStream=%s\nAccept=yes\n", sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "acc.socket", content), 0);
        }
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock = manager_get_unit(m, "acc.socket");
        ASSERT_TRUE(sock != NULL);
        ASSERT_EQ_INT(sock->load_state, UNIT_ERROR); /* refused, not silently accepted */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_no_listen_fails(void) {
        Manager *m;
        Unit *sock;
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);

        ASSERT_EQ_INT(test_write_file(dir, "empty.socket", "[Socket]\nBacklog=64\n"), 0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock = manager_get_unit(m, "empty.socket");
        ASSERT_TRUE(sock != NULL);
        ASSERT_EQ_INT(sock->load_state, UNIT_ERROR);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The coordinator's logd-review finding: SO_PASSCRED has to be set on a
 * unix ListenDatagram= fd BEFORE bind(), because the kernel decides whether
 * to attach SCM_CREDENTIALS to a queued datagram based on the receiving
 * socket's SO_PASSCRED state at the moment it is queued -- not at whatever
 * later moment a consumer calls recvmsg(). Proven here the way that matters
 * for this project: a datagram sent (and left queued, unread) BEFORE
 * anything ever touches the socket still carries full, correct credentials
 * once read back -- exactly the "service was dead when this arrived"
 * backlog the whole fd-ownership design exists to preserve.
 */
static void test_datagram_passcred_set_before_bind(void) {
        Manager *m;
        Unit *sock_u;
        Socket *s;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX];
        int cfd;
        struct sockaddr_un addr;
        struct msghdr msg;
        struct iovec iov;
        char buf[16];
        char cmsgbuf[CMSG_SPACE(sizeof(struct ucred))];
        struct cmsghdr *cmsg;
        struct ucred *cred = NULL;
        ssize_t n;

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/cred.sock", dir);

        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenDatagram=%s\n", sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "cred.socket", content), 0);
        }
        ASSERT_EQ_INT(test_write_file(dir, "cred.service", "[Service]\nType=simple\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock_u = manager_get_unit(m, "cred.socket");
        s = SOCKET(sock_u);
        ASSERT_EQ_INT(unit_start(sock_u), 0); /* binds -- SO_PASSCRED must already be set by this point */

        {
                int val = 0;
                socklen_t len = sizeof(val);
                ASSERT_EQ_INT(getsockopt(s->ports->fd, SOL_SOCKET, SO_PASSCRED, &val, &len), 0);
                ASSERT_TRUE(val != 0);
        }

        /* Queue a datagram BEFORE anything ever calls recvmsg() on this fd. */
        cfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        ASSERT_TRUE(cfd >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
        ASSERT_EQ_INT((int) sendto(cfd, "cred", 4, 0, (struct sockaddr *) &addr, sizeof(addr)), 4);
        close(cfd);

        memset(&iov, 0, sizeof(iov));
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);

        n = recvmsg(s->ports->fd, &msg, 0);
        ASSERT_EQ_INT((int) n, 4);

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
                        cred = (struct ucred *) (void *) CMSG_DATA(cmsg);
                        break;
                }

        ASSERT_TRUE(cred != NULL); /* cmsg present: SO_PASSCRED was already on at queue time */
        ASSERT_EQ_INT((int) cred->pid, (int) getpid()); /* and correctly attributed, not pid 0 */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* --- S1: real listen, trigger, fd-pass --- */

/*
 * The manager loop driver every S1/S2 test below uses.
 *
 * An earlier version of this file hand-rolled its own epoll_wait()/dispatch
 * loop instead of calling manager_loop(). That was a real, found-by-running
 * bug, not a style choice: it never handled PICO_EPOLL_CGROUP wakeups, and a
 * cgroup.events fd that is never read back stays level-triggered-ready
 * forever, so epoll_wait() returned instantly on every call and the whole
 * "wait up to N iterations" budget burned through in microseconds, giving
 * the forked child no real wall-clock time at all before the test gave up
 * on it -- even though the underlying LISTEN_FDS/LISTEN_PID/trigger/re-arm
 * machinery was already fully correct (proven by inspecting the child's own
 * result file after the "failed" test process had already exited). Driving
 * the real manager_loop() instead avoids re-diagnosing that class of bug a
 * second time: it is the same, already-tested production event loop.
 *
 * The one piece manager_loop() cannot provide on its own is the pending
 * service.c hook (see this file's top-of-file comment): socket_notify_
 * service_dead() is simulated by calling it, unconditionally and harmlessly
 * when nothing died, from a repeating 5ms timer tick for the duration of
 * the drive. The same tick checks the caller's stopping condition and ends
 * the loop via MANAGER_EXIT once satisfied, or after a generous tick budget
 * as a safety net against a genuine regression hanging the suite.
 */

typedef enum DriveWaitKind {
        DRIVE_WAIT_FILE,
        DRIVE_WAIT_SOCKET_STATE,
        DRIVE_WAIT_SERVICE_RESULT,
} DriveWaitKind;

typedef struct DriveWait {
        DriveWaitKind kind;
        const char *path;
        Socket *sock;
        SocketState want_state;
        Service *svc;
        ServiceResult want_result;
} DriveWait;

static bool drive_wait_done(const DriveWait *w) {
        switch (w->kind) {
        case DRIVE_WAIT_FILE:
                return access(w->path, F_OK) == 0;
        case DRIVE_WAIT_SOCKET_STATE:
                return w->sock->state == w->want_state;
        case DRIVE_WAIT_SERVICE_RESULT:
                return w->svc->result == w->want_result;
        default:
                return false;
        }
}

static Manager *g_drive_m;
static Unit *g_drive_service;
static const DriveWait *g_drive_wait;
static int g_drive_ticks;
static int g_drive_max_ticks;

static void drive_tick(void *userdata, usec_t now) {
        (void) userdata;
        (void) now;

        if (g_drive_service)
                socket_notify_service_dead(g_drive_service);

        g_drive_ticks++;

        if (drive_wait_done(g_drive_wait) || g_drive_ticks >= g_drive_max_ticks)
                g_drive_m->objective = MANAGER_EXIT;
        else
                ASSERT_EQ_INT(pico_timer_add(g_drive_m->timer,
                                             now_monotonic() + 5 * USEC_PER_MSEC,
                                             drive_tick,
                                             NULL,
                                             NULL),
                              0);
}

/* Returns whether `wait` was actually satisfied (false means the tick
 * budget ran out first). */
static bool drive_until(Manager *m, Unit *service, const DriveWait *wait, int max_ticks) {
        g_drive_m = m;
        g_drive_service = service;
        g_drive_wait = wait;
        g_drive_ticks = 0;
        g_drive_max_ticks = max_ticks;

        /* A previous call on this same Manager left objective at whatever
         * it stopped the loop with (MANAGER_EXIT); the loop only runs while
         * it is MANAGER_RUNNING. */
        m->objective = MANAGER_RUNNING;

        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 5 * USEC_PER_MSEC, drive_tick, NULL, NULL),
                      0);
        manager_loop(m);

        return drive_wait_done(wait);
}

static void write_helper_service(const char *dir, const char *name, const char *mode, const char *restart) {
        char content[PATH_MAX + 256];

        snprintf(content,
                 sizeof(content),
                 "[Service]\nType=simple\nExecStart=%s %s\n%s",
                 g_self_exe,
                 mode,
                 restart ? restart : "");
        ASSERT_EQ_INT(test_write_file(dir, name, content), 0);
}

/* S1's done-when, half one: real bind, a real connect wakes the manager, and
 * a test client reimplementing sd_listen_fds()'s checks (LISTEN_PID,
 * LISTEN_FDS, fd 3, FD_CLOEXEC clear) accepts the queued connection
 * end-to-end. */
static void test_stream_end_to_end(void) {
        Manager *m;
        Unit *sock_u, *svc_u;
        Socket *s;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX], resultpath[PATH_MAX];
        int cfd;
        struct sockaddr_un addr;
        FILE *f;
        char line[128] = "";

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/echo.sock", dir);
        snprintf(resultpath, sizeof(resultpath), "%s/result", dir);
        setenv("TEST_RESULT_PATH", resultpath, 1);

        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenStream=%s\n", sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "echo.socket", content), 0);
        }
        write_helper_service(dir, "echo.service", "--accept-echo", NULL);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock_u = manager_get_unit(m, "echo.socket");
        svc_u = manager_get_unit(m, "echo.service");
        ASSERT_TRUE(sock_u != NULL && svc_u != NULL);
        s = SOCKET(sock_u);

        ASSERT_EQ_INT(unit_start(sock_u), 0);
        ASSERT_EQ_INT(s->state, SOCKET_LISTENING);
        ASSERT_TRUE(s->ports->fd >= 0);

        /* a real connect() wakes the manager */
        cfd = socket(AF_UNIX, SOCK_STREAM, 0);
        ASSERT_TRUE(cfd >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
        ASSERT_EQ_INT(connect(cfd, (struct sockaddr *) &addr, sizeof(addr)), 0);
        ASSERT_EQ_INT((int) write(cfd, "hello", 5), 5);

        /* triggers, spawns the helper, the helper accept()s/read()s/writes
         * its result/exits, and gets reaped -- all through the real
         * manager_loop(). */
        {
                DriveWait wait = { .kind = DRIVE_WAIT_FILE, .path = resultpath };

                ASSERT_TRUE(drive_until(m, svc_u, &wait, 4000)); /* 20s budget */
        }
        /* RUNNING (still handling this connection) or already re-armed to
         * LISTENING (the helper finished and was reaped in the same tick
         * that observed the result file) are both correct outcomes here --
         * either way the unit never went inactive/failed. */
        ASSERT_TRUE(s->state == SOCKET_RUNNING || s->state == SOCKET_LISTENING);
        close(cfd);

        f = fopen(resultpath, "re");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fgets(line, sizeof(line), f) != NULL);
        fclose(f);
        ASSERT_EQ_INT(strncmp(line, "OK hello", 8), 0);

        unsetenv("TEST_RESULT_PATH");
        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* S1's done-when, half two: a boot-ordered start (the socket already
 * listening, never triggered) collects the same fds the same way. */
static void test_boot_ordered_collects_fds_without_trigger(void) {
        Manager *m;
        Unit *sock_u, *svc_u;
        Socket *s;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX], resultpath[PATH_MAX];
        int cfd;
        struct sockaddr_un addr;
        FILE *f;
        char line[128] = "";

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/boot.sock", dir);
        snprintf(resultpath, sizeof(resultpath), "%s/result", dir);
        setenv("TEST_RESULT_PATH", resultpath, 1);

        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenDatagram=%s\n", sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "boot.socket", content), 0);
        }
        write_helper_service(dir, "boot.service", "--recv-echo", NULL);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock_u = manager_get_unit(m, "boot.socket");
        svc_u = manager_get_unit(m, "boot.service");
        ASSERT_TRUE(sock_u != NULL && svc_u != NULL);
        s = SOCKET(sock_u);

        /* boot order: the socket first (as the auto Before=/After= would
         * enforce in a real transaction), then the service directly -- not
         * through socket_trigger()/socket_dispatch_io() at all. */
        ASSERT_EQ_INT(unit_start(sock_u), 0);
        ASSERT_EQ_INT(s->state, SOCKET_LISTENING);

        ASSERT_EQ_INT(unit_start(svc_u), 0);
        ASSERT_EQ_INT(unit_active_state(svc_u), UNIT_ACTIVE);

        /* d137a488af: the socket must already have noticed and stopped
         * watching its fd -- no trigger ever ran, so nothing else would. */
        ASSERT_EQ_INT(s->state, SOCKET_RUNNING);

        cfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        ASSERT_TRUE(cfd >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
        ASSERT_EQ_INT((int) sendto(cfd, "world", 5, 0, (struct sockaddr *) &addr, sizeof(addr)), 5);
        close(cfd);

        {
                DriveWait wait = { .kind = DRIVE_WAIT_FILE, .path = resultpath };

                ASSERT_TRUE(drive_until(m, svc_u, &wait, 4000));
        }

        f = fopen(resultpath, "re");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fgets(line, sizeof(line), f) != NULL);
        fclose(f);
        ASSERT_EQ_INT(strncmp(line, "OK world", 8), 0);

        unsetenv("TEST_RESULT_PATH");
        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A socket-activated unit with Environment= and EnvironmentFile= gets both in
 * one envp: LISTEN_FDS/LISTEN_PID intact (the reserved slot still last and
 * still the child's own pid, even with a LISTEN_PID= in Environment=), the
 * unit's own variables with the file overriding Environment=, and the
 * inherited TEST_RESULT_PATH -- each name exactly once.
 */
static void test_socket_activation_with_unit_environment(void) {
        Manager *m;
        Unit *sock_u, *svc_u;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX], resultpath[PATH_MAX], envpath[PATH_MAX];
        char extra[PATH_MAX + 256];
        int cfd;
        struct sockaddr_un addr;
        FILE *f;
        char line[128] = "";

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/env.sock", dir);
        snprintf(resultpath, sizeof(resultpath), "%s/result", dir);
        snprintf(envpath, sizeof(envpath), "%s/env.conf", dir);
        setenv("TEST_RESULT_PATH", resultpath, 1);

        ASSERT_EQ_INT(test_write_file(dir, "env.conf", "# comment\nPICO_ENV_B=\"from file\"\n"), 0);
        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenDatagram=%s\n", sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "env.socket", content), 0);
        }
        snprintf(extra,
                 sizeof(extra),
                 "Environment=PICO_ENV_A=from-unit \"PICO_ENV_B=unit default\" LISTEN_PID=1\n"
                 "EnvironmentFile=%s\n",
                 envpath);
        write_helper_service(dir, "env.service", "--recv-echo-env", extra);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock_u = manager_get_unit(m, "env.socket");
        svc_u = manager_get_unit(m, "env.service");
        ASSERT_TRUE(sock_u != NULL && svc_u != NULL);

        ASSERT_EQ_INT(unit_start(sock_u), 0);
        ASSERT_EQ_INT(unit_start(svc_u), 0);
        ASSERT_EQ_INT(unit_active_state(svc_u), UNIT_ACTIVE);

        cfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        ASSERT_TRUE(cfd >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
        ASSERT_EQ_INT((int) sendto(cfd, "world", 5, 0, (struct sockaddr *) &addr, sizeof(addr)), 5);
        close(cfd);

        {
                DriveWait wait = { .kind = DRIVE_WAIT_FILE, .path = resultpath };

                ASSERT_TRUE(drive_until(m, svc_u, &wait, 4000));
        }

        f = fopen(resultpath, "re");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fgets(line, sizeof(line), f) != NULL);
        fclose(f);
        ASSERT_STREQ(line, "OK world A=from-unit B=from file\n");

        unsetenv("TEST_RESULT_PATH");
        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * plans/41 E3's named hazard: service_spawn() recognizes the main command by
 * pointer identity, and a $VAR-expanded ExecStart= runs from a fresh copy.
 * The socket fds must still be handed over, alongside the expanded argv: a
 * bare $VAR split into two words, a ${VAR} substituted, an unset $VAR gone.
 */
static void test_socket_activation_with_expanded_argv(void) {
        Manager *m;
        Unit *sock_u, *svc_u;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX], resultpath[PATH_MAX];
        int cfd;
        struct sockaddr_un addr;
        FILE *f;
        char line[128] = "";

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/argv.sock", dir);
        snprintf(resultpath, sizeof(resultpath), "%s/result", dir);
        setenv("TEST_RESULT_PATH", resultpath, 1);

        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenDatagram=%s\n", sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "argv.socket", content), 0);
        }
        write_helper_service(
                        dir,
                        "argv.service",
                        "--recv-echo-argv $PICO_ARGS $PICO_UNSET x${PICO_ONE}",
                        "Environment=\"PICO_ARGS=alpha beta\" PICO_ONE=gamma\n");
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock_u = manager_get_unit(m, "argv.socket");
        svc_u = manager_get_unit(m, "argv.service");
        ASSERT_TRUE(sock_u != NULL && svc_u != NULL);

        ASSERT_EQ_INT(unit_start(sock_u), 0);
        ASSERT_EQ_INT(unit_start(svc_u), 0);
        ASSERT_EQ_INT(unit_active_state(svc_u), UNIT_ACTIVE);
        ASSERT_EQ_INT(SOCKET(sock_u)->state, SOCKET_RUNNING); /* fds were collected */

        cfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        ASSERT_TRUE(cfd >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
        ASSERT_EQ_INT((int) sendto(cfd, "world", 5, 0, (struct sockaddr *) &addr, sizeof(addr)), 5);
        close(cfd);

        {
                DriveWait wait = { .kind = DRIVE_WAIT_FILE, .path = resultpath };

                ASSERT_TRUE(drive_until(m, svc_u, &wait, 4000));
        }

        f = fopen(resultpath, "re");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fgets(line, sizeof(line), f) != NULL);
        fclose(f);
        ASSERT_STREQ(line, "OK world argc=3 [alpha] [beta] [xgamma]\n");

        unsetenv("TEST_RESULT_PATH");
        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* --- S2: lifecycle hardening --- */

/* kill-the-service -> re-listen -> next-connect-retriggers, repeated. */
static void test_relisten_repeated_cycles(void) {
        Manager *m;
        Unit *sock_u, *svc_u;
        Socket *s;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX], resultpath[PATH_MAX];
        int cycle;

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/cyc.sock", dir);
        snprintf(resultpath, sizeof(resultpath), "%s/result", dir);
        setenv("TEST_RESULT_PATH", resultpath, 1);

        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenDatagram=%s\n", sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "cyc.socket", content), 0);
        }
        write_helper_service(dir, "cyc.service", "--recv-echo", NULL); /* Restart=no (default) */
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock_u = manager_get_unit(m, "cyc.socket");
        svc_u = manager_get_unit(m, "cyc.service");
        s = SOCKET(sock_u);

        ASSERT_EQ_INT(unit_start(sock_u), 0);

        for (cycle = 0; cycle < 3; cycle++) {
                int cfd;
                struct sockaddr_un addr;

                ASSERT_EQ_INT(s->state, SOCKET_LISTENING);
                unlink(resultpath);

                cfd = socket(AF_UNIX, SOCK_DGRAM, 0);
                ASSERT_TRUE(cfd >= 0);
                memset(&addr, 0, sizeof(addr));
                addr.sun_family = AF_UNIX;
                strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
                ASSERT_EQ_INT((int) sendto(cfd, "poke", 4, 0, (struct sockaddr *) &addr, sizeof(addr)), 4);
                close(cfd);

                /* phase 1: triggers, runs the helper, the helper recv()s+
                 * exits. Waiting on the socket's OWN state here would be
                 * wrong on this first phase -- it is already LISTENING
                 * before anything happens this cycle, so that predicate
                 * would look satisfied at tick 0. */
                {
                        DriveWait wait = { .kind = DRIVE_WAIT_FILE, .path = resultpath };

                        ASSERT_TRUE(drive_until(m, svc_u, &wait, 2000));
                }

                /* phase 2: the service dies (now genuinely, so the state
                 * predicate is meaningful) and, simulating the pending
                 * service.c hook, the socket is re-armed to LISTENING. */
                {
                        DriveWait wait = { .kind = DRIVE_WAIT_SOCKET_STATE,
                                           .sock = s,
                                           .want_state = SOCKET_LISTENING };

                        ASSERT_TRUE(drive_until(m, svc_u, &wait, 2000));
                }

                ASSERT_EQ_INT(s->state, SOCKET_LISTENING); /* re-armed, ready for the next connect */
        }

        unsetenv("TEST_RESULT_PATH");
        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* c2f3480897: a service that keeps failing until IT OWN 5-per-10s start
 * limit trips must fail its SOCKET too, not get re-listened for -- a
 * re-listen would just re-drive the identical crash loop the instant new
 * traffic arrived. Restart=on-failure with an always-failing ExecStart= is
 * what drives the service to its own limit here, exactly like test-
 * service.c's test_b7_start_limit_stops_the_loop(), but socket-triggered. */
static void test_service_start_limit_yields_socket_failed(void) {
        Manager *m;
        Unit *sock_u, *svc_u;
        Socket *s;
        Service *svc;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX];
        int cfd;
        struct sockaddr_un addr;

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/loop.sock", dir);

        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenDatagram=%s\n", sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "loop.socket", content), 0);
        }
        {
                char content[PATH_MAX + 256];
                snprintf(content,
                         sizeof(content),
                         "[Service]\nType=simple\nExecStart=/nonexistent/does-not-exist\n"
                         "Restart=on-failure\nRestartSec=5ms\n");
                ASSERT_EQ_INT(test_write_file(dir, "loop.service", content), 0);
        }
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock_u = manager_get_unit(m, "loop.socket");
        svc_u = manager_get_unit(m, "loop.service");
        s = SOCKET(sock_u);
        svc = SERVICE(svc_u);

        ASSERT_EQ_INT(unit_start(sock_u), 0);

        cfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        ASSERT_TRUE(cfd >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
        ASSERT_EQ_INT((int) sendto(cfd, "x", 1, 0, (struct sockaddr *) &addr, sizeof(addr)), 1);
        close(cfd);

        /*
         * One real trigger, then the service's own crash/restart machinery
         * (fork fails -- ENOENT -- Restart=on-failure -- RestartSec=5ms --
         * repeat) runs entirely on its own via the timer, exactly as in
         * test-service.c's B7 test, all inside the real manager_loop().
         * drive_until()'s own tick calls socket_notify_service_dead(svc_u)
         * every 5ms regardless -- including on the exact tick this
         * predicate is satisfied, which is the pending service.c hook at
         * service_do_start()'s start-limit branch (a DIFFERENT call site
         * than service_enter_dead() -- see socket.c's header for both), so
         * by the time drive_until() returns the socket has already been
         * notified and should already be FAILED.
         */
        {
                DriveWait wait = { .kind = DRIVE_WAIT_SERVICE_RESULT,
                                   .svc = svc,
                                   .want_result = SERVICE_FAILURE_START_LIMIT };

                ASSERT_TRUE(drive_until(m, svc_u, &wait, 4000));
        }

        ASSERT_EQ_INT(svc->state, SERVICE_FAILED);
        ASSERT_EQ_INT(svc->result, SERVICE_FAILURE_START_LIMIT);
        ASSERT_EQ_INT(s->state, SOCKET_FAILED);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * A connect-flood bounded by the SOCKET's own trigger ratelimit (20/2s),
 * isolated from the SERVICE's separate, tighter 5-per-10s start-limit.
 *
 * The two are not interchangeable in a fast/no-sleep test: socket_dispatch_
 * io() only ever fires while LISTENING, and a successful trigger unwatches
 * the fd immediately (H7) -- so in this project's design one socket-level
 * trigger corresponds to exactly one service start attempt, and 5 < 20
 * means the service's own limiter always wins a real lockstep race,
 * regardless of how fast the cycle runs. That is a real, useful finding
 * (recorded in the coordinator report), not a bug: the two limiters guard
 * different things -- the service's own limit protects against a service
 * that keeps failing on its own even without repeated external triggers,
 * the socket's guards specifically against repeated DISTINCT trigger
 * events that do not each consume the service's budget (an already-
 * running/already-queued service, socket_trigger()'s H2 no-op branch).
 * This test drives exactly that branch: the paired service is marked
 * SERVICE_RUNNING once, up front, so every one of socket_dispatch_io()'s
 * ratelimit-metered calls takes the "already active" no-op path and never
 * touches service_start_limit_check() at all -- isolating the mechanism
 * under test to the one this milestone actually asks for.
 */
static void test_connect_flood_bounded_by_socket_trigger_limit(void) {
        Manager *m;
        Unit *sock_u, *svc_u;
        Socket *s;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX];
        unsigned i;

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/flood.sock", dir);

        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenStream=%s\n", sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "flood.socket", content), 0);
        }
        ASSERT_EQ_INT(test_write_file(dir, "flood.service", "[Service]\nType=simple\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock_u = manager_get_unit(m, "flood.socket");
        svc_u = manager_get_unit(m, "flood.service");
        s = SOCKET(sock_u);

        ASSERT_EQ_INT(unit_start(sock_u), 0);
        SERVICE(svc_u)->state = SERVICE_RUNNING; /* see the comment above */

        /* Each iteration: put the socket back in LISTENING (as
         * socket_notify_service_dead() would once the service really died --
         * skipped here on purpose, see above) and fire one dispatch. Bounded
         * comfortably past the burst so a regression that forgets to ever
         * fail is caught rather than looping forever. */
        for (i = 0; i < 40 && s->state != SOCKET_FAILED; i++) {
                if (s->state != SOCKET_LISTENING) {
                        /* still RUNNING from the "already active" no-op path */
                        ASSERT_EQ_INT(s->state, SOCKET_RUNNING);
                        s->state = SOCKET_LISTENING; /* re-arm for the next trigger, matching
                                                        notify_service_dead()'s own transition */
                }
                socket_dispatch_io(NULL, s->ports->fd, EPOLLIN, s->ports);
        }

        ASSERT_EQ_INT(s->state, SOCKET_FAILED);
        ASSERT_TRUE(i < 40); /* actually failed within the bound, not merely hit it */

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/*
 * S2's explicit requirement: a ListenDatagram= socket whose service crashes
 * without draining must terminate in FAILED via a real, wired ratelimit
 * mechanism, not spin. Driven end to end through the real service state
 * machine (fork/exec via service_spawn(), real ENOENT-class or instant-exit
 * failures, real SIGCHLD reaping) -- unlike the isolated test above, this
 * one lets whichever limiter actually fires first in the real combined
 * system do so, because that IS the property being proven: SOMETHING stops
 * it, well short of "at fork/exec rate, forever" (H4).
 */
static void test_datagram_livelock_terminates_failed(void) {
        Manager *m;
        Unit *sock_u, *svc_u;
        Socket *s;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX];
        int cfd;
        struct sockaddr_un addr;

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/dgram-loop.sock", dir);

        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenDatagram=%s\n", sockpath);
                ASSERT_EQ_INT(test_write_file(dir, "dloop.socket", content), 0);
        }
        /* --instant-exit: the datagram is NEVER recv()'d, so it stays
         * queued and the fd is readable again the instant it is re-armed --
         * exactly H4's shape. Restart=no: each re-trigger is a genuinely
         * fresh socket-level trigger, not a Restart= reschedule. */
        write_helper_service(dir, "dloop.service", "--instant-exit", NULL);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock_u = manager_get_unit(m, "dloop.socket");
        svc_u = manager_get_unit(m, "dloop.service");
        s = SOCKET(sock_u);

        ASSERT_EQ_INT(unit_start(sock_u), 0);

        cfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        ASSERT_TRUE(cfd >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
        ASSERT_EQ_INT((int) sendto(cfd, "z", 1, 0, (struct sockaddr *) &addr, sizeof(addr)), 1);
        close(cfd);

        /* Bounded well past either limiter's burst count (20 socket-side,
         * 5 service-side): this must terminate FAILED long before the
         * bound, or the livelock is real. */
        {
                DriveWait wait = { .kind = DRIVE_WAIT_SOCKET_STATE, .sock = s, .want_state = SOCKET_FAILED };

                ASSERT_TRUE(drive_until(m, svc_u, &wait, 4000));
        }

        ASSERT_EQ_INT(s->state, SOCKET_FAILED);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

int main(int argc, char **argv) {
        if (argc >= 2 && argv[1][0] == '-' && argv[1][1] == '-')
                return run_as_helper(argc, argv);

        g_self_exe = self_exe_path();
        ASSERT_TRUE(g_self_exe != NULL);

        test_pairing_same_basename();
        test_pairing_explicit_service();
        test_repeated_listen_lines();
        test_ignored_directives_tolerated();
        test_accept_yes_fails_loudly();
        test_no_listen_fails();
        test_datagram_passcred_set_before_bind();

        test_stream_end_to_end();
        test_boot_ordered_collects_fds_without_trigger();
        test_socket_activation_with_unit_environment();
        test_socket_activation_with_expanded_argv();

        test_relisten_repeated_cycles();
        test_service_start_limit_yields_socket_failed();
        test_connect_flood_bounded_by_socket_trigger_limit();
        test_datagram_livelock_terminates_failed();

        free(g_self_exe);

        printf("test-socket: all S0-S2 checks passed\n");
        return 0;
}
