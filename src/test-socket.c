/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Socket unit tests: parsing and pairing, real listen/trigger/fd-pass
 * and lifecycle hardening.
 *
 * This binary does double duty. Run with no arguments it is the test suite;
 * run with one of a handful of "--helper" flags it instead behaves as a
 * tiny socket-activation CONSUMER, re-execed as a unit's own ExecStart= via
 * /proc/self/exe. That lets the "a test client reimplementing
 * sd_listen_fds()'s checks accepts the queued connection end-to-end" test
 * use a REAL forked, REAL exec'd, REAL socket-syscall process rather than a
 * shell script -- accept()/recv() have no portable shell spelling, and a
 * second binary would need its own meson registration.
 *
 * service.c calls socket_notify_service_dead() itself when a service reaches
 * a terminal state (service_enter_dead() and the start-limit-exceeded branch
 * of service_do_start()). The drive loop below additionally calls it from a
 * timer tick, which is harmless when nothing died.
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

/* Exits immediately without ever touching fd 3: a service that keeps
 * getting (re-)triggered but never consumes what triggered it. */
static int helper_instant_exit(void) {
        return 0;
}

/*
 * --exec-fds N: LISTEN_FDS=N with fds 3..N+2 open, inherited (no
 * FD_CLOEXEC), and sockets; nothing else open above them (the exec pipe
 * and every other manager fd gone). Then recv()s one datagram on the last
 * of them. Same write-aside-and-rename as above.
 */
static int helper_exec_fds(int argc, char **argv) {
        const char *result_path = getenv("TEST_RESULT_PATH");
        const char *fds_s = getenv("LISTEN_FDS");
        char buf[64], tmp_path[PATH_MAX];
        int ret = 1, n, fd, type;
        socklen_t sl = sizeof(type);
        ssize_t r;
        FILE *f;

        if (!result_path || argc < 3)
                return 90;
        n = atoi(argv[2]);
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", result_path);
        f = fopen(tmp_path, "we");
        if (!f)
                return 91;
        /* fopen() took the lowest free fd, above the passed ones */

        if (!fds_s || atoi(fds_s) != n) {
                fprintf(f, "FAIL LISTEN_FDS %s != %d\n", fds_s ? fds_s : "(unset)", n);
                goto finish;
        }

        for (fd = 3; fd < 3 + n; fd++) {
                int flags = fcntl(fd, F_GETFD);

                if (flags < 0 || (flags & FD_CLOEXEC) || getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &sl) < 0) {
                        fprintf(f, "FAIL fd %d not an inherited socket\n", fd);
                        goto finish;
                }
        }

        for (fd = 3 + n; fd < 256; fd++)
                if (fd != fileno(f) && fcntl(fd, F_GETFD) >= 0) {
                        fprintf(f, "FAIL stray fd %d\n", fd);
                        goto finish;
                }

        r = recv(3 + n - 1, buf, sizeof(buf) - 1, 0);
        if (r <= 0) {
                fprintf(f, "FAIL recv\n");
                goto finish;
        }
        buf[r] = '\0';

        fprintf(f, "OK %s\n", buf);
        ret = 0;

finish:
        fclose(f);
        return rename(tmp_path, result_path) < 0 ? 92 : ret;
}

/*
 * --accept-conn <%i>: an Accept=yes instance. fd 3 must already be the
 * connection (connected, not listening), so it is read directly, never
 * accept()ed. Writes "OK <data> <%i>" to $TEST_RESULT_PATH.<%i> (write-
 * aside-and-rename) and acks the client, proving which instance got which
 * connection.
 */
static int helper_accept_conn(int argc, char **argv) {
        const char *result_path = getenv("TEST_RESULT_PATH");
        char buf[64], path[PATH_MAX], tmp_path[PATH_MAX + 8];
        int ret = 1, listening = 1;
        socklen_t sl = sizeof(listening);
        ssize_t n;
        FILE *f;

        if (!result_path || argc < 3)
                return 90;
        snprintf(path, sizeof(path), "%s.%s", result_path, argv[2]);
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
        f = fopen(tmp_path, "we");
        if (!f)
                return 91;

        if (!check_listen_env(f))
                goto finish;

        if (getsockopt(3, SOL_SOCKET, SO_ACCEPTCONN, &listening, &sl) < 0 || listening) {
                fprintf(f, "FAIL fd 3 is not an accepted connection\n");
                goto finish;
        }

        n = read(3, buf, sizeof(buf) - 1);
        if (n <= 0) {
                fprintf(f, "FAIL read\n");
                goto finish;
        }
        buf[n] = '\0';

        if (write(3, "ack", 3) != 3) {
                fprintf(f, "FAIL write\n");
                goto finish;
        }

        fprintf(f, "OK %s %s\n", buf, argv[2]);
        ret = 0;

finish:
        fclose(f);
        return rename(tmp_path, path) < 0 ? 92 : ret;
}

/* --accept-hold: keeps its connection until the client closes it. */
static int helper_accept_hold(void) {
        char buf[64];

        while (read(3, buf, sizeof(buf)) > 0)
                ;

        return 0;
}

static int run_as_helper(int argc, char **argv) {
        const char *mode = argv[1];

        if (strcmp(mode, "--accept-conn") == 0)
                return helper_accept_conn(argc, argv);
        if (strcmp(mode, "--accept-hold") == 0)
                return helper_accept_hold();

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
        if (strcmp(mode, "--exec-fds") == 0)
                return helper_exec_fds(argc, argv);

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

/* --- unit type, parser, pairing --- */

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

        /* declaration order preserved (the order the ports are declared in the unit) */
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

/* Loads one "acc.socket" with `extra` appended to a ListenStream= line and
 * returns its load state. */
static UnitLoadState accept_socket_load_state(const char *extra, unsigned *ret_max_connections) {
        Manager *m;
        Unit *sock;
        UnitLoadState st;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX];

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/acc.sock", dir);

        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenStream=%s\n%s", sockpath, extra);
                ASSERT_EQ_INT(test_write_file(dir, "acc.socket", content), 0);
        }
        ASSERT_EQ_INT(test_write_file(dir, "acc@.service", "[Service]\nType=simple\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "other.service", "[Service]\nType=simple\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock = manager_get_unit(m, "acc.socket");
        ASSERT_TRUE(sock != NULL);
        st = sock->load_state;
        if (ret_max_connections)
                *ret_max_connections = SOCKET(sock)->max_connections;

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
        return st;
}

/* v30 socket_verify()'s Accept=yes rules: a stream-only socket with no
 * Service= loads (pairing with nothing up front); a datagram port or an
 * explicit Service= fails the load. */
static void test_accept_yes_verify(void) {
        unsigned max = 0;

        ASSERT_EQ_INT(accept_socket_load_state("Accept=yes\n", &max), UNIT_LOADED);
        ASSERT_EQ_INT((int) max, 64);
        ASSERT_EQ_INT(accept_socket_load_state("Accept=yes\nMaxConnections=3\n", &max), UNIT_LOADED);
        ASSERT_EQ_INT((int) max, 3);
        ASSERT_EQ_INT(accept_socket_load_state("Accept=yes\nMaxConnections=0\n", &max), UNIT_LOADED);
        ASSERT_EQ_INT((int) max, 64);
        ASSERT_EQ_INT(accept_socket_load_state("Accept=yes\nService=other.service\n", NULL), UNIT_ERROR);
        ASSERT_EQ_INT(accept_socket_load_state("Accept=yes\nListenDatagram=12345\n", NULL), UNIT_ERROR);
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
 * SO_PASSCRED has to be set on a
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

/* --- real listen, trigger, fd-pass --- */

/*
 * The manager loop driver every listen/trigger and lifecycle test below uses.
 *
 * It drives the real manager_loop() rather than a hand-rolled epoll loop: a
 * cgroup.events fd that is never read back stays level-triggered-ready, so a
 * loop that ignores PICO_EPOLL_CGROUP wakeups spins and burns its iteration
 * budget before the forked child has run.
 *
 * A repeating 5ms timer tick calls socket_notify_service_dead() (harmless
 * when nothing died). The same tick checks the caller's stopping condition and ends
 * the loop via MANAGER_EXIT once satisfied, or after a generous tick budget
 * as a safety net against a genuine regression hanging the suite.
 */

typedef enum DriveWaitKind {
        DRIVE_WAIT_FILE,
        DRIVE_WAIT_SOCKET_STATE,
        DRIVE_WAIT_SERVICE_RESULT,
        DRIVE_WAIT_SERVICE_STATE,
        DRIVE_WAIT_CONNECTIONS, /* Accept=yes: sock->n_connections == want_connections */
        DRIVE_WAIT_PEER_CLOSED, /* client end `fd` reads EOF */
} DriveWaitKind;

typedef struct DriveWait {
        DriveWaitKind kind;
        const char *path;
        Socket *sock;
        SocketState want_state;
        Service *svc;
        ServiceResult want_result;
        ServiceState want_svc_state;
        unsigned want_connections;
        int fd;
} DriveWait;

static bool peer_closed(int fd) {
        char c;

        return recv(fd, &c, 1, MSG_DONTWAIT | MSG_PEEK) == 0;
}

static bool drive_wait_done(const DriveWait *w) {
        switch (w->kind) {
        case DRIVE_WAIT_FILE:
                return access(w->path, F_OK) == 0;
        case DRIVE_WAIT_SOCKET_STATE:
                return w->sock->state == w->want_state;
        case DRIVE_WAIT_SERVICE_RESULT:
                return w->svc->result == w->want_result;
        case DRIVE_WAIT_SERVICE_STATE:
                return w->svc->state == w->want_svc_state;
        case DRIVE_WAIT_CONNECTIONS:
                return w->sock->n_connections == w->want_connections;
        case DRIVE_WAIT_PEER_CLOSED:
                return peer_closed(w->fd);
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

/* Socket activation, half one: real bind, a real connect wakes the manager, and
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

/* Socket activation, half two: a boot-ordered start (the socket already
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
 * service_spawn() recognizes the main command by
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

/* --- lifecycle hardening --- */

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
         * test-service.c's start-rate-limit test, all inside the real manager_loop().
         * drive_until()'s own tick calls socket_notify_service_dead(svc_u)
         * every 5ms regardless -- including on the exact tick this
         * predicate is satisfied, which stands in for service_do_start()'s
         * start-limit branch (a DIFFERENT call site than
         * service_enter_dead()), so
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
 * the fd immediately -- so in this project's design one socket-level
 * trigger corresponds to exactly one service start attempt, and 5 < 20
 * means the service's own limiter always wins a real lockstep race,
 * regardless of how fast the cycle runs. That is a real, useful finding
 * not a bug: the two limiters guard
 * different things -- the service's own limit protects against a service
 * that keeps failing on its own even without repeated external triggers,
 * the socket's guards specifically against repeated DISTINCT trigger
 * events that do not each consume the service's budget (an already-
 * running/already-queued service, socket_trigger()'s no-op branch for a running service).
 * This test drives exactly that branch: the paired service is marked
 * SERVICE_RUNNING once, up front, so every one of socket_dispatch_io()'s
 * ratelimit-metered calls takes the "already active" no-op path and never
 * touches service_start_limit_check() at all -- isolating the mechanism
 * under test.
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
 * Requirement: a ListenDatagram= socket whose service crashes
 * without draining must terminate in FAILED via a real, wired ratelimit
 * mechanism, not spin. Driven end to end through the real service state
 * machine (fork/exec via service_spawn(), real ENOENT-class or instant-exit
 * failures, real SIGCHLD reaping) -- unlike the isolated test above, this
 * one lets whichever limiter actually fires first in the real combined
 * system do so, because that IS the property being proven: SOMETHING stops
 * it, well short of "at fork/exec rate, forever".
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
         * exactly the livelock shape. Restart=no: each re-trigger is a genuinely
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

/*
 * A trigger whose start job ends without the service ever starting -- an
 * unmet Condition*=, or a Requires= dependency failing -- must re-arm the
 * socket rather than leave it RUNNING with its fds unwatched. No
 * socket_notify_service_dead() simulation here (NULL service to
 * drive_until()): service_enter_dead() is never reached, so only the job
 * ending can re-arm it. The datagram is never consumed, so the socket keeps
 * re-triggering until its own trigger limit fails it; stuck RUNNING, it
 * never gets that far.
 */
static void run_skipped_start_case(const char *tag, const char *svc_extra, const char *dep_unit) {
        Manager *m;
        Unit *sock_u, *svc_u;
        Socket *s;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX], name[64];
        int cfd;
        struct sockaddr_un addr;

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(sockpath, sizeof(sockpath), "%s/%s.sock", dir, tag);

        {
                char content[PATH_MAX + 256];

                snprintf(content, sizeof(content), "[Socket]\nListenDatagram=%s\n", sockpath);
                snprintf(name, sizeof(name), "%s.socket", tag);
                ASSERT_EQ_INT(test_write_file(dir, name, content), 0);

                snprintf(content,
                         sizeof(content),
                         "[Unit]\n%s[Service]\nType=simple\nExecStart=/bin/sleep 100\n",
                         svc_extra);
                snprintf(name, sizeof(name), "%s.service", tag);
                ASSERT_EQ_INT(test_write_file(dir, name, content), 0);
        }
        if (dep_unit)
                ASSERT_EQ_INT(test_write_file(dir, "skipdep.service", dep_unit), 0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        snprintf(name, sizeof(name), "%s.socket", tag);
        sock_u = manager_get_unit(m, name);
        snprintf(name, sizeof(name), "%s.service", tag);
        svc_u = manager_get_unit(m, name);
        ASSERT_TRUE(sock_u != NULL && svc_u != NULL);
        s = SOCKET(sock_u);

        ASSERT_EQ_INT(unit_start(sock_u), 0);
        ASSERT_EQ_INT(s->state, SOCKET_LISTENING);

        cfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        ASSERT_TRUE(cfd >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
        ASSERT_EQ_INT((int) sendto(cfd, "q", 1, 0, (struct sockaddr *) &addr, sizeof(addr)), 1);
        close(cfd);

        {
                DriveWait wait = { .kind = DRIVE_WAIT_SOCKET_STATE, .sock = s, .want_state = SOCKET_FAILED };

                ASSERT_TRUE(drive_until(m, NULL, &wait, 800));
        }

        ASSERT_EQ_INT(s->state, SOCKET_FAILED);
        ASSERT_TRUE(svc_u->job == NULL);
        ASSERT_EQ_INT(SERVICE(svc_u)->main_pid, 0); /* never started */
        ASSERT_EQ_INT(m->n_jobs, 0);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_skipped_start_rearms_socket(void) {
        run_skipped_start_case("skipcond", "ConditionPathExists=/nonexistent/skipcond\n", NULL);
        run_skipped_start_case(
                        "skipreq",
                        "Requires=skipdep.service\nAfter=skipdep.service\n",
                        "[Service]\nType=oneshot\nExecStart=/bin/false\n");
}

/*
 * Type=exec with several socket fds: the exec pipe has to stay out of the
 * fd range LISTEN_FDS renumbers into (child_exec() step 5b), survive the fd
 * sweep, and be gone after execve(). The start completes only on the
 * confirmed execve(), and the service then sees exactly its N sockets.
 */
static void test_exec_type_with_socket_fds(void) {
        enum { N_PORTS = 3 };
        Manager *m;
        Unit *sock_u, *svc_u;
        Service *svc;
        char *dir = test_tmpdir_new();
        char sockpath[N_PORTS][PATH_MAX], resultpath[PATH_MAX];
        char content[N_PORTS * (PATH_MAX + 32) + 64];
        size_t off = 0;
        struct sockaddr_un addr;
        FILE *f;
        char line[128] = "";
        int cfd, i;

        ASSERT_TRUE(dir != NULL);
        m = manager_for(dir);
        snprintf(resultpath, sizeof(resultpath), "%s/result", dir);
        setenv("TEST_RESULT_PATH", resultpath, 1);

        off += (size_t) snprintf(content + off, sizeof(content) - off, "[Socket]\n");
        for (i = 0; i < N_PORTS; i++) {
                snprintf(sockpath[i], sizeof(sockpath[i]), "%s/exec%d.sock", dir, i);
                off += (size_t) snprintf(
                                content + off, sizeof(content) - off, "ListenDatagram=%s\n", sockpath[i]);
        }
        ASSERT_EQ_INT(test_write_file(dir, "execfds.socket", content), 0);

        snprintf(content,
                 sizeof(content),
                 "[Service]\nType=exec\nExecStart=%s --exec-fds %d\n",
                 g_self_exe,
                 N_PORTS);
        ASSERT_EQ_INT(test_write_file(dir, "execfds.service", content), 0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock_u = manager_get_unit(m, "execfds.socket");
        svc_u = manager_get_unit(m, "execfds.service");
        ASSERT_TRUE(sock_u != NULL && svc_u != NULL);
        svc = SERVICE(svc_u);

        ASSERT_EQ_INT(unit_start(sock_u), 0);
        ASSERT_EQ_INT(manager_add_job(m, JOB_START, svc_u, NULL), 0);

        {
                DriveWait wait = { .kind = DRIVE_WAIT_SERVICE_STATE,
                                   .svc = svc,
                                   .want_svc_state = SERVICE_RUNNING };

                ASSERT_TRUE(drive_until(m, NULL, &wait, 400));
        }
        ASSERT_TRUE(svc_u->job == NULL);

        cfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        ASSERT_TRUE(cfd >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sockpath[N_PORTS - 1], sizeof(addr.sun_path) - 1);
        ASSERT_EQ_INT((int) sendto(cfd, "last", 4, 0, (struct sockaddr *) &addr, sizeof(addr)), 4);
        close(cfd);

        {
                DriveWait wait = { .kind = DRIVE_WAIT_FILE, .path = resultpath };

                ASSERT_TRUE(drive_until(m, NULL, &wait, 400));
        }

        f = fopen(resultpath, "re");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fgets(line, sizeof(line), f) != NULL);
        fclose(f);
        ASSERT_STREQ(line, "OK last\n");

        unsetenv("TEST_RESULT_PATH");
        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* --- Accept=yes: one instance per connection --- */

static int connect_unix(const char *path) {
        struct sockaddr_un addr;
        int fd;

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        ASSERT_TRUE(fd >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
        ASSERT_EQ_INT(connect(fd, (struct sockaddr *) &addr, sizeof(addr)), 0);

        return fd;
}

/* Writes acc.socket (Accept=yes, `extra` appended) and, unless NULL, the
 * acc@.service template; loads everything and starts the socket. */
static Manager *accept_setup(
                const char *dir, const char *sockpath, const char *extra, const char *tmpl, Socket **ret) {
        Manager *m = manager_for(dir);
        Unit *sock_u;

        {
                char content[PATH_MAX + 256];
                snprintf(content, sizeof(content), "[Socket]\nListenStream=%s\nAccept=yes\n%s", sockpath, extra);
                ASSERT_EQ_INT(test_write_file(dir, "acc.socket", content), 0);
        }
        if (tmpl)
                ASSERT_EQ_INT(test_write_file(dir, "acc@.service", tmpl), 0);
        ASSERT_EQ_INT(test_write_file(dir, "anchor.service", "[Service]\nType=simple\nExecStart=/bin/true\n"),
                      0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        sock_u = manager_get_unit(m, "acc.socket");
        ASSERT_TRUE(sock_u != NULL);
        ASSERT_EQ_INT(sock_u->load_state, UNIT_LOADED);
        ASSERT_EQ_INT(unit_start(sock_u), 0);
        ASSERT_EQ_INT(SOCKET(sock_u)->state, SOCKET_LISTENING);

        *ret = SOCKET(sock_u);
        return m;
}

static void read_line(const char *path, char *buf, size_t size) {
        FILE *f = fopen(path, "re");

        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fgets(buf, (int) size, f) != NULL);
        fclose(f);
}

/*
 * Two connections held open at once get two independent instances of
 * acc@.service, each with %i naming its own connection ("<nr>-<pid>-<uid>"
 * for AF_UNIX) and each handed only its own connection on fd 3. Once both
 * exit, both are dropped from the unit table -- the template's After= edge
 * with them -- and the socket is still LISTENING.
 */
static void test_accept_yes_instance_per_connection(void) {
        Manager *m;
        Socket *s;
        Unit *anchor;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX], resultpath[PATH_MAX], tmpl[PATH_MAX + 256];
        /* name[]/file[] sized well past what inst[]'s real content (a
         * short "%d-%lu-%lu") ever produces -- GCC's format-truncation
         * analysis can't trace inst[i]'s actual runtime bound through the
         * loop and conservatively assumes up to inst[]'s full declared
         * size, so the destination has to out-size that worst case too. */
        char inst[2][64], name[2][192], file[2][PATH_MAX + 256], line[160], expect[160], ack[8];
        int c[2], i;

        ASSERT_TRUE(dir != NULL);
        snprintf(sockpath, sizeof(sockpath), "%s/acc.sock", dir);
        snprintf(resultpath, sizeof(resultpath), "%s/result", dir);
        setenv("TEST_RESULT_PATH", resultpath, 1);
        snprintf(tmpl,
                 sizeof(tmpl),
                 "[Unit]\nAfter=anchor.service\n[Service]\nType=simple\nExecStart=%s --accept-conn %%i\n",
                 g_self_exe);
        m = accept_setup(dir, sockpath, "", tmpl, &s);

        anchor = manager_get_unit(m, "anchor.service");
        ASSERT_TRUE(anchor != NULL);

        for (i = 0; i < 2; i++) {
                snprintf(inst[i],
                         sizeof(inst[i]),
                         "%d-%lu-%lu",
                         i,
                         (unsigned long) getpid(),
                         (unsigned long) getuid());
                snprintf(name[i], sizeof(name[i]), "acc@%s.service", inst[i]);
                snprintf(file[i], sizeof(file[i]), "%s.%s", resultpath, inst[i]);
        }

        /* both connected before the manager runs at all: two queued
         * connections, accepted in order */
        c[0] = connect_unix(sockpath);
        c[1] = connect_unix(sockpath);
        ASSERT_EQ_INT((int) write(c[0], "one", 3), 3);
        ASSERT_EQ_INT((int) write(c[1], "two", 3), 3);

        for (i = 0; i < 2; i++) {
                DriveWait wait = { .kind = DRIVE_WAIT_FILE, .path = file[i] };

                ASSERT_TRUE(drive_until(m, NULL, &wait, 4000));
        }
        ASSERT_EQ_INT((int) s->n_accepted, 2);

        read_line(file[0], line, sizeof(line));
        snprintf(expect, sizeof(expect), "OK one %s\n", inst[0]);
        ASSERT_EQ_INT(strcmp(line, expect), 0);
        read_line(file[1], line, sizeof(line));
        snprintf(expect, sizeof(expect), "OK two %s\n", inst[1]);
        ASSERT_EQ_INT(strcmp(line, expect), 0);

        for (i = 0; i < 2; i++) {
                ASSERT_EQ_INT((int) read(c[i], ack, sizeof(ack)), 3);
                close(c[i]);
        }

        {
                DriveWait wait = { .kind = DRIVE_WAIT_CONNECTIONS, .sock = s, .want_connections = 0 };

                ASSERT_TRUE(drive_until(m, NULL, &wait, 4000));
        }
        ASSERT_TRUE(manager_get_unit(m, name[0]) == NULL);
        ASSERT_TRUE(manager_get_unit(m, name[1]) == NULL);
        ASSERT_EQ_INT((int) anchor->n_dependencies[UNIT_BEFORE], 0);
        ASSERT_EQ_INT(s->state, SOCKET_LISTENING);

        unsetenv("TEST_RESULT_PATH");
        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* MaxConnections=1: a second connection while the first instance is still
 * up is closed at once without ever naming or loading an instance; after
 * the first closes, its instance is reaped and the count is back at 0. */
static void test_accept_yes_max_connections(void) {
        Manager *m;
        Socket *s;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX], tmpl[PATH_MAX + 256];
        int c1, c2;

        ASSERT_TRUE(dir != NULL);
        snprintf(sockpath, sizeof(sockpath), "%s/acc.sock", dir);
        snprintf(tmpl, sizeof(tmpl), "[Service]\nType=simple\nExecStart=%s --accept-hold\n", g_self_exe);
        m = accept_setup(dir, sockpath, "MaxConnections=1\n", tmpl, &s);

        c1 = connect_unix(sockpath);
        {
                DriveWait wait = { .kind = DRIVE_WAIT_CONNECTIONS, .sock = s, .want_connections = 1 };

                ASSERT_TRUE(drive_until(m, NULL, &wait, 4000));
        }

        c2 = connect_unix(sockpath);
        {
                DriveWait wait = { .kind = DRIVE_WAIT_PEER_CLOSED, .fd = c2 };

                ASSERT_TRUE(drive_until(m, NULL, &wait, 4000));
        }
        ASSERT_EQ_INT((int) s->n_accepted, 1);
        ASSERT_EQ_INT((int) s->n_connections, 1);
        close(c2);

        close(c1);
        {
                DriveWait wait = { .kind = DRIVE_WAIT_CONNECTIONS, .sock = s, .want_connections = 0 };

                ASSERT_TRUE(drive_until(m, NULL, &wait, 4000));
        }
        ASSERT_EQ_INT(s->state, SOCKET_LISTENING);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A connection whose instance cannot run correctly is closed and its
 * instance never kept: no template at all, or a template that wants the
 * connection on stdin (StandardInput=, not supported). */
static void run_accept_refused_case(const char *tmpl) {
        Manager *m;
        Socket *s;
        char *dir = test_tmpdir_new();
        char sockpath[PATH_MAX], name[128];
        size_t n_units;
        int c;

        ASSERT_TRUE(dir != NULL);
        snprintf(sockpath, sizeof(sockpath), "%s/acc.sock", dir);
        m = accept_setup(dir, sockpath, "", tmpl, &s);
        n_units = m->n_units;
        snprintf(name, sizeof(name), "acc@0-%lu-%lu.service", (unsigned long) getpid(), (unsigned long) getuid());

        c = connect_unix(sockpath);
        {
                DriveWait wait = { .kind = DRIVE_WAIT_PEER_CLOSED, .fd = c };

                ASSERT_TRUE(drive_until(m, NULL, &wait, 4000));
        }
        close(c);

        ASSERT_EQ_INT((int) s->n_accepted, 1);
        ASSERT_EQ_INT((int) s->n_connections, 0);
        ASSERT_TRUE(manager_get_unit(m, name) == NULL);
        ASSERT_EQ_INT((int) m->n_units, (int) n_units);
        ASSERT_EQ_INT(s->state, SOCKET_LISTENING);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

static void test_accept_yes_refused_instances(void) {
        char tmpl[PATH_MAX + 256];

        run_accept_refused_case(NULL);

        snprintf(tmpl,
                 sizeof(tmpl),
                 "[Unit]\nAfter=anchor.service\n[Service]\nType=simple\nExecStart=%s --accept-hold\n"
                 "StandardInput=socket\n",
                 g_self_exe);
        run_accept_refused_case(tmpl);
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
        test_accept_yes_verify();
        test_no_listen_fails();
        test_datagram_passcred_set_before_bind();

        test_stream_end_to_end();
        test_boot_ordered_collects_fds_without_trigger();
        test_socket_activation_with_unit_environment();
        test_socket_activation_with_expanded_argv();
        test_exec_type_with_socket_fds();

        test_relisten_repeated_cycles();
        test_service_start_limit_yields_socket_failed();
        test_connect_flood_bounded_by_socket_trigger_limit();
        test_datagram_livelock_terminates_failed();
        test_skipped_start_rearms_socket();

        test_accept_yes_instance_per_connection();
        test_accept_yes_max_connections();
        test_accept_yes_refused_instances();

        free(g_self_exe);

        printf("test-socket: all S0-S2 checks passed\n");
        return 0;
}
