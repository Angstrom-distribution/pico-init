/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The receive path (plan §3, J1): a fake service writing multi-line/partial/oversized output, a real syslog(3)
 * client against a bound test socket, and correct ucred+cgroup attribution and framing for every entry.
 *
 * The load-bearing case is test_real_sockets_two_streams_same_pid(): the
 * corrected design keys the fragment tail by stream identity (the sender's
 * bound source address) rather than by PID, specifically because a PID can
 * be reused across streams and a real kernel-reported PID is used to prove
 * it -- two real AF_UNIX client sockets, each bound to its own abstract-
 * namespace address before connect() (exactly what service-exec.c will do
 * per plan §3.6), both sent from THIS one test process so the kernel
 * reports the identical real PID for both via SCM_CREDENTIALS. That is the
 * precise scenario that corrupted the original per-PID design; this test
 * demonstrates the corrected one cannot, with real recvmsg()/SO_PASSCRED
 * involved throughout, not synthetic parameters. A second, narrower test
 * (test_pid_change_on_stream) exercises the complementary case -- a real
 * PID *change* reported on one already-known stream -- directly with
 * injected ucred values, since that half needs no OS cooperation to be
 * exact. The one sub-case this file does not attempt to reproduce live is
 * a numeric PID silently recycled to a *different* process while still
 * reported as unchanged on the same stream: that needs actual kernel PID
 * wraparound (root, a lowered pid_max, real fork()/exec() timing) the way
 * the design review itself reproduced it, which is out of reach for a
 * hermetic unit test; the /proc/<pid>/stat start-time re-validation this
 * file's logd-recv.c carries for it is verified by code reading and by the
 * negative case (an unchanged real process across many datagrams never
 * spuriously flushes) rather than a live positive repro -- recorded here
 * rather than overclaimed.
 */

/* logd-recv.h declares struct ucred in its own signatures -- see
 * logd-recv.c's identical comment for why this has to be first. */
#define _GNU_SOURCE

#include "logd-kmsg.h"
#include "logd-read.h"
#include "logd-recv.h"
#include "logd-write.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include "../test-util.h"
#include "logd.h"

#define TEST_BOOT_ID "cafef00ddeadbeefcafef00ddeadbeef"

static LogdWriter *new_test_writer(const char *dir) {
        LogdWriter *w;

        ASSERT_EQ_INT(logd_writer_new(&w), 0);
        ASSERT_EQ_INT(logd_writer_set_runtime_dir(w, dir), 0);
        ASSERT_EQ_INT(logd_writer_set_boot_id(w, TEST_BOOT_ID), 0);
        ASSERT_EQ_INT(logd_writer_open(w), 0);

        return w;
}

/* An abstract-namespace (sun_path[0] == '\0') address, unique per call --
 * a synthetic peer for tests that drive logd_recv_process_stdout()
 * directly rather than through real sockets. */
static socklen_t make_synthetic_peer(struct sockaddr_un *addr, const char *tag) {
        int n;

        memset(addr, 0, sizeof(*addr));
        addr->sun_family = AF_UNIX;
        n = snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1, "test-logd-recv-%s", tag);

        return (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 1 + (size_t) n);
}

static void test_stdout_multiline(void) {
        char *dir = test_tmpdir_new();
        LogdWriter *w = new_test_writer(dir);
        LogdRecv *rc;
        struct sockaddr_un peer;
        socklen_t peer_len = make_synthetic_peer(&peer, "multiline");
        struct ucred cred = { .pid = 111, .uid = 0, .gid = 0 };
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_recv_new(w, &rc), 0);

        {
                static const char payload[] = "line1\nline2\nline3\n";

                ASSERT_EQ_INT(logd_recv_process_stdout(rc, payload, strlen(payload), &peer, peer_len, &cred),
                              0);
        }

        logd_recv_free(rc);
        logd_writer_free(w);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 3);
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 0), "MESSAGE"), "line1"));
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 1), "MESSAGE"), "line2"));
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 2), "MESSAGE"), "line3"));
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 0), "PRIORITY"), "6"));
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 0), "_TRANSPORT"), "stdout"));
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 0), "_PID"), "111"));
        ASSERT_TRUE(logd_entry_field(logd_ring_entry(ring, 0), "_LINE_BREAK") == NULL); /* ordinary newline */
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: three complete lines in one datagram become three records\n");
}

static void test_stdout_partial_then_continuation(void) {
        char *dir = test_tmpdir_new();
        LogdWriter *w = new_test_writer(dir);
        LogdRecv *rc;
        struct sockaddr_un peer;
        socklen_t peer_len = make_synthetic_peer(&peer, "partial");
        struct ucred cred = { .pid = 222, .uid = 0, .gid = 0 };
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_recv_new(w, &rc), 0);

        ASSERT_EQ_INT(logd_recv_process_stdout(
                                      rc,
                                      "partial-line-no-newline",
                                      strlen("partial-line-no-newline"),
                                      &peer,
                                      peer_len,
                                      &cred),
                      0);

        /* Nothing emitted yet -- the ring must still be empty. */
        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 0);
        logd_ring_free(ring);

        ASSERT_EQ_INT(logd_recv_process_stdout(
                                      rc, "-continues\n", strlen("-continues\n"), &peer, peer_len, &cred),
                      0);

        logd_recv_free(rc);
        logd_writer_free(w);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 1);
        ASSERT_TRUE(logd_field_equals(
                        logd_entry_field(logd_ring_entry(ring, 0), "MESSAGE"),
                        "partial-line-no-newline-continues"));
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: a line split across two datagrams is reassembled via the per-stream tail\n");
}

static void test_stdout_oversized_split(void) {
        char *dir = test_tmpdir_new();
        LogdWriter *w = new_test_writer(dir);
        LogdRecv *rc;
        struct sockaddr_un peer;
        socklen_t peer_len = make_synthetic_peer(&peer, "oversized");
        struct ucred cred = { .pid = 333, .uid = 0, .gid = 0 };
        char *payload;
        size_t payload_len = LOGD_LINE_MAX + 500;
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_recv_new(w, &rc), 0);

        payload = malloc(payload_len);
        ASSERT_TRUE(payload != NULL);
        memset(payload, 'x', payload_len); /* no newline anywhere -- forces the line-max split */

        ASSERT_EQ_INT(logd_recv_process_stdout(rc, payload, payload_len, &peer, peer_len, &cred), 0);
        free(payload);

        logd_recv_free(rc); /* frees LogdRecv, which flushes the remaining 500-byte tail (tagged eof) */
        logd_writer_free(w);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 2);
        {
                const LogdReadField *m0 = logd_entry_field(logd_ring_entry(ring, 0), "MESSAGE");
                const LogdReadField *m1 = logd_entry_field(logd_ring_entry(ring, 1), "MESSAGE");

                ASSERT_TRUE(m0 != NULL && m0->value_len == LOGD_LINE_MAX);
                ASSERT_TRUE(logd_field_equals(
                                logd_entry_field(logd_ring_entry(ring, 0), "_LINE_BREAK"), "line-max"));

                ASSERT_TRUE(m1 != NULL && m1->value_len == 500);
                ASSERT_TRUE(logd_field_equals(
                                logd_entry_field(logd_ring_entry(ring, 1), "_LINE_BREAK"), "eof"));
        }
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: an unterminated line past LOGD_LINE_MAX is SPLIT (tagged line-max), not "
               "flushed as-is\n");
}

static void test_stdout_embedded_nul(void) {
        char *dir = test_tmpdir_new();
        LogdWriter *w = new_test_writer(dir);
        LogdRecv *rc;
        struct sockaddr_un peer;
        socklen_t peer_len = make_synthetic_peer(&peer, "nul");
        struct ucred cred = { .pid = 444, .uid = 0, .gid = 0 };
        static const char payload[] = "abc\0def\n";
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_recv_new(w, &rc), 0);

        ASSERT_EQ_INT(logd_recv_process_stdout(rc, payload, sizeof(payload) - 1, &peer, peer_len, &cred), 0);

        logd_recv_free(rc);
        logd_writer_free(w);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 2);
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 0), "MESSAGE"), "abc"));
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 0), "_LINE_BREAK"), "nul"));
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 1), "MESSAGE"), "def"));
        ASSERT_TRUE(logd_entry_field(logd_ring_entry(ring, 1), "_LINE_BREAK") == NULL);
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: a literal embedded NUL breaks a line exactly like '\\n' (tagged nul), "
               "journald-stream.c's own rule\n");
}

static void test_stdout_no_credentials(void) {
        char *dir = test_tmpdir_new();
        LogdWriter *w = new_test_writer(dir);
        LogdRecv *rc;
        struct sockaddr_un peer;
        socklen_t peer_len = make_synthetic_peer(&peer, "nocred");
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_recv_new(w, &rc), 0);

        ASSERT_EQ_INT(logd_recv_process_stdout(
                                      rc, "no-cred-line\n", strlen("no-cred-line\n"), &peer, peer_len, NULL),
                      0);

        logd_recv_free(rc);
        logd_writer_free(w);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 1);
        {
                const LogdEntry *e = logd_ring_entry(ring, 0);

                ASSERT_TRUE(logd_field_equals(logd_entry_field(e, "MESSAGE"), "no-cred-line"));
                ASSERT_TRUE(logd_entry_field(e, "_PID") == NULL);
                ASSERT_TRUE(logd_entry_field(e, "_UID") == NULL);
                ASSERT_TRUE(logd_entry_field(e, "_COMM") == NULL);
                ASSERT_TRUE(logd_entry_field(e, "_SYSTEMD_UNIT") == NULL);
        }
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: unavailable attribution writes the record without _PID/_UID/_COMM/_SYSTEMD_UNIT, "
               "never guessed and never dropped\n");
}

static void test_stdout_anonymous_peer(void) {
        char *dir = test_tmpdir_new();
        LogdWriter *w = new_test_writer(dir);
        LogdRecv *rc;
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_recv_new(w, &rc), 0);

        /* A complete line: emitted immediately either way. */
        ASSERT_EQ_INT(logd_recv_process_stdout(rc, "anon-line\n", strlen("anon-line\n"), NULL, 0, NULL), 0);

        /* An unterminated one: an anonymous sender gets no tail carried
         * across calls at all (logd-recv.h), so this must be force-flushed
         * immediately (tagged eof) rather than buffered and possibly never
         * seen again. */
        ASSERT_EQ_INT(logd_recv_process_stdout(rc, "anon-partial", strlen("anon-partial"), NULL, 0, NULL), 0);

        logd_recv_free(rc);
        logd_writer_free(w);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 2);
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 0), "MESSAGE"), "anon-line"));
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 1), "MESSAGE"), "anon-partial"));
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 1), "_LINE_BREAK"), "eof"));
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: an anonymous (unbound) sender never carries a tail across calls\n");
}

static void test_pid_change_on_stream(void) {
        char *dir = test_tmpdir_new();
        LogdWriter *w = new_test_writer(dir);
        LogdRecv *rc;
        struct sockaddr_un peer;
        socklen_t peer_len = make_synthetic_peer(&peer, "pidchange");
        struct ucred cred1 = { .pid = 12345, .uid = 0, .gid = 0 };
        struct ucred cred2 = { .pid = 54321, .uid = 0, .gid = 0 };
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_recv_new(w, &rc), 0);

        ASSERT_EQ_INT(logd_recv_process_stdout(
                                      rc, "first-pid-partial", strlen("first-pid-partial"), &peer, peer_len, &cred1),
                      0);
        ASSERT_EQ_INT(logd_recv_process_stdout(
                                      rc, "second-pid-line\n", strlen("second-pid-line\n"), &peer, peer_len, &cred2),
                      0);

        logd_recv_free(rc);
        logd_writer_free(w);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 2);
        {
                const LogdEntry *e0 = logd_ring_entry(ring, 0);
                const LogdEntry *e1 = logd_ring_entry(ring, 1);

                ASSERT_TRUE(logd_field_equals(logd_entry_field(e0, "MESSAGE"), "first-pid-partial"));
                ASSERT_TRUE(logd_field_equals(logd_entry_field(e0, "_LINE_BREAK"), "pid-change"));
                ASSERT_TRUE(logd_field_equals(logd_entry_field(e0, "_PID"), "12345"));

                ASSERT_TRUE(logd_field_equals(logd_entry_field(e1, "MESSAGE"), "second-pid-line"));
                ASSERT_TRUE(logd_entry_field(e1, "_LINE_BREAK") == NULL);
                ASSERT_TRUE(logd_field_equals(logd_entry_field(e1, "_PID"), "54321"));
        }
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: a PID change reported on one stream force-flushes its tail, tagged "
               "_LINE_BREAK=pid-change\n");
}

/*
 * Mimics exactly what service-exec.c (plan §3.6) does for each service
 * invocation: bind an outbound socket to a unique Linux abstract-namespace
 * address before connect(), so the receiver's recvfrom() reports a stable,
 * unforgeable per-invocation source address on every datagram it sends.
 */
static int bind_abstract_client(void) {
        static int counter = 0;
        struct sockaddr_un addr;
        int fd, n;

        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -1;

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        n = snprintf(addr.sun_path + 1,
                     sizeof(addr.sun_path) - 1,
                     "test-logd-recv-client-%d-%d",
                     (int) getpid(),
                     counter++);

        if (bind(fd,
                 (struct sockaddr *) &addr,
                 (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 1 + (size_t) n)) < 0) {
                close(fd);
                return -1;
        }

        return fd;
}

/*
 * The load-bearing reproduction (see this file's header): two real client
 * sockets, each bound to its own abstract-namespace address, both from
 * this one test process -- so the kernel reports the SAME real PID for
 * both via SCM_CREDENTIALS, exactly the scenario that corrupted the
 * original per-PID design. If the tail were still keyed by PID, stream
 * B's datagram would splice onto stream A's pending partial line, or
 * clobber it outright.
 */
static void test_real_sockets_two_streams_same_pid(void) {
        char *dir = test_tmpdir_new();
        char sock_path[512];
        int recv_fd, client_a, client_b;
        LogdWriter *w;
        LogdRecv *rc;
        struct sockaddr_un recv_addr;
        size_t plen;
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);
        snprintf(sock_path, sizeof(sock_path), "%s/stdout", dir);

        ASSERT_EQ_INT(logd_recv_bind_socket(sock_path, 0600, &recv_fd), 0);

        w = new_test_writer(dir);
        ASSERT_EQ_INT(logd_recv_new(w, &rc), 0);

        client_a = bind_abstract_client();
        client_b = bind_abstract_client();
        ASSERT_TRUE(client_a >= 0 && client_b >= 0);

        memset(&recv_addr, 0, sizeof(recv_addr));
        recv_addr.sun_family = AF_UNIX;
        plen = strlen(sock_path);
        ASSERT_TRUE(plen < sizeof(recv_addr.sun_path));
        memcpy(recv_addr.sun_path, sock_path, plen);

        ASSERT_TRUE(connect(client_a, (struct sockaddr *) &recv_addr, sizeof(recv_addr)) == 0);
        ASSERT_TRUE(connect(client_b, (struct sockaddr *) &recv_addr, sizeof(recv_addr)) == 0);

        ASSERT_TRUE(send(client_a, "stream-a-partial", strlen("stream-a-partial"), 0) > 0);
        ASSERT_EQ_INT(logd_recv_drain_stdout(rc, recv_fd), 1);

        ASSERT_TRUE(send(client_b, "stream-b-line\n", strlen("stream-b-line\n"), 0) > 0);
        ASSERT_EQ_INT(logd_recv_drain_stdout(rc, recv_fd), 1);

        ASSERT_TRUE(send(client_a, "-finished\n", strlen("-finished\n"), 0) > 0);
        ASSERT_EQ_INT(logd_recv_drain_stdout(rc, recv_fd), 1);

        logd_recv_free(rc);
        close(client_a);
        close(client_b);
        close(recv_fd);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 2);
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 0), "MESSAGE"), "stream-b-line"));
        ASSERT_TRUE(logd_field_equals(
                        logd_entry_field(logd_ring_entry(ring, 1), "MESSAGE"), "stream-a-partial-finished"));
        {
                /* Both really are this same process -- confirm the kernel
                 * actually did report the identical PID for both, which is
                 * the whole point: the isolation held despite that, not
                 * because of some accidental difference. */
                const LogdReadField *pid0 = logd_entry_field(logd_ring_entry(ring, 0), "_PID");
                const LogdReadField *pid1 = logd_entry_field(logd_ring_entry(ring, 1), "_PID");

                ASSERT_TRUE(pid0 != NULL && pid1 != NULL);
                ASSERT_TRUE(pid0->value_len == pid1->value_len &&
                            memcmp(pid0->value, pid1->value, pid0->value_len) == 0);
        }
        logd_ring_free(ring);

        logd_writer_free(w);
        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: two real streams sharing one real kernel-reported PID never cross-contaminate "
               "fragment tails (the corrected per-stream keying, end to end with real sockets)\n");
}

static bool setup_fake_cgroup(char *orig_cgroup_out, size_t orig_sz) {
        FILE *f;

        orig_cgroup_out[0] = '\0';
        f = fopen("/proc/self/cgroup", "re");
        if (f) {
                char line[512];

                if (fgets(line, sizeof(line), f) && strncmp(line, "0::", 3) == 0) {
                        char *nl = strchr(line, '\n');

                        if (nl)
                                *nl = '\0';
                        snprintf(orig_cgroup_out, orig_sz, "/sys/fs/cgroup%s", line + 3);
                }
                fclose(f);
        }

        if (mkdir("/sys/fs/cgroup/system.slice", 0755) < 0 && errno != EEXIST)
                return false;
        if (mkdir("/sys/fs/cgroup/system.slice/test-logd-recv-fake.service", 0755) < 0 && errno != EEXIST)
                return false;
        if (mkdir("/sys/fs/cgroup/system.slice/test-logd-recv-fake.service/init.scope", 0755) < 0 &&
            errno != EEXIST)
                return false;

        {
                FILE *pf = fopen(
                                "/sys/fs/cgroup/system.slice/test-logd-recv-fake.service/init.scope/cgroup.procs",
                                "we");
                bool ok;

                if (!pf)
                        return false;
                ok = fprintf(pf, "%d", (int) getpid()) > 0;
                if (fclose(pf) != 0)
                        ok = false;
                return ok;
        }
}

static void restore_and_cleanup_cgroup(const char *orig_cgroup) {
        if (orig_cgroup[0]) {
                char procs_path[600];
                FILE *pf;

                snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", orig_cgroup);
                pf = fopen(procs_path, "we");
                if (pf) {
                        fprintf(pf, "%d", (int) getpid());
                        fclose(pf);
                }
        }

        (void) rmdir("/sys/fs/cgroup/system.slice/test-logd-recv-fake.service/init.scope");
        (void) rmdir("/sys/fs/cgroup/system.slice/test-logd-recv-fake.service");
        /* system.slice itself is never removed -- it likely predates this
         * test and other things may use it. */
}

/*
 * Real cgroup-v2 attribution (plan §3.3, corrected 2026-08-24): a process
 * under /system.slice/test-logd-recv-fake.service/init.scope must
 * attribute to the FIRST non-slice component (the service), not the
 * trailing .scope. This moves the whole test process into a real,
 * freshly-created cgroup for the duration of one check and restores it
 * before returning -- skipped cleanly (not failed) if this environment's
 * cgroupfs is not writable, since that is a real, legitimate possibility
 * under some container/sandbox configurations rather than a bug.
 */
static void test_cgroup_unit_extraction_real_kernel(void) {
        char orig_cgroup[512];

        if (!setup_fake_cgroup(orig_cgroup, sizeof(orig_cgroup))) {
                printf("test-logd-recv: skipping real-cgroup unit-extraction check (cgroupfs not writable here)\n");
                restore_and_cleanup_cgroup(orig_cgroup);
                return;
        }

        {
                char *dir = test_tmpdir_new();
                LogdWriter *w = new_test_writer(dir);
                LogdRecv *rc;
                struct sockaddr_un peer;
                socklen_t peer_len = make_synthetic_peer(&peer, "cgroup");
                struct ucred cred = { .pid = getpid(), .uid = getuid(), .gid = getgid() };
                LogdRing *ring;

                ASSERT_TRUE(dir != NULL);
                ASSERT_EQ_INT(logd_recv_new(w, &rc), 0);

                ASSERT_EQ_INT(logd_recv_process_stdout(rc, "hello\n", strlen("hello\n"), &peer, peer_len, &cred),
                              0);

                logd_recv_free(rc);
                logd_writer_free(w);

                ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
                ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 1);
                ASSERT_TRUE(logd_field_equals(
                                logd_entry_field(logd_ring_entry(ring, 0), "_SYSTEMD_UNIT"),
                                "test-logd-recv-fake.service"));
                logd_ring_free(ring);

                test_rm_rf(dir);
                free(dir);
        }

        restore_and_cleanup_cgroup(orig_cgroup);
        printf("test-logd-recv: real cgroup-v2 attribution picks the FIRST non-slice component (the service), "
               "not the trailing .scope\n");
}

static void test_syslog_basic(void) {
        char *dir = test_tmpdir_new();
        LogdWriter *w = new_test_writer(dir);
        LogdRecv *rc;
        static const char payload[] = "<11>myident[555]: hello world";
        struct ucred cred = { .pid = 777, .uid = 0, .gid = 0 };
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_recv_new(w, &rc), 0);

        ASSERT_EQ_INT(logd_recv_process_syslog(rc, payload, strlen(payload), &cred), 0);

        logd_recv_free(rc);
        logd_writer_free(w);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 1);
        {
                const LogdEntry *e = logd_ring_entry(ring, 0);

                ASSERT_TRUE(logd_field_equals(logd_entry_field(e, "PRIORITY"), "3")); /* 11 & 7 */
                ASSERT_TRUE(logd_field_equals(logd_entry_field(e, "SYSLOG_IDENTIFIER"), "myident"));
                ASSERT_TRUE(logd_field_equals(logd_entry_field(e, "MESSAGE"), "hello world"));
                ASSERT_TRUE(logd_field_equals(logd_entry_field(e, "_TRANSPORT"), "syslog"));
                /* The kernel-verified ucred pid, never the client-supplied
                 * "[555]" bracket in the message text (logd-recv.h). */
                ASSERT_TRUE(logd_field_equals(logd_entry_field(e, "_PID"), "777"));
        }
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: <N>identifier[pid]: parsing is correct, and _PID always comes from the "
               "kernel-verified ucred, never the spoofable bracket text\n");
}

/* A real syslog(3)/openlog()/closelog() call against a bound test socket
 * (the J1 done-when's own wording). Binds the receiving socket at the
 * real /dev/log path for the duration of this one check, since glibc's
 * syslog(3) has no override for that path -- skipped cleanly if /dev/log
 * already exists (a real syslog daemon's socket must never be disturbed)
 * or cannot be bound here. */
static void test_syslog_real_client(void) {
        struct stat st;
        int recv_fd, r;
        LogdWriter *w;
        LogdRecv *rc;
        char *dir = test_tmpdir_new();
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);

        if (stat("/dev/log", &st) == 0) {
                printf("test-logd-recv: skipping real syslog(3) client test (/dev/log already exists here)\n");
                test_rm_rf(dir);
                free(dir);
                return;
        }

        r = logd_recv_bind_socket("/dev/log", 0666, &recv_fd);
        if (r < 0) {
                printf("test-logd-recv: skipping real syslog(3) client test (cannot bind /dev/log: %s)\n",
                       strerror(-r));
                test_rm_rf(dir);
                free(dir);
                return;
        }

        w = new_test_writer(dir);
        ASSERT_EQ_INT(logd_recv_new(w, &rc), 0);

        openlog("logdtestident", 0, LOG_USER);
        syslog(LOG_WARNING, "hello from a real syslog(3) call");
        closelog();

        usleep(20000); /* let the datagram actually land before draining */
        ASSERT_EQ_INT(logd_recv_drain_syslog(rc, recv_fd), 1);

        logd_recv_free(rc);
        logd_writer_free(w);
        close(recv_fd);
        unlink("/dev/log");

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 1);
        {
                const LogdReadField *prio = logd_entry_field(logd_ring_entry(ring, 0), "PRIORITY");
                const LogdReadField *msg = logd_entry_field(logd_ring_entry(ring, 0), "MESSAGE");
                char buf[512];
                size_t n;

                ASSERT_TRUE(logd_field_equals(prio, "4")); /* LOG_WARNING */
                ASSERT_TRUE(msg != NULL);
                n = msg->value_len < sizeof(buf) - 1 ? msg->value_len : sizeof(buf) - 1;
                memcpy(buf, msg->value, n);
                buf[n] = '\0';
                ASSERT_TRUE(strstr(buf, "hello from a real syslog(3) call") != NULL);
        }
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: a real syslog(3) client's datagram against a bound /dev/log is received and "
               "parsed correctly\n");
}

static void test_shutdown_flushes_pending_tail(void) {
        char *dir = test_tmpdir_new();
        LogdWriter *w = new_test_writer(dir);
        LogdRecv *rc;
        struct sockaddr_un peer;
        socklen_t peer_len = make_synthetic_peer(&peer, "shutdown");
        struct ucred cred = { .pid = 999, .uid = 0, .gid = 0 };
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(logd_recv_new(w, &rc), 0);

        ASSERT_EQ_INT(logd_recv_process_stdout(
                                      rc, "never-terminated", strlen("never-terminated"), &peer, peer_len, &cred),
                      0);

        logd_recv_free(rc); /* must flush the pending tail, not silently drop it */
        logd_writer_free(w);

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), 1);
        ASSERT_TRUE(logd_field_equals(
                        logd_entry_field(logd_ring_entry(ring, 0), "MESSAGE"), "never-terminated"));
        ASSERT_TRUE(logd_field_equals(logd_entry_field(logd_ring_entry(ring, 0), "_LINE_BREAK"), "eof"));
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: logd_recv_free() flushes every stream's pending tail rather than losing it\n");
}

static void test_bind_socket_sets_passcred(void) {
        char *dir = test_tmpdir_new();
        char sock_path[512];
        int fd, val = 0;
        socklen_t vlen = sizeof(val);

        ASSERT_TRUE(dir != NULL);
        snprintf(sock_path, sizeof(sock_path), "%s/test.sock", dir);

        ASSERT_EQ_INT(logd_recv_bind_socket(sock_path, 0600, &fd), 0);
        ASSERT_TRUE(getsockopt(fd, SOL_SOCKET, SO_PASSCRED, &val, &vlen) == 0);
        ASSERT_TRUE(val != 0);

        close(fd);
        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: logd_recv_bind_socket() sets SO_PASSCRED before bind()\n");
}

/*
 * The real /dev/kmsg backfill mechanism (plan §3.2, milestone J2): a
 * fresh open() starts at the ring's beginning, not "now", so draining it
 * immediately captures the whole kernel ring already accumulated before
 * logd's kmsg reader ever existed -- exercised here against the real,
 * running kernel's actual ring, not a fixture (no dedicated test-logd-
 * kmsg is registered in meson.build, so this lives alongside J1's other
 * real-kernel-backed checks). Skipped cleanly, not failed, if this
 * environment has no /dev/kmsg or no permission to read it.
 */
static void test_kmsg_backfill_and_transport(void) {
        LogdKmsg *k;
        LogdWriter *w;
        char *dir = test_tmpdir_new();
        int r, n;
        LogdRing *ring;

        ASSERT_TRUE(dir != NULL);

        r = logd_kmsg_new(&k);
        if (r < 0) {
                printf("test-logd-recv: skipping /dev/kmsg backfill check (unavailable here: %s)\n",
                       strerror(-r));
                test_rm_rf(dir);
                free(dir);
                return;
        }

        w = new_test_writer(dir);
        n = logd_kmsg_drain(k, w);
        logd_kmsg_free(k);
        logd_writer_free(w);

        ASSERT_TRUE(n > 0); /* a real kernel always has something in its ring by the time this runs */

        ASSERT_EQ_INT(logd_ring_read(dir, &ring), 0);
        ASSERT_EQ_INT((int) logd_ring_n_entries(ring), n);
        {
                size_t i;

                for (i = 0; i < logd_ring_n_entries(ring); i++) {
                        const LogdEntry *e = logd_ring_entry(ring, i);
                        const LogdReadField *transport = logd_entry_field(e, "_TRANSPORT");
                        const LogdReadField *prio = logd_entry_field(e, "PRIORITY");
                        const LogdReadField *msg = logd_entry_field(e, "MESSAGE");

                        ASSERT_TRUE(logd_field_equals(transport, "kernel"));
                        ASSERT_TRUE(prio != NULL && !prio->binary && prio->value_len == 1);
                        ASSERT_TRUE(((const char *) prio->value)[0] >= '0' &&
                                    ((const char *) prio->value)[0] <= '7');
                        ASSERT_TRUE(msg != NULL);
                }
        }
        logd_ring_free(ring);

        test_rm_rf(dir);
        free(dir);
        printf("test-logd-recv: /dev/kmsg backfill against the real running kernel produced %d correctly "
               "framed _TRANSPORT=kernel records\n",
               n);
}

int main(void) {
        test_stdout_multiline();
        test_stdout_partial_then_continuation();
        test_stdout_oversized_split();
        test_stdout_embedded_nul();
        test_stdout_no_credentials();
        test_stdout_anonymous_peer();
        test_pid_change_on_stream();
        test_real_sockets_two_streams_same_pid();
        test_cgroup_unit_extraction_real_kernel();
        test_syslog_basic();
        test_syslog_real_client();
        test_shutdown_flushes_pending_tail();
        test_bind_socket_sets_passcred();
        test_kmsg_backfill_and_transport();

        printf("test-logd-recv: all cases passed\n");
        return 0;
}
