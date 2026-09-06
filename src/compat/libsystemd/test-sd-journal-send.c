/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The write side, against a real receiving socket wherever one is needed --
 * never a mocked transport. Two real sockets stand in for logd's own:
 *
 *   - a SOCK_DGRAM bound at the literal path "/dev/log" for the syslog
 *     transport sd_journal_sendv() always addresses; this doubles as the
 *     compliance oracle for the ENOENT-is-silent-success case, which is
 *     tested FIRST, before that socket exists.
 *   - a SOCK_DGRAM bound at "/run/logd/stdout" for sd_journal_stream_fd(),
 *     matching LOGD_STDOUT_SOCKET_PATH exactly (that path is not
 *     overridable, unlike logd's own runtime dir -- see logd.h).
 *
 * Both need real filesystem paths outside this test's own tmpdir, so the
 * whole file skips (exit 77) rather than fails when not running as root
 * (the pico-init-build container always is; a stray local run may not be).
 */

/* program_invocation_short_name is a glibc/GNU extension; -std=gnu17 alone
 * does not imply _GNU_SOURCE (socket.c's own note, same reasoning here). */
#define _GNU_SOURCE

/* Exercise the plain sd_journal_print()/send()/sendv()/perror() symbols
 * themselves in most of this file -- test_with_location_variants() below
 * calls the four *_with_location() functions directly instead, so both the
 * macro-suppressed and macro-redirected paths get real coverage. */
#define SD_JOURNAL_SUPPRESS_LOCATION

#include "sd-journal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "../../test-util.h"

static int bind_dgram(const char *path) {
        int fd;
        struct sockaddr_un addr = { .sun_family = AF_UNIX };

        unlink(path); /* a stale socket from a prior interrupted run, never anything else */

        fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        ASSERT_TRUE(fd >= 0);

        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
        if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                fprintf(stderr, "test-sd-journal-send: bind(%s) failed: %s\n", path, strerror(errno));
                exit(1);
        }

        return fd;
}

/* Non-blocking recv with a short real wait: the datagram is sent by a
 * plain sendto() on a connectionless socket, so it is either already
 * queued or never coming -- a brief poll is only to absorb scheduling
 * jitter between the sender and this recv, not a real timeout budget. */
static ssize_t recv_one(int fd, char *buf, size_t bufsize, struct sockaddr_un *peer, socklen_t *peer_len) {
        for (int tries = 0; tries < 200; tries++) {
                ssize_t n = recvfrom(fd, buf, bufsize - 1, MSG_DONTWAIT, (struct sockaddr *) peer, peer_len);

                if (n >= 0) {
                        buf[n] = '\0';
                        return n;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                        return -1;
                usleep(1000);
        }
        return -2; /* nothing arrived */
}

static bool nothing_arrived(int fd) {
        char buf[256];
        ssize_t n = recv_one(fd, buf, sizeof(buf), NULL, NULL);

        return n == -2;
}

/* --- /dev/log absent: the documented silent-success case --- */

static void test_enoent_is_silent_success(void) {
        struct stat st;

        /* Only meaningful if nothing is already listening there -- true in
         * this project's own build container, checked rather than assumed.
         * A leftover SOCK_DGRAM socket file from an earlier run of this
         * same binary that exited before reaching its own unlink("/dev/log")
         * at the bottom of main() (an assertion failure part-way through,
         * say) is cleaned up here rather than treated as a real listener --
         * anything else there is left alone and the case is skipped. */
        if (stat("/dev/log", &st) == 0) {
                if (S_ISSOCK(st.st_mode))
                        unlink("/dev/log");
                else {
                        fprintf(stderr,
                                "test-sd-journal-send: /dev/log already exists, skipping ENOENT case\n");
                        return;
                }
        }
        if (stat("/dev/log", &st) == 0) {
                fprintf(stderr, "test-sd-journal-send: /dev/log reappeared, skipping ENOENT case\n");
                return;
        }

        ASSERT_EQ_INT(sd_journal_print(LOG_INFO, "nobody is listening"), 0);
        ASSERT_EQ_INT(sd_journal_send("MESSAGE=%s", "still nobody", NULL), 0);
}

/* --- real /dev/log round trip --- */

static int g_devlog_fd = -1;

static void test_print_and_priority_and_identifier(void) {
        char buf[512];
        char expect[600];

        ASSERT_EQ_INT(sd_journal_print(LOG_WARNING, "hello %d", 42), 0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);

        /* <PRI> = facility(1, default LOG_USER) << 3 | severity(4, WARNING) = 12. */
        snprintf(expect, sizeof(expect), "<12>%s: hello 42", program_invocation_short_name);
        ASSERT_STREQ(buf, expect);
}

static void test_printv_strips_trailing_whitespace_and_suppresses_empty(void) {
        char buf[512];

        ASSERT_EQ_INT(sd_journal_print(LOG_INFO, "trimmed   \t\n"), 0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);
        ASSERT_TRUE(strstr(buf, "trimmed") != NULL);
        ASSERT_TRUE(strstr(buf, "trimmed   ") == NULL); /* trailing whitespace really gone */

        /* An all-whitespace message must not be sent at all. */
        ASSERT_EQ_INT(sd_journal_print(LOG_INFO, "   \n\t "), 0);
        ASSERT_TRUE(nothing_arrived(g_devlog_fd));
}

static void test_printv_grows_past_stack_buffer(void) {
        char big[9000];
        char buf[9200];
        char expect[9200];

        memset(big, 'x', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';

        ASSERT_EQ_INT(sd_journal_print(LOG_INFO, "%s", big), 0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);

        snprintf(expect, sizeof(expect), "<%d>%s: %s", (1 << 3) | 6, program_invocation_short_name, big);
        ASSERT_STREQ(buf, expect);
}

/* Exercises advance_va() on a field whose OWN format uses a precision
 * float, a length-modified integer and a string all in one conversion
 * list, immediately followed by a second real field -- if advance_va()
 * mis-consumed the first field's args, the second field's format string
 * argument would be read from the wrong slot and this would either send
 * the wrong message or crash interpreting a double/long as a pointer. */
static void test_send_variadic_scanning(void) {
        char buf[512];
        char expect[600];

        ASSERT_EQ_INT(sd_journal_send("X=%5.2f %ld %s", 3.14, (long) 100, "str", "MESSAGE=%s", "confirmed", NULL),
                      0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);
        /* No PRIORITY field this time: no <PRI> prefix. No SYSLOG_IDENTIFIER
         * field either: falls back to program_invocation_short_name. */
        snprintf(expect, sizeof(expect), "%s: confirmed", program_invocation_short_name);
        ASSERT_STREQ(buf, expect);
}

static void test_send_message_and_priority_fields(void) {
        char buf[512];
        char expect[600];

        ASSERT_EQ_INT(sd_journal_send("MESSAGE=%s and %d", "hi", 5, "PRIORITY=%i", 6, NULL), 0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);

        snprintf(expect, sizeof(expect), "<%d>%s: hi and 5", (1 << 3) | 6, program_invocation_short_name);
        ASSERT_STREQ(buf, expect);
}

static void test_sendv_field_syntax_validation(void) {
        struct iovec bad;

        ASSERT_EQ_INT(sd_journal_sendv(NULL, 1), -EINVAL);
        ASSERT_EQ_INT(sd_journal_sendv(
                                      ((const struct iovec[]){
                                                      { "x", 1 }
        }),
                                      0),
                      -EINVAL);

        bad.iov_base = (void *) "noequalssign";
        bad.iov_len = strlen("noequalssign");
        ASSERT_EQ_INT(sd_journal_sendv(&bad, 1), -EINVAL);

        bad.iov_base = (void *) "=leadingeq";
        bad.iov_len = strlen("=leadingeq");
        ASSERT_EQ_INT(sd_journal_sendv(&bad, 1), -EINVAL);

        bad.iov_base = (void *) "BAD\nNAME=x";
        bad.iov_len = strlen("BAD\nNAME=x");
        ASSERT_EQ_INT(sd_journal_sendv(&bad, 1), -EINVAL);

        bad.iov_base = (void *) "x";
        bad.iov_len = 1; /* iov_len must be > 1 */
        ASSERT_EQ_INT(sd_journal_sendv(&bad, 1), -EINVAL);
}

static void test_syslog_identifier_rules(void) {
        char buf[512];
        char expect[600];
        struct iovec iov[2];

        /* Valid identifier: used verbatim. */
        iov[0] = (struct iovec){ (void *) "MESSAGE=hi", strlen("MESSAGE=hi") };
        iov[1] = (struct iovec){ (void *) "SYSLOG_IDENTIFIER=myapp", strlen("SYSLOG_IDENTIFIER=myapp") };
        ASSERT_EQ_INT(sd_journal_sendv(iov, 2), 0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);
        ASSERT_STREQ(buf, "myapp: hi");

        /* Invalid identifier (embedded space): dropped, no fallback --
         * message is sent bare, not under program_invocation_short_name. */
        iov[1] = (struct iovec){ (void *) "SYSLOG_IDENTIFIER=has space",
                                 strlen("SYSLOG_IDENTIFIER=has space") };
        ASSERT_EQ_INT(sd_journal_sendv(iov, 2), 0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);
        ASSERT_STREQ(buf, "hi");

        /* No SYSLOG_IDENTIFIER field at all: falls back to argv[0]'s basename. */
        ASSERT_EQ_INT(sd_journal_sendv(iov, 1), 0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);
        snprintf(expect, sizeof(expect), "%s: hi", program_invocation_short_name);
        ASSERT_STREQ(buf, expect);
}

static void test_message_embedded_nul_becomes_space(void) {
        char msgbuf[] = "MESSAGE=one\0two";
        struct iovec iov = { msgbuf,
                             sizeof(msgbuf) - 1 }; /* include the embedded NUL, exclude the final one */
        char buf[512];
        char expect[600];

        ASSERT_EQ_INT(sd_journal_sendv(&iov, 1), 0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);
        /* No SYSLOG_IDENTIFIER field: falls back to program_invocation_short_name. */
        snprintf(expect, sizeof(expect), "%s: one two", program_invocation_short_name);
        ASSERT_STREQ(buf, expect); /* NUL replaced with a space, never truncated */
}

static void test_perror(void) {
        char buf[512];
        char expect[600];

        errno = ENOENT;
        ASSERT_EQ_INT(sd_journal_perror("opening config"), 0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);

        /* <PRI> = facility(1, default LOG_USER) << 3 | severity(3, LOG_ERR) = 11. */
        snprintf(expect,
                 sizeof(expect),
                 "<11>%s: opening config: %s",
                 program_invocation_short_name,
                 strerror(ENOENT));
        ASSERT_STREQ(buf, expect);
}

/* Calls the four *_with_location() symbols directly (this file suppresses
 * the header's macro redirection above, so a plain sd_journal_print() etc.
 * exercises the undecorated function -- this is the only place the
 * with_location entry points themselves get called). CODE_FILE=/CODE_LINE=/
 * CODE_FUNC= must be accepted and then simply not appear in the
 * transmitted text -- sendv drops them, same as any other untransportable
 * field. */
static void test_with_location_variants(void) {
        char buf[512];
        struct iovec iov = { (void *) "MESSAGE=direct sendv", strlen("MESSAGE=direct sendv") };

        ASSERT_EQ_INT(sd_journal_print_with_location(LOG_INFO, "CODE_FILE=x.c", "CODE_LINE=1", "func", "hi"),
                      0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);
        ASSERT_TRUE(strstr(buf, "hi") != NULL);
        ASSERT_TRUE(strstr(buf, "CODE_FILE") == NULL);

        ASSERT_EQ_INT(sd_journal_send_with_location(
                                      "CODE_FILE=x.c", "CODE_LINE=1", "func", "MESSAGE=%s", "loc-send", NULL),
                      0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);
        ASSERT_TRUE(strstr(buf, "loc-send") != NULL);

        ASSERT_EQ_INT(sd_journal_sendv_with_location("CODE_FILE=x.c", "CODE_LINE=1", "func", &iov, 1), 0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);
        {
                char expect[600];

                snprintf(expect, sizeof(expect), "%s: direct sendv", program_invocation_short_name);
                ASSERT_STREQ(buf, expect);
        }

        errno = ENOENT;
        ASSERT_EQ_INT(sd_journal_perror_with_location("CODE_FILE=x.c", "CODE_LINE=1", "func", "loc-perror"),
                      0);
        ASSERT_TRUE(recv_one(g_devlog_fd, buf, sizeof(buf), NULL, NULL) > 0);
        ASSERT_TRUE(strstr(buf, "loc-perror") != NULL);
        ASSERT_TRUE(strstr(buf, "CODE_FUNC") == NULL);
}

/* --- sd_journal_stream_fd() --- */

static void test_stream_fd(void) {
        int server_fd, stream_fd;
        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        char buf[512];
        struct sockaddr_un peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t n;

        if (mkdir("/run/logd", 0755) < 0)
                ASSERT_TRUE(errno == EEXIST);

        unlink("/run/logd/stdout");
        server_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        ASSERT_TRUE(server_fd >= 0);
        strncpy(addr.sun_path, "/run/logd/stdout", sizeof(addr.sun_path) - 1);
        ASSERT_EQ_INT(bind(server_fd, (struct sockaddr *) &addr, sizeof(addr)), 0);

        ASSERT_EQ_INT(sd_journal_stream_fd(NULL, -1, 0), -EINVAL); /* priority out of range */

        stream_fd = sd_journal_stream_fd("ignored-identifier", LOG_INFO, 0);
        ASSERT_TRUE(stream_fd >= 0);

        ASSERT_TRUE(write(stream_fd, "a line\n", 7) == 7);

        n = recvfrom(server_fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *) &peer, &peer_len);
        ASSERT_TRUE(n > 0);
        buf[n] = '\0';
        ASSERT_STREQ(buf, "a line\n");

        /* The bound source address is abstract (leading NUL) and carries
         * this process's own pid, per sd-journal-stream.c's own design. */
        ASSERT_TRUE(peer_len > (socklen_t) sizeof(sa_family_t));
        ASSERT_EQ_INT(peer.sun_path[0], '\0');
        ASSERT_TRUE(strstr(peer.sun_path + 1, "picoinit-jstream-") == peer.sun_path + 1);

        /* shutdown(SHUT_RD) really happened: reading from our own end must
         * never return real data (EOF or an error, depending on how the
         * kernel represents a read-shut datagram socket). */
        {
                char tmp[8];
                ssize_t rr = read(stream_fd, tmp, sizeof(tmp));

                ASSERT_TRUE(rr <= 0);
        }

        close(stream_fd);
        close(server_fd);
        unlink("/run/logd/stdout");

        ASSERT_EQ_INT(sd_journal_stream_fd_with_namespace("ns", "id", LOG_INFO, 0), -EOPNOTSUPP);
}

int main(void) {
        if (geteuid() != 0) {
                printf("test-sd-journal-send: not running as root, cannot bind /dev/log or "
                       "/run/logd/stdout -- SKIPPED\n");
                return 77;
        }

        test_enoent_is_silent_success();

        g_devlog_fd = bind_dgram("/dev/log");

        test_print_and_priority_and_identifier();
        test_printv_strips_trailing_whitespace_and_suppresses_empty();
        test_printv_grows_past_stack_buffer();
        test_send_variadic_scanning();
        test_send_message_and_priority_fields();
        test_sendv_field_syntax_validation();
        test_syslog_identifier_rules();
        test_message_embedded_nul_becomes_space();
        test_perror();
        test_with_location_variants();

        close(g_devlog_fd);
        unlink("/dev/log");

        test_stream_fd();

        printf("test-sd-journal-send: all cases passed\n");
        return 0;
}
