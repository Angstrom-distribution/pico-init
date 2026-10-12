/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Calls every sd_varlink_*() function. No sd_varlink or sd_varlink_server
 * can exist, so the answers are upstream's for a NULL handle (-EINVAL, NULL,
 * a no-op or zero), -EINVAL or -EBADF for a bad argument and -EOPNOTSUPP
 * wherever a Varlink engine would be needed. The handle-free helpers are
 * checked against their real behavior.
 */

#define _GNU_SOURCE /* the SD_VARLINK_DEFINE_* macros need __VA_OPT__ */

#include "sd-varlink.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../test-util.h"

#define FAKE_LINK ((sd_varlink *) 0x1)
#define FAKE_SERVER ((sd_varlink_server *) 0x1)

/* The definers initialize a flexible array member, a GNU extension. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
static SD_VARLINK_DEFINE_METHOD(
                Ping,
                SD_VARLINK_DEFINE_INPUT(text, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(text, SD_VARLINK_STRING, 0));
static SD_VARLINK_DEFINE_ERROR(Broken, SD_VARLINK_DEFINE_FIELD(why, SD_VARLINK_STRING, 0));
static SD_VARLINK_DEFINE_INTERFACE(test, "org.example.test", &vl_method_Ping, &vl_error_Broken);
#pragma GCC diagnostic pop

static int
                call_ap(sd_varlink *v,
                        const char *method,
                        sd_json_variant **ret,
                        const char **error_id,
                        sd_varlink_reply_flags_t *flags,
                        ...) {
        va_list ap;
        int r;

        va_start(ap, flags);
        r = sd_varlink_callb_ap(v, method, ret, error_id, flags, ap);
        va_end(ap);
        return r;
}

static void check_connect(void) {
        sd_varlink *v = FAKE_LINK;

        ASSERT_EQ_INT(sd_varlink_connect_address(NULL, "/run/x"), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_address(&v, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_address(&v, "/run/x"), -EOPNOTSUPP);

        ASSERT_EQ_INT(sd_varlink_connect_exec(NULL, "/bin/true", NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_exec(&v, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_exec(&v, "/bin/true", NULL), -EOPNOTSUPP);

        ASSERT_EQ_INT(sd_varlink_connect_fd(NULL, 3), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_fd(&v, -1), -EBADF);
        ASSERT_EQ_INT(sd_varlink_connect_fd(&v, 3), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_varlink_connect_fd_pair(NULL, 3, 4, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_fd_pair(&v, -1, 4, NULL), -EBADF);
        ASSERT_EQ_INT(sd_varlink_connect_fd_pair(&v, 3, -1, NULL), -EBADF);
        ASSERT_EQ_INT(sd_varlink_connect_fd_pair(&v, 3, 4, NULL), -EOPNOTSUPP);

        ASSERT_EQ_INT(sd_varlink_connect_url(NULL, "unix:/run/x"), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "unix:/run/x"), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "unix:@abstract"), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "exec:/usr/bin/x"), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "ssh:host:/run/x"), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "ssh-exec:host:/bin/x"), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "unix:relative"), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "unix:"), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "exec:@x"), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "unix:/run/../x"), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "unix:/run/./x"), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "unix:/run//x/"), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "unix:/run/x;y"), -EPROTONOSUPPORT);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "unix:/run/x?y"), -EPROTONOSUPPORT);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "ssh:host#x"), -EPROTONOSUPPORT);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "no-colon"), -EPROTONOSUPPORT);
        ASSERT_EQ_INT(sd_varlink_connect_url(&v, "bridge:thing"), -EPROTONOSUPPORT);

        ASSERT_TRUE(v == FAKE_LINK); /* untouched on failure */
}

static void check_server_new(void) {
        sd_varlink_server *s = FAKE_SERVER;

        ASSERT_EQ_INT(sd_varlink_server_new(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_new(&s, (sd_varlink_server_flags_t) (1 << 11)), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_new(
                                      &s,
                                      (sd_varlink_server_flags_t) (SD_VARLINK_SERVER_ROOT_ONLY | (1 << 20))),
                      -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_new(&s, 0), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_varlink_server_new(&s, SD_VARLINK_SERVER_UPGRADABLE | SD_VARLINK_SERVER_ROOT_ONLY),
                      -EOPNOTSUPP);
        ASSERT_TRUE(s == FAKE_SERVER);
}

static void check_null_link(void) {
        sd_varlink *v = NULL;
        uint64_t u;
        const char *c;
        sd_json_variant *j;
        sd_varlink_reply_flags_t rf;
        int in, out;
        uid_t uid;
        gid_t gid;
        pid_t pid;
        const sd_json_dispatch_field table[1] = { { .name = NULL } };

        ASSERT_TRUE(sd_varlink_ref(NULL) == NULL);
        ASSERT_TRUE(sd_varlink_unref(NULL) == NULL);
        ASSERT_TRUE(sd_varlink_close_unref(NULL) == NULL);
        ASSERT_TRUE(sd_varlink_flush_close_unref(NULL) == NULL);
        sd_varlink_detach_event(NULL);
        ASSERT_TRUE(sd_varlink_get_event(NULL) == NULL);
        ASSERT_TRUE(sd_varlink_get_server(NULL) == NULL);
        ASSERT_TRUE(sd_varlink_get_description(NULL) == NULL);
        ASSERT_TRUE(sd_varlink_set_userdata(NULL, &u) == NULL);
        ASSERT_TRUE(sd_varlink_get_userdata(NULL) == NULL);

        ASSERT_EQ_INT(sd_varlink_get_fd(v), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_get_input_fd(v), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_get_output_fd(v), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_get_events(v), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_get_timeout(v, &u), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_attach_event(v, NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_process(v), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_wait(v, 0), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_is_idle(v), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_is_connected(v), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_flush(v), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_close(v), -EINVAL);

        ASSERT_EQ_INT(sd_varlink_send(v, "m", NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_sendb(v, "m", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR_STRING("k", "v"))),
                      -EINVAL);
        ASSERT_EQ_INT(sd_varlink_sendbo(v, "m", SD_JSON_BUILD_PAIR_STRING("k", "v")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_call_full(v, "m", NULL, &j, &c, &rf), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_call(v, "m", NULL, &j, &c), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_callb(v, "m", &j, &c, SD_JSON_BUILD_STRING("x")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_callbo(v, "m", &j, &c, SD_JSON_BUILD_PAIR_STRING("k", "v")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_callb_full(v, "m", &j, &c, &rf, SD_JSON_BUILD_STRING("x")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_callbo_full(v, "m", &j, &c, &rf, SD_JSON_BUILD_PAIR_STRING("k", "v")),
                      -EINVAL);
        ASSERT_EQ_INT(call_ap(v, "m", &j, &c, &rf), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_call_and_upgrade(v, "m", NULL, &j, &c, &in, &out), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_call_and_upgradeb(v, "m", &j, &c, &in, &out, SD_JSON_BUILD_STRING("x")),
                      -EINVAL);
        ASSERT_EQ_INT(sd_varlink_call_and_upgradebo(
                                      v, "m", &j, &c, &in, &out, SD_JSON_BUILD_PAIR_STRING("k", "v")),
                      -EINVAL);
        ASSERT_EQ_INT(sd_varlink_collect_full(v, "m", NULL, &j, &c, &rf), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_collect(v, "m", NULL, &j, &c), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_collectb(v, "m", &j, &c, SD_JSON_BUILD_STRING("x")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_collectbo(v, "m", &j, &c, SD_JSON_BUILD_PAIR_STRING("k", "v")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_invoke(v, "m", NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_invokeb(v, "m", SD_JSON_BUILD_STRING("x")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_invokebo(v, "m", SD_JSON_BUILD_PAIR_STRING("k", "v")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_observe(v, "m", NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_observeb(v, "m", SD_JSON_BUILD_STRING("x")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_observebo(v, "m", SD_JSON_BUILD_PAIR_STRING("k", "v")), -EINVAL);

        ASSERT_EQ_INT(sd_varlink_reply(v, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_replyb(v, SD_JSON_BUILD_STRING("x")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_replybo(v, SD_JSON_BUILD_PAIR_STRING("k", "v")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_reply_and_upgrade(v, NULL, &in, &out), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_respond_and_upgrade(v, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_respond_and_upgradeb(v, SD_JSON_BUILD_STRING("x")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_respond_and_upgradebo(v, SD_JSON_BUILD_PAIR_STRING("k", "v")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_error(v, SD_VARLINK_ERROR_SYSTEM, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_errorb(v, SD_VARLINK_ERROR_SYSTEM, SD_JSON_BUILD_STRING("x")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_errorbo(v, SD_VARLINK_ERROR_SYSTEM, SD_JSON_BUILD_PAIR_STRING("k", "v")),
                      -EINVAL);
        ASSERT_EQ_INT(sd_varlink_error_invalid_parameter(v, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_error_invalid_parameter_name(v, "x"), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_error_errno(v, EPERM), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_notify(v, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_notifyb(v, SD_JSON_BUILD_STRING("x")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_notifybo(v, SD_JSON_BUILD_PAIR_STRING("k", "v")), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_dispatch_again(v), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_get_current_method(v, &c), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_get_current_parameters(v, &j), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_dispatch(v, NULL, table, NULL), -EINVAL);

        ASSERT_EQ_INT(sd_varlink_push_fd(v, 3), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_push_dup_fd(v, 3), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_reset_fds(v), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_peek_fd(v, 0), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_peek_dup_fd(v, 0), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_take_fd(v, 0), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_get_n_fds(v), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_set_allow_fd_passing_input(v, 1), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_set_allow_fd_passing_output(v, 1), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_bind_reply(v, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_bind_upgrade(v, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_set_sentinel(v, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_get_peer_uid(v, &uid), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_get_peer_gid(v, &gid), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_get_peer_pid(v, &pid), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_get_peer_pidfd(v), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_set_relative_timeout(v, 0), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_set_description(v, "x"), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_set_input_sensitive(v), -EINVAL);

        /* A pointer this library did not hand out is refused the same way. */
        ASSERT_EQ_INT(sd_varlink_close(FAKE_LINK), -EINVAL);
        ASSERT_TRUE(sd_varlink_unref(FAKE_LINK) == NULL);
}

static void check_null_server(void) {
        sd_varlink_server *s = NULL;
        sd_varlink *l;

        ASSERT_TRUE(sd_varlink_server_ref(NULL) == NULL);
        ASSERT_TRUE(sd_varlink_server_unref(NULL) == NULL);
        ASSERT_TRUE(sd_varlink_server_set_userdata(NULL, &l) == NULL);
        ASSERT_TRUE(sd_varlink_server_get_userdata(NULL) == NULL);
        ASSERT_TRUE(sd_varlink_server_get_event(NULL) == NULL);
        ASSERT_EQ_INT(sd_varlink_server_current_connections(NULL), 0);

        ASSERT_EQ_INT(sd_varlink_server_set_info(s, "v", "p", "1", "u"), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_listen_address(s, "/run/x", 0755), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_listen_address(s, "/run/x", SD_VARLINK_SERVER_MODE_MKDIR_0755 | 0755),
                      -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_listen_fd(s, 3), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_listen_auto(s), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_listen_name(s, "varlink"), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_add_connection(s, 3, &l), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_add_connection_pair(s, 3, 4, NULL, &l), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_add_connection_stdio(s, &l), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_bind_method(s, "m", NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_bind_method_many(s, "m", (sd_varlink_method_t) NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_bind_connect(s, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_bind_disconnect(s, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_add_interface(s, &vl_interface_test), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_add_interface_many(s, &vl_interface_test), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_attach_event(s, NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_detach_event(s), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_loop_auto(s), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_shutdown(s), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_set_exit_on_idle(s, 1), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_set_connections_per_uid_max(s, 1), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_set_connections_max(s, 1), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_server_set_description(s, "x"), -EINVAL);
}

static void check_limits(void) {
        unsigned max = sd_varlink_server_connections_max(NULL);
        unsigned per_uid = sd_varlink_server_connections_per_uid_max(NULL);

        ASSERT_TRUE(max > 0 && max <= 4096);
        ASSERT_TRUE(max <= (unsigned) getdtablesize() / 4 * 3);
        ASSERT_TRUE(per_uid > 0 && per_uid <= 128);
        ASSERT_TRUE(per_uid <= max);
}

static void listen_env(const char *fds, const char *names) {
        char pid[32];

        snprintf(pid, sizeof(pid), "%d", (int) getpid());
        setenv("LISTEN_PID", pid, 1);
        setenv("LISTEN_FDS", fds, 1);
        setenv("LISTEN_FDNAMES", names, 1);
}

static void check_invocation(void) {
        const sd_varlink_invocation_flags_t both = SD_VARLINK_ALLOW_LISTEN | SD_VARLINK_ALLOW_ACCEPT;
        int fds[2], high[2];

        unsetenv("SYSTEMD_VARLINK_LISTEN");
        unsetenv("LISTEN_PID");
        unsetenv("LISTEN_FDS");
        unsetenv("LISTEN_FDNAMES");
        ASSERT_EQ_INT(sd_varlink_invocation(both), 0);

        setenv("SYSTEMD_VARLINK_LISTEN", "/run/x", 1);
        ASSERT_EQ_INT(sd_varlink_invocation(0), 1);
        unsetenv("SYSTEMD_VARLINK_LISTEN");

        /* Descriptors 3 and 4: connected sockets, not listening. The pair is moved
         * out of the way first, as socketpair() may already have returned 3 and 4. */
        ASSERT_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
        high[0] = fcntl(fds[0], F_DUPFD, 10);
        high[1] = fcntl(fds[1], F_DUPFD, 10);
        ASSERT_TRUE(high[0] >= 10 && high[1] >= 10);
        close(fds[0]);
        close(fds[1]);
        ASSERT_EQ_INT(dup2(high[0], 3), 3);
        ASSERT_EQ_INT(dup2(high[1], 4), 4);
        close(high[0]);
        close(high[1]);

        listen_env("1", "varlink");
        ASSERT_EQ_INT(sd_varlink_invocation(both), 1);
        ASSERT_EQ_INT(sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT), 1);
        ASSERT_EQ_INT(sd_varlink_invocation(SD_VARLINK_ALLOW_LISTEN), -EISCONN);
        ASSERT_EQ_INT(sd_varlink_invocation(0), -EISCONN);

        listen_env("1", "other");
        ASSERT_EQ_INT(sd_varlink_invocation(both), 0);

        listen_env("2", "varlink:varlink");
        ASSERT_EQ_INT(sd_varlink_invocation(both), -ETOOMANYREFS);

        unsetenv("LISTEN_PID");
        unsetenv("LISTEN_FDS");
        unsetenv("LISTEN_FDNAMES");
}

static void check_errors(void) {
        static const struct {
                const char *error;
                int value;
        } table[] = {
                {           SD_VARLINK_ERROR_DISCONNECTED,    -ECONNRESET },
                {                SD_VARLINK_ERROR_TIMEOUT,     -ETIMEDOUT },
                {               SD_VARLINK_ERROR_PROTOCOL,        -EPROTO },
                {    SD_VARLINK_ERROR_INTERFACE_NOT_FOUND, -EADDRNOTAVAIL },
                {       SD_VARLINK_ERROR_METHOD_NOT_FOUND,         -ENXIO },
                { SD_VARLINK_ERROR_METHOD_NOT_IMPLEMENTED,        -ENOTTY },
                {      SD_VARLINK_ERROR_INVALID_PARAMETER,        -EINVAL },
                {      SD_VARLINK_ERROR_PERMISSION_DENIED,        -EACCES },
                {          SD_VARLINK_ERROR_EXPECTED_MORE,         -EBADE },
                {       SD_VARLINK_ERROR_EXPECTED_UPGRADE,    -EPROTOTYPE },
        };

        for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++)
                ASSERT_EQ_INT(sd_varlink_error_to_errno(table[i].error, NULL), table[i].value);

        ASSERT_EQ_INT(sd_varlink_error_to_errno(NULL, NULL), 0);
        ASSERT_EQ_INT(sd_varlink_error_to_errno(SD_VARLINK_ERROR_SYSTEM, NULL), -EBADR);
        ASSERT_EQ_INT(sd_varlink_error_to_errno(SD_VARLINK_ERROR_INTERACTIVE_AUTHENTICATION_REQUIRED, NULL),
                      -EBADR);
        ASSERT_EQ_INT(sd_varlink_error_to_errno("org.example.Unknown", NULL), -EBADR);

        ASSERT_EQ_INT(sd_varlink_error_is_invalid_parameter(SD_VARLINK_ERROR_INVALID_PARAMETER, NULL, NULL),
                      1);
        ASSERT_EQ_INT(sd_varlink_error_is_invalid_parameter(SD_VARLINK_ERROR_INVALID_PARAMETER, NULL, "x"), 0);
        ASSERT_EQ_INT(sd_varlink_error_is_invalid_parameter(SD_VARLINK_ERROR_SYSTEM, NULL, NULL), 0);
        ASSERT_EQ_INT(sd_varlink_error_is_invalid_parameter(NULL, NULL, NULL), 0);
}

static void check_idl(void) {
        char *s = (char *) 0x1;
        sd_varlink_interface *i = (sd_varlink_interface *) 0x1;
        unsigned line = 7, column = 7;

        ASSERT_STREQ(vl_interface_test.name, "org.example.test");
        ASSERT_TRUE(vl_interface_test.symbols[0] == &vl_method_Ping);
        ASSERT_TRUE(vl_interface_test.symbols[1] == &vl_error_Broken);
        ASSERT_TRUE(vl_interface_test.symbols[2] == NULL);
        ASSERT_EQ_INT(vl_method_Ping.symbol_type, SD_VARLINK_METHOD);
        ASSERT_EQ_INT(vl_method_Ping.fields[0].field_direction, SD_VARLINK_INPUT);
        ASSERT_EQ_INT(vl_method_Ping.fields[0].field_flags, SD_VARLINK_NULLABLE);
        ASSERT_EQ_INT(vl_method_Ping.fields[1].field_direction, SD_VARLINK_OUTPUT);
        ASSERT_EQ_INT(vl_method_Ping.fields[2].field_type, _SD_VARLINK_FIELD_TYPE_END_MARKER);

        ASSERT_EQ_INT(sd_varlink_idl_dump(NULL, NULL, 0, SIZE_MAX), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_idl_dump(NULL, &vl_interface_test, 0, SIZE_MAX), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_varlink_idl_format_full(NULL, 0, SIZE_MAX, &s), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_idl_format_full(&vl_interface_test, SD_VARLINK_IDL_FORMAT_COLOR, 80, &s),
                      -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_varlink_idl_format(NULL, &s), -EINVAL);
        ASSERT_EQ_INT(sd_varlink_idl_format(&vl_interface_test, &s), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_varlink_idl_parse("interface a.b\n", &line, &column, &i), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_varlink_idl_parse("interface a.b\n", NULL, NULL, NULL), -EOPNOTSUPP);
        ASSERT_TRUE(sd_varlink_interface_free(NULL) == NULL);

        ASSERT_TRUE(s == (char *) 0x1);
        ASSERT_TRUE(i == (sd_varlink_interface *) 0x1);
        ASSERT_EQ_INT(line, 7);
}

int main(void) {
        check_connect();
        check_server_new();
        check_null_link();
        check_null_server();
        check_limits();
        check_invocation();
        check_errors();
        check_idl();
        return 0;
}
