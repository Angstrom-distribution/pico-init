/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The sd-varlink.h entry points that need no Varlink engine. No sd_varlink
 * or sd_varlink_server can ever exist (sd-varlink-stubs.c: every constructor
 * fails), so NULL is the only handle a program can hold, and these return
 * what upstream returns for it: -EINVAL where upstream asserts a handle, NULL
 * for the pointer-returning accessors, a no-op for the void ones, 0 for a
 * server's connection count. Any other pointer was not made by this library
 * and is refused the same way.
 *
 * The functions that do not depend on a handle are implemented:
 * sd_varlink_error_to_errno() and sd_varlink_error_is_invalid_parameter()
 * for the NULL parameters object, sd_varlink_invocation(), and the default
 * connection limits.
 */

#ifndef _GNU_SOURCE
#        define _GNU_SOURCE /* secure_getenv() */
#endif

#include "sd-varlink.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-daemon.h"

int sd_varlink_get_fd(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_get_input_fd(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_get_output_fd(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_get_events(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_get_timeout(sd_varlink *v, uint64_t *ret) {
        (void) v;
        (void) ret;
        return -EINVAL;
}

int sd_varlink_attach_event(sd_varlink *v, sd_event *e, int64_t priority) {
        (void) v;
        (void) e;
        (void) priority;
        return -EINVAL;
}

int sd_varlink_process(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_wait(sd_varlink *v, uint64_t timeout) {
        (void) v;
        (void) timeout;
        return -EINVAL;
}

int sd_varlink_is_idle(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_is_connected(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_flush(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_close(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_send(sd_varlink *v, const char *method, sd_json_variant *parameters) {
        (void) v;
        (void) method;
        (void) parameters;
        return -EINVAL;
}

int sd_varlink_sendb(sd_varlink *v, const char *method, ...) {
        (void) v;
        (void) method;
        return -EINVAL;
}

int sd_varlink_call_full(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                sd_varlink_reply_flags_t *ret_flags) {
        (void) v;
        (void) method;
        (void) parameters;
        (void) ret_parameters;
        (void) ret_error_id;
        (void) ret_flags;
        return -EINVAL;
}

int sd_varlink_call(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id) {
        (void) v;
        (void) method;
        (void) parameters;
        (void) ret_parameters;
        (void) ret_error_id;
        return -EINVAL;
}

int sd_varlink_callb_ap(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                sd_varlink_reply_flags_t *ret_flags,
                va_list ap) {
        (void) v;
        (void) method;
        (void) ret_parameters;
        (void) ret_error_id;
        (void) ret_flags;
        (void) ap;
        return -EINVAL;
}

int sd_varlink_callb_full(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                sd_varlink_reply_flags_t *ret_flags,
                ...) {
        (void) v;
        (void) method;
        (void) ret_parameters;
        (void) ret_error_id;
        (void) ret_flags;
        return -EINVAL;
}

int sd_varlink_callb(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                ...) {
        (void) v;
        (void) method;
        (void) ret_parameters;
        (void) ret_error_id;
        return -EINVAL;
}

int sd_varlink_call_and_upgrade(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                int *ret_input_fd,
                int *ret_output_fd) {
        (void) v;
        (void) method;
        (void) parameters;
        (void) ret_parameters;
        (void) ret_error_id;
        (void) ret_input_fd;
        (void) ret_output_fd;
        return -EINVAL;
}

int sd_varlink_call_and_upgradeb(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                int *ret_input_fd,
                int *ret_output_fd,
                ...) {
        (void) v;
        (void) method;
        (void) ret_parameters;
        (void) ret_error_id;
        (void) ret_input_fd;
        (void) ret_output_fd;
        return -EINVAL;
}

int sd_varlink_collect_full(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                sd_varlink_reply_flags_t *ret_flags) {
        (void) v;
        (void) method;
        (void) parameters;
        (void) ret_parameters;
        (void) ret_error_id;
        (void) ret_flags;
        return -EINVAL;
}

int sd_varlink_collect(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id) {
        (void) v;
        (void) method;
        (void) parameters;
        (void) ret_parameters;
        (void) ret_error_id;
        return -EINVAL;
}

int sd_varlink_collectb(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                ...) {
        (void) v;
        (void) method;
        (void) ret_parameters;
        (void) ret_error_id;
        return -EINVAL;
}

int sd_varlink_invoke(sd_varlink *v, const char *method, sd_json_variant *parameters) {
        (void) v;
        (void) method;
        (void) parameters;
        return -EINVAL;
}

int sd_varlink_invokeb(sd_varlink *v, const char *method, ...) {
        (void) v;
        (void) method;
        return -EINVAL;
}

int sd_varlink_observe(sd_varlink *v, const char *method, sd_json_variant *parameters) {
        (void) v;
        (void) method;
        (void) parameters;
        return -EINVAL;
}

int sd_varlink_observeb(sd_varlink *v, const char *method, ...) {
        (void) v;
        (void) method;
        return -EINVAL;
}

int sd_varlink_reply(sd_varlink *v, sd_json_variant *parameters) {
        (void) v;
        (void) parameters;
        return -EINVAL;
}

int sd_varlink_replyb(sd_varlink *v, ...) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_reply_and_upgrade(
                sd_varlink *v, sd_json_variant *parameters, int *ret_input_fd, int *ret_output_fd) {
        (void) v;
        (void) parameters;
        (void) ret_input_fd;
        (void) ret_output_fd;
        return -EINVAL;
}

int sd_varlink_respond_and_upgrade(sd_varlink *v, sd_json_variant *parameters) {
        (void) v;
        (void) parameters;
        return -EINVAL;
}

int sd_varlink_respond_and_upgradeb(sd_varlink *v, ...) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_error(sd_varlink *v, const char *error_id, sd_json_variant *parameters) {
        (void) v;
        (void) error_id;
        (void) parameters;
        return -EINVAL;
}

int sd_varlink_errorb(sd_varlink *v, const char *error_id, ...) {
        (void) v;
        (void) error_id;
        return -EINVAL;
}

int sd_varlink_error_invalid_parameter(sd_varlink *v, sd_json_variant *parameters) {
        (void) v;
        (void) parameters;
        return -EINVAL;
}

int sd_varlink_error_invalid_parameter_name(sd_varlink *v, const char *name) {
        (void) v;
        (void) name;
        return -EINVAL;
}

int sd_varlink_error_errno(sd_varlink *v, int error) {
        (void) v;
        (void) error;
        return -EINVAL;
}

int sd_varlink_notify(sd_varlink *v, sd_json_variant *parameters) {
        (void) v;
        (void) parameters;
        return -EINVAL;
}

int sd_varlink_notifyb(sd_varlink *v, ...) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_dispatch_again(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_get_current_method(sd_varlink *v, const char **ret) {
        (void) v;
        (void) ret;
        return -EINVAL;
}

int sd_varlink_get_current_parameters(sd_varlink *v, sd_json_variant **ret) {
        (void) v;
        (void) ret;
        return -EINVAL;
}

int sd_varlink_dispatch(
                sd_varlink *v,
                sd_json_variant *parameters,
                const sd_json_dispatch_field dispatch_table[],
                void *userdata) {
        (void) v;
        (void) parameters;
        (void) dispatch_table;
        (void) userdata;
        return -EINVAL;
}

int sd_varlink_push_fd(sd_varlink *v, int fd) {
        (void) v;
        (void) fd;
        return -EINVAL;
}

int sd_varlink_push_dup_fd(sd_varlink *v, int fd) {
        (void) v;
        (void) fd;
        return -EINVAL;
}

int sd_varlink_reset_fds(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_peek_fd(sd_varlink *v, size_t i) {
        (void) v;
        (void) i;
        return -EINVAL;
}

int sd_varlink_peek_dup_fd(sd_varlink *v, size_t i) {
        (void) v;
        (void) i;
        return -EINVAL;
}

int sd_varlink_take_fd(sd_varlink *v, size_t i) {
        (void) v;
        (void) i;
        return -EINVAL;
}

int sd_varlink_get_n_fds(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_set_allow_fd_passing_input(sd_varlink *v, int b) {
        (void) v;
        (void) b;
        return -EINVAL;
}

int sd_varlink_set_allow_fd_passing_output(sd_varlink *v, int b) {
        (void) v;
        (void) b;
        return -EINVAL;
}

int sd_varlink_bind_reply(sd_varlink *v, sd_varlink_reply_t reply) {
        (void) v;
        (void) reply;
        return -EINVAL;
}

int sd_varlink_bind_upgrade(sd_varlink *v, sd_varlink_upgrade_t upgrade) {
        (void) v;
        (void) upgrade;
        return -EINVAL;
}

int sd_varlink_set_sentinel(sd_varlink *v, const char *error_id) {
        (void) v;
        (void) error_id;
        return -EINVAL;
}

int sd_varlink_get_peer_uid(sd_varlink *v, uid_t *ret) {
        (void) v;
        (void) ret;
        return -EINVAL;
}

int sd_varlink_get_peer_gid(sd_varlink *v, gid_t *ret) {
        (void) v;
        (void) ret;
        return -EINVAL;
}

int sd_varlink_get_peer_pid(sd_varlink *v, pid_t *ret) {
        (void) v;
        (void) ret;
        return -EINVAL;
}

int sd_varlink_get_peer_pidfd(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_set_relative_timeout(sd_varlink *v, uint64_t timeout) {
        (void) v;
        (void) timeout;
        return -EINVAL;
}

int sd_varlink_set_description(sd_varlink *v, const char *d) {
        (void) v;
        (void) d;
        return -EINVAL;
}

int sd_varlink_set_input_sensitive(sd_varlink *v) {
        (void) v;
        return -EINVAL;
}

int sd_varlink_server_set_info(
                sd_varlink_server *s,
                const char *vendor,
                const char *product,
                const char *version,
                const char *url) {
        (void) s;
        (void) vendor;
        (void) product;
        (void) version;
        (void) url;
        return -EINVAL;
}

int sd_varlink_server_listen_address(sd_varlink_server *s, const char *address, mode_t mode) {
        (void) s;
        (void) address;
        (void) mode;
        return -EINVAL;
}

int sd_varlink_server_listen_fd(sd_varlink_server *s, int fd) {
        (void) s;
        (void) fd;
        return -EINVAL;
}

int sd_varlink_server_listen_auto(sd_varlink_server *s) {
        (void) s;
        return -EINVAL;
}

int sd_varlink_server_listen_name(sd_varlink_server *s, const char *name) {
        (void) s;
        (void) name;
        return -EINVAL;
}

int sd_varlink_server_add_connection(sd_varlink_server *s, int fd, sd_varlink **ret) {
        (void) s;
        (void) fd;
        (void) ret;
        return -EINVAL;
}

int sd_varlink_server_add_connection_pair(
                sd_varlink_server *s,
                int input_fd,
                int output_fd,
                const struct ucred *override_ucred,
                sd_varlink **ret) {
        (void) s;
        (void) input_fd;
        (void) output_fd;
        (void) override_ucred;
        (void) ret;
        return -EINVAL;
}

int sd_varlink_server_add_connection_stdio(sd_varlink_server *s, sd_varlink **ret) {
        (void) s;
        (void) ret;
        return -EINVAL;
}

int sd_varlink_server_bind_method(sd_varlink_server *s, const char *method, sd_varlink_method_t callback) {
        (void) s;
        (void) method;
        (void) callback;
        return -EINVAL;
}

int sd_varlink_server_bind_method_many_internal(sd_varlink_server *s, ...) {
        (void) s;
        return -EINVAL;
}

int sd_varlink_server_bind_connect(sd_varlink_server *s, sd_varlink_connect_t connect) {
        (void) s;
        (void) connect;
        return -EINVAL;
}

int sd_varlink_server_bind_disconnect(sd_varlink_server *s, sd_varlink_disconnect_t disconnect) {
        (void) s;
        (void) disconnect;
        return -EINVAL;
}

int sd_varlink_server_add_interface(sd_varlink_server *s, const sd_varlink_interface *interface) {
        (void) s;
        (void) interface;
        return -EINVAL;
}

int sd_varlink_server_add_interface_many_internal(sd_varlink_server *s, ...) {
        (void) s;
        return -EINVAL;
}

int sd_varlink_server_attach_event(sd_varlink_server *s, sd_event *e, int64_t priority) {
        (void) s;
        (void) e;
        (void) priority;
        return -EINVAL;
}

int sd_varlink_server_detach_event(sd_varlink_server *s) {
        (void) s;
        return -EINVAL;
}

int sd_varlink_server_loop_auto(sd_varlink_server *s) {
        (void) s;
        return -EINVAL;
}

int sd_varlink_server_shutdown(sd_varlink_server *s) {
        (void) s;
        return -EINVAL;
}

int sd_varlink_server_set_exit_on_idle(sd_varlink_server *s, int b) {
        (void) s;
        (void) b;
        return -EINVAL;
}

int sd_varlink_server_set_connections_per_uid_max(sd_varlink_server *s, unsigned m) {
        (void) s;
        (void) m;
        return -EINVAL;
}

int sd_varlink_server_set_connections_max(sd_varlink_server *s, unsigned m) {
        (void) s;
        (void) m;
        return -EINVAL;
}

int sd_varlink_server_set_description(sd_varlink_server *s, const char *description) {
        (void) s;
        (void) description;
        return -EINVAL;
}

sd_varlink *sd_varlink_ref(sd_varlink *v) {
        (void) v;
        return NULL;
}

sd_varlink *sd_varlink_unref(sd_varlink *v) {
        (void) v;
        return NULL;
}

sd_varlink_server *sd_varlink_server_ref(sd_varlink_server *s) {
        (void) s;
        return NULL;
}

sd_varlink_server *sd_varlink_server_unref(sd_varlink_server *s) {
        (void) s;
        return NULL;
}

sd_varlink *sd_varlink_close_unref(sd_varlink *v) {
        (void) v;
        return NULL;
}

sd_varlink *sd_varlink_flush_close_unref(sd_varlink *v) {
        (void) v;
        return NULL;
}

void sd_varlink_detach_event(sd_varlink *v) {
        (void) v;
}

sd_event *sd_varlink_get_event(sd_varlink *v) {
        (void) v;
        return NULL;
}

void *sd_varlink_set_userdata(sd_varlink *v, void *userdata) {
        (void) v;
        (void) userdata;
        return NULL;
}

void *sd_varlink_get_userdata(sd_varlink *v) {
        (void) v;
        return NULL;
}

sd_varlink_server *sd_varlink_get_server(sd_varlink *v) {
        (void) v;
        return NULL;
}

const char *sd_varlink_get_description(sd_varlink *v) {
        (void) v;
        return NULL;
}

void *sd_varlink_server_set_userdata(sd_varlink_server *s, void *userdata) {
        (void) s;
        (void) userdata;
        return NULL;
}

void *sd_varlink_server_get_userdata(sd_varlink_server *s) {
        (void) s;
        return NULL;
}

sd_event *sd_varlink_server_get_event(sd_varlink_server *s) {
        (void) s;
        return NULL;
}

unsigned sd_varlink_server_current_connections(sd_varlink_server *s) {
        (void) s;
        return 0;
}

/* A NULL server answers with the defaults: at most 4096 connections and
 * never more than three quarters of the descriptor table, and 128 per UID
 * unless that is above three quarters of the total. */
unsigned sd_varlink_server_connections_max(sd_varlink_server *s) {
        int dts = getdtablesize();
        unsigned limit = dts > 0 ? (unsigned) dts / 4 * 3 : 0;

        (void) s;
        return limit < 4096U ? limit : 4096U;
}

unsigned sd_varlink_server_connections_per_uid_max(sd_varlink_server *s) {
        unsigned m = sd_varlink_server_connections_max(NULL);

        (void) s;
        return m < 128U ? m / 4 * 3 : 128U;
}

/* Returns whether this is a pure Varlink server invocation: exactly one
 * descriptor, named "varlink", of the kind the flags allow. */
int sd_varlink_invocation(sd_varlink_invocation_flags_t flags) {
        char **names = NULL;
        bool ok = false;
        int r, b;
        socklen_t l = sizeof(b);

        if (secure_getenv("SYSTEMD_VARLINK_LISTEN"))
                return true;

        r = sd_listen_fds_with_names(/* unset_environment= */ 0, &names);
        if (r == 1)
                ok = names && names[0] && strcmp(names[0], "varlink") == 0 && !names[1];

        for (char **n = names; n && *n; n++)
                free(*n);
        free(names);

        if (r < 0)
                return r;
        if (r == 0)
                return false;
        if (r > 1)
                return -ETOOMANYREFS;
        if (!ok)
                return false;

        if ((flags & (SD_VARLINK_ALLOW_LISTEN | SD_VARLINK_ALLOW_ACCEPT)) ==
            (SD_VARLINK_ALLOW_LISTEN | SD_VARLINK_ALLOW_ACCEPT))
                return true;
        if ((flags & (SD_VARLINK_ALLOW_LISTEN | SD_VARLINK_ALLOW_ACCEPT)) == 0)
                return -EISCONN;

        if (getsockopt(SD_LISTEN_FDS_START, SOL_SOCKET, SO_ACCEPTCONN, &b, &l) < 0)
                return -errno;

        if (!(flags & (b ? SD_VARLINK_ALLOW_LISTEN : SD_VARLINK_ALLOW_ACCEPT)))
                return -EISCONN;

        return true;
}

/* The parameters object, which carries the errno of io.systemd.System, can
 * only be NULL here, so that error is always -EBADR. */
int sd_varlink_error_to_errno(const char *error, sd_json_variant *parameters) {
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

        (void) parameters;

        if (!error)
                return 0;

        for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++)
                if (strcmp(error, table[i].error) == 0)
                        return table[i].value;

        return -EBADR;
}

/* A parameter name can only be matched against a parameters object. */
int sd_varlink_error_is_invalid_parameter(const char *error, sd_json_variant *parameter, const char *name) {
        (void) parameter;

        if (!error || strcmp(error, SD_VARLINK_ERROR_INVALID_PARAMETER) != 0)
                return false;

        return !name;
}
