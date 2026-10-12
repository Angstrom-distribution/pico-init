/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-init's declaration of the sd-varlink.h ABI surface, matching
 * systemd's src/systemd/sd-varlink.h in names, signatures, enum values and
 * macros. There is no Varlink engine in this build, so no sd_varlink or
 * sd_varlink_server object can ever exist; see sd-varlink-stubs.c and
 * sd-varlink-noop.c.
 */

#pragma once

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "_sd-common.h"
#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink-idl.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_varlink sd_varlink;
typedef struct sd_varlink_server sd_varlink_server;

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_varlink_reply_flags_t) {
        SD_VARLINK_REPLY_ERROR = 1 << 0,
        SD_VARLINK_REPLY_CONTINUES = 1 << 1,
        SD_VARLINK_REPLY_LOCAL = 1 << 2,
        _SD_ENUM_FORCE_S64(SD_VARLINK_REPLY)
} sd_varlink_reply_flags_t;

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_varlink_method_flags_t) {
        SD_VARLINK_METHOD_ONEWAY = 1 << 0,
        SD_VARLINK_METHOD_MORE = 1 << 1,
        SD_VARLINK_METHOD_UPGRADE = 1 << 2,
        _SD_ENUM_FORCE_S64(SD_VARLINK_METHOD)
} sd_varlink_method_flags_t;

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_varlink_server_flags_t) {
        SD_VARLINK_SERVER_ROOT_ONLY = 1 << 0,
        SD_VARLINK_SERVER_MYSELF_ONLY = 1 << 1,
        SD_VARLINK_SERVER_ACCOUNT_UID = 1 << 2,
        SD_VARLINK_SERVER_INHERIT_USERDATA = 1 << 3,
        SD_VARLINK_SERVER_INPUT_SENSITIVE = 1 << 4,
        SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT = 1 << 5,
        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT = 1 << 6,
        SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT = 1 << 7,
        SD_VARLINK_SERVER_HANDLE_SIGINT = 1 << 8,
        SD_VARLINK_SERVER_HANDLE_SIGTERM = 1 << 9,
        SD_VARLINK_SERVER_UPGRADABLE = 1 << 10,
        _SD_ENUM_FORCE_S64(SD_VARLINK_SERVER)
} sd_varlink_server_flags_t;

__extension__ typedef enum _SD_ENUM_TYPE_S64(sd_varlink_invocation_flags_t) {
        SD_VARLINK_ALLOW_LISTEN = 1 << 0,
        SD_VARLINK_ALLOW_ACCEPT = 1 << 1,
        _SD_ENUM_FORCE_S64(SD_VARLINK_INVOCATION)
} sd_varlink_invocation_flags_t;

typedef int (*sd_varlink_method_t)(
                sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
typedef int (*sd_varlink_reply_t)(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata);
typedef int (*sd_varlink_upgrade_t)(sd_varlink *link, int input_fd, int output_fd, void *userdata);
typedef int (*sd_varlink_connect_t)(sd_varlink_server *server, sd_varlink *link, void *userdata);
typedef void (*sd_varlink_disconnect_t)(sd_varlink_server *server, sd_varlink *link, void *userdata);

struct ucred;

int sd_varlink_connect_address(sd_varlink **ret, const char *address);
int sd_varlink_connect_exec(sd_varlink **ret, const char *command, char **argv);
int sd_varlink_connect_url(sd_varlink **ret, const char *url);
int sd_varlink_connect_fd(sd_varlink **ret, int fd);
int sd_varlink_connect_fd_pair(sd_varlink **ret, int input_fd, int output_fd, const struct ucred *override_ucred);

sd_varlink *sd_varlink_ref(sd_varlink *v);
sd_varlink *sd_varlink_unref(sd_varlink *v);

int sd_varlink_get_fd(sd_varlink *v);
int sd_varlink_get_input_fd(sd_varlink *v);
int sd_varlink_get_output_fd(sd_varlink *v);
int sd_varlink_get_events(sd_varlink *v);
int sd_varlink_get_timeout(sd_varlink *v, uint64_t *ret);

int sd_varlink_attach_event(sd_varlink *v, sd_event *e, int64_t priority);
void sd_varlink_detach_event(sd_varlink *v);
sd_event *sd_varlink_get_event(sd_varlink *v);

int sd_varlink_process(sd_varlink *v);
int sd_varlink_wait(sd_varlink *v, uint64_t timeout);

int sd_varlink_is_idle(sd_varlink *v);
int sd_varlink_is_connected(sd_varlink *v);

int sd_varlink_flush(sd_varlink *v);
int sd_varlink_close(sd_varlink *v);

sd_varlink *sd_varlink_flush_close_unref(sd_varlink *v);
sd_varlink *sd_varlink_close_unref(sd_varlink *v);

/* Enqueue a method call without expecting a reply. */
int sd_varlink_send(sd_varlink *v, const char *method, sd_json_variant *parameters);
int sd_varlink_sendb(sd_varlink *v, const char *method, ...);
#define sd_varlink_sendbo(v, method, ...) sd_varlink_sendb((v), (method), SD_JSON_BUILD_OBJECT(__VA_ARGS__))

/* Send a method call and wait for the reply. */
int sd_varlink_call_full(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                sd_varlink_reply_flags_t *ret_flags);
int sd_varlink_call(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id);

int sd_varlink_callb_ap(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                sd_varlink_reply_flags_t *ret_flags,
                va_list ap);
int sd_varlink_callb_full(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                sd_varlink_reply_flags_t *ret_flags,
                ...);
#define sd_varlink_callbo_full(v, method, ret_parameters, ret_error_id, ret_flags, ...) \
        sd_varlink_callb_full(                                                          \
                        (v),                                                            \
                        (method),                                                       \
                        (ret_parameters),                                               \
                        (ret_error_id),                                                 \
                        (ret_flags),                                                    \
                        SD_JSON_BUILD_OBJECT(__VA_ARGS__))
int sd_varlink_callb(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                ...);
#define sd_varlink_callbo(v, method, ret_parameters, ret_error_id, ...) \
        sd_varlink_callb((v), (method), (ret_parameters), (ret_error_id), SD_JSON_BUILD_OBJECT(__VA_ARGS__))

/* Send a method call with the upgrade flag, wait for the reply and take over the connection's fds.
 * Returns > 0 if the connection was upgraded, 0 if the server replied with an error (set in
 * ret_error_id) and < 0 on a local failure. */
int sd_varlink_call_and_upgrade(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                int *ret_input_fd,
                int *ret_output_fd);
int sd_varlink_call_and_upgradeb(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                int *ret_input_fd,
                int *ret_output_fd,
                ...);
#define sd_varlink_call_and_upgradebo(                                                     \
                v, method, ret_parameters, ret_error_id, ret_input_fd, ret_output_fd, ...) \
        sd_varlink_call_and_upgradeb(                                                      \
                        (v),                                                               \
                        (method),                                                          \
                        (ret_parameters),                                                  \
                        (ret_error_id),                                                    \
                        (ret_input_fd),                                                    \
                        (ret_output_fd),                                                   \
                        SD_JSON_BUILD_OBJECT(__VA_ARGS__))

/* Send a method call with the "more" flag and collect every reply into an array. */
int sd_varlink_collect_full(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                sd_varlink_reply_flags_t *ret_flags);
int sd_varlink_collect(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id);
int sd_varlink_collectb(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                ...);
#define sd_varlink_collectbo(v, method, ret_parameters, ret_error_id, ...) \
        sd_varlink_collectb(                                               \
                        (v), (method), (ret_parameters), (ret_error_id), SD_JSON_BUILD_OBJECT(__VA_ARGS__))

/* Enqueue a method call and deliver the reply to the reply callback. */
int sd_varlink_invoke(sd_varlink *v, const char *method, sd_json_variant *parameters);
int sd_varlink_invokeb(sd_varlink *v, const char *method, ...);
#define sd_varlink_invokebo(v, method, ...) \
        sd_varlink_invokeb((v), (method), SD_JSON_BUILD_OBJECT(__VA_ARGS__))

/* Enqueue a method call and deliver this and all later replies to the reply callback. */
int sd_varlink_observe(sd_varlink *v, const char *method, sd_json_variant *parameters);
int sd_varlink_observeb(sd_varlink *v, const char *method, ...);
#define sd_varlink_observebo(v, method, ...) \
        sd_varlink_observeb((v), (method), SD_JSON_BUILD_OBJECT(__VA_ARGS__))

/* Enqueue a final reply. */
int sd_varlink_reply(sd_varlink *v, sd_json_variant *parameters);
int sd_varlink_replyb(sd_varlink *v, ...);
#define sd_varlink_replybo(v, ...) sd_varlink_replyb((v), SD_JSON_BUILD_OBJECT(__VA_ARGS__))

/* Send the final reply to an upgrade request, flush it and hand the connection's fds to the caller. Either
 * ret pointer may be NULL, not both. Blocks until the reply is written. */
int sd_varlink_reply_and_upgrade(
                sd_varlink *v, sd_json_variant *parameters, int *ret_input_fd, int *ret_output_fd);

/* The asynchronous form of the above. */
int sd_varlink_respond_and_upgrade(sd_varlink *v, sd_json_variant *parameters);
int sd_varlink_respond_and_upgradeb(sd_varlink *v, ...);
#define sd_varlink_respond_and_upgradebo(v, ...) \
        sd_varlink_respond_and_upgradeb((v), SD_JSON_BUILD_OBJECT(__VA_ARGS__))

/* Enqueue a final error. */
int sd_varlink_error(sd_varlink *v, const char *error_id, sd_json_variant *parameters);
int sd_varlink_errorb(sd_varlink *v, const char *error_id, ...);
#define sd_varlink_errorbo(v, error_id, ...) \
        sd_varlink_errorb((v), (error_id), SD_JSON_BUILD_OBJECT(__VA_ARGS__))
int sd_varlink_error_invalid_parameter(sd_varlink *v, sd_json_variant *parameters);
int sd_varlink_error_invalid_parameter_name(sd_varlink *v, const char *name);
int sd_varlink_error_errno(sd_varlink *v, int error);

/* Enqueue a "more" reply. */
int sd_varlink_notify(sd_varlink *v, sd_json_variant *parameters);
int sd_varlink_notifyb(sd_varlink *v, ...);
#define sd_varlink_notifybo(v, ...) sd_varlink_notifyb((v), SD_JSON_BUILD_OBJECT(__VA_ARGS__))

/* Ask for the current message to be dispatched again. */
int sd_varlink_dispatch_again(sd_varlink *v);

/* The message being processed. */
int sd_varlink_get_current_method(sd_varlink *v, const char **ret);
int sd_varlink_get_current_parameters(sd_varlink *v, sd_json_variant **ret);

/* sd_json_dispatch_full() on the parameters, answering a bad field with an InvalidParameter error. */
int sd_varlink_dispatch(
                sd_varlink *v,
                sd_json_variant *parameters,
                const sd_json_dispatch_field dispatch_table[],
                void *userdata);

/* Fds to send along with the next message. */
int sd_varlink_push_fd(sd_varlink *v, int fd);
int sd_varlink_push_dup_fd(sd_varlink *v, int fd);
int sd_varlink_reset_fds(sd_varlink *v);

/* Fds received along with the current message. */
int sd_varlink_peek_fd(sd_varlink *v, size_t i);
int sd_varlink_peek_dup_fd(sd_varlink *v, size_t i);
int sd_varlink_take_fd(sd_varlink *v, size_t i);
int sd_varlink_get_n_fds(sd_varlink *v);

int sd_varlink_set_allow_fd_passing_input(sd_varlink *v, int b);
int sd_varlink_set_allow_fd_passing_output(sd_varlink *v, int b);

int sd_varlink_bind_reply(sd_varlink *v, sd_varlink_reply_t reply);
int sd_varlink_bind_upgrade(sd_varlink *v, sd_varlink_upgrade_t upgrade);

void *sd_varlink_set_userdata(sd_varlink *v, void *userdata);
void *sd_varlink_get_userdata(sd_varlink *v);

/* The error to reply with if the method callback sends no reply; NULL for an empty final reply. */
int sd_varlink_set_sentinel(sd_varlink *v, const char *error_id);

int sd_varlink_get_peer_uid(sd_varlink *v, uid_t *ret);
int sd_varlink_get_peer_gid(sd_varlink *v, gid_t *ret);
int sd_varlink_get_peer_pid(sd_varlink *v, pid_t *ret);
int sd_varlink_get_peer_pidfd(sd_varlink *v);

int sd_varlink_set_relative_timeout(sd_varlink *v, uint64_t timeout);

sd_varlink_server *sd_varlink_get_server(sd_varlink *v);

int sd_varlink_set_description(sd_varlink *v, const char *d);
const char *sd_varlink_get_description(sd_varlink *v);

int sd_varlink_set_input_sensitive(sd_varlink *v);

int sd_varlink_server_new(sd_varlink_server **ret, sd_varlink_server_flags_t flags);
sd_varlink_server *sd_varlink_server_ref(sd_varlink_server *s);
sd_varlink_server *sd_varlink_server_unref(sd_varlink_server *s);

int sd_varlink_server_set_info(
                sd_varlink_server *s,
                const char *vendor,
                const char *product,
                const char *version,
                const char *url);

/* OR into the mode of sd_varlink_server_listen_address() to create the leading directories with mode 0755. */
#define SD_VARLINK_SERVER_MODE_MKDIR_0755 ((mode_t) 1 << 30)

int sd_varlink_server_listen_address(sd_varlink_server *s, const char *address, mode_t mode);
int sd_varlink_server_listen_fd(sd_varlink_server *s, int fd);
int sd_varlink_server_listen_auto(sd_varlink_server *s);
int sd_varlink_server_listen_name(sd_varlink_server *s, const char *name);
int sd_varlink_server_add_connection(sd_varlink_server *s, int fd, sd_varlink **ret);
int sd_varlink_server_add_connection_pair(
                sd_varlink_server *s,
                int input_fd,
                int output_fd,
                const struct ucred *override_ucred,
                sd_varlink **ret);
int sd_varlink_server_add_connection_stdio(sd_varlink_server *s, sd_varlink **ret);

int sd_varlink_server_bind_method(sd_varlink_server *s, const char *method, sd_varlink_method_t callback);
int sd_varlink_server_bind_method_many_internal(sd_varlink_server *s, ...);
#define sd_varlink_server_bind_method_many(s, ...) \
        sd_varlink_server_bind_method_many_internal(s, __VA_ARGS__, NULL)
int sd_varlink_server_bind_connect(sd_varlink_server *s, sd_varlink_connect_t connect);
int sd_varlink_server_bind_disconnect(sd_varlink_server *s, sd_varlink_disconnect_t disconnect);

int sd_varlink_server_add_interface(sd_varlink_server *s, const sd_varlink_interface *interface);
int sd_varlink_server_add_interface_many_internal(sd_varlink_server *s, ...);
#define sd_varlink_server_add_interface_many(s, ...) \
        sd_varlink_server_add_interface_many_internal(s, __VA_ARGS__, NULL)

void *sd_varlink_server_set_userdata(sd_varlink_server *s, void *userdata);
void *sd_varlink_server_get_userdata(sd_varlink_server *s);

int sd_varlink_server_attach_event(sd_varlink_server *s, sd_event *e, int64_t priority);
int sd_varlink_server_detach_event(sd_varlink_server *s);
sd_event *sd_varlink_server_get_event(sd_varlink_server *s);

int sd_varlink_server_loop_auto(sd_varlink_server *server);

int sd_varlink_server_shutdown(sd_varlink_server *server);

int sd_varlink_server_set_exit_on_idle(sd_varlink_server *s, int b);

unsigned sd_varlink_server_connections_max(sd_varlink_server *s);
unsigned sd_varlink_server_connections_per_uid_max(sd_varlink_server *s);

int sd_varlink_server_set_connections_per_uid_max(sd_varlink_server *s, unsigned m);
int sd_varlink_server_set_connections_max(sd_varlink_server *s, unsigned m);

unsigned sd_varlink_server_current_connections(sd_varlink_server *s);

int sd_varlink_server_set_description(sd_varlink_server *s, const char *description);

int sd_varlink_invocation(sd_varlink_invocation_flags_t flags);

int sd_varlink_error_to_errno(const char *error, sd_json_variant *parameters);

int sd_varlink_error_is_invalid_parameter(const char *error, sd_json_variant *parameter, const char *name);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_varlink, sd_varlink_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_varlink, sd_varlink_close_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_varlink, sd_varlink_flush_close_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_varlink_server, sd_varlink_server_unref);

/* Local errors that never cross the wire. */
#define SD_VARLINK_ERROR_DISCONNECTED "io.systemd.Disconnected"
#define SD_VARLINK_ERROR_TIMEOUT "io.systemd.TimedOut"
#define SD_VARLINK_ERROR_PROTOCOL "io.systemd.Protocol"

/* Carries an errno to the client. */
#define SD_VARLINK_ERROR_SYSTEM "io.systemd.System"

/* A weaker PermissionDenied: interactive authentication might allow the call. */
#define SD_VARLINK_ERROR_INTERACTIVE_AUTHENTICATION_REQUIRED "io.systemd.InteractiveAuthenticationRequired"

/* Defined by the Varlink specification. */
#define SD_VARLINK_ERROR_INTERFACE_NOT_FOUND "org.varlink.service.InterfaceNotFound"
#define SD_VARLINK_ERROR_METHOD_NOT_FOUND "org.varlink.service.MethodNotFound"
#define SD_VARLINK_ERROR_METHOD_NOT_IMPLEMENTED "org.varlink.service.MethodNotImplemented"
#define SD_VARLINK_ERROR_INVALID_PARAMETER "org.varlink.service.InvalidParameter"
#define SD_VARLINK_ERROR_PERMISSION_DENIED "org.varlink.service.PermissionDenied"
#define SD_VARLINK_ERROR_EXPECTED_MORE "org.varlink.service.ExpectedMore"
#define SD_VARLINK_ERROR_EXPECTED_UPGRADE "org.varlink.service.ExpectedUpgrade"

_SD_END_DECLARATIONS;
