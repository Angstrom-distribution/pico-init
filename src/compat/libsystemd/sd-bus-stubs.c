/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The bulk of sd-bus.h: every entry point that needs a live sd_bus,
 * sd_bus_message, sd_bus_slot, sd_bus_track or sd_bus_creds object to do
 * anything. None of those objects can ever exist -- sd_bus_new() and every
 * sd_bus_open_*()/sd_bus_default*() variant (sd-bus-open.c) always fail --
 * so every function below has exactly one honest answer: -EINVAL, the
 * same errno upstream's own assert_return(ptr, -EINVAL) gives a NULL
 * handle, touching no output parameter and invoking no callback.
 *
 * Three sections, matching the design doc's own grouping by first-argument
 * type -- sd_bus*, sd_bus_message*, or one of sd_bus_slot* / sd_bus_track* /
 * sd_bus_creds* -- respectively; the reply_method_errno(0)/method_error variants keep
 * -EINVAL too -- upstream's own "r==0 means success" shortcut is
 * unreachable when the message argument cannot exist).
 *
 * Three functions the design doc lists in this bucket are deliberately
 * NOT here, because their real return type cannot hold -EINVAL at all --
 * a plain type mismatch in the doc's own grouping, caught two different
 * ways below. Each moves to sd-bus-noop.c instead, next to the sibling
 * accessor it actually matches:
 *  - sd_bus_get_event() returns sd_event* -- the compiler rejects
 *    `return -EINVAL;` outright. Joins sd_bus_get_current_message() and
 *    friends (already true_noop, NULL).
 *  - sd_bus_track_contains() returns const char* -- same rejection.
 *    Joins sd_bus_track_first()/next() (already true_noop, NULL).
 *  - sd_bus_track_count() returns plain unsigned -- -EINVAL compiles (it
 *    silently becomes a huge unsigned value) but is not a real error
 *    channel: nothing distinguishes it from a legitimate huge count. Joins
 *    sd_bus_creds_get_mask()/get_augmented_mask() (already true_noop, 0)
 *    as the true, honest count: zero, since no sd_bus_track can exist.
 *
 * Mechanically generated from the real header's own signatures (every
 * parameter (void)-cast, matching this family's "touch no output
 * parameters" contract by construction) and cross-checked against the
 * design doc's function-name lists before being hand-reviewed -- exactly
 * the kind of 250-function boilerplate transcription where a slipped name
 * would otherwise go unnoticed.
 */

#include "sd-bus.h"

#include <errno.h>

/* BUCKET B (bus-arg) */
int sd_bus_start(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_set_address(sd_bus *bus, const char *address) {
        (void) bus;
        (void) address;
        return -EINVAL;
}

int sd_bus_set_fd(sd_bus *bus, int input_fd, int output_fd) {
        (void) bus;
        (void) input_fd;
        (void) output_fd;
        return -EINVAL;
}

int sd_bus_set_exec(sd_bus *bus, const char *path, char * const *argv) {
        (void) bus;
        (void) path;
        (void) argv;
        return -EINVAL;
}

int sd_bus_get_address(sd_bus *bus, const char **ret) {
        (void) bus;
        (void) ret;
        return -EINVAL;
}

int sd_bus_set_bus_client(sd_bus *bus, int b) {
        (void) bus;
        (void) b;
        return -EINVAL;
}

int sd_bus_is_bus_client(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_set_server(sd_bus *bus, int b, sd_id128_t server_id) {
        (void) bus;
        (void) b;
        (void) server_id;
        return -EINVAL;
}

int sd_bus_is_server(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_set_anonymous(sd_bus *bus, int b) {
        (void) bus;
        (void) b;
        return -EINVAL;
}

int sd_bus_is_anonymous(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_set_trusted(sd_bus *bus, int b) {
        (void) bus;
        (void) b;
        return -EINVAL;
}

int sd_bus_is_trusted(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_set_monitor(sd_bus *bus, int b) {
        (void) bus;
        (void) b;
        return -EINVAL;
}

int sd_bus_is_monitor(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_set_description(sd_bus *bus, const char *description) {
        (void) bus;
        (void) description;
        return -EINVAL;
}

int sd_bus_get_description(sd_bus *bus, const char **ret) {
        (void) bus;
        (void) ret;
        return -EINVAL;
}

int sd_bus_negotiate_creds(sd_bus *bus, int b, uint64_t creds_mask) {
        (void) bus;
        (void) b;
        (void) creds_mask;
        return -EINVAL;
}

int sd_bus_negotiate_timestamp(sd_bus *bus, int b) {
        (void) bus;
        (void) b;
        return -EINVAL;
}

int sd_bus_negotiate_fds(sd_bus *bus, int b) {
        (void) bus;
        (void) b;
        return -EINVAL;
}

int sd_bus_can_send(sd_bus *bus, char type) {
        (void) bus;
        (void) type;
        return -EINVAL;
}

int sd_bus_get_creds_mask(sd_bus *bus, uint64_t *ret) {
        (void) bus;
        (void) ret;
        return -EINVAL;
}

int sd_bus_set_allow_interactive_authorization(sd_bus *bus, int b) {
        (void) bus;
        (void) b;
        return -EINVAL;
}

int sd_bus_get_allow_interactive_authorization(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_set_exit_on_disconnect(sd_bus *bus, int b) {
        (void) bus;
        (void) b;
        return -EINVAL;
}

int sd_bus_get_exit_on_disconnect(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_set_close_on_exit(sd_bus *bus, int b) {
        (void) bus;
        (void) b;
        return -EINVAL;
}

int sd_bus_get_close_on_exit(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_set_watch_bind(sd_bus *bus, int b) {
        (void) bus;
        (void) b;
        return -EINVAL;
}

int sd_bus_get_watch_bind(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_set_connected_signal(sd_bus *bus, int b) {
        (void) bus;
        (void) b;
        return -EINVAL;
}

int sd_bus_get_connected_signal(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_set_sender(sd_bus *bus, const char *sender) {
        (void) bus;
        (void) sender;
        return -EINVAL;
}

int sd_bus_get_sender(sd_bus *bus, const char **ret) {
        (void) bus;
        (void) ret;
        return -EINVAL;
}

int sd_bus_try_close(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_is_open(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_is_ready(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_get_bus_id(sd_bus *bus, sd_id128_t *ret) {
        (void) bus;
        (void) ret;
        return -EINVAL;
}

int sd_bus_get_scope(sd_bus *bus, const char **ret) {
        (void) bus;
        (void) ret;
        return -EINVAL;
}

int sd_bus_get_tid(sd_bus *bus, pid_t *ret) {
        (void) bus;
        (void) ret;
        return -EINVAL;
}

int sd_bus_get_unique_name(sd_bus *bus, const char **unique) {
        (void) bus;
        (void) unique;
        return -EINVAL;
}

int sd_bus_request_name(sd_bus *bus, const char *name, uint64_t flags) {
        (void) bus;
        (void) name;
        (void) flags;
        return -EINVAL;
}

int sd_bus_request_name_async(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *name,
                uint64_t flags,
                sd_bus_message_handler_t callback,
                void *userdata) {
        (void) bus;
        (void) ret_slot;
        (void) name;
        (void) flags;
        (void) callback;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_release_name(sd_bus *bus, const char *name) {
        (void) bus;
        (void) name;
        return -EINVAL;
}

int sd_bus_release_name_async(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *name,
                sd_bus_message_handler_t callback,
                void *userdata) {
        (void) bus;
        (void) ret_slot;
        (void) name;
        (void) callback;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_list_names(sd_bus *bus, char ***ret_acquired, char ***ret_activatable) {
        (void) bus;
        (void) ret_acquired;
        (void) ret_activatable;
        return -EINVAL;
}

int sd_bus_get_name_creds(sd_bus *bus, const char *name, uint64_t mask, sd_bus_creds **ret) {
        (void) bus;
        (void) name;
        (void) mask;
        (void) ret;
        return -EINVAL;
}

int sd_bus_get_owner_creds(sd_bus *bus, uint64_t creds_mask, sd_bus_creds **ret) {
        (void) bus;
        (void) creds_mask;
        (void) ret;
        return -EINVAL;
}

int sd_bus_get_name_machine_id(sd_bus *bus, const char *name, sd_id128_t *ret) {
        (void) bus;
        (void) name;
        (void) ret;
        return -EINVAL;
}

int sd_bus_call(sd_bus *bus,
                sd_bus_message *m,
                uint64_t usec,
                sd_bus_error *reterr_error,
                sd_bus_message **ret_reply) {
        (void) bus;
        (void) m;
        (void) usec;
        (void) reterr_error;
        (void) ret_reply;
        return -EINVAL;
}

int sd_bus_call_async(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                sd_bus_message *m,
                sd_bus_message_handler_t callback,
                void *userdata,
                uint64_t usec) {
        (void) bus;
        (void) ret_slot;
        (void) m;
        (void) callback;
        (void) userdata;
        (void) usec;
        return -EINVAL;
}

int sd_bus_get_fd(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_get_events(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_get_timeout(sd_bus *bus, uint64_t *ret) {
        (void) bus;
        (void) ret;
        return -EINVAL;
}

int sd_bus_process(sd_bus *bus, sd_bus_message **ret) {
        (void) bus;
        (void) ret;
        return -EINVAL;
}

int sd_bus_process_priority(sd_bus *bus, int64_t max_priority, sd_bus_message **ret) {
        (void) bus;
        (void) max_priority;
        (void) ret;
        return -EINVAL;
}

int sd_bus_wait(sd_bus *bus, uint64_t timeout_usec) {
        (void) bus;
        (void) timeout_usec;
        return -EINVAL;
}

int sd_bus_flush(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_enqueue_for_read(sd_bus *bus, sd_bus_message *m) {
        (void) bus;
        (void) m;
        return -EINVAL;
}

int sd_bus_send(sd_bus *bus, sd_bus_message *m, uint64_t *ret_cookie) {
        (void) bus;
        (void) m;
        (void) ret_cookie;
        return -EINVAL;
}

int sd_bus_send_to(sd_bus *bus, sd_bus_message *m, const char *destination, uint64_t *ret_cookie) {
        (void) bus;
        (void) m;
        (void) destination;
        (void) ret_cookie;
        return -EINVAL;
}

int sd_bus_pending_method_calls(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_attach_event(sd_bus *bus, sd_event *e, int priority) {
        (void) bus;
        (void) e;
        (void) priority;
        return -EINVAL;
}

int sd_bus_detach_event(sd_bus *bus) {
        (void) bus;
        return -EINVAL;
}

int sd_bus_get_method_call_timeout(sd_bus *bus, uint64_t *ret) {
        (void) bus;
        (void) ret;
        return -EINVAL;
}

int sd_bus_set_method_call_timeout(sd_bus *bus, uint64_t usec) {
        (void) bus;
        (void) usec;
        return -EINVAL;
}

int sd_bus_get_n_queued_read(sd_bus *bus, uint64_t *ret) {
        (void) bus;
        (void) ret;
        return -EINVAL;
}

int sd_bus_get_n_queued_write(sd_bus *bus, uint64_t *ret) {
        (void) bus;
        (void) ret;
        return -EINVAL;
}

int sd_bus_add_filter(sd_bus *bus, sd_bus_slot **ret_slot, sd_bus_message_handler_t callback, void *userdata) {
        (void) bus;
        (void) ret_slot;
        (void) callback;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_add_match(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *match,
                sd_bus_message_handler_t callback,
                void *userdata) {
        (void) bus;
        (void) ret_slot;
        (void) match;
        (void) callback;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_add_match_async(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *match,
                sd_bus_message_handler_t callback,
                sd_bus_message_handler_t install_callback,
                void *userdata) {
        (void) bus;
        (void) ret_slot;
        (void) match;
        (void) callback;
        (void) install_callback;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_match_signal(
                sd_bus *bus,
                sd_bus_slot **ret,
                const char *sender,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_message_handler_t callback,
                void *userdata) {
        (void) bus;
        (void) ret;
        (void) sender;
        (void) path;
        (void) interface;
        (void) member;
        (void) callback;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_match_signal_async(
                sd_bus *bus,
                sd_bus_slot **ret,
                const char *sender,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_message_handler_t match_callback,
                sd_bus_message_handler_t install_callback,
                void *userdata) {
        (void) bus;
        (void) ret;
        (void) sender;
        (void) path;
        (void) interface;
        (void) member;
        (void) match_callback;
        (void) install_callback;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_add_object(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *path,
                sd_bus_message_handler_t callback,
                void *userdata) {
        (void) bus;
        (void) ret_slot;
        (void) path;
        (void) callback;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_add_fallback(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *prefix,
                sd_bus_message_handler_t callback,
                void *userdata) {
        (void) bus;
        (void) ret_slot;
        (void) prefix;
        (void) callback;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_add_object_vtable(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *path,
                const char *interface,
                const sd_bus_vtable *vtable,
                void *userdata) {
        (void) bus;
        (void) ret_slot;
        (void) path;
        (void) interface;
        (void) vtable;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_add_fallback_vtable(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *prefix,
                const char *interface,
                const sd_bus_vtable *vtable,
                sd_bus_object_find_t find,
                void *userdata) {
        (void) bus;
        (void) ret_slot;
        (void) prefix;
        (void) interface;
        (void) vtable;
        (void) find;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_add_node_enumerator(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *path,
                sd_bus_node_enumerator_t callback,
                void *userdata) {
        (void) bus;
        (void) ret_slot;
        (void) path;
        (void) callback;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_add_object_manager(sd_bus *bus, sd_bus_slot **ret_slot, const char *path) {
        (void) bus;
        (void) ret_slot;
        (void) path;
        return -EINVAL;
}

int sd_bus_query_sender_creds(sd_bus_message *m, uint64_t mask, sd_bus_creds **ret) {
        (void) m;
        (void) mask;
        (void) ret;
        return -EINVAL;
}

int sd_bus_query_sender_privilege(sd_bus_message *m, int capability) {
        (void) m;
        (void) capability;
        return -EINVAL;
}

int sd_bus_call_method(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *reterr_error,
                sd_bus_message **ret_reply,
                const char *types,
                ...) {
        (void) bus;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        (void) reterr_error;
        (void) ret_reply;
        (void) types;
        return -EINVAL;
}

int sd_bus_call_methodv(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *reterr_error,
                sd_bus_message **ret_reply,
                const char *types,
                va_list ap) {
        (void) bus;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        (void) reterr_error;
        (void) ret_reply;
        (void) types;
        (void) ap;
        return -EINVAL;
}

int sd_bus_call_method_async(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_message_handler_t callback,
                void *userdata,
                const char *types,
                ...) {
        (void) bus;
        (void) ret_slot;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        (void) callback;
        (void) userdata;
        (void) types;
        return -EINVAL;
}

int sd_bus_call_method_asyncv(
                sd_bus *bus,
                sd_bus_slot **ret_slot,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_message_handler_t callback,
                void *userdata,
                const char *types,
                va_list ap) {
        (void) bus;
        (void) ret_slot;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        (void) callback;
        (void) userdata;
        (void) types;
        (void) ap;
        return -EINVAL;
}

int sd_bus_get_property(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *reterr_error,
                sd_bus_message **ret_reply,
                const char *type) {
        (void) bus;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        (void) reterr_error;
        (void) ret_reply;
        (void) type;
        return -EINVAL;
}

int sd_bus_get_property_trivial(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *reterr_error,
                char type,
                void *ret) {
        (void) bus;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        (void) reterr_error;
        (void) type;
        (void) ret;
        return -EINVAL;
}

int sd_bus_get_property_string(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *reterr_error,
                char **ret) {
        (void) bus;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        (void) reterr_error;
        (void) ret;
        return -EINVAL;
}

int sd_bus_get_property_strv(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *reterr_error,
                char ***ret) {
        (void) bus;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        (void) reterr_error;
        (void) ret;
        return -EINVAL;
}

int sd_bus_set_property(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *reterr_error,
                const char *type,
                ...) {
        (void) bus;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        (void) reterr_error;
        (void) type;
        return -EINVAL;
}

int sd_bus_set_propertyv(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                sd_bus_error *reterr_error,
                const char *type,
                va_list ap) {
        (void) bus;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        (void) reterr_error;
        (void) type;
        (void) ap;
        return -EINVAL;
}

int sd_bus_reply_method_return(sd_bus_message *call, const char *types, ...) {
        (void) call;
        (void) types;
        return -EINVAL;
}

int sd_bus_reply_method_returnv(sd_bus_message *call, const char *types, va_list ap) {
        (void) call;
        (void) types;
        (void) ap;
        return -EINVAL;
}

int sd_bus_reply_method_error(sd_bus_message *call, const sd_bus_error *e) {
        (void) call;
        (void) e;
        return -EINVAL;
}

int sd_bus_reply_method_errorf(sd_bus_message *call, const char *name, const char *format, ...) {
        (void) call;
        (void) name;
        (void) format;
        return -EINVAL;
}

int sd_bus_reply_method_errorfv(sd_bus_message *call, const char *name, const char *format, va_list ap) {
        (void) call;
        (void) name;
        (void) format;
        (void) ap;
        return -EINVAL;
}

int sd_bus_reply_method_errno(sd_bus_message *call, int error, const sd_bus_error *e) {
        (void) call;
        (void) error;
        (void) e;
        return -EINVAL;
}

int sd_bus_reply_method_errnof(sd_bus_message *call, int error, const char *format, ...) {
        (void) call;
        (void) error;
        (void) format;
        return -EINVAL;
}

int sd_bus_reply_method_errnofv(sd_bus_message *call, int error, const char *format, va_list ap) {
        (void) call;
        (void) error;
        (void) format;
        (void) ap;
        return -EINVAL;
}

int sd_bus_emit_signal(
                sd_bus *bus, const char *path, const char *interface, const char *member, const char *types, ...) {
        (void) bus;
        (void) path;
        (void) interface;
        (void) member;
        (void) types;
        return -EINVAL;
}

int sd_bus_emit_signalv(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *member,
                const char *types,
                va_list ap) {
        (void) bus;
        (void) path;
        (void) interface;
        (void) member;
        (void) types;
        (void) ap;
        return -EINVAL;
}

int sd_bus_emit_signal_to(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                const char *types,
                ...) {
        (void) bus;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        (void) types;
        return -EINVAL;
}

int sd_bus_emit_signal_tov(
                sd_bus *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                const char *types,
                va_list ap) {
        (void) bus;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        (void) types;
        (void) ap;
        return -EINVAL;
}

int sd_bus_emit_properties_changed_strv(sd_bus *bus, const char *path, const char *interface, char **names) {
        (void) bus;
        (void) path;
        (void) interface;
        (void) names;
        return -EINVAL;
}

int sd_bus_emit_properties_changed(sd_bus *bus, const char *path, const char *interface, const char *name, ...) {
        (void) bus;
        (void) path;
        (void) interface;
        (void) name;
        return -EINVAL;
}

int sd_bus_emit_object_added(sd_bus *bus, const char *path) {
        (void) bus;
        (void) path;
        return -EINVAL;
}

int sd_bus_emit_object_removed(sd_bus *bus, const char *path) {
        (void) bus;
        (void) path;
        return -EINVAL;
}

int sd_bus_emit_interfaces_added_strv(sd_bus *bus, const char *path, char **interfaces) {
        (void) bus;
        (void) path;
        (void) interfaces;
        return -EINVAL;
}

int sd_bus_emit_interfaces_added(sd_bus *bus, const char *path, const char *interface, ...) {
        (void) bus;
        (void) path;
        (void) interface;
        return -EINVAL;
}

int sd_bus_emit_interfaces_removed_strv(sd_bus *bus, const char *path, char **interfaces) {
        (void) bus;
        (void) path;
        (void) interfaces;
        return -EINVAL;
}

int sd_bus_emit_interfaces_removed(sd_bus *bus, const char *path, const char *interface, ...) {
        (void) bus;
        (void) path;
        (void) interface;
        return -EINVAL;
}

/* BUCKET B (message) */
int sd_bus_message_new(sd_bus *bus, sd_bus_message **ret, uint8_t type) {
        (void) bus;
        (void) ret;
        (void) type;
        return -EINVAL;
}

int sd_bus_message_new_signal(
                sd_bus *bus, sd_bus_message **ret, const char *path, const char *interface, const char *member) {
        (void) bus;
        (void) ret;
        (void) path;
        (void) interface;
        (void) member;
        return -EINVAL;
}

int sd_bus_message_new_signal_to(
                sd_bus *bus,
                sd_bus_message **ret,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member) {
        (void) bus;
        (void) ret;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        return -EINVAL;
}

int sd_bus_message_new_method_call(
                sd_bus *bus,
                sd_bus_message **ret,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member) {
        (void) bus;
        (void) ret;
        (void) destination;
        (void) path;
        (void) interface;
        (void) member;
        return -EINVAL;
}

int sd_bus_message_new_method_return(sd_bus_message *call, sd_bus_message **ret) {
        (void) call;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_new_method_error(sd_bus_message *call, sd_bus_message **ret, const sd_bus_error *e) {
        (void) call;
        (void) ret;
        (void) e;
        return -EINVAL;
}

int sd_bus_message_new_method_errorf(
                sd_bus_message *call, sd_bus_message **ret, const char *name, const char *format, ...) {
        (void) call;
        (void) ret;
        (void) name;
        (void) format;
        return -EINVAL;
}

int sd_bus_message_new_method_errno(sd_bus_message *call, sd_bus_message **ret, int error, const sd_bus_error *e) {
        (void) call;
        (void) ret;
        (void) error;
        (void) e;
        return -EINVAL;
}

int sd_bus_message_new_method_errnof(
                sd_bus_message *call, sd_bus_message **ret, int error, const char *format, ...) {
        (void) call;
        (void) ret;
        (void) error;
        (void) format;
        return -EINVAL;
}

int sd_bus_message_seal(sd_bus_message *m, uint64_t cookie, uint64_t timeout_usec) {
        (void) m;
        (void) cookie;
        (void) timeout_usec;
        return -EINVAL;
}

int sd_bus_message_get_type(sd_bus_message *m, uint8_t *ret) {
        (void) m;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_get_cookie(sd_bus_message *m, uint64_t *ret) {
        (void) m;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_get_reply_cookie(sd_bus_message *m, uint64_t *ret) {
        (void) m;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_get_priority(sd_bus_message *m, int64_t *ret) {
        (void) m;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_get_expect_reply(sd_bus_message *m) {
        (void) m;
        return -EINVAL;
}

int sd_bus_message_get_auto_start(sd_bus_message *m) {
        (void) m;
        return -EINVAL;
}

int sd_bus_message_get_allow_interactive_authorization(sd_bus_message *m) {
        (void) m;
        return -EINVAL;
}

int sd_bus_message_is_signal(sd_bus_message *m, const char *interface, const char *member) {
        (void) m;
        (void) interface;
        (void) member;
        return -EINVAL;
}

int sd_bus_message_is_method_call(sd_bus_message *m, const char *interface, const char *member) {
        (void) m;
        (void) interface;
        (void) member;
        return -EINVAL;
}

int sd_bus_message_is_method_error(sd_bus_message *m, const char *name) {
        (void) m;
        (void) name;
        return -EINVAL;
}

int sd_bus_message_is_empty(sd_bus_message *m) {
        (void) m;
        return -EINVAL;
}

int sd_bus_message_has_signature(sd_bus_message *m, const char *signature) {
        (void) m;
        (void) signature;
        return -EINVAL;
}

int sd_bus_message_get_monotonic_usec(sd_bus_message *m, uint64_t *ret) {
        (void) m;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_get_realtime_usec(sd_bus_message *m, uint64_t *ret) {
        (void) m;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_get_seqnum(sd_bus_message *m, uint64_t *ret) {
        (void) m;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_get_errno(sd_bus_message *m) {
        (void) m;
        return -EINVAL;
}

int sd_bus_message_set_expect_reply(sd_bus_message *m, int b) {
        (void) m;
        (void) b;
        return -EINVAL;
}

int sd_bus_message_set_auto_start(sd_bus_message *m, int b) {
        (void) m;
        (void) b;
        return -EINVAL;
}

int sd_bus_message_set_allow_interactive_authorization(sd_bus_message *m, int b) {
        (void) m;
        (void) b;
        return -EINVAL;
}

int sd_bus_message_set_destination(sd_bus_message *m, const char *destination) {
        (void) m;
        (void) destination;
        return -EINVAL;
}

int sd_bus_message_set_sender(sd_bus_message *m, const char *sender) {
        (void) m;
        (void) sender;
        return -EINVAL;
}

int sd_bus_message_set_priority(sd_bus_message *m, int64_t priority) {
        (void) m;
        (void) priority;
        return -EINVAL;
}

int sd_bus_message_append(sd_bus_message *m, const char *types, ...) {
        (void) m;
        (void) types;
        return -EINVAL;
}

int sd_bus_message_appendv(sd_bus_message *m, const char *types, va_list ap) {
        (void) m;
        (void) types;
        (void) ap;
        return -EINVAL;
}

int sd_bus_message_append_basic(sd_bus_message *m, char type, const void *p) {
        (void) m;
        (void) type;
        (void) p;
        return -EINVAL;
}

int sd_bus_message_append_array(sd_bus_message *m, char type, const void *ptr, size_t size) {
        (void) m;
        (void) type;
        (void) ptr;
        (void) size;
        return -EINVAL;
}

int sd_bus_message_append_array_space(sd_bus_message *m, char type, size_t size, void **ret) {
        (void) m;
        (void) type;
        (void) size;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_append_array_iovec(sd_bus_message *m, char type, const struct iovec *iov, unsigned n) {
        (void) m;
        (void) type;
        (void) iov;
        (void) n;
        return -EINVAL;
}

int sd_bus_message_append_array_memfd(sd_bus_message *m, char type, int memfd, uint64_t offset, uint64_t size) {
        (void) m;
        (void) type;
        (void) memfd;
        (void) offset;
        (void) size;
        return -EINVAL;
}

int sd_bus_message_append_string_space(sd_bus_message *m, size_t size, char **ret) {
        (void) m;
        (void) size;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_append_string_iovec(sd_bus_message *m, const struct iovec *iov, unsigned n) {
        (void) m;
        (void) iov;
        (void) n;
        return -EINVAL;
}

int sd_bus_message_append_string_memfd(sd_bus_message *m, int memfd, uint64_t offset, uint64_t size) {
        (void) m;
        (void) memfd;
        (void) offset;
        (void) size;
        return -EINVAL;
}

int sd_bus_message_append_strv(sd_bus_message *m, char **l) {
        (void) m;
        (void) l;
        return -EINVAL;
}

int sd_bus_message_open_container(sd_bus_message *m, char type, const char *contents) {
        (void) m;
        (void) type;
        (void) contents;
        return -EINVAL;
}

int sd_bus_message_close_container(sd_bus_message *m) {
        (void) m;
        return -EINVAL;
}

int sd_bus_message_copy(sd_bus_message *m, sd_bus_message *source, int all) {
        (void) m;
        (void) source;
        (void) all;
        return -EINVAL;
}

int sd_bus_message_read(sd_bus_message *m, const char *types, ...) {
        (void) m;
        (void) types;
        return -EINVAL;
}

int sd_bus_message_readv(sd_bus_message *m, const char *types, va_list ap) {
        (void) m;
        (void) types;
        (void) ap;
        return -EINVAL;
}

int sd_bus_message_read_basic(sd_bus_message *m, char type, void *ret) {
        (void) m;
        (void) type;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_read_array(sd_bus_message *m, char type, const void **ret_ptr, size_t *ret_size) {
        (void) m;
        (void) type;
        (void) ret_ptr;
        (void) ret_size;
        return -EINVAL;
}

int sd_bus_message_read_strv(sd_bus_message *m, char ***ret) {
        (void) m;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_read_strv_extend(sd_bus_message *m, char ***l) {
        (void) m;
        (void) l;
        return -EINVAL;
}

int sd_bus_message_skip(sd_bus_message *m, const char *types) {
        (void) m;
        (void) types;
        return -EINVAL;
}

int sd_bus_message_enter_container(sd_bus_message *m, char type, const char *contents) {
        (void) m;
        (void) type;
        (void) contents;
        return -EINVAL;
}

int sd_bus_message_exit_container(sd_bus_message *m) {
        (void) m;
        return -EINVAL;
}

int sd_bus_message_peek_type(sd_bus_message *m, char *ret_type, const char **ret_contents) {
        (void) m;
        (void) ret_type;
        (void) ret_contents;
        return -EINVAL;
}

int sd_bus_message_verify_type(sd_bus_message *m, char type, const char *contents) {
        (void) m;
        (void) type;
        (void) contents;
        return -EINVAL;
}

int sd_bus_message_at_end(sd_bus_message *m, int complete) {
        (void) m;
        (void) complete;
        return -EINVAL;
}

int sd_bus_message_rewind(sd_bus_message *m, int complete) {
        (void) m;
        (void) complete;
        return -EINVAL;
}

int sd_bus_message_send(sd_bus_message *m) {
        (void) m;
        return -EINVAL;
}

int sd_bus_message_dump(sd_bus_message *m, FILE *f, uint64_t flags) {
        (void) m;
        (void) f;
        (void) flags;
        return -EINVAL;
}

int sd_bus_message_dump_json(sd_bus_message *m, uint64_t flags, sd_json_variant **ret) {
        (void) m;
        (void) flags;
        (void) ret;
        return -EINVAL;
}

int sd_bus_message_sensitive(sd_bus_message *m) {
        (void) m;
        return -EINVAL;
}

/* BUCKET B (slot/track/creds) */
int sd_bus_slot_get_floating(sd_bus_slot *slot) {
        (void) slot;
        return -EINVAL;
}

int sd_bus_slot_set_floating(sd_bus_slot *slot, int b) {
        (void) slot;
        (void) b;
        return -EINVAL;
}

int sd_bus_slot_set_description(sd_bus_slot *slot, const char *description) {
        (void) slot;
        (void) description;
        return -EINVAL;
}

int sd_bus_slot_get_description(sd_bus_slot *slot, const char **ret) {
        (void) slot;
        (void) ret;
        return -EINVAL;
}

int sd_bus_slot_get_destroy_callback(sd_bus_slot *s, sd_bus_destroy_t *ret) {
        (void) s;
        (void) ret;
        return -EINVAL;
}

int sd_bus_slot_set_destroy_callback(sd_bus_slot *s, sd_bus_destroy_t callback) {
        (void) s;
        (void) callback;
        return -EINVAL;
}

int sd_bus_track_new(sd_bus *bus, sd_bus_track **ret, sd_bus_track_handler_t handler, void *userdata) {
        (void) bus;
        (void) ret;
        (void) handler;
        (void) userdata;
        return -EINVAL;
}

int sd_bus_track_get_recursive(sd_bus_track *track) {
        (void) track;
        return -EINVAL;
}

int sd_bus_track_set_recursive(sd_bus_track *track, int b) {
        (void) track;
        (void) b;
        return -EINVAL;
}

int sd_bus_track_add_sender(sd_bus_track *track, sd_bus_message *m) {
        (void) track;
        (void) m;
        return -EINVAL;
}

int sd_bus_track_remove_sender(sd_bus_track *track, sd_bus_message *m) {
        (void) track;
        (void) m;
        return -EINVAL;
}

int sd_bus_track_add_name(sd_bus_track *track, const char *name) {
        (void) track;
        (void) name;
        return -EINVAL;
}

int sd_bus_track_remove_name(sd_bus_track *track, const char *name) {
        (void) track;
        (void) name;
        return -EINVAL;
}

int sd_bus_track_count_sender(sd_bus_track *track, sd_bus_message *m) {
        (void) track;
        (void) m;
        return -EINVAL;
}

int sd_bus_track_count_name(sd_bus_track *track, const char *name) {
        (void) track;
        (void) name;
        return -EINVAL;
}

int sd_bus_track_get_destroy_callback(sd_bus_track *track, sd_bus_destroy_t *ret) {
        (void) track;
        (void) ret;
        return -EINVAL;
}

int sd_bus_track_set_destroy_callback(sd_bus_track *track, sd_bus_destroy_t callback) {
        (void) track;
        (void) callback;
        return -EINVAL;
}

int sd_bus_creds_get_pid(sd_bus_creds *c, pid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_ppid(sd_bus_creds *c, pid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_tid(sd_bus_creds *c, pid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_pidfd_dup(sd_bus_creds *c, int *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_uid(sd_bus_creds *c, uid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_euid(sd_bus_creds *c, uid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_suid(sd_bus_creds *c, uid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_fsuid(sd_bus_creds *c, uid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_gid(sd_bus_creds *c, gid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_egid(sd_bus_creds *c, gid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_sgid(sd_bus_creds *c, gid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_fsgid(sd_bus_creds *c, gid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_supplementary_gids(sd_bus_creds *c, const gid_t **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_comm(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_tid_comm(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_exe(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_cmdline(sd_bus_creds *c, char ***ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_cgroup(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_unit(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_slice(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_user_unit(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_user_slice(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_session(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_owner_uid(sd_bus_creds *c, uid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_has_effective_cap(sd_bus_creds *c, int capability) {
        (void) c;
        (void) capability;
        return -EINVAL;
}

int sd_bus_creds_has_permitted_cap(sd_bus_creds *c, int capability) {
        (void) c;
        (void) capability;
        return -EINVAL;
}

int sd_bus_creds_has_inheritable_cap(sd_bus_creds *c, int capability) {
        (void) c;
        (void) capability;
        return -EINVAL;
}

int sd_bus_creds_has_bounding_cap(sd_bus_creds *c, int capability) {
        (void) c;
        (void) capability;
        return -EINVAL;
}

int sd_bus_creds_get_selinux_context(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_audit_session_id(sd_bus_creds *c, uint32_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_audit_login_uid(sd_bus_creds *c, uid_t *ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_tty(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_unique_name(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_well_known_names(sd_bus_creds *c, char ***ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}

int sd_bus_creds_get_description(sd_bus_creds *c, const char **ret) {
        (void) c;
        (void) ret;
        return -EINVAL;
}
