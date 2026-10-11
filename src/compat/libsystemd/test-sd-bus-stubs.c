/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Calls every function in sd-bus-stubs.c and asserts -EINVAL.
 */

#include "sd-bus.h"

#include <errno.h>
#include <stdarg.h>

#include "../../test-util.h"

/* Several calls below use _PICO_SD_DEPRECATED_ entry points; they are still
 * part of the ABI and need a tested answer. */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static sd_id128_t zero_id128;

static void call_plain_einval_variants(void) {
        ASSERT_EQ_INT(sd_bus_start(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_address(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_fd(NULL, 0, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_exec(NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_address(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_bus_client(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_is_bus_client(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_server(NULL, 0, zero_id128), -EINVAL);
        ASSERT_EQ_INT(sd_bus_is_server(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_anonymous(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_is_anonymous(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_trusted(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_is_trusted(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_monitor(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_is_monitor(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_description(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_description(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_negotiate_creds(NULL, 0, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_negotiate_timestamp(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_negotiate_fds(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_can_send(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_creds_mask(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_allow_interactive_authorization(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_allow_interactive_authorization(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_exit_on_disconnect(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_exit_on_disconnect(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_close_on_exit(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_close_on_exit(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_watch_bind(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_watch_bind(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_connected_signal(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_connected_signal(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_sender(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_sender(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_try_close(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_is_open(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_is_ready(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_bus_id(NULL, &zero_id128), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_scope(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_tid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_unique_name(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_request_name(NULL, NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_request_name_async(NULL, NULL, NULL, 0, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_release_name(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_release_name_async(NULL, NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_list_names(NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_name_creds(NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_owner_creds(NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_name_machine_id(NULL, NULL, &zero_id128), -EINVAL);
        ASSERT_EQ_INT(sd_bus_call(NULL, NULL, 0, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_call_async(NULL, NULL, NULL, 0, NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_fd(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_events(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_timeout(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_process(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_process_priority(NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_wait(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_flush(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_enqueue_for_read(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_send(NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_send_to(NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_pending_method_calls(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_attach_event(NULL, NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_detach_event(NULL), -EINVAL);
        /* sd_bus_get_event() is in sd-bus-noop.c; see its header. */
        ASSERT_EQ_INT(sd_bus_get_method_call_timeout(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_method_call_timeout(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_n_queued_read(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_n_queued_write(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_add_filter(NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_add_match(NULL, NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_add_match_async(NULL, NULL, NULL, 0, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_match_signal(NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_match_signal_async(NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_add_object(NULL, NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_add_fallback(NULL, NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_add_object_vtable(NULL, NULL, NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_add_fallback_vtable(NULL, NULL, NULL, NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_add_node_enumerator(NULL, NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_add_object_manager(NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_query_sender_creds(NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_query_sender_privilege(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_call_method(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_call_method_async(NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_property(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_property_trivial(NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_property_string(NULL, NULL, NULL, NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_get_property_strv(NULL, NULL, NULL, NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_property(NULL, NULL, NULL, NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_reply_method_return(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_reply_method_error(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_reply_method_errorf(NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_reply_method_errno(NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_reply_method_errnof(NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_emit_signal(NULL, NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_emit_signal_to(NULL, NULL, NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_emit_properties_changed_strv(NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_emit_properties_changed(NULL, NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_emit_object_added(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_emit_object_removed(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_emit_interfaces_added_strv(NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_emit_interfaces_added(NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_emit_interfaces_removed_strv(NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_emit_interfaces_removed(NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_new(NULL, NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_new_signal(NULL, NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_new_signal_to(NULL, NULL, NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_new_method_call(NULL, NULL, NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_new_method_return(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_new_method_error(NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_new_method_errorf(NULL, NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_new_method_errno(NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_new_method_errnof(NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_seal(NULL, 0, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_get_type(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_get_cookie(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_get_reply_cookie(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_get_priority(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_get_expect_reply(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_get_auto_start(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_get_allow_interactive_authorization(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_is_signal(NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_is_method_call(NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_is_method_error(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_is_empty(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_has_signature(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_get_monotonic_usec(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_get_realtime_usec(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_get_seqnum(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_get_errno(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_set_expect_reply(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_set_auto_start(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_set_allow_interactive_authorization(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_set_destination(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_set_sender(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_set_priority(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_append(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_append_basic(NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_append_array(NULL, 0, NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_append_array_space(NULL, 0, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_append_array_iovec(NULL, 0, NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_append_array_memfd(NULL, 0, 0, 0, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_append_string_space(NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_append_string_iovec(NULL, NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_append_string_memfd(NULL, 0, 0, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_append_strv(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_open_container(NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_close_container(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_copy(NULL, NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_read(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_read_basic(NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_read_array(NULL, 0, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_read_strv(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_read_strv_extend(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_skip(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_enter_container(NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_exit_container(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_peek_type(NULL, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_verify_type(NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_at_end(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_rewind(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_send(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_dump(NULL, NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_dump_json(NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_sensitive(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_slot_get_floating(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_slot_set_floating(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_slot_set_description(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_slot_get_description(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_slot_get_destroy_callback(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_slot_set_destroy_callback(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_track_new(NULL, NULL, 0, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_track_get_recursive(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_track_set_recursive(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_track_add_sender(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_track_remove_sender(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_track_add_name(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_track_remove_name(NULL, NULL), -EINVAL);
        /* sd_bus_track_count()/track_contains() are in sd-bus-noop.c. */
        ASSERT_EQ_INT(sd_bus_track_count_sender(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_track_count_name(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_track_get_destroy_callback(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_track_set_destroy_callback(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_pid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_ppid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_tid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_pidfd_dup(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_uid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_euid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_suid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_fsuid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_gid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_egid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_sgid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_fsgid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_supplementary_gids(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_comm(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_tid_comm(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_exe(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_cmdline(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_cgroup(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_unit(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_slice(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_user_unit(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_user_slice(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_session(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_owner_uid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_has_effective_cap(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_has_permitted_cap(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_has_inheritable_cap(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_has_bounding_cap(NULL, 0), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_selinux_context(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_audit_session_id(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_audit_login_uid(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_tty(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_unique_name(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_well_known_names(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_creds_get_description(NULL, NULL), -EINVAL);
}

/* va_list-taking variants: none of them touch ap (they return -EINVAL
 * before ever looking at it), so one real va_list frame, started once,
 * is safe to reuse across every call below. */
static void call_va_einval_variants(int dummy, ...) {
        va_list ap;

        va_start(ap, dummy);
        ASSERT_EQ_INT(sd_bus_call_methodv(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ap), -EINVAL);
        ASSERT_EQ_INT(sd_bus_call_method_asyncv(NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, ap),
                      -EINVAL);
        ASSERT_EQ_INT(sd_bus_set_propertyv(NULL, NULL, NULL, NULL, NULL, NULL, NULL, ap), -EINVAL);
        ASSERT_EQ_INT(sd_bus_reply_method_returnv(NULL, NULL, ap), -EINVAL);
        ASSERT_EQ_INT(sd_bus_reply_method_errorfv(NULL, NULL, "x", ap), -EINVAL);
        ASSERT_EQ_INT(sd_bus_reply_method_errnofv(NULL, 0, "x", ap), -EINVAL);
        ASSERT_EQ_INT(sd_bus_emit_signalv(NULL, NULL, NULL, NULL, NULL, ap), -EINVAL);
        ASSERT_EQ_INT(sd_bus_emit_signal_tov(NULL, NULL, NULL, NULL, NULL, NULL, ap), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_appendv(NULL, NULL, ap), -EINVAL);
        ASSERT_EQ_INT(sd_bus_message_readv(NULL, NULL, ap), -EINVAL);
        va_end(ap);
}

int main(void) {
        call_plain_einval_variants();
        call_va_einval_variants(0);

        printf("test-sd-bus-stubs: all checks passed\n");
        return 0;
}
