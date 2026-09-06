/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Exhaustively calls every function in sd-bus-noop.c's true_noop bucket
 * and asserts NULL/0/void -- generated the same mechanical way the noop
 * bodies themselves were (see that file's header).
 */

#include "sd-bus.h"

#include "../../test-util.h"

static void call_noop_variants(void) {
        ASSERT_TRUE(sd_bus_ref(NULL) == NULL);
        ASSERT_TRUE(sd_bus_unref(NULL) == NULL);
        ASSERT_TRUE(sd_bus_close_unref(NULL) == NULL);
        ASSERT_TRUE(sd_bus_flush_close_unref(NULL) == NULL);
        ASSERT_TRUE(sd_bus_slot_ref(NULL) == NULL);
        ASSERT_TRUE(sd_bus_slot_unref(NULL) == NULL);
        ASSERT_TRUE(sd_bus_message_ref(NULL) == NULL);
        ASSERT_TRUE(sd_bus_message_unref(NULL) == NULL);
        ASSERT_TRUE(sd_bus_creds_ref(NULL) == NULL);
        ASSERT_TRUE(sd_bus_creds_unref(NULL) == NULL);
        ASSERT_TRUE(sd_bus_track_ref(NULL) == NULL);
        ASSERT_TRUE(sd_bus_track_unref(NULL) == NULL);
        sd_bus_close(NULL);
        sd_bus_default_flush_close();
        /* Re-bucketed from the -EINVAL family -- see sd-bus-stubs.c's header. */
        ASSERT_TRUE(sd_bus_get_event(NULL) == NULL);
        ASSERT_TRUE(sd_bus_get_current_message(NULL) == NULL);
        ASSERT_TRUE(sd_bus_get_current_slot(NULL) == NULL);
        ASSERT_TRUE(sd_bus_get_current_handler(NULL) == NULL);
        ASSERT_TRUE(sd_bus_get_current_userdata(NULL) == NULL);
        ASSERT_TRUE(sd_bus_message_get_bus(NULL) == NULL);
        ASSERT_TRUE(sd_bus_message_get_signature(NULL, 0) == NULL);
        ASSERT_TRUE(sd_bus_message_get_path(NULL) == NULL);
        ASSERT_TRUE(sd_bus_message_get_interface(NULL) == NULL);
        ASSERT_TRUE(sd_bus_message_get_member(NULL) == NULL);
        ASSERT_TRUE(sd_bus_message_get_destination(NULL) == NULL);
        ASSERT_TRUE(sd_bus_message_get_sender(NULL) == NULL);
        ASSERT_TRUE(sd_bus_message_get_error(NULL) == NULL);
        ASSERT_TRUE(sd_bus_message_get_creds(NULL) == NULL);
        ASSERT_TRUE(sd_bus_slot_get_bus(NULL) == NULL);
        ASSERT_TRUE(sd_bus_slot_get_userdata(NULL) == NULL);
        ASSERT_TRUE(sd_bus_slot_set_userdata(NULL, NULL) == NULL);
        ASSERT_TRUE(sd_bus_slot_get_current_message(NULL) == NULL);
        ASSERT_TRUE(sd_bus_slot_get_current_handler(NULL) == NULL);
        ASSERT_TRUE(sd_bus_slot_get_current_userdata(NULL) == NULL);
        ASSERT_TRUE(sd_bus_track_get_bus(NULL) == NULL);
        ASSERT_TRUE(sd_bus_track_get_userdata(NULL) == NULL);
        ASSERT_TRUE(sd_bus_track_set_userdata(NULL, NULL) == NULL);
        ASSERT_TRUE(sd_bus_track_contains(NULL, NULL) == NULL);
        ASSERT_TRUE(sd_bus_track_first(NULL) == NULL);
        ASSERT_TRUE(sd_bus_track_next(NULL) == NULL);
        ASSERT_EQ_INT(sd_bus_track_count(NULL), 0);
        ASSERT_EQ_INT(sd_bus_creds_get_mask(NULL), 0);
        ASSERT_EQ_INT(sd_bus_creds_get_augmented_mask(NULL), 0);
}

int main(void) {
        call_noop_variants();

        printf("test-sd-bus-noop: all checks passed\n");
        return 0;
}
