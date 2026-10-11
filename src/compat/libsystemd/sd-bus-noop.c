/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The sd-bus.h entry points whose upstream answer for a NULL handle is a
 * plain value: ref/unref, sd_bus_close()/sd_bus_default_flush_close(), and
 * the pointer/mask "current thing" accessors. No sd_bus, sd_bus_message,
 * sd_bus_slot, sd_bus_track or sd_bus_creds object can ever exist
 * (sd-bus-open.c, sd-bus-stubs.c), so ref/unref(NULL) is NULL,
 * sd_bus_close(NULL) is a no-op and "no current message/slot" is NULL, as
 * in real libsystemd.
 *
 * sd_bus_object_vtable_format's storage lives here (see sd-bus-vtable.h):
 * SD_BUS_VTABLE_START() takes its address, so a vtable[] at file scope
 * needs the symbol at link time.
 *
 * sd_bus_get_event(), sd_bus_track_contains() and sd_bus_track_count() are
 * here rather than in sd-bus-stubs.c because their return types (sd_event*,
 * const char*, unsigned) cannot carry -EINVAL; they return NULL/NULL/0.
 */

#include "sd-bus.h"

#include <stddef.h>

const unsigned sd_bus_object_vtable_format = 1;

/* ref/unref */
sd_bus *sd_bus_ref(sd_bus *p) {
        (void) p;
        return NULL;
}

sd_bus *sd_bus_unref(sd_bus *p) {
        (void) p;
        return NULL;
}

sd_bus *sd_bus_close_unref(sd_bus *bus) {
        (void) bus;
        return NULL;
}

sd_bus *sd_bus_flush_close_unref(sd_bus *bus) {
        (void) bus;
        return NULL;
}

sd_bus_slot *sd_bus_slot_ref(sd_bus_slot *p) {
        (void) p;
        return NULL;
}

sd_bus_slot *sd_bus_slot_unref(sd_bus_slot *p) {
        (void) p;
        return NULL;
}

sd_bus_message *sd_bus_message_ref(sd_bus_message *p) {
        (void) p;
        return NULL;
}

sd_bus_message *sd_bus_message_unref(sd_bus_message *p) {
        (void) p;
        return NULL;
}

sd_bus_creds *sd_bus_creds_ref(sd_bus_creds *p) {
        (void) p;
        return NULL;
}

sd_bus_creds *sd_bus_creds_unref(sd_bus_creds *p) {
        (void) p;
        return NULL;
}

sd_bus_track *sd_bus_track_ref(sd_bus_track *p) {
        (void) p;
        return NULL;
}

sd_bus_track *sd_bus_track_unref(sd_bus_track *p) {
        (void) p;
        return NULL;
}

/* void no-ops */
void sd_bus_close(sd_bus *bus) {
        (void) bus;
}

void sd_bus_default_flush_close(void) {
}

/* accessors */
sd_event *sd_bus_get_event(sd_bus *bus) {
        (void) bus;
        return NULL;
}

sd_bus_message *sd_bus_get_current_message(sd_bus *bus) {
        (void) bus;
        return NULL;
}

sd_bus_slot *sd_bus_get_current_slot(sd_bus *bus) {
        (void) bus;
        return NULL;
}

sd_bus_message_handler_t sd_bus_get_current_handler(sd_bus *bus) {
        (void) bus;
        return NULL;
}

void *sd_bus_get_current_userdata(sd_bus *bus) {
        (void) bus;
        return NULL;
}

sd_bus *sd_bus_message_get_bus(sd_bus_message *m) {
        (void) m;
        return NULL;
}

const char *sd_bus_message_get_signature(sd_bus_message *m, int complete) {
        (void) m;
        (void) complete;
        return NULL;
}

const char *sd_bus_message_get_path(sd_bus_message *m) {
        (void) m;
        return NULL;
}

const char *sd_bus_message_get_interface(sd_bus_message *m) {
        (void) m;
        return NULL;
}

const char *sd_bus_message_get_member(sd_bus_message *m) {
        (void) m;
        return NULL;
}

const char *sd_bus_message_get_destination(sd_bus_message *m) {
        (void) m;
        return NULL;
}

const char *sd_bus_message_get_sender(sd_bus_message *m) {
        (void) m;
        return NULL;
}

const sd_bus_error *sd_bus_message_get_error(sd_bus_message *m) {
        (void) m;
        return NULL;
}

sd_bus_creds *sd_bus_message_get_creds(sd_bus_message *m) {
        (void) m;
        return NULL;
}

sd_bus *sd_bus_slot_get_bus(sd_bus_slot *slot) {
        (void) slot;
        return NULL;
}

void *sd_bus_slot_get_userdata(sd_bus_slot *slot) {
        (void) slot;
        return NULL;
}

void *sd_bus_slot_set_userdata(sd_bus_slot *slot, void *userdata) {
        (void) slot;
        (void) userdata;
        return NULL;
}

sd_bus_message *sd_bus_slot_get_current_message(sd_bus_slot *slot) {
        (void) slot;
        return NULL;
}

sd_bus_message_handler_t sd_bus_slot_get_current_handler(sd_bus_slot *slot) {
        (void) slot;
        return NULL;
}

void *sd_bus_slot_get_current_userdata(sd_bus_slot *slot) {
        (void) slot;
        return NULL;
}

sd_bus *sd_bus_track_get_bus(sd_bus_track *track) {
        (void) track;
        return NULL;
}

void *sd_bus_track_get_userdata(sd_bus_track *track) {
        (void) track;
        return NULL;
}

void *sd_bus_track_set_userdata(sd_bus_track *track, void *userdata) {
        (void) track;
        (void) userdata;
        return NULL;
}

const char *sd_bus_track_contains(sd_bus_track *track, const char *name) {
        (void) track;
        (void) name;
        return NULL;
}

const char *sd_bus_track_first(sd_bus_track *track) {
        (void) track;
        return NULL;
}

const char *sd_bus_track_next(sd_bus_track *track) {
        (void) track;
        return NULL;
}

unsigned sd_bus_track_count(sd_bus_track *track) {
        (void) track;
        return 0;
}

uint64_t sd_bus_creds_get_mask(const sd_bus_creds *c) {
        (void) c;
        return 0;
}

uint64_t sd_bus_creds_get_augmented_mask(const sd_bus_creds *c) {
        (void) c;
        return 0;
}
