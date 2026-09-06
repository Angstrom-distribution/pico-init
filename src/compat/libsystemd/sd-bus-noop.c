/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The true_noop corner of sd-bus.h: ref/unref, sd_bus_close()/
 * sd_bus_default_flush_close(), and the pointer/mask "current thing"
 * accessors. Every one of these is reachable only with a NULL/invalid
 * handle -- no sd_bus/sd_bus_message/sd_bus_slot/sd_bus_track/sd_bus_creds
 * object can ever exist (sd-bus-open.c, sd-bus-stubs.c) -- and upstream's
 * own contract for that case is exactly what these return: ref/unref(NULL)
 * is NULL, sd_bus_close(NULL) is a documented no-op, and "no current
 * message"/"no current slot"/etc. is NULL in real libsystemd too. Nothing
 * here can mislead a caller; it is the same answer the real library gives
 * in the same situation.
 *
 * sd_bus_object_vtable_format's storage lives here (see sd-bus-vtable.h's
 * header comment): SD_BUS_VTABLE_START() takes its address, so any
 * vtable[] a caller builds at file scope needs the symbol to exist at
 * link time even though sd_bus_add_object_vtable() (sd-bus-stubs.c) never
 * reads it.
 *
 * Mechanically generated from the real header's own signatures, the same
 * way as sd-bus-stubs.c -- see that file's header for why.
 *
 * sd_bus_get_event() and sd_bus_track_contains() are hand-added here, not
 * generated: the design doc lists both in sd-bus-stubs.c's -EINVAL bucket,
 * but their real return types (sd_event*, const char*) can't hold -EINVAL
 * at all -- see sd-bus-stubs.c's header for the full note. Both get the
 * same NULL "no such thing exists" answer as their sibling accessors
 * immediately below (sd_bus_get_current_message() and
 * sd_bus_track_first()/next()).
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
