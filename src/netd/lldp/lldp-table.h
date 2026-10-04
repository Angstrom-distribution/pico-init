/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The LLDP neighbours heard on one link. No I/O and no clock of its own: every
 * call that needs the time is given it, so expiry is testable without sleeping.
 *
 * Memory is bounded twice over. The table holds at most LLDP_TABLE_MAX
 * neighbours and each is one allocation of its raw frame (at most
 * LLDP_FRAME_MAX bytes) plus a small header; strings are never copied out of
 * the frame, the parsed offsets point into it. A link on a hostile segment
 * therefore costs at most LLDP_TABLE_MAX * (LLDP_FRAME_MAX + header) bytes.
 *
 * When the table is full a frame from an unknown neighbour is dropped, as in
 * lldpd, and a known neighbour is still refreshed. systemd evicts the oldest
 * entry instead, which lets a transmitter that cycles chassis IDs push every
 * real neighbour out; here the first LLDP_TABLE_MAX stay until they expire.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "lldp-frame.h"

#define LLDP_TABLE_MAX 8

typedef struct LldpNeighbor {
        LldpFrame f;     /* offsets into frame[] */
        uint64_t expiry; /* absolute, in the caller's clock (microseconds) */
        uint16_t len;
        uint8_t frame[]; /* the frame as received */
} LldpNeighbor;

typedef struct LldpTable {
        LldpNeighbor *entries[LLDP_TABLE_MAX];
        unsigned n;
} LldpTable;

typedef enum LldpEvent {
        LLDP_EVENT_IGNORED, /* nothing changed: shutdown for an unknown neighbour, or a routers-only mismatch */
        LLDP_EVENT_ADDED,     /* a new neighbour */
        LLDP_EVENT_UPDATED,   /* a known neighbour whose frame content changed */
        LLDP_EVENT_REFRESHED, /* a known neighbour, same content, only the expiry moved */
        LLDP_EVENT_REMOVED,   /* a shutdown frame removed a neighbour */
        LLDP_EVENT_FULL,      /* dropped: the table is full of other neighbours */
        LLDP_EVENT_NOMEM,
} LldpEvent;

/*
 * Offers a parsed frame. `capability_mask` filters neighbours that advertise
 * enabled capabilities none of which are in the mask (UINT16_MAX accepts all;
 * a neighbour with no capabilities TLV is always accepted). `now` in
 * microseconds. Expired entries are dropped first, so a full table is only
 * reported while it is really full.
 */
LldpEvent lldp_table_offer(
                LldpTable *t,
                const uint8_t *frame,
                size_t len,
                const LldpFrame *parsed,
                uint16_t capability_mask,
                uint64_t now);

/* Drops every entry whose expiry is at or before `now`; returns how many. */
unsigned lldp_table_expire(LldpTable *t, uint64_t now);

/* The earliest expiry, or 0 when the table is empty. */
uint64_t lldp_table_next_expiry(const LldpTable *t);

/* Frees everything. */
void lldp_table_clear(LldpTable *t);
