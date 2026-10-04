/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* See lldp-table.h. */

#include <stdlib.h>
#include <string.h>

#include "lldp-table.h"

#define USEC_PER_SEC_U64 1000000ull

static void remove_at(LldpTable *t, unsigned i) {
        free(t->entries[i]);
        t->entries[i] = t->entries[--t->n];
        t->entries[t->n] = NULL;
}

unsigned lldp_table_expire(LldpTable *t, uint64_t now) {
        unsigned i = 0, removed = 0;

        while (i < t->n) {
                if (t->entries[i]->expiry <= now) {
                        remove_at(t, i);
                        removed++;
                } else
                        i++;
        }
        return removed;
}

uint64_t lldp_table_next_expiry(const LldpTable *t) {
        uint64_t next = 0;
        unsigned i;

        for (i = 0; i < t->n; i++)
                if (next == 0 || t->entries[i]->expiry < next)
                        next = t->entries[i]->expiry;
        return next;
}

void lldp_table_clear(LldpTable *t) {
        unsigned i;

        for (i = 0; i < t->n; i++) {
                free(t->entries[i]);
                t->entries[i] = NULL;
        }
        t->n = 0;
}

static int find(const LldpTable *t, const uint8_t *frame, const LldpFrame *parsed) {
        unsigned i;

        for (i = 0; i < t->n; i++)
                if (lldp_frame_same_msap(t->entries[i]->frame, &t->entries[i]->f, frame, parsed))
                        return (int) i;
        return -1;
}

LldpEvent lldp_table_offer(
                LldpTable *t,
                const uint8_t *frame,
                size_t len,
                const LldpFrame *parsed,
                uint16_t capability_mask,
                uint64_t now) {
        LldpNeighbor *n;
        int i;

        (void) lldp_table_expire(t, now);

        i = find(t, frame, parsed);

        if (parsed->ttl == 0) { /* shutdown */
                if (i < 0)
                        return LLDP_EVENT_IGNORED;
                remove_at(t, (unsigned) i);
                return LLDP_EVENT_REMOVED;
        }

        if (parsed->has_capabilities && (parsed->enabled_capabilities & capability_mask) == 0) {
                /* No longer of interest, and it may be a neighbour that changed its mind. */
                if (i < 0)
                        return LLDP_EVENT_IGNORED;
                remove_at(t, (unsigned) i);
                return LLDP_EVENT_REMOVED;
        }

        if (i >= 0) {
                LldpNeighbor *old = t->entries[i];
                /* Content is everything but the TTL, which changes on its own as the sender's hold time does. */
                bool same = old->len == len && old->f.ttl_off == parsed->ttl_off &&
                                memcmp(old->frame, frame, parsed->ttl_off) == 0 &&
                                memcmp(old->frame + parsed->ttl_off + 2,
                                       frame + parsed->ttl_off + 2,
                                       len - parsed->ttl_off - 2) == 0;

                old->expiry = now + (uint64_t) parsed->ttl * USEC_PER_SEC_U64;
                if (same) {
                        old->f.ttl = parsed->ttl;
                        memcpy(old->frame + parsed->ttl_off, frame + parsed->ttl_off, 2);
                        return LLDP_EVENT_REFRESHED;
                }

                if (old->len != len) {
                        n = realloc(old, sizeof(*n) + len);
                        if (!n)
                                return LLDP_EVENT_NOMEM;
                        t->entries[i] = n;
                } else
                        n = old;
                memcpy(n->frame, frame, len);
                n->len = (uint16_t) len;
                n->f = *parsed;
                n->expiry = now + (uint64_t) parsed->ttl * USEC_PER_SEC_U64;
                return LLDP_EVENT_UPDATED;
        }

        if (t->n >= LLDP_TABLE_MAX)
                return LLDP_EVENT_FULL;

        n = malloc(sizeof(*n) + len);
        if (!n)
                return LLDP_EVENT_NOMEM;
        memcpy(n->frame, frame, len);
        n->len = (uint16_t) len;
        n->f = *parsed;
        n->expiry = now + (uint64_t) parsed->ttl * USEC_PER_SEC_U64;
        t->entries[t->n++] = n;
        return LLDP_EVENT_ADDED;
}
