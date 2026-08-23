/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from src/libsystemd-network/tlv-util.h (85 lines). Missing from
 * plan §2.2's quarry table, and not optional: dhcp-message.h embeds a
 * DhcpTlv by value and dhcp-message.c cannot compile without it. No
 * upstream copyright line.
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. History review
 * (4925d9f07f..main, plan §2.2): no fix in the 26-commit lift-set window
 * touches tlv-util.{c,h}.
 *
 * Redesigned, not just adapted, for one reason: upstream's TLV is a
 * Hashmap of tag -> struct iovec_wrapper (a growable iovec array), and
 * plan §2.2's Support row is explicit that hashmap.h must never enter this
 * lift. DHCPv4 only ever needs TLV_TAG_U8 (options 0-255) with
 * TLV_LENGTH_U8 (RFC 1531's one-byte option length) -- the U16/U32 tag and
 * length widths, and the TLV_DHCP4_VENDOR_IDENTIFYING_OPTION flavour built
 * on a U32 tag (enterprise numbers under option 124/125's sub-TLV), are
 * upstream features this file never exercises, so they are cut rather than
 * carried unused. What is left needs no hashmap at all: since a uint8_t
 * tag has exactly 256 possible values, "hashmap of tag -> value list"
 * becomes "array of 256 buckets, indexed by the tag itself" -- the same
 * move netd-compat.h already made for the parameter-request-list Set, one
 * level up. Every other TLV entry point (append, get, parse, build,
 * iterate, ref-count) keeps upstream's shape and name.
 *
 * TLV_MERGE (splitting an over-length value across multiple same-tag
 * entries, then concatenating them back together as one blob on read) is
 * kept: overload_file-roundtrip and long vendor-class strings both depend
 * on it, and the bucket model makes it cheap -- each bucket is already a
 * growable array of iovecs.
 *
 * Cut with the json block at the tail of the upstream file:
 * tlv_build_json()/tlv_parse_json() (plan §2.2, TLV container row, 13 json
 * references).
 */

#pragma once

/* Self-sufficient regardless of what a consumer includes first (a real
 * cross-agent bug: netd-resolv.c included dhcp-lease-internal.h without
 * netd-compat.h first, and this header needs its bool/usec_t/macros) --
 * safe to include redundantly, netd-compat.h has its own #pragma once. */
#include "netd-compat.h"


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

#define TLV_TAG_PAD UINT32_C(0)
#define TLV_TAG_END UINT32_C(0xFF)

typedef enum TLVFlag {
        TLV_PAD = 1 << 0,        /* tag 0 is a pad byte with no length field */
        TLV_END = 1 << 1,        /* tag 0xFF ends the sequence on parse */
        TLV_APPEND_END = 1 << 2, /* append the END tag on build */
        TLV_MERGE = 1 << 3, /* tlv_get_alloc() concatenates same-tag entries; tlv_append() splits long data */

        /* DHCPv4 top-level options: RFC 1531 tag+len+data, PAD/END/merge all apply. */
        TLV_DHCP4 = TLV_PAD | TLV_END | TLV_APPEND_END | TLV_MERGE,
        /* DHCPv4 sub-options (option 82 Relay Agent Information and similar): PAD is
         * gracefully tolerated though not in the RFC; END is prohibited on build but
         * gracefully accepted on parse, same as upstream. No merge, no appended END. */
        TLV_DHCP4_SUBOPTION = TLV_PAD | TLV_END,
} TLVFlag;

/* One tag's values: possibly more than one iovec when TLV_MERGE split a
 * long append, or when the wire form legitimately repeats a tag. Each
 * iovec's data is heap-owned by the bucket (tlv_done() frees it), except
 * when the tag was populated via tlv_parse() with TLV_TEMPORARY semantics
 * -- netd does not use TLV_TEMPORARY (upstream's zero-copy fast path is
 * not worth the lifetime hazard for a lift this size), so that distinction
 * upstream draws does not exist here: every byte a DhcpTlv holds is always
 * its own copy. */
typedef struct TlvBucket {
        struct iovec *iov;
        size_t count;
        size_t allocated;
} TlvBucket;

typedef struct DhcpTlv {
        unsigned n_ref;
        TLVFlag flags;
        unsigned n_entries;
        /* 256 buckets, one per possible uint8_t tag, indexed directly by
         * the tag value -- see the file header for why this replaces
         * upstream's Hashmap. Zeroed buckets cost zeroed memory, not a
         * hashmap allocation; only a bucket actually written to ever grows
         * an iovec array via GREEDY_REALLOC. */
        TlvBucket buckets[256];
} DhcpTlv;

#define TLV_INIT(f)                                      \
        (DhcpTlv) {                                      \
                .n_ref = 1, .flags = tlv_flags_verify(f) \
        }

TLVFlag tlv_flags_verify(TLVFlag flags);

void tlv_done(DhcpTlv *tlv);
DhcpTlv *tlv_ref(DhcpTlv *p);
DhcpTlv *tlv_unref(DhcpTlv *p);
DhcpTlv *tlv_new(TLVFlag flags);

bool tlv_isempty(const DhcpTlv *tlv);

static inline bool tlv_contains(const DhcpTlv *tlv, uint8_t tag) {
        return tlv && tlv->buckets[tag].count > 0;
}

int tlv_get_full(const DhcpTlv *tlv, uint8_t tag, size_t length, struct iovec *ret);
static inline int tlv_get(const DhcpTlv *tlv, uint8_t tag, struct iovec *ret) {
        return tlv_get_full(tlv, tag, SIZE_MAX, ret);
}
int tlv_get_alloc(const DhcpTlv *tlv, uint8_t tag, struct iovec *ret);

void tlv_remove(DhcpTlv *tlv, uint8_t tag);
int tlv_append(DhcpTlv *tlv, uint8_t tag, size_t length, const void *data);
int tlv_append_tlv(DhcpTlv *tlv, const DhcpTlv *source);

int tlv_parse(DhcpTlv *tlv, const struct iovec *iov);
size_t tlv_size(const DhcpTlv *tlv);
int tlv_build(const DhcpTlv *tlv, struct iovec *ret);
