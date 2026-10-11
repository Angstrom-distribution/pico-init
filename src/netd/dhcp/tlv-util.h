/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/tlv-util.h. dhcp-message.h
 * embeds a DhcpTlv by value.
 *
 * Redesigned: upstream's TLV is a Hashmap of tag -> struct iovec_wrapper (a
 * growable iovec array), and no hashmap is used here. DHCPv4 only needs
 * TLV_TAG_U8 (options 0-255) with TLV_LENGTH_U8 (RFC 1531's one-byte option
 * length), so the U16/U32 tag and length widths and the
 * TLV_DHCP4_VENDOR_IDENTIFYING_OPTION flavour (U32 tag) are cut. A uint8_t
 * tag has 256 possible values, so the hashmap becomes an array of 256 buckets
 * indexed by the tag. Every other TLV entry point (append, get, parse,
 * build, iterate, ref-count) keeps upstream's shape and name.
 *
 * TLV_MERGE (splitting an over-length value across multiple same-tag
 * entries, concatenating them on read) is kept for long vendor-class strings
 * and the Overload option; each bucket is already a growable iovec array.
 *
 * Cut with the json block at the tail of the upstream file:
 * tlv_build_json()/tlv_parse_json().
 */

#pragma once

/* Self-sufficient: needs bool/usec_t/macros from netd-compat.h. */
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
 * long append, or when the wire form repeats a tag. Each iovec's data is
 * heap-owned by the bucket (tlv_done() frees it); upstream's TLV_TEMPORARY
 * zero-copy mode is not carried. */
typedef struct TlvBucket {
        struct iovec *iov;
        size_t count;
        size_t allocated;
} TlvBucket;

typedef struct DhcpTlv {
        unsigned n_ref;
        TLVFlag flags;
        unsigned n_entries;
        /* One bucket per possible uint8_t tag, indexed by the tag; see the
         * file header. Only a bucket written to ever allocates. */
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
