/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/tlv-util.c, redesigned
 * around a flat 256-bucket array instead of upstream's Hashmap (see
 * tlv-util.h).
 *
 * Assertion policy (netd-compat.h): every length read off the wire in
 * tlv_parse() is externally supplied, so those checks are
 * netd_validate()/-EBADMSG, never assert(). tlv_flags_verify() and the
 * tag/length-width switches assert on flag combinations netd's own code
 * passes as constants (TLV_DHCP4, TLV_DHCP4_SUBOPTION): internal invariants,
 * not packet input.
 */

#include "netd-compat.h"

#include "tlv-util.h"

#define FLAGS_SET(flags, flag) (((flags) & (flag)) == (flag))


/* Overflow-saturating arithmetic (upstream's size_add()/size_multiply()):
 * both saturate at SIZE_MAX rather than wrapping. */
static size_t size_add(size_t a, size_t b) {
        size_t r = a + b;
        return r < a ? SIZE_MAX : r;
}

static size_t size_multiply(size_t a, size_t b) {
        if (a != 0 && b > SIZE_MAX / a)
                return SIZE_MAX;
        return a * b;
}

TLVFlag tlv_flags_verify(TLVFlag flags) {
        /* Internal invariant: only netd's own two constant flavours (TLV_DHCP4,
         * TLV_DHCP4_SUBOPTION) are ever passed here. */
        assert(!(flags & ~(TLV_PAD | TLV_END | TLV_APPEND_END | TLV_MERGE)));
        assert(!FLAGS_SET(flags, TLV_APPEND_END) || FLAGS_SET(flags, TLV_END));

        return flags;
}

static void tlv_bucket_done(TlvBucket *b) {
        FOREACH_ARRAY(iov, b->iov, b->count)
        mfree(iov->iov_base);
        mfree(b->iov);
        *b = (TlvBucket){ 0 };
}

void tlv_done(DhcpTlv *tlv) {
        assert(tlv);

        FOREACH_ELEMENT(b, tlv->buckets)
        tlv_bucket_done(b);
        tlv->n_entries = 0;
}

static DhcpTlv *tlv_free(DhcpTlv *tlv) {
        if (!tlv)
                return NULL;

        tlv_done(tlv);
        return mfree(tlv);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DhcpTlv, tlv, tlv_free);

DhcpTlv *tlv_new(TLVFlag flags) {
        DhcpTlv *tlv = new0(DhcpTlv, 1);
        if (!tlv)
                return NULL;

        *tlv = TLV_INIT(flags);
        return tlv;
}

bool tlv_isempty(const DhcpTlv *tlv) {
        return !tlv || tlv->n_entries == 0;
}

static const TlvBucket *tlv_bucket(const DhcpTlv *tlv, uint8_t tag) {
        assert(tlv);
        return &tlv->buckets[tag];
}

int tlv_get_full(const DhcpTlv *tlv, uint8_t tag, size_t length, struct iovec *ret) {
        assert(tlv);

        const TlvBucket *b = tlv_bucket(tlv, tag);
        if (b->count == 0)
                return -ENODATA;

        /* Local non-const alias: through a pointer-to-const, b->iov would be
         * `struct iovec *const`, which FOREACH_ARRAY cannot increment. */
        struct iovec *entries = b->iov;

        /* When multiple entries exist, use the first one matching the length. */
        FOREACH_ARRAY(iov, entries, b->count) {
                if (length != SIZE_MAX && iov->iov_len != length)
                        continue;

                if (ret)
                        *ret = *iov;
                return 0;
        }

        return -ENODATA;
}

int tlv_get_alloc(const DhcpTlv *tlv, uint8_t tag, struct iovec *ret) {
        assert(tlv);

        const TlvBucket *b = tlv_bucket(tlv, tag);
        if (b->count == 0)
                return -ENODATA;

        if (!ret)
                return 0;

        struct iovec *entries = b->iov; /* see tlv_get_full()'s comment */

        if (FLAGS_SET(tlv->flags, TLV_MERGE)) {
                /* Concatenate every same-tag entry, plus one byte so the result
                 * can double as a NUL-terminated string
                 * (dhcp_message_get_option_string() relies on this). */
                size_t total = 0;
                FOREACH_ARRAY(iov, entries, b->count)
                total = size_add(total, iov->iov_len);
                if (total == SIZE_MAX)
                        return -ENOBUFS;

                uint8_t *buf = new (uint8_t, total + 1);
                if (!buf)
                        return -ENOMEM;

                uint8_t *p = buf;
                FOREACH_ARRAY(iov, entries, b->count) {
                        memcpy(p, iov->iov_base, iov->iov_len);
                        p += iov->iov_len;
                }
                *p = 0;

                *ret = (struct iovec){ .iov_base = buf, .iov_len = total };
                return 0;
        }

        /* No merge: hand back a copy of the first entry only. */
        void *copy = netd_memdup(b->iov[0].iov_base, b->iov[0].iov_len + 1);
        if (!copy)
                return -ENOMEM;

        *ret = (struct iovec){ .iov_base = copy, .iov_len = b->iov[0].iov_len };
        return 0;
}

void tlv_remove(DhcpTlv *tlv, uint8_t tag) {
        assert(tlv);

        TlvBucket *b = &tlv->buckets[tag];
        assert(tlv->n_entries >= b->count);
        tlv->n_entries -= b->count;
        tlv_bucket_done(b);
}

static int tlv_bucket_add(TlvBucket *b, size_t length, const void *data) {
        /* Not GREEDY_REALLOC(): it token-pastes "_allocated" onto the array
         * name to find its counter, which only works for a bare local, not
         * TlvBucket's "allocated" member. */
        if (!netd_greedy_realloc((void **) &b->iov, b->count + 1, sizeof(b->iov[0]), &b->allocated))
                return -ENOMEM;

        void *copy = netd_memdup(data, length);
        if (length > 0 && !copy)
                return -ENOMEM;

        b->iov[b->count++] = (struct iovec){ .iov_base = copy, .iov_len = length };
        return 0;
}

static int tlv_append_impl(DhcpTlv *tlv, uint8_t tag, size_t length, const void *data) {
        int r;

        assert(tlv);
        assert(length == 0 || data);

        r = tlv_bucket_add(&tlv->buckets[tag], length, data);
        if (r < 0)
                return r;

        tlv->n_entries++;
        return 0;
}

int tlv_append(DhcpTlv *tlv, uint8_t tag, size_t length, const void *data) {
        int r;

        assert(tlv);
        assert(length == 0 || data);

        if ((FLAGS_SET(tlv->flags, TLV_PAD) && tag == TLV_TAG_PAD) ||
            (FLAGS_SET(tlv->flags, TLV_END) && tag == TLV_TAG_END))
                return -EINVAL;

        if (FLAGS_SET(tlv->flags, TLV_MERGE) && length > UINT8_MAX) {
                /* Split data over multiple same-tag entries; the caller must
                 * discard everything on failure (upstream's contract too). */
                const uint8_t *p = data;
                while (length > UINT8_MAX) {
                        r = tlv_append_impl(tlv, tag, UINT8_MAX, p);
                        if (r < 0)
                                return r;

                        p += UINT8_MAX;
                        length -= UINT8_MAX;
                }

                return tlv_append_impl(tlv, tag, length, p);
        }

        if (length > UINT8_MAX)
                return -EINVAL;

        return tlv_append_impl(tlv, tag, length, data);
}

int tlv_append_tlv(DhcpTlv *tlv, const DhcpTlv *source) {
        int r;

        assert(tlv);

        if (!source)
                return 0;
        if (source == tlv)
                return -EINVAL;

        for (unsigned tag = 0; tag < 256; tag++) {
                const TlvBucket *b = &source->buckets[tag];
                struct iovec *entries = b->iov; /* see tlv_get_full()'s comment */

                FOREACH_ARRAY(iov, entries, b->count) {
                        r = tlv_append(tlv, (uint8_t) tag, iov->iov_len, iov->iov_base);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

int tlv_parse(DhcpTlv *tlv, const struct iovec *iov) {
        int r;

        assert(tlv);

        if (!iov || !iov->iov_base || iov->iov_len == 0)
                return 0;

        const uint8_t *p = iov->iov_base;
        size_t left = iov->iov_len;

        while (left > 0) {
                uint8_t tag = *p++;
                left--;

                if (FLAGS_SET(tlv->flags, TLV_PAD) && tag == TLV_TAG_PAD)
                        continue;
                if (FLAGS_SET(tlv->flags, TLV_END) && tag == TLV_TAG_END)
                        break;

                /* Externally-supplied packet data: a real error, not an assert. */
                netd_validate(left >= 1, -EBADMSG);
                uint8_t len = *p++;
                left--;

                netd_validate(left >= len, -EBADMSG);

                r = tlv_append_impl(tlv, tag, len, p);
                if (r < 0)
                        return r;

                p += len;
                left -= len;
        }

        return 0;
}

size_t tlv_size(const DhcpTlv *tlv) {
        assert(tlv);

        /* Every DHCPv4 flavour netd carries uses a 1-byte tag + 1-byte length
         * header per entry (see tlv-util.h). */
        size_t sz = FLAGS_SET(tlv->flags, TLV_APPEND_END) ? 1 : 0;

        FOREACH_ELEMENT(b, tlv->buckets) {
                if (b->count == 0)
                        continue;

                sz = size_add(sz, size_multiply(2, b->count));
                struct iovec *entries = b->iov; /* see tlv_get_full()'s comment */
                FOREACH_ARRAY(iov, entries, b->count)
                sz = size_add(sz, iov->iov_len);
        }

        return sz;
}

int tlv_build(const DhcpTlv *tlv, struct iovec *ret) {
        assert(tlv);
        assert(ret);

        size_t sz = tlv_size(tlv);
        if (sz == SIZE_MAX)
                return -ENOBUFS;

        uint8_t *buf = new (uint8_t, sz);
        if (!buf)
                return -ENOMEM;

        uint8_t *p = buf;
        for (unsigned tag = 0; tag < 256; tag++) {
                const TlvBucket *b = &tlv->buckets[tag];
                if (b->count == 0)
                        continue;

                if ((FLAGS_SET(tlv->flags, TLV_PAD) && tag == TLV_TAG_PAD) ||
                    (FLAGS_SET(tlv->flags, TLV_END) && tag == TLV_TAG_END)) {
                        free(buf);
                        return -EINVAL;
                }

                struct iovec *entries = b->iov; /* see tlv_get_full()'s comment */
                FOREACH_ARRAY(iov, entries, b->count) {
                        if (iov->iov_len > UINT8_MAX) {
                                free(buf);
                                return -EINVAL;
                        }

                        *p++ = (uint8_t) tag;
                        *p++ = (uint8_t) iov->iov_len;
                        if (iov->iov_len > 0) {
                                memcpy(p, iov->iov_base, iov->iov_len);
                                p += iov->iov_len;
                        }
                }
        }

        if (FLAGS_SET(tlv->flags, TLV_APPEND_END))
                *p++ = TLV_TAG_END;

        assert(sz == (size_t) (p - buf));

        *ret = (struct iovec){ .iov_base = buf, .iov_len = sz };
        return 0;
}
