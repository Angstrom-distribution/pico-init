/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * See lldp-frame.h for the rules. Shaped after lldpd's decoder (strict
 * position of the mandatory TLVs, subtype checks, first-one-wins for the
 * optional ones) and systemd's frame builder (the same TLV set), written to
 * allocate nothing: the parser only reads, the builder writes into the buffer
 * it is given.
 */

#include <errno.h>
#include <string.h>

#include "lldp-frame.h"

static const uint8_t scope_address[_LLDP_SCOPE_MAX][6] = {
        [LLDP_SCOPE_NEAREST_BRIDGE] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e },
        [LLDP_SCOPE_NON_TPMR_BRIDGE] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 },
        [LLDP_SCOPE_CUSTOMER_BRIDGE] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 },
};

static const uint8_t oui_802_1[3] = { 0x00, 0x80, 0xc2 };
static const uint8_t oui_iana[3] = { 0x00, 0x00, 0x5e };

const uint8_t *lldp_scope_address(LldpScope scope) {
        if ((unsigned) scope >= _LLDP_SCOPE_MAX)
                return NULL;
        return scope_address[scope];
}

const char *lldp_scope_to_string(LldpScope scope) {
        switch (scope) {
        case LLDP_SCOPE_NEAREST_BRIDGE:
                return "nearest-bridge";
        case LLDP_SCOPE_NON_TPMR_BRIDGE:
                return "non-tpmr-bridge";
        case LLDP_SCOPE_CUSTOMER_BRIDGE:
                return "customer-bridge";
        default:
                return "invalid";
        }
}

static uint16_t be16(const uint8_t *p) {
        return (uint16_t) ((p[0] << 8) | p[1]);
}

static int reject(const char **why, const char *reason) {
        if (why)
                *why = reason;
        return -EBADMSG;
}

/* Which scope, if any, a destination address is. */
static bool scope_from_destination(const uint8_t *dst, LldpScope *ret) {
        int i;

        for (i = 0; i < _LLDP_SCOPE_MAX; i++)
                if (memcmp(dst, scope_address[i], 6) == 0) {
                        *ret = (LldpScope) i;
                        return true;
                }
        return false;
}

/* A Management Address TLV value; picks out the first IPv4 address, ignores anything it cannot make sense of. */
static void parse_management_address(const uint8_t *v, size_t len, LldpFrame *f) {
        size_t addr_len, oid_off;

        if (f->has_management_ipv4 || len < 1)
                return;

        addr_len = v[0]; /* the subtype byte plus the address */
        if (addr_len < 2 || addr_len > 32)
                return;
        /* address string, interface numbering subtype (1) and number (4), OID length (1) */
        if (len < 1 + addr_len + 1 + 4 + 1)
                return;
        oid_off = 1 + addr_len + 1 + 4;
        if (len < oid_off + 1 + (size_t) v[oid_off] || v[oid_off] > 128)
                return;

        if (addr_len == 5 && v[1] == 1) { /* IANA address family 1: IPv4 */
                memcpy(f->management_ipv4, v + 2, 4);
                f->has_management_ipv4 = true;
        }
}

int lldp_frame_parse(const uint8_t *frame, size_t len, LldpFrame *ret, const char **why) {
        LldpFrame f;
        size_t pos = LLDP_ETH_HEADER;
        unsigned index = 0;
        bool seen_descr = false, seen_name = false, seen_sysdescr = false, seen_end = false;

        if (!frame || !ret)
                return -EINVAL;
        if (len > LLDP_FRAME_MAX) {
                if (why)
                        *why = "frame too long";
                return -EMSGSIZE;
        }
        if (len < LLDP_ETH_HEADER + 6)
                return reject(why, "frame too short");

        memset(&f, 0, sizeof(f));

        if (be16(frame + 12) != LLDP_ETHERTYPE)
                return reject(why, "not an LLDP frame");
        if (!scope_from_destination(frame, &f.scope))
                return reject(why, "not sent to an LLDP group address");

        memcpy(f.src, frame + 6, 6);
        if (f.src[0] & 1)
                return reject(why, "source address is a group address");
        if (!(f.src[0] | f.src[1] | f.src[2] | f.src[3] | f.src[4] | f.src[5]))
                return reject(why, "source address is all zero");

        while (pos < len) {
                const uint8_t *v;
                unsigned type;
                size_t length;

                if (len - pos < 2)
                        return reject(why, "truncated TLV header");

                type = frame[pos] >> 1;
                length = ((size_t) (frame[pos] & 1) << 8) | frame[pos + 1];
                pos += 2;
                if (length > len - pos)
                        return reject(why, "TLV overruns the frame");
                v = frame + pos;
                index++;

                /* The first three TLVs are fixed; those types may appear nowhere else. */
                if (index <= 3 ? type != index : type >= 1 && type <= 3)
                        return reject(why, "mandatory TLVs missing or out of order");

                switch (type) {
                case LLDP_TLV_END:
                        if (length != 0)
                                return reject(why, "End TLV is not empty");
                        seen_end = true;
                        break;

                case LLDP_TLV_CHASSIS_ID:
                case LLDP_TLV_PORT_ID:
                        if (length < 2 || length > 256)
                                return reject(why, "ID TLV size out of range");
                        if (v[0] < 1 || v[0] > 7)
                                return reject(why, "ID subtype out of range");
                        if (type == LLDP_TLV_CHASSIS_ID) {
                                f.chassis_subtype = v[0];
                                f.chassis = (LldpSlice){ (uint16_t) (pos + 1), (uint16_t) (length - 1) };
                        } else {
                                f.port_subtype = v[0];
                                f.port = (LldpSlice){ (uint16_t) (pos + 1), (uint16_t) (length - 1) };
                        }
                        break;

                case LLDP_TLV_TTL:
                        if (length != 2)
                                return reject(why, "TTL TLV has the wrong size");
                        f.ttl = be16(v);
                        break;

                case LLDP_TLV_PORT_DESCRIPTION:
                        if (!seen_descr && length >= 1 && length <= 255) {
                                f.port_description = (LldpSlice){ (uint16_t) pos, (uint16_t) length };
                                seen_descr = true;
                        }
                        break;
                case LLDP_TLV_SYSTEM_NAME:
                        if (!seen_name && length >= 1 && length <= 255) {
                                f.system_name = (LldpSlice){ (uint16_t) pos, (uint16_t) length };
                                seen_name = true;
                        }
                        break;
                case LLDP_TLV_SYSTEM_DESCRIPTION:
                        if (!seen_sysdescr && length >= 1 && length <= 255) {
                                f.system_description = (LldpSlice){ (uint16_t) pos, (uint16_t) length };
                                seen_sysdescr = true;
                        }
                        break;

                case LLDP_TLV_SYSTEM_CAPABILITIES:
                        if (!f.has_capabilities && length == 4) {
                                f.capabilities = be16(v);
                                f.enabled_capabilities = be16(v + 2);
                                f.has_capabilities = true;
                        }
                        break;

                case LLDP_TLV_MANAGEMENT_ADDRESS:
                        parse_management_address(v, length, &f);
                        break;

                case LLDP_TLV_ORGANIZATION:
                        if (length < 4)
                                break;
                        if (memcmp(v, oui_802_1, 3) == 0 && v[3] == 1) {
                                if (!f.has_port_vlan_id && length == 6) {
                                        f.port_vlan_id = be16(v + 4);
                                        f.has_port_vlan_id = true;
                                }
                        } else if (memcmp(v, oui_iana, 3) == 0 && v[3] == 1) {
                                if (f.mud_url.len == 0 && length > 4 && length - 4 <= 255)
                                        f.mud_url = (LldpSlice){ (uint16_t) (pos + 4),
                                                                 (uint16_t) (length - 4) };
                        }
                        break;

                default:
                        break; /* reserved and unknown types are skipped */
                }

                pos += length;
                if (seen_end)
                        break; /* whatever follows is padding */
        }

        if (index < 3)
                return reject(why, "mandatory TLVs missing");

        *ret = f;
        return 0;
}

bool lldp_frame_same_msap(const uint8_t *a, const LldpFrame *pa, const uint8_t *b, const LldpFrame *pb) {
        return pa->chassis_subtype == pb->chassis_subtype && pa->chassis.len == pb->chassis.len &&
                        pa->port_subtype == pb->port_subtype && pa->port.len == pb->port.len &&
                        memcmp(a + pa->chassis.off, b + pb->chassis.off, pa->chassis.len) == 0 &&
                        memcmp(a + pa->port.off, b + pb->port.off, pa->port.len) == 0;
}

/* --- building --- */

static int put_header(uint8_t *buf, size_t size, size_t *pos, unsigned type, size_t length) {
        if (type > 127 || length > 511)
                return -EINVAL;
        if (size - *pos < 2 + length)
                return -ENOBUFS;
        buf[(*pos)++] = (uint8_t) ((type << 1) | (length >> 8));
        buf[(*pos)++] = (uint8_t) (length & 0xff);
        return 0;
}

/* An ID TLV: the subtype byte, then the value. */
static int
                put_id(uint8_t *buf,
                       size_t size,
                       size_t *pos,
                       unsigned type,
                       uint8_t subtype,
                       const uint8_t *id,
                       size_t id_len) {
        int r = put_header(buf, size, pos, type, 1 + id_len);

        if (r < 0)
                return r;
        buf[(*pos)++] = subtype;
        memcpy(buf + *pos, id, id_len);
        *pos += id_len;
        return 0;
}

static int put_string(uint8_t *buf, size_t size, size_t *pos, unsigned type, const char *s) {
        size_t n, i;
        int r;

        if (!s || !*s)
                return 0;
        n = strnlen(s, 255);

        r = put_header(buf, size, pos, type, n);
        if (r < 0)
                return r;
        for (i = 0; i < n; i++) {
                uint8_t c = (uint8_t) s[i];

                buf[(*pos)++] = c < 0x20 || c == 0x7f ? ' ' : c;
        }
        return 0;
}

int lldp_frame_build(uint8_t *buf, size_t size, const LldpBuild *in, size_t *ret_len) {
        size_t pos = LLDP_ETH_HEADER;
        int r;

        if (!buf || !in || !ret_len || !lldp_scope_address(in->scope))
                return -EINVAL;
        if (!in->chassis || in->chassis_len < 1 || in->chassis_len > 255 || in->chassis_subtype < 1 ||
            in->chassis_subtype > 7)
                return -EINVAL;
        if (!in->port || in->port_len < 1 || in->port_len > 255 || in->port_subtype < 1 || in->port_subtype > 7)
                return -EINVAL;
        if (size < LLDP_ETH_MIN_FRAME)
                return -ENOBUFS;

        memcpy(buf, lldp_scope_address(in->scope), 6);
        memcpy(buf + 6, in->src, 6);
        buf[12] = LLDP_ETHERTYPE >> 8;
        buf[13] = LLDP_ETHERTYPE & 0xff;

        /* The three mandatory TLVs, in their fixed order. */
        r = put_id(buf, size, &pos, LLDP_TLV_CHASSIS_ID, in->chassis_subtype, in->chassis, in->chassis_len);
        if (r < 0)
                return r;
        r = put_id(buf, size, &pos, LLDP_TLV_PORT_ID, in->port_subtype, in->port, in->port_len);
        if (r < 0)
                return r;
        r = put_header(buf, size, &pos, LLDP_TLV_TTL, 2);
        if (r < 0)
                return r;
        buf[pos++] = (uint8_t) (in->ttl >> 8);
        buf[pos++] = (uint8_t) (in->ttl & 0xff);

        r = put_string(buf, size, &pos, LLDP_TLV_PORT_DESCRIPTION, in->port_description);
        if (r < 0)
                return r;
        r = put_string(buf, size, &pos, LLDP_TLV_SYSTEM_NAME, in->system_name);
        if (r < 0)
                return r;
        r = put_string(buf, size, &pos, LLDP_TLV_SYSTEM_DESCRIPTION, in->system_description);
        if (r < 0)
                return r;

        if (in->has_capabilities) {
                r = put_header(buf, size, &pos, LLDP_TLV_SYSTEM_CAPABILITIES, 4);
                if (r < 0)
                        return r;
                buf[pos++] = (uint8_t) (in->capabilities >> 8);
                buf[pos++] = (uint8_t) (in->capabilities & 0xff);
                buf[pos++] = (uint8_t) (in->enabled_capabilities >> 8);
                buf[pos++] = (uint8_t) (in->enabled_capabilities & 0xff);
        }

        if (in->has_management_ipv4) {
                uint32_t ifindex = (uint32_t) in->management_ifindex;

                /* address length 5, IPv4, address, interface number subtype 2 (ifIndex), number, OID length 0 */
                r = put_header(buf, size, &pos, LLDP_TLV_MANAGEMENT_ADDRESS, 12);
                if (r < 0)
                        return r;
                buf[pos++] = 5;
                buf[pos++] = 1;
                memcpy(buf + pos, in->management_ipv4, 4);
                pos += 4;
                buf[pos++] = 2;
                buf[pos++] = (uint8_t) (ifindex >> 24);
                buf[pos++] = (uint8_t) (ifindex >> 16);
                buf[pos++] = (uint8_t) (ifindex >> 8);
                buf[pos++] = (uint8_t) ifindex;
                buf[pos++] = 0;
        }

        r = put_header(buf, size, &pos, LLDP_TLV_END, 0);
        if (r < 0)
                return r;

        if (pos < LLDP_ETH_MIN_FRAME) {
                memset(buf + pos, 0, LLDP_ETH_MIN_FRAME - pos);
                pos = LLDP_ETH_MIN_FRAME;
        }

        *ret_len = pos;
        return 0;
}
