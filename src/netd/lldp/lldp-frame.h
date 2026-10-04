/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * LLDP frames (IEEE 802.1AB): a strict parser and an encoder, with no I/O and
 * no allocation, so both can be tested and fuzzed on their own.
 *
 * The parser is written for a hostile network. A frame is either accepted
 * whole or rejected whole; every offset it reports lies inside the frame it
 * was given, and nothing in it is copied. The rules, from the standard and
 * from lldpd's decoder (systemd's accepts the three mandatory TLVs in any
 * order, which lets a frame be shaped to confuse other tools):
 *
 *   - ethertype 0x88cc, destination one of the three reserved group
 *     addresses, source a unicast address that is not all zero;
 *   - the first three TLVs are Chassis ID, Port ID and Time To Live, in that
 *     order; their sizes are checked and the ID subtypes must be 1..7;
 *   - the LLDPDU ends with an End TLV of length zero, or ends exactly at a
 *     TLV boundary; whatever follows an End TLV is padding and is ignored;
 *   - an optional TLV with an impossible size is skipped, a repeated one is
 *     ignored (the first wins), unknown types are skipped.
 *
 * Offsets are 16 bit: no accepted frame is longer than LLDP_FRAME_MAX.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LLDP_ETHERTYPE 0x88cc
#define LLDP_ETH_HEADER 14
#define LLDP_ETH_MIN_FRAME 60 /* without FCS; shorter frames are zero padded when sent */

/* Longest frame accepted or built. The standard allows an LLDPDU up to the MTU. */
#define LLDP_FRAME_MAX 1536

typedef enum LldpTlvType {
        LLDP_TLV_END = 0,
        LLDP_TLV_CHASSIS_ID = 1,
        LLDP_TLV_PORT_ID = 2,
        LLDP_TLV_TTL = 3,
        LLDP_TLV_PORT_DESCRIPTION = 4,
        LLDP_TLV_SYSTEM_NAME = 5,
        LLDP_TLV_SYSTEM_DESCRIPTION = 6,
        LLDP_TLV_SYSTEM_CAPABILITIES = 7,
        LLDP_TLV_MANAGEMENT_ADDRESS = 8,
        LLDP_TLV_ORGANIZATION = 127,
} LldpTlvType;

/* Chassis ID subtypes (the ones that need a name here). */
#define LLDP_CHASSIS_SUBTYPE_MAC 4
#define LLDP_CHASSIS_SUBTYPE_LOCAL 7
/* Port ID subtypes. */
#define LLDP_PORT_SUBTYPE_MAC 3
#define LLDP_PORT_SUBTYPE_INTERFACE_NAME 5
#define LLDP_PORT_SUBTYPE_LOCAL 7

/* System capability bits (802.1AB table 8-4). */
#define LLDP_CAP_OTHER (1u << 0)
#define LLDP_CAP_REPEATER (1u << 1)
#define LLDP_CAP_BRIDGE (1u << 2)
#define LLDP_CAP_WLAN_AP (1u << 3)
#define LLDP_CAP_ROUTER (1u << 4)
#define LLDP_CAP_TELEPHONE (1u << 5)
#define LLDP_CAP_DOCSIS (1u << 6)
#define LLDP_CAP_STATION (1u << 7)
#define LLDP_CAP_CVLAN (1u << 8)
#define LLDP_CAP_SVLAN (1u << 9)
#define LLDP_CAP_TPMR (1u << 10)

/* The three group addresses LLDP may be sent to, nearest first. */
typedef enum LldpScope {
        LLDP_SCOPE_NEAREST_BRIDGE,  /* 01:80:c2:00:00:0e */
        LLDP_SCOPE_NON_TPMR_BRIDGE, /* 01:80:c2:00:00:03 */
        LLDP_SCOPE_CUSTOMER_BRIDGE, /* 01:80:c2:00:00:00 */
        _LLDP_SCOPE_MAX,
} LldpScope;

const uint8_t *lldp_scope_address(LldpScope scope);
const char *lldp_scope_to_string(LldpScope scope);

/* A slice of the frame: where the value of a TLV starts and how long it is. len 0 means absent. */
typedef struct LldpSlice {
        uint16_t off;
        uint16_t len;
} LldpSlice;

typedef struct LldpFrame {
        uint8_t src[6];
        LldpScope scope;

        /* The ID values exclude the subtype byte. */
        uint8_t chassis_subtype;
        LldpSlice chassis;
        uint8_t port_subtype;
        LldpSlice port;
        uint16_t ttl; /* seconds; 0 is a shutdown frame */

        LldpSlice port_description;
        LldpSlice system_name;
        LldpSlice system_description;
        LldpSlice mud_url; /* RFC 8520, IANA OUI subtype 1 */

        bool has_capabilities;
        uint16_t capabilities;
        uint16_t enabled_capabilities;

        bool has_port_vlan_id; /* 802.1 organizationally specific, subtype 1 */
        uint16_t port_vlan_id;

        bool has_management_ipv4; /* Management Address TLV carrying an IPv4 address */
        uint8_t management_ipv4[4];
} LldpFrame;

/*
 * Parses `len` bytes at `frame`. 0 on success, -EBADMSG for a frame that
 * breaks a rule above, -EMSGSIZE for one longer than LLDP_FRAME_MAX. `why`,
 * when not NULL, is set to a short static reason for a rejection.
 */
int lldp_frame_parse(const uint8_t *frame, size_t len, LldpFrame *ret, const char **why);

/* The bytes of a slice, for a frame that parsed. */
static inline const uint8_t *lldp_slice_data(const uint8_t *frame, LldpSlice s) {
        return frame + s.off;
}

/* Two frames are the same neighbour (same MSAP: chassis ID and port ID with subtypes). */
bool lldp_frame_same_msap(const uint8_t *a, const LldpFrame *pa, const uint8_t *b, const LldpFrame *pb);

typedef struct LldpBuild {
        uint8_t src[6];
        LldpScope scope;
        uint8_t chassis_subtype;
        const uint8_t *chassis;
        size_t chassis_len; /* 1..255 */
        uint8_t port_subtype;
        const uint8_t *port;
        size_t port_len; /* 1..255 */
        uint16_t ttl;
        const char *port_description; /* NULL or empty: left out; longer than 255 bytes: cut */
        const char *system_name;
        const char *system_description;
        bool has_capabilities;
        uint16_t capabilities;
        uint16_t enabled_capabilities;
        bool has_management_ipv4;
        uint8_t management_ipv4[4];
        int management_ifindex; /* interface number of the management address */
} LldpBuild;

/*
 * Builds a frame into `buf`, padded with zeros to LLDP_ETH_MIN_FRAME. 0 and
 * *ret_len set, -EINVAL for an impossible request, -ENOBUFS if it does not
 * fit in `size`. Control bytes in the strings are replaced by spaces.
 */
int lldp_frame_build(uint8_t *buf, size_t size, const LldpBuild *in, size_t *ret_len);
