/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/dhcp-client-id-internal.h
 * and dhcp-duid-internal.h, merged into one file: a DUID only ever exists
 * wrapped inside a DHCPv4 client-id (type 255, RFC 4361) here.
 *
 * Cut on the way in:
 *  - DUID_TYPE_UUID / dhcp_duid_set_uuid(): needs
 *    sd_id128_get_machine_app_specific(), an HMAC-SHA256-based derivation
 *    that is a different primitive than the SipHash-based netd_machine_id()
 *    shim in netd-compat.h. DUID-LLT, DUID-LL and DUID-EN are kept; DUID-EN
 *    has an in-source golden vector (sd-dhcp-duid.c:191), carried in
 *    test-netd-codec.c.
 *  - client_id_hash_func()/client_id_compare_func(): Hashmap/Set key-ops for
 *    a client-id-keyed lease table. The DHCP server lease table is a flat
 *    array, so nothing calls them.
 *  - sd_device support in dhcp_identifier_set_iaid(): netd has no udev
 *    dependency, so only the MAC-address IAID source is carried.
 */

#pragma once

/* Self-sufficient: needs bool/usec_t/macros from netd-compat.h. */
#include "netd-compat.h"

#include "dhcp-protocol.h"

/* RFC 2132 9.14: minimum client-id length is 2 (1 type byte + >=1 data
 * byte); maximum is not specified upstream either, so 255 (the DHCP option
 * length ceiling) is used, same as upstream. */
#define MIN_CLIENT_ID_LEN 2
#define MAX_CLIENT_ID_LEN 255
#define MIN_CLIENT_ID_DATA_LEN (MIN_CLIENT_ID_LEN - 1)
#define MAX_CLIENT_ID_DATA_LEN (MAX_CLIENT_ID_LEN - 1)

/* RFC 8415 11.1: a DUID is a 2-byte type code plus 1-128 bytes of identifier. */
#define MIN_DUID_DATA_LEN 1
#define MAX_DUID_DATA_LEN 128
#define MIN_DUID_LEN (2 + MIN_DUID_DATA_LEN)
#define MAX_DUID_LEN (2 + MAX_DUID_DATA_LEN)

typedef enum DuidType {
        DUID_TYPE_LLT = 1,
        DUID_TYPE_EN = 2,
        DUID_TYPE_LL = 3,
        _DUID_TYPE_MAX,
        _DUID_TYPE_INVALID = -EINVAL,
} DuidType;

typedef struct Duid {
        be16_t type;
        union {
                struct {
                        be16_t htype;
                        be32_t time;
                        uint8_t haddr[HW_ADDR_MAX_SIZE];
                } _packed_ llt;
                struct {
                        be32_t pen;
                        /* RFC 8415 11.3 does not fix a maximum vendor-ID length;
                         * upstream uses 8 bytes and so does the golden
                         * vector, which this must reproduce exactly. */
                        uint8_t id[8];
                } _packed_ en;
                struct {
                        be16_t htype;
                        uint8_t haddr[HW_ADDR_MAX_SIZE];
                } _packed_ ll;
                uint8_t data[MAX_DUID_DATA_LEN];
        };
} _packed_ Duid;

assert_cc(sizeof(Duid) == MAX_DUID_LEN);

typedef struct DhcpDuid {
        size_t size;
        union {
                Duid duid;
                uint8_t raw[MAX_DUID_LEN];
        };
} DhcpDuid;

typedef struct DhcpClientId {
        size_t size;
        union {
                struct {
                        uint8_t type;
                        union {
                                struct {
                                        /* type 0: generic (non-link-layer), RFC 2132 */
                                        uint8_t data[MAX_CLIENT_ID_DATA_LEN];
                                } _packed_ gen;
                                struct {
                                        /* type 1: Ethernet link-layer, RFC 2132 */
                                        uint8_t haddr[6];
                                } _packed_ eth;
                                struct {
                                        /* types 2-254: ARP/link-layer, RFC 2132 */
                                        uint8_t haddr[HW_ADDR_MAX_SIZE];
                                } _packed_ ll;
                                struct {
                                        /* type 255: IAID + DUID, RFC 4361 */
                                        be32_t iaid;
                                        Duid duid;
                                } _packed_ ns;
                                uint8_t data[MAX_CLIENT_ID_DATA_LEN];
                        };
                } _packed_ id;
                uint8_t raw[MAX_CLIENT_ID_LEN];
        };
} DhcpClientId;

assert_cc(sizeof(((DhcpClientId *) 0)->id) <= MAX_CLIENT_ID_LEN);

static inline bool dhcp_client_id_size_is_valid(size_t size) {
        return size >= MIN_CLIENT_ID_LEN && size <= MAX_CLIENT_ID_LEN;
}

/* --- client id --- */

bool dhcp_client_id_is_set(const DhcpClientId *client_id);
int dhcp_client_id_get(const DhcpClientId *client_id, uint8_t *ret_type, const void **ret_data, size_t *ret_size);
int dhcp_client_id_get_raw(const DhcpClientId *client_id, const void **ret_data, size_t *ret_size);
int dhcp_client_id_set(DhcpClientId *client_id, uint8_t type, const void *data, size_t data_size);
int dhcp_client_id_set_raw(DhcpClientId *client_id, const void *data, size_t data_size);
int dhcp_client_id_set_iaid_duid(DhcpClientId *client_id, uint32_t iaid, const DhcpDuid *duid);
int dhcp_client_id_to_string(const DhcpClientId *client_id, char **ret);

/* --- DUID --- */

bool dhcp_duid_is_set(const DhcpDuid *duid);
int dhcp_duid_get(const DhcpDuid *duid, uint16_t *ret_type, const void **ret_data, size_t *ret_size);
int dhcp_duid_set(DhcpDuid *duid, uint16_t type, const void *data, size_t data_size);
int dhcp_duid_set_raw(DhcpDuid *duid, const void *data, size_t data_size);
int dhcp_duid_set_llt(DhcpDuid *duid, const void *hw_addr, size_t hw_addr_size, uint16_t arp_type, usec_t usec);
int dhcp_duid_set_ll(DhcpDuid *duid, const void *hw_addr, size_t hw_addr_size, uint16_t arp_type);
/* Machine-ID-derived DUID-EN (SipHash over /etc/machine-id, SYSTEMD_PEN).
 * With NETD_TEST_MODE set, uses a fixed machine ID and asserts the result
 * against the golden vector from sd-dhcp-duid.c:191. */
int dhcp_duid_set_en(DhcpDuid *duid);
int dhcp_duid_to_string(const DhcpDuid *duid, char **ret);

/* MAC-address path only (see the header). `ret` must point at 4 writable
 * bytes. */
int dhcp_identifier_set_iaid(const struct hw_addr_data *hw_addr, bool legacy_unstable_byteorder, void *ret);
