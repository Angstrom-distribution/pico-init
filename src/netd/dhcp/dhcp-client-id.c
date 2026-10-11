/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/sd-dhcp-client-id.c and
 * sd-dhcp-duid.c. See dhcp-client-id-internal.h for the cut list.
 *
 * sd_id128_get_machine() becomes netd_machine_id() (netd-compat.h), a small
 * /etc/machine-id reader. NETD_TEST_MODE=1 in the environment substitutes a
 * fixed machine ID in dhcp_duid_set_en(), standing in for upstream's
 * network_test_mode_enabled().
 *
 * The offsetof() calls say __typeof__ where upstream says typeof: clang
 * treats the bare spelling as -Wlanguage-extension-token, and the build uses
 * -Werror.
 *
 * sd_dhcp_duid_set_llt()'s time_from_2000y is a uint16_t despite writing into
 * a 32-bit wire field. That is upstream's own code and is kept as is.
 */

#include <byteswap.h>

#include "netd-compat.h"

#include "dhcp-client-id-internal.h"
#include "siphash24.h"
#include "unaligned.h"

#define SYSTEMD_PEN 43793
/* SD_ID128_MAKE(80,11,8c,c2,fe,4a,03,ee,3e,d6,0c,6f,36,39,14,09) */
static const NetdId128 HASH_KEY = {
        { 0x80, 0x11, 0x8c, 0xc2, 0xfe, 0x4a, 0x03, 0xee, 0x3e, 0xd6, 0x0c, 0x6f, 0x36, 0x39, 0x14, 0x09 }
};
/* 2000-01-01 00:00:00 UTC */
#define USEC_2000 ((usec_t) 946684800000000ULL)

static bool netd_test_mode_enabled(void) {
        return getenv("NETD_TEST_MODE") != NULL;
}

/* --- client id --- */

bool dhcp_client_id_is_set(const DhcpClientId *client_id) {
        return client_id && dhcp_client_id_size_is_valid(client_id->size);
}

int dhcp_client_id_get(const DhcpClientId *client_id, uint8_t *ret_type, const void **ret_data, size_t *ret_size) {
        assert_return(dhcp_client_id_is_set(client_id), -EINVAL);
        assert_return(ret_type, -EINVAL);
        assert_return(ret_data, -EINVAL);
        assert_return(ret_size, -EINVAL);

        *ret_type = client_id->id.type;
        *ret_data = client_id->id.data;
        *ret_size = client_id->size - offsetof(__typeof__(client_id->id), data);
        return 0;
}

int dhcp_client_id_get_raw(const DhcpClientId *client_id, const void **ret_data, size_t *ret_size) {
        assert_return(dhcp_client_id_is_set(client_id), -EINVAL);
        assert_return(ret_data, -EINVAL);
        assert_return(ret_size, -EINVAL);

        *ret_data = client_id->raw;
        *ret_size = client_id->size;
        return 0;
}

int dhcp_client_id_set(DhcpClientId *client_id, uint8_t type, const void *data, size_t data_size) {
        assert_return(client_id, -EINVAL);
        assert_return(data, -EINVAL);

        if (data_size < MIN_CLIENT_ID_DATA_LEN || data_size > MAX_CLIENT_ID_DATA_LEN)
                return -EINVAL;

        client_id->id.type = type;
        memcpy(client_id->id.data, data, data_size);

        client_id->size = offsetof(__typeof__(client_id->id), data) + data_size;
        return 0;
}

int dhcp_client_id_set_raw(DhcpClientId *client_id, const void *data, size_t data_size) {
        assert_return(client_id, -EINVAL);
        assert_return(data, -EINVAL);

        if (!dhcp_client_id_size_is_valid(data_size))
                return -EINVAL;

        memcpy(client_id->raw, data, data_size);
        client_id->size = data_size;
        return 0;
}

int dhcp_client_id_set_iaid_duid(DhcpClientId *client_id, uint32_t iaid, const DhcpDuid *duid) {
        assert_return(client_id, -EINVAL);
        assert_return(duid, -EINVAL);
        assert_return(dhcp_duid_is_set(duid), -ESTALE);

        client_id->id.type = 255;
        unaligned_write_be32(&client_id->id.ns.iaid, iaid);
        memcpy(&client_id->id.ns.duid, &duid->duid, duid->size);

        client_id->size = offsetof(__typeof__(client_id->id), ns.duid) + duid->size;
        return 0;
}

int dhcp_client_id_to_string(const DhcpClientId *client_id, char **ret) {
        _cleanup_free_ char *t = NULL;
        size_t len;
        int r;

        assert_return(dhcp_client_id_is_set(client_id), -EINVAL);
        assert_return(ret, -EINVAL);

        len = client_id->size - offsetof(__typeof__(client_id->id), data);

        switch (client_id->id.type) {
        case 0:
                r = asprintf(&t, "DATA(%zu)", len);
                break;
        case 1:
                if (len == sizeof(client_id->id.eth.haddr))
                        r = asprintf(&t,
                                     "%02x:%02x:%02x:%02x:%02x:%02x",
                                     client_id->id.eth.haddr[0],
                                     client_id->id.eth.haddr[1],
                                     client_id->id.eth.haddr[2],
                                     client_id->id.eth.haddr[3],
                                     client_id->id.eth.haddr[4],
                                     client_id->id.eth.haddr[5]);
                else
                        r = asprintf(&t, "ETHER");
                break;
        case 255:
                if (len < sizeof(uint32_t))
                        r = asprintf(&t, "IAID/DUID");
                else
                        r = asprintf(&t, "IAID:0x%x/DUID", be32toh(client_id->id.ns.iaid));
                break;
        default:
                r = asprintf(&t, "ARP/LL");
                break;
        }
        if (r < 0)
                return -ENOMEM;

        *ret = TAKE_PTR(t);
        return 0;
}

/* --- DUID --- */

bool dhcp_duid_is_set(const DhcpDuid *duid) {
        return duid && duid->size >= MIN_DUID_LEN && duid->size <= MAX_DUID_LEN;
}

int dhcp_duid_get(const DhcpDuid *duid, uint16_t *ret_type, const void **ret_data, size_t *ret_size) {
        assert_return(dhcp_duid_is_set(duid), -EINVAL);
        assert_return(ret_type, -EINVAL);
        assert_return(ret_data, -EINVAL);
        assert_return(ret_size, -EINVAL);

        *ret_type = be16toh(duid->duid.type);
        *ret_data = duid->duid.data;
        *ret_size = duid->size - offsetof(Duid, data);
        return 0;
}

int dhcp_duid_set(DhcpDuid *duid, uint16_t type, const void *data, size_t data_size) {
        assert_return(duid, -EINVAL);
        assert_return(data, -EINVAL);

        if (data_size < MIN_DUID_DATA_LEN || data_size > MAX_DUID_DATA_LEN)
                return -EINVAL;

        unaligned_write_be16(&duid->duid.type, type);
        memcpy(duid->duid.data, data, data_size);

        duid->size = offsetof(Duid, data) + data_size;
        return 0;
}

int dhcp_duid_set_raw(DhcpDuid *duid, const void *data, size_t data_size) {
        assert_return(duid, -EINVAL);
        assert_return(data, -EINVAL);

        if (data_size < MIN_DUID_LEN || data_size > MAX_DUID_LEN)
                return -EINVAL;

        memcpy(duid->raw, data, data_size);
        duid->size = data_size;
        return 0;
}

int dhcp_duid_set_llt(DhcpDuid *duid, const void *hw_addr, size_t hw_addr_size, uint16_t arp_type, usec_t usec) {
        uint16_t time_from_2000y;

        assert_return(duid, -EINVAL);
        assert_return(hw_addr, -EINVAL);
        assert_return(hw_addr_size <= HW_ADDR_MAX_SIZE, -EINVAL);

        time_from_2000y = (uint16_t) ((usec_sub_unsigned(usec, USEC_2000) / USEC_PER_SEC) & 0xffffffffULL);

        unaligned_write_be16(&duid->duid.type, DUID_TYPE_LLT);
        unaligned_write_be16(&duid->duid.llt.htype, arp_type);
        unaligned_write_be32(&duid->duid.llt.time, time_from_2000y);
        memcpy(duid->duid.llt.haddr, hw_addr, hw_addr_size);

        duid->size = offsetof(Duid, llt.haddr) + hw_addr_size;
        return 0;
}

int dhcp_duid_set_ll(DhcpDuid *duid, const void *hw_addr, size_t hw_addr_size, uint16_t arp_type) {
        assert_return(duid, -EINVAL);
        assert_return(hw_addr, -EINVAL);
        assert_return(hw_addr_size <= HW_ADDR_MAX_SIZE, -EINVAL);

        unaligned_write_be16(&duid->duid.type, DUID_TYPE_LL);
        unaligned_write_be16(&duid->duid.ll.htype, arp_type);
        memcpy(duid->duid.ll.haddr, hw_addr, hw_addr_size);

        duid->size = offsetof(Duid, ll.haddr) + hw_addr_size;
        return 0;
}

int dhcp_duid_set_en(DhcpDuid *duid) {
        NetdId128 machine_id;
        bool test_mode;
        uint64_t hash;
        int r;

        assert_return(duid, -EINVAL);

        test_mode = netd_test_mode_enabled();

        if (!test_mode) {
                r = netd_machine_id(&machine_id);
                if (r < 0)
                        return r;
        } else
                /* Reproducibility for tests/fuzzers:
                 * 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10. */
                machine_id = (NetdId128){
                        .bytes = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 }
                };

        unaligned_write_be16(&duid->duid.type, DUID_TYPE_EN);
        unaligned_write_be32(&duid->duid.en.pen, SYSTEMD_PEN);

        /* No need to expose the machine ID directly; duid->en.id might not be
         * aligned, so copy rather than cast. */
        hash = htole64(siphash24(&machine_id, sizeof(machine_id), HASH_KEY.bytes));
        memcpy(duid->duid.en.id, &hash, sizeof(hash));

        duid->size = offsetof(Duid, en.id) + sizeof(hash);

        if (test_mode)
                /* Golden vector: catches a regression in SipHash, HASH_KEY, byte
                 * order or the DUID-EN layout. */
                assert(memcmp(&duid->duid,
                              (const uint8_t[]){ 0x00,
                                                 0x02,
                                                 0x00,
                                                 0x00,
                                                 0xab,
                                                 0x11,
                                                 0x61,
                                                 0x77,
                                                 0x40,
                                                 0xde,
                                                 0x13,
                                                 0x42,
                                                 0xc3,
                                                 0xa2 },
                              duid->size) == 0);

        return 0;
}

int dhcp_duid_to_string(const DhcpDuid *duid, char **ret) {
        uint16_t type;
        const void *data;
        size_t data_size;
        int r;
        _cleanup_free_ char *x = NULL;

        assert_return(dhcp_duid_is_set(duid), -EINVAL);
        assert_return(ret, -EINVAL);

        r = dhcp_duid_get(duid, &type, &data, &data_size);
        if (r < 0)
                return r;

        x = new (char, data_size * 2 + 1);
        if (!x)
                return -ENOMEM;
        for (size_t i = 0; i < data_size; i++)
                sprintf(x + i * 2, "%02x", ((const uint8_t *) data)[i]);

        r = asprintf(ret, "DUID(0x%04x):%s", type, x);
        return r < 0 ? -ENOMEM : 0;
}

/* --- IAID --- */

int dhcp_identifier_set_iaid(const struct hw_addr_data *hw_addr, bool legacy_unstable_byteorder, void *ret) {
        uint32_t id32;
        uint64_t id;

        assert(hw_addr);
        assert(ret);

        /* No sd_device/persistent-name source; always derive from the MAC. */
        id = siphash24(hw_addr->bytes, hw_addr->length, HASH_KEY.bytes);

        id32 = (uint32_t) ((id & 0xffffffff) ^ (id >> 32));

        if (legacy_unstable_byteorder)
                /* Historical (buggy) endianness-dependent behaviour, preserved
                 * for compatibility as upstream itself does. */
                id32 = bswap_32(id32);
        else
                id32 = be32toh(id32);

        unaligned_write_ne32(ret, id32);
        return 0;
}
