/* SPDX-FileCopyrightText: 2013 Intel Corporation */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from src/libsystemd-network/dhcp-protocol.h (104 lines) plus the
 * option-code enum from src/systemd/sd-dhcp-protocol.h (public header,
 * folded in here since netd ships no separate library API surface), and a
 * minimal hardware-address type standing in for src/basic/ether-addr-util.h
 * (out of the lift set; netd has no other user of it).
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. History review
 * (4925d9f07f..main, plan §2.2) covered dhcp-protocol.h in the 26-commit
 * lift-set window and found no fix touching this file; the window's one
 * backport-worthy commit, 7bd9f0f805 ("dhcp-server: reject pool offsets
 * beyond the subnet"), touches sd-dhcp-server.c only -- not carried here,
 * see dhcp-lease-internal.h and the final report for the forward note to
 * the server agent.
 *
 * Cut on the way in: DHCP_MAX_FQDN_LENGTH and the DHCP_FQDN_FLAG_* enum
 * (option 81 is cut, plan §2.1); DHCP_RELAY_AGENT_FLAG_* and the relay
 * sub-option enum (relay is not part of this lift). MIN_V6ONLY_WAIT_USEC is
 * kept even though netd does not request option 108 today -- it is a
 * one-line RFC constant, not a dependency magnet, so there is no reason to
 * drop it ahead of need.
 *
 * Every header in this lift set includes netd-compat.h itself (below) rather
 * than assuming the consuming .c file already did -- upstream could rely on
 * sd-forward.h/basic-forward.h being pulled in first, but a real cross-agent
 * bug here (netd-resolv.c including dhcp-lease-internal.h with no
 * netd-compat.h in sight) showed that assumption does not hold across an
 * API boundary other milestones build against. MIN_V6ONLY_WAIT_USEC's
 * USEC_PER_SEC comes from netd-compat.h's util.h, pulled in that way.
 */

#pragma once

/* Self-sufficient regardless of what a consumer includes first (a real
 * cross-agent bug: netd-resolv.c included dhcp-lease-internal.h without
 * netd-compat.h first, and this header needs its bool/usec_t/macros) --
 * safe to include redundantly, netd-compat.h has its own #pragma once. */
#include "netd-compat.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "sparse-endian.h"

/* --- hardware address (stand-in for src/basic/ether-addr-util.h) --- */

/* 20 bytes covers every ARP hardware type netd cares about (Ethernet is 6);
 * upstream's HW_ADDR_MAX_SIZE is 32 to cover Infiniband, which netd does not
 * support (dhcp_message_init_header() below forces hw_addr to NULL for
 * ARPHRD_INFINIBAND, matching upstream), so this stays deliberately smaller. */
#define HW_ADDR_MAX_SIZE 20

struct hw_addr_data {
        size_t length;
        uint8_t bytes[HW_ADDR_MAX_SIZE];
};

/* --- wire header --- */

struct DHCPMessageHeader {
        uint8_t op;
        uint8_t htype;
        uint8_t hlen;
        uint8_t hops;
        be32_t xid;
        be16_t secs;
        be16_t flags;
        be32_t ciaddr;
        be32_t yiaddr;
        be32_t siaddr;
        be32_t giaddr;
        uint8_t chaddr[16];
        uint8_t sname[64];
        uint8_t file[128];
        be32_t magic;
} _packed_;

typedef struct DHCPMessageHeader DHCPMessageHeader;

#define DHCP_MAGIC_COOKIE ((uint32_t) 0x63825363)

/* offsetof(DHCPMessageHeader, magic) + 64 -- the vendor-specific area size
 * BOOTP (RFC 951) defines, kept as the minimum build/pad size (plan's
 * dhcp-message.c note on dhcp_message_build()'s BOOTP_MESSAGE_SIZE floor). */
#define BOOTP_MESSAGE_SIZE (offsetof(DHCPMessageHeader, magic) + 64)

enum {
        DHCP_PORT_SERVER = 67,
        DHCP_PORT_CLIENT = 68,
};

typedef enum {
        BOOTREQUEST = 1,
        BOOTREPLY = 2,
        _BOOTP_MESSAGE_TYPE_MAX,
        _BOOTP_MESSAGE_TYPE_INVALID = -EINVAL,
} BOOTPMessageType;

typedef enum {
        DHCP_DISCOVER = 1,
        DHCP_OFFER = 2,
        DHCP_REQUEST = 3,
        DHCP_DECLINE = 4,
        DHCP_ACK = 5,
        DHCP_NAK = 6,
        DHCP_RELEASE = 7,
        DHCP_INFORM = 8,
        DHCP_FORCERENEW = 9,
        _DHCP_MESSAGE_TYPE_MAX,
        _DHCP_MESSAGE_TYPE_INVALID = -EINVAL,
} DHCPMessageType;

typedef enum {
        DHCP_OVERLOAD_NONE = 0,
        DHCP_OVERLOAD_FILE = 1 << 0,
        DHCP_OVERLOAD_SNAME = 1 << 1,
        _DHCP_OVERLOAD_ALL = DHCP_OVERLOAD_FILE | DHCP_OVERLOAD_SNAME,
} DHCPOptionOverload;

/* https://www.iana.org/assignments/bootp-dhcp-parameters/ -- only the
 * options netd's own lift set (dhcp-message.c/dhcp-lease.c) touches, plus
 * the handful kept for the option-code name table's completeness. Option 81
 * (FQDN), 119 (Domain Search) and 162 (encrypted DNS/DNR) are deliberately
 * absent: their get/append paths are cut (plan §2.1), so keeping the
 * numeric constants around would invite a call site that can't work. */
enum {
        SD_DHCP_OPTION_PAD = 0,
        SD_DHCP_OPTION_SUBNET_MASK = 1,
        SD_DHCP_OPTION_TIME_OFFSET = 2,
        SD_DHCP_OPTION_ROUTER = 3,
        SD_DHCP_OPTION_TIME_SERVER = 4,
        SD_DHCP_OPTION_NAME_SERVER = 5,
        SD_DHCP_OPTION_DOMAIN_NAME_SERVER = 6,
        SD_DHCP_OPTION_LOG_SERVER = 7,
        SD_DHCP_OPTION_HOST_NAME = 12,
        SD_DHCP_OPTION_BOOT_FILE_SIZE = 13,
        SD_DHCP_OPTION_DOMAIN_NAME = 15,
        SD_DHCP_OPTION_ROOT_PATH = 17,
        SD_DHCP_OPTION_MTU_INTERFACE = 26,
        SD_DHCP_OPTION_BROADCAST = 28,
        SD_DHCP_OPTION_STATIC_ROUTE = 33,
        SD_DHCP_OPTION_NTP_SERVER = 42,
        SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION = 43,
        SD_DHCP_OPTION_REQUESTED_IP_ADDRESS = 50,
        SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME = 51,
        SD_DHCP_OPTION_OVERLOAD = 52,
        SD_DHCP_OPTION_MESSAGE_TYPE = 53,
        SD_DHCP_OPTION_SERVER_IDENTIFIER = 54,
        SD_DHCP_OPTION_PARAMETER_REQUEST_LIST = 55,
        SD_DHCP_OPTION_ERROR_MESSAGE = 56,
        SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE = 57,
        SD_DHCP_OPTION_RENEWAL_TIME = 58,
        SD_DHCP_OPTION_REBINDING_TIME = 59,
        SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER = 60,
        SD_DHCP_OPTION_CLIENT_IDENTIFIER = 61,
        SD_DHCP_OPTION_RAPID_COMMIT = 80,
        SD_DHCP_OPTION_RELAY_AGENT_INFORMATION = 82,
        SD_DHCP_OPTION_POSIX_TIMEZONE = 100,
        SD_DHCP_OPTION_TZDB_TIMEZONE = 101,
        SD_DHCP_OPTION_IPV6_ONLY_PREFERRED = 108,
        SD_DHCP_OPTION_DHCP_CAPTIVE_PORTAL = 114,
        SD_DHCP_OPTION_SIP_SERVER = 120,
        SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE = 121,
        SD_DHCP_OPTION_6RD = 212,
        SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE = 249,
        SD_DHCP_OPTION_END = 255,
};

/* RFC 8925 3.4: the lower boundary for V6ONLY_WAIT. Kept for API
 * completeness even though netd does not request option 108 (plan's DHCP
 * option set is limited to what §2.5/§2.6 name); one RFC constant is not a
 * dependency magnet the way the option itself would be. */
#define MIN_V6ONLY_WAIT_USEC (300U * USEC_PER_SEC)

typedef enum DHCPState {
        DHCP_STATE_STOPPED,
        DHCP_STATE_INIT,
        DHCP_STATE_SELECTING,
        DHCP_STATE_INIT_REBOOT,
        DHCP_STATE_REBOOTING,
        DHCP_STATE_REQUESTING,
        DHCP_STATE_BOUND,
        DHCP_STATE_RENEWING,
        DHCP_STATE_REBINDING,
        _DHCP_STATE_MAX,
        _DHCP_STATE_INVALID = -EINVAL,
} DHCPState;

const char *dhcp_option_code_to_string(int code);
const char *dhcp_message_type_to_string(DHCPMessageType type);
const char *dhcp_state_to_string(DHCPState state);
