/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from src/libsystemd-network/dhcp-protocol.c (204 lines): option
 * code / message-type / state name tables, used only for log messages
 * (dhcp-lease.c logs every option it fails to parse by name).
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. History review
 * (4925d9f07f..main, plan §2.2): no fix in the 26-commit lift-set window
 * touches this file. See dhcp-protocol.h's header for the one backport in
 * the window (7bd9f0f805, sd-dhcp-server.c, not carried here).
 *
 * Upstream builds these tables with DECLARE/DEFINE_STRING_TABLE_LOOKUP_TO_
 * STRING from src/basic/string-table.h, which is not in the lift set (it
 * pulls in nothing netd needs otherwise, so lifting a whole header for
 * three lookup functions did not seem worth it). The table shape and
 * out-of-range-returns-NULL semantics are kept exactly; only the lookup
 * mechanism -- a small local helper instead of the macro pair -- differs.
 * Trimmed to the option codes dhcp-protocol.h declares (see that file's
 * header for what was cut and why).
 */

#include "netd-compat.h"

#include "dhcp-protocol.h"

static const char *table_lookup(const char * const *table, size_t len, int i) {
        if (i < 0 || (size_t) i >= len)
                return NULL;

        return table[i];
}

static const char * const dhcp_message_type_table[_DHCP_MESSAGE_TYPE_MAX] = {
        [DHCP_DISCOVER] = "DISCOVER", [DHCP_OFFER] = "OFFER",   [DHCP_REQUEST] = "REQUEST",
        [DHCP_DECLINE] = "DECLINE",   [DHCP_ACK] = "ACK",       [DHCP_NAK] = "NAK",
        [DHCP_RELEASE] = "RELEASE",   [DHCP_INFORM] = "INFORM", [DHCP_FORCERENEW] = "FORCERENEW",
};

const char *dhcp_message_type_to_string(DHCPMessageType type) {
        return table_lookup(dhcp_message_type_table, ELEMENTSOF(dhcp_message_type_table), type);
}

/* Sized to the largest option code this file names (256), not to the
 * enum's holes -- unused slots stay NULL, exactly as upstream's sparse
 * designated-initializer table does. */
static const char * const dhcp_option_code_table[256] = {
        [SD_DHCP_OPTION_PAD] = "pad",
        [SD_DHCP_OPTION_SUBNET_MASK] = "subnet mask",
        [SD_DHCP_OPTION_TIME_OFFSET] = "time offset",
        [SD_DHCP_OPTION_ROUTER] = "router",
        [SD_DHCP_OPTION_TIME_SERVER] = "time server",
        [SD_DHCP_OPTION_NAME_SERVER] = "name server",
        [SD_DHCP_OPTION_DOMAIN_NAME_SERVER] = "domain name server",
        [SD_DHCP_OPTION_LOG_SERVER] = "log server",
        [SD_DHCP_OPTION_HOST_NAME] = "hostname",
        [SD_DHCP_OPTION_BOOT_FILE_SIZE] = "boot file size",
        [SD_DHCP_OPTION_DOMAIN_NAME] = "domain name",
        [SD_DHCP_OPTION_ROOT_PATH] = "root path",
        [SD_DHCP_OPTION_MTU_INTERFACE] = "MTU size",
        [SD_DHCP_OPTION_BROADCAST] = "broadcast address",
        [SD_DHCP_OPTION_STATIC_ROUTE] = "static route",
        [SD_DHCP_OPTION_NTP_SERVER] = "NTP server",
        [SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION] = "vendor-specific information",
        [SD_DHCP_OPTION_REQUESTED_IP_ADDRESS] = "requested IP address",
        [SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME] = "lease time",
        [SD_DHCP_OPTION_OVERLOAD] = "overload",
        [SD_DHCP_OPTION_MESSAGE_TYPE] = "message type",
        [SD_DHCP_OPTION_SERVER_IDENTIFIER] = "server identifier",
        [SD_DHCP_OPTION_PARAMETER_REQUEST_LIST] = "parameter request list",
        [SD_DHCP_OPTION_ERROR_MESSAGE] = "error message",
        [SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE] = "max message size",
        [SD_DHCP_OPTION_RENEWAL_TIME] = "renewal time",
        [SD_DHCP_OPTION_REBINDING_TIME] = "rebinding time",
        [SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER] = "vendor class identifier",
        [SD_DHCP_OPTION_CLIENT_IDENTIFIER] = "client identifier",
        [SD_DHCP_OPTION_RAPID_COMMIT] = "rapid commit",
        [SD_DHCP_OPTION_RELAY_AGENT_INFORMATION] = "relay agent information",
        [SD_DHCP_OPTION_POSIX_TIMEZONE] = "posix timezone",
        [SD_DHCP_OPTION_TZDB_TIMEZONE] = "tzdb timezone",
        [SD_DHCP_OPTION_IPV6_ONLY_PREFERRED] = "IPv6-only preferred",
        [SD_DHCP_OPTION_DHCP_CAPTIVE_PORTAL] = "captive portal",
        [SD_DHCP_OPTION_SIP_SERVER] = "SIP server",
        [SD_DHCP_OPTION_CLASSLESS_STATIC_ROUTE] = "classless static route",
        [SD_DHCP_OPTION_6RD] = "6rd",
        [SD_DHCP_OPTION_PRIVATE_CLASSLESS_STATIC_ROUTE] = "(private) classless static route",
        [SD_DHCP_OPTION_END] = "end",
};

const char *dhcp_option_code_to_string(int code) {
        return table_lookup(dhcp_option_code_table, ELEMENTSOF(dhcp_option_code_table), code);
}

static const char * const dhcp_state_table[_DHCP_STATE_MAX] = {
        [DHCP_STATE_STOPPED] = "stopped",     [DHCP_STATE_INIT] = "initialization",
        [DHCP_STATE_SELECTING] = "selecting", [DHCP_STATE_INIT_REBOOT] = "init-reboot",
        [DHCP_STATE_REBOOTING] = "rebooting", [DHCP_STATE_REQUESTING] = "requesting",
        [DHCP_STATE_BOUND] = "bound",         [DHCP_STATE_RENEWING] = "renewing",
        [DHCP_STATE_REBINDING] = "rebinding",
};

const char *dhcp_state_to_string(DHCPState state) {
        return table_lookup(dhcp_state_table, ELEMENTSOF(dhcp_state_table), state);
}
