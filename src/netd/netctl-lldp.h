/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Reading the neighbours netd publishes in /run/netd/lldp/<ifindex> for
 * `networkctl lldp`. Pure string handling, split out of netctl.c so a test can
 * feed it state lines directly.
 *
 * Everything in a row came from the network, so every string is reduced to
 * printable ASCII here: a neighbour must not be able to put terminal escape
 * sequences on an administrator's screen.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NETCTL_LLDP_ID_MAX 96
#define NETCTL_LLDP_NAME_MAX 64
#define NETCTL_LLDP_CAPS_LEN 12 /* eleven capability letters and a NUL */

typedef struct NetctlLldpRow {
        char link[16];
        char chassis[NETCTL_LLDP_ID_MAX];
        char name[NETCTL_LLDP_NAME_MAX];
        char caps[NETCTL_LLDP_CAPS_LEN];
        char port[NETCTL_LLDP_ID_MAX];
        char descr[NETCTL_LLDP_NAME_MAX];
        uint64_t expires; /* CLOCK_MONOTONIC seconds */
} NetctlLldpRow;

/*
 * Decodes the %XX escaping of the state file into `out`. Returns the decoded
 * length, or (size_t) -1 for a malformed escape or a result that does not fit.
 */
size_t netctl_lldp_unescape(uint8_t *out, size_t size, const char *in, size_t len);

/* A chassis (kind 0) or port (kind 1) ID as text: a MAC address, an IPv4 address, plain text, or hex. */
void netctl_lldp_format_id(char *out, size_t size, int kind, unsigned subtype, const uint8_t *id, size_t len);

/* Eleven characters, a capability letter where the bit is set and '.' where not. */
void netctl_lldp_format_caps(char out[NETCTL_LLDP_CAPS_LEN], uint16_t caps);

/* One "N key=value ..." line. False for anything that is not a well-formed neighbour line. */
bool netctl_lldp_parse_row(const char *line, const char *ifname, NetctlLldpRow *row);
