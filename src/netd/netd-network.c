/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * .network file parsing, discovery and matching.
 *
 * N0 scaffold: allocation, defaulting and the value tables are real -- they
 * are no harder than a stub and they fix the defaults every other file
 * assumes, in particular UseTimezone=yes. The scanner, the search-path walk
 * and matching land with N0's parser work.
 *
 * INI SCANNER: the line-level scanner (sections, comments, continuations,
 * BOM, malformed-line-skips-line) is deliberately absent here. Plan §2.5
 * leaves the factor-out-of-unit-parse.c versus duplicate-~100-lines question
 * open at N0, and unit-parse.c belongs to PID 1. Whichever way it is decided,
 * this file gets the scanner and network_parse_file() drives it with a
 * netd-specific key handler.
 */

#include "netd-network.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../util.h"
#include "netd.h"

int network_new(Network **ret) {
        Network *nw;

        if (!ret)
                return -EINVAL;

        nw = calloc(1, sizeof(*nw));
        if (!nw)
                return -ENOMEM;

        nw->dhcp = NETWORK_DHCP_NO;

        /*
         * The [DHCPv4] defaults, and the one that matters: UseTimezone
         * defaults to *yes* here where networkd defaults it to no. That is
         * netd's founding requirement, not an oversight -- see netd-network.h.
         */
        nw->dhcp_use_dns = true;
        nw->dhcp_use_ntp = true;
        nw->dhcp_use_timezone = true;

        *ret = nw;
        return 0;
}

Network *network_free(Network *nw) {
        if (!nw)
                return NULL;

        free(nw->filename);
        free(nw->basename);
        pico_strv_free(nw->match_name);
        free(nw->addresses);
        free(nw->dns);
        free(nw->ntp);
        free(nw);
        return NULL;
}

void network_free_all(Netd *n) {
        if (!n)
                return;

        for (size_t i = 0; i < n->n_networks; i++)
                network_free(n->networks[i]);

        free(n->networks);
        n->networks = NULL;
        n->n_networks = 0;
}

bool network_dhcp4_enabled(const Network *nw) {
        if (!nw)
                return false;

        /* YES and IPV4 both arm the v4 client; IPV6 parses and does nothing. */
        return nw->dhcp == NETWORK_DHCP_YES || nw->dhcp == NETWORK_DHCP_IPV4;
}

int network_parse_file(const char *path, Network **ret) {
        if (!path || !ret)
                return -EINVAL;

        return -ENOSYS;
}

int network_load_all(Netd *n) {
        if (!n)
                return -EINVAL;

        return -ENOSYS;
}

bool network_matches(const Network *nw, const char *ifname) {
        (void) nw;
        (void) ifname;

        return false;
}

Network *network_find(Netd *n, const char *ifname) {
        (void) n;
        (void) ifname;

        return NULL;
}

/*
 * Value spellings. "yes"/"no"/"true"/"false"/"1"/"0" are handled by the
 * boolean parser; this table is only for the address-family words, plus the
 * truthy spellings that mean "both".
 */
static const char * const network_dhcp_table[_NETWORK_DHCP_MAX] = {
        [NETWORK_DHCP_NO] = "no",
        [NETWORK_DHCP_IPV4] = "ipv4",
        [NETWORK_DHCP_IPV6] = "ipv6",
        [NETWORK_DHCP_YES] = "yes",
};

const char *network_dhcp_to_string(NetworkDHCP d) {
        if (d < 0 || d >= _NETWORK_DHCP_MAX)
                return "invalid";

        return network_dhcp_table[d];
}

NetworkDHCP network_dhcp_from_string(const char *s) {
        if (!s)
                return _NETWORK_DHCP_INVALID;

        for (NetworkDHCP d = 0; d < _NETWORK_DHCP_MAX; d++)
                if (strcmp(s, network_dhcp_table[d]) == 0)
                        return d;

        /* The other truthy/falsy spellings systemd accepts everywhere. */
        if (strcmp(s, "true") == 0 || strcmp(s, "1") == 0 || strcmp(s, "on") == 0)
                return NETWORK_DHCP_YES;
        if (strcmp(s, "false") == 0 || strcmp(s, "0") == 0 || strcmp(s, "off") == 0)
                return NETWORK_DHCP_NO;

        return _NETWORK_DHCP_INVALID;
}
