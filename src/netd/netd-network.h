/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * .network files: discovery, parsing and matching (plan §2.5).
 *
 * The syntax is systemd.network(5)'s, and the subset below is deliberately
 * small -- but it is a subset, not a dialect: every directive netd implements
 * means exactly what networkd means by it, and every directive it does not
 * implement is accepted as valid INI and dropped at debug level rather than
 * failing the file. That is the same drop-in tolerance rule unit-parse.c
 * already applies to unit files, and it is what lets the two real files this
 * project already ships (usb0.network, usb0-server.network) parse unmodified.
 *
 * Implemented in netd-network.c, whose line-level scanner follows
 * unit-parse.c's conventions: [Section] headers, '#'/';' comments, backslash
 * continuations, a leading UTF-8 BOM, and a malformed line skipping just that
 * line.
 */

#pragma once

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct Netd Netd;
typedef struct Network Network;

/*
 * The search path, highest priority first. Three entries, not two: /run is
 * what makes runtime reconfiguration possible once the rootfs or /etc is
 * read-only, which is exactly the state a pico image ships in, and it costs
 * one array entry. These are networkd's real directories, deliberately --
 * netd is a drop-in for the files, not a new location for them.
 */
#define NETD_NETWORK_DIR "/etc/systemd/network"
#define NETD_RUNTIME_NETWORK_DIR "/run/systemd/network"
#define NETD_PACKAGED_NETWORK_DIR "/usr/lib/systemd/network"

#define NETWORK_FILE_SUFFIX ".network"

/*
 * DHCP=. Upstream's value is an address-family selector, not a boolean, and
 * netd parses the whole set so a file written for networkd keeps its meaning
 * -- but only the v4 half does anything (§2.9: all of IPv6 is out of scope).
 * A file saying DHCP=ipv6 parses cleanly, logs at debug, and configures
 * nothing, which is a better answer than refusing to load.
 */
typedef enum NetworkDHCP {
        NETWORK_DHCP_NO,
        NETWORK_DHCP_IPV4,
        NETWORK_DHCP_IPV6, /* parsed, then ignored */
        NETWORK_DHCP_YES,  /* both; in practice v4 only */
        _NETWORK_DHCP_MAX,
        _NETWORK_DHCP_INVALID = -1,
} NetworkDHCP;

/* LLDP=: receive neighbour announcements; routers-only keeps just infrastructure neighbours. */
typedef enum NetworkLldp {
        NETWORK_LLDP_NO,
        NETWORK_LLDP_YES,
        NETWORK_LLDP_ROUTERS_ONLY,
} NetworkLldp;

/* EmitLLDP=: which group address announcements go to. "yes" is the nearest bridge. */
typedef enum NetworkEmitLldp {
        NETWORK_EMIT_LLDP_NO,
        NETWORK_EMIT_LLDP_NEAREST_BRIDGE,
        NETWORK_EMIT_LLDP_NON_TPMR_BRIDGE,
        NETWORK_EMIT_LLDP_CUSTOMER_BRIDGE,
} NetworkEmitLldp;

/* One Address= entry: a CIDR literal, split. */
typedef struct NetworkAddress {
        struct in_addr address;
        unsigned char prefixlen;
} NetworkAddress;

struct Network {
        /*
         * Where it came from. `filename` is the full path of the file that
         * actually won; `basename` is what shadowing and ordering are decided
         * on. Both owned.
         */
        char *filename;
        char *basename;

        /*
         * [Match] Name= -- a space-separated list of fnmatch(3) globs, the
         * only match key in the MVP (§2.9). NULL means the file has no
         * [Match] Name= at all, which matches *nothing*: an unconditional
         * catch-all that silently claimed every interface would be a far
         * worse failure mode than a file that does nothing.
         */
        char **match_name;

        /* --- [Network] --- */
        NetworkDHCP dhcp;

        /*
         * Address= accumulates rather than overriding, matching networkd. A
         * scalar here would have been enough for both real usb0 files, and
         * would also have baked the wrong semantics into the parser contract
         * for whoever writes the second one.
         */
        NetworkAddress *addresses;
        size_t n_addresses;

        struct in_addr gateway;
        bool gateway_set;

        /* Address literals only -- netd has no resolver, so a hostname in
         * DNS= or NTP= is a parse error, not a lookup. */
        struct in_addr *dns;
        size_t n_dns;
        struct in_addr *ntp;
        size_t n_ntp;

        bool dhcp_server; /* DHCPServer= */

        NetworkLldp lldp;          /* LLDP= */
        NetworkEmitLldp emit_lldp; /* EmitLLDP= */

        /* --- [DHCPv4] --- */
        bool dhcp_use_dns; /* UseDNS=, default yes */
        bool dhcp_use_ntp; /* UseNTP=, default yes */

        /*
         * UseTimezone=, default *yes*. This is a deliberate, owner-confirmed
         * divergence from networkd, whose default is no: bringing the
         * DHCP-supplied timezone back is netd's founding requirement (§2.5,
         * §2.6). An explicit UseTimezone=no is honoured.
         */
        bool dhcp_use_timezone;
};

/* --- netd-network.c --- */

/* Parse one file. The Network is fully defaulted first, so a file that sets
 * nothing still comes back with UseDNS/UseNTP/UseTimezone at yes. 0 or
 * -errno; -EINVAL only for a file that cannot be made sense of at all, since
 * an unknown section or directive is a debug message, not an error. */
int network_parse_file(const char *path, Network **ret);

/* Allocate a Network with every default applied and nothing set. 0 or -errno. */
int network_new(Network **ret);

Network *network_free(Network *nw); /* returns NULL */

/*
 * Walk every entry of n->network_path and build n->networks:
 *
 *   - files ending in .network are collected from all three directories;
 *   - a basename found in a higher-priority directory shadows the same
 *     basename in a lower one (the lower file is never even opened);
 *   - the surviving union is sorted lexicographically by basename.
 *
 * The old set is replaced only once the new one is complete, so a reload that
 * fails leaves the running configuration alone. Number of files loaded, or
 * -errno.
 */
int network_load_all(Netd *n);

/* Drop every parsed Network. */
void network_free_all(Netd *n);

/* True when any [Match] Name= glob matches `ifname`. */
bool network_matches(const Network *nw, const char *ifname);

/* The first Network in n->networks whose [Match] matches, or NULL. First
 * match wins, which is why the lexicographic sort above is part of the
 * contract and not an implementation detail. */
Network *network_find(Netd *n, const char *ifname);

/* True when this file should arm the DHCPv4 client. Folded into one helper
 * so no caller has to remember that YES and IPV4 both count and IPV6 does
 * not. */
bool network_dhcp4_enabled(const Network *nw);

const char *network_dhcp_to_string(NetworkDHCP d);
NetworkDHCP network_dhcp_from_string(const char *s);
