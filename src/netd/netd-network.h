/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * .network files: discovery, parsing and matching.
 *
 * The syntax is systemd.network(5)'s, and the subset below is small but not a
 * dialect: every directive netd implements means what networkd means by it,
 * and every directive it does not implement is accepted as valid INI and
 * dropped at debug level rather than failing the file. unit-parse.c applies
 * the same drop-in tolerance rule to unit files.
 *
 * Implemented in netd-network.c, whose line-level scanner follows
 * unit-parse.c's conventions: [Section] headers, '#'/';' comments, backslash
 * continuations, a leading UTF-8 BOM, and a malformed line skipping just that
 * line.
 */

#pragma once

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "netd-addr.h"

typedef struct Netd Netd;
typedef struct Network Network;

/*
 * The search path, highest priority first. /run allows runtime
 * reconfiguration when the rootfs or /etc is read-only. These are networkd's
 * own directories: netd is a drop-in for the files, not a new location.
 */
#define NETD_NETWORK_DIR "/etc/systemd/network"
#define NETD_RUNTIME_NETWORK_DIR "/run/systemd/network"
#define NETD_PACKAGED_NETWORK_DIR "/usr/lib/systemd/network"

#define NETWORK_FILE_SUFFIX ".network"

/*
 * DHCP=. Upstream's value is an address-family selector, not a boolean, and
 * netd parses the whole set so a file written for networkd keeps its meaning
 * -- but only the v4 half does anything (IPv6 is not implemented).
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

/*
 * One address, from an [Address] section or an Address= line in [Network].
 * What an entry means is decided when the file is parsed: network_parse_file()
 * drops the entries networkd drops and fills in the scope and DAD defaults, so
 * a Network holds only entries that can be applied. The IPv6 check is not made
 * there: whether the kernel has IPv6 is for the link code, so a parse is the
 * same on every host.
 */
typedef struct NetworkAddress {
        uint8_t family; /* AF_INET or AF_INET6; 0 until Address= is seen */
        uint8_t peer_family;
        unsigned char prefixlen;
        uint8_t scope; /* RT_SCOPE_* */
        bool scope_set;
        bool peer_set;
        bool deprecated; /* PreferredLifetime=0 */
        bool dad;        /* IPv6 duplicate address detection; off sends IFA_F_NODAD */
        bool dad_set;
        bool no_prefix_route; /* AddPrefixRoute=no */
        NetdInAddr address;
        NetdInAddr peer;
        uint32_t route_metric; /* of the prefix route, IFA_RT_PRIORITY */
        char label[IFNAMSIZ];  /* IPv4 only; empty for none */
        unsigned line;
} NetworkAddress;

/* At most this many address entries per file: each costs one netlink write per
 * change and some memory on every link; more is a mistake on these boards. */
#define NETWORK_ADDRESS_MAX 16

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
         * only match key supported. NULL means the file has no
         * [Match] Name= at all, which matches *nothing*: an unconditional
         * catch-all that silently claimed every interface would be a far
         * worse failure mode than a file that does nothing.
         */
        char **match_name;

        /* --- [Network] --- */
        NetworkDHCP dhcp;

        /*
         * [Address] sections and Address= lines in [Network], in file order,
         * both families, at most NETWORK_ADDRESS_MAX. A later duplicate
         * replaces the earlier entry, and an empty Address= in [Network]
         * clears every entry collected so far, as in networkd.
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
         * UseTimezone=, default *yes*. This deliberately diverges from
         * networkd, whose default is no: applying the DHCP-supplied timezone is
         * a core netd feature. An explicit UseTimezone=no is honoured.
         */
        bool dhcp_use_timezone;

        /*
         * RouteMetric=, from [DHCPv4] or the legacy [DHCP]. Unset means
         * networkd's default, 1024. _v4 records that [DHCPv4] set it,
         * so a [DHCP] line, earlier or later, cannot override it, as in
         * networkd.
         */
        uint32_t dhcp_route_metric;
        bool dhcp_route_metric_set;
        bool dhcp_route_metric_v4;
};

/* --- netd-network.c --- */

/* Parse one file. The Network is fully defaulted first, so a file that sets
 * nothing still comes back with UseDNS/UseNTP/UseTimezone at yes and no
 * RouteMetric=. 0 or -errno; -EINVAL only for a file that cannot be made
 * sense of at all, since an unknown section or directive is a debug message,
 * not an error. */
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

/* The first IPv4 entry of nw->addresses, or NULL: the address the DHCP server
 * serves from. */
const NetworkAddress *network_first_address_v4(const Network *nw);

/* True when this file should arm the DHCPv4 client. Folded into one helper
 * so no caller has to remember that YES and IPV4 both count and IPV6 does
 * not. */
bool network_dhcp4_enabled(const Network *nw);

const char *network_dhcp_to_string(NetworkDHCP d);
NetworkDHCP network_dhcp_from_string(const char *s);
