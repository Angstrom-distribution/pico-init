/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * .network file parsing, discovery and matching.
 *
 * The line-level scanning (sections, comments, continuations, BOM, the
 * malformed-line-skips-line policy) is conf-scan.c's -- shared with
 * unit-parse.c so the same backported upstream fixes apply here too. This
 * file is conf-scan.c's second caller: a value-level handler table below,
 * following unit-parse.c's own ConfigItem convention, plus discovery
 * (search-path walk, basename shadowing, lexicographic union sort) and
 * [Match] Name= glob matching, neither of which conf-scan.c knows about.
 */

#include "netd-network.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp, for the boolean spellings */
#include <sys/stat.h>

#include "../conf-scan.h"
#include "../dropin-files.h"
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
         * deliberate -- see netd-network.h.
         */
        nw->dhcp_use_dns = true;
        nw->dhcp_use_ntp = true;
        nw->dhcp_use_timezone = true;

        nw->ipv6_accept_ra = -1;
        nw->ra_use_gateway = true;
        nw->ra_use_onlink_prefix = true;
        nw->ra_use_autonomous_prefix = true;
        nw->ra_use_dns = true;
        nw->ra_use_mtu = true;
        nw->ra_route_metric[0] = NETWORK_RA_METRIC_HIGH;
        nw->ra_route_metric[1] = NETWORK_RA_METRIC_MEDIUM;
        nw->ra_route_metric[2] = NETWORK_RA_METRIC_LOW;

        *ret = nw;
        return 0;
}

Network *network_free(Network *nw) {
        if (!nw)
                return NULL;

        free(nw->filename);
        free(nw->basename);
        pico_strv_free(nw->match_name);
        pico_strv_free(nw->dropins);
        free(nw->addresses);
        free(nw->routes);
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

const NetworkAddress *network_first_address_v4(const Network *nw) {
        if (!nw)
                return NULL;

        for (size_t i = 0; i < nw->n_addresses; i++)
                if (nw->addresses[i].family == AF_INET)
                        return &nw->addresses[i];

        return NULL;
}

bool network_dhcp4_enabled(const Network *nw) {
        if (!nw)
                return false;

        /* YES and IPV4 both arm the v4 client; IPV6 parses and does nothing. */
        return nw->dhcp == NETWORK_DHCP_YES || nw->dhcp == NETWORK_DHCP_IPV4;
}

/* --- value parsing --- */

/*
 * systemd's own boolean spellings, same set unit-parse.c's
 * parse_boolean_value() accepts (case-insensitively): 1/yes/y/true/t/on and
 * 0/no/n/false/f/off. Duplicated rather than shared because it is ten lines
 * and unit-parse.c's copy is file-static -- not a dialect difference.
 */
static int network_parse_bool(const char *v, bool *ret) {
        if (strcmp(v, "1") == 0 || strcasecmp(v, "yes") == 0 || strcasecmp(v, "y") == 0 ||
            strcasecmp(v, "true") == 0 || strcasecmp(v, "t") == 0 || strcasecmp(v, "on") == 0) {
                *ret = true;
                return 0;
        }

        if (strcmp(v, "0") == 0 || strcasecmp(v, "no") == 0 || strcasecmp(v, "n") == 0 ||
            strcasecmp(v, "false") == 0 || strcasecmp(v, "f") == 0 || strcasecmp(v, "off") == 0) {
                *ret = false;
                return 0;
        }

        return -EINVAL;
}

/* --- [Match] --- */

static int config_parse_match_name(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        char *copy, *saveptr = NULL, *tok;
        (void) path;
        (void) line;
        (void) lvalue;

        /* Heap, not a VLA: rvalue comes from conf-scan.c's unbounded
         * getline(), the same stack-overflow hazard unit-parse.c's
         * config_parse_unit_deps() documents -- see that file's header. */
        /* An empty assignment resets the list, as in systemd. */
        if (*rvalue == '\0') {
                nw->match_name = pico_strv_free(nw->match_name);
                return 0;
        }

        copy = pico_strdup(rvalue);
        if (!copy)
                return -ENOMEM;

        for (tok = strtok_r(copy, " \t", &saveptr); tok; tok = strtok_r(NULL, " \t", &saveptr)) {
                int r = pico_strv_extend(&nw->match_name, tok);
                if (r < 0) {
                        pico_mfree(copy);
                        return r;
                }
        }

        pico_mfree(copy);
        return 0;
}

/* --- [Network] --- */

static int config_parse_dhcp(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        NetworkDHCP d = network_dhcp_from_string(rvalue);
        (void) lvalue;

        if (d == _NETWORK_DHCP_INVALID) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid DHCP= value '%s', ignoring", path, line, rvalue);
                return 0;
        }

        nw->dhcp = d;
        return 0;
}

static int config_parse_gateway(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        struct in_addr a;
        (void) lvalue;

        if (inet_pton(AF_INET, rvalue, &a) != 1) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid Gateway= value '%s', ignoring", path, line, rvalue);
                return 0;
        }

        nw->gateway = a;
        nw->gateway_set = true;
        return 0;
}

/* systemd's MAX_NTP_SERVERS: a longer list is a misconfiguration. */
#define NETWORK_ADDR_LIST_MAX 128

/*
 * NTP=: a space-separated list of address literals -- netd has no resolver,
 * so a hostname here is a parse error for that one token, not a lookup. A
 * link-local IPv6 address may name its interface as `fe80::1%eth0` or by
 * index as `fe80::1%2`; without one it is used on each link the file is
 * applied to. A bad token is dropped
 * with a warning; the rest of the line still lands, the same per-directive
 * tolerance the rest of this project uses.
 */
static int config_parse_ntp(Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        char *copy, *saveptr = NULL, *tok;

        /* An empty assignment resets the list, as in systemd. */
        if (*rvalue == '\0') {
                nw->ntp = pico_mfree(nw->ntp);
                nw->n_ntp = 0;
                return 0;
        }

        copy = pico_strdup(rvalue);
        if (!copy)
                return -ENOMEM;

        for (tok = strtok_r(copy, " \t", &saveptr); tok; tok = strtok_r(NULL, " \t", &saveptr)) {
                NetworkNtp e = { 0 }, *grown;
                char *zone;

                if (nw->n_ntp >= NETWORK_ADDR_LIST_MAX) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: %s= holds more than %d entries, ignoring the rest",
                                 path,
                                 line,
                                 lvalue,
                                 NETWORK_ADDR_LIST_MAX);
                        break;
                }

                if (inet_pton(AF_INET, tok, &e.address.in) == 1)
                        e.family = AF_INET;
                else {
                        zone = strchr(tok, '%');
                        if (zone)
                                *zone++ = '\0';

                        if (inet_pton(AF_INET6, tok, &e.address.in6) != 1) {
                                if (zone)
                                        zone[-1] = '%';
                                pico_log(PICO_LOG_WARNING,
                                         "%s:%u: %s= value '%s' is not an address literal, ignoring",
                                         path,
                                         line,
                                         lvalue,
                                         tok);
                                continue;
                        }
                        e.family = AF_INET6;

                        /* A V6ONLY socket cannot send to a mapped address,
                         * and no server answers from the others. */
                        if (IN6_IS_ADDR_UNSPECIFIED(&e.address.in6) ||
                            IN6_IS_ADDR_MULTICAST(&e.address.in6) || IN6_IS_ADDR_V4MAPPED(&e.address.in6)) {
                                if (zone)
                                        zone[-1] = '%';
                                pico_log(PICO_LOG_WARNING,
                                         "%s:%u: %s= value '%s' cannot be a server address, ignoring",
                                         path,
                                         line,
                                         lvalue,
                                         tok);
                                continue;
                        }

                        if (zone) {
                                if (!IN6_IS_ADDR_LINKLOCAL(&e.address.in6)) {
                                        pico_log(PICO_LOG_WARNING,
                                                 "%s:%u: %s= value '%s%%%s' takes an interface name only on a link-local address, ignoring",
                                                 path,
                                                 line,
                                                 lvalue,
                                                 tok,
                                                 zone);
                                        continue;
                                }
                                if (*zone == '\0' || strlen(zone) >= sizeof(e.zone) || strchr(zone, '/')) {
                                        pico_log(PICO_LOG_WARNING,
                                                 "%s:%u: %s= value '%s%%%s' has an invalid interface name, ignoring",
                                                 path,
                                                 line,
                                                 lvalue,
                                                 tok,
                                                 zone);
                                        continue;
                                }
                                memcpy(e.zone, zone, strlen(zone) + 1);

                                /* A number is an interface index, as for
                                 * systemd's rtnl_resolve_interface(). */
                                if (strspn(zone, "0123456789") == strlen(zone)) {
                                        unsigned long v;

                                        errno = 0;
                                        v = strtoul(zone, NULL, 10);
                                        if (errno == ERANGE || v == 0 || v > INT_MAX) {
                                                pico_log(PICO_LOG_WARNING,
                                                         "%s:%u: %s= value '%s%%%s' has an invalid interface index, ignoring",
                                                         path,
                                                         line,
                                                         lvalue,
                                                         tok,
                                                         zone);
                                                continue;
                                        }
                                        e.zone_ifindex = (int) v;
                                }
                        }
                }

                grown = realloc(nw->ntp, (nw->n_ntp + 1) * sizeof(*grown));
                if (!grown) {
                        pico_mfree(copy);
                        return -ENOMEM;
                }
                nw->ntp = grown;
                nw->ntp[nw->n_ntp++] = e;
        }

        pico_mfree(copy);
        return 0;
}

/* DNS=: the same list rules, both families. A %scope is not taken: a
 * link-local server is written with the interface of its own link. */
static int config_parse_dns(Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        char *copy, *saveptr = NULL, *tok;

        if (*rvalue == '\0') {
                nw->dns = pico_mfree(nw->dns);
                nw->n_dns = 0;
                return 0;
        }

        copy = pico_strdup(rvalue);
        if (!copy)
                return -ENOMEM;

        for (tok = strtok_r(copy, " \t", &saveptr); tok; tok = strtok_r(NULL, " \t", &saveptr)) {
                NetworkDns *grown;
                NetdInAddr a;
                int family;

                if (nw->n_dns >= NETWORK_ADDR_LIST_MAX) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: %s= holds more than %d entries, ignoring the rest",
                                 path,
                                 line,
                                 lvalue,
                                 NETWORK_ADDR_LIST_MAX);
                        break;
                }

                if (netd_addr_parse(tok, &family, &a) < 0 || netd_addr_is_null(family, &a)) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: %s= value '%s' is not an address literal, ignoring",
                                 path,
                                 line,
                                 lvalue,
                                 tok);
                        continue;
                }

                grown = realloc(nw->dns, (nw->n_dns + 1) * sizeof(*grown));
                if (!grown) {
                        pico_mfree(copy);
                        return -ENOMEM;
                }
                nw->dns = grown;
                nw->dns[nw->n_dns].family = (uint8_t) family;
                nw->dns[nw->n_dns].address = a;
                nw->n_dns++;
        }

        pico_mfree(copy);
        return 0;
}

static int config_parse_bool_field(
                const char *path, unsigned line, const char *lvalue, const char *rvalue, bool *field) {
        bool b;

        if (network_parse_bool(rvalue, &b) < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
                return 0;
        }

        *field = b;
        return 0;
}

static int config_parse_lldp(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        bool b;

        if (strcmp(rvalue, "routers-only") == 0)
                nw->lldp = NETWORK_LLDP_ROUTERS_ONLY;
        else if (network_parse_bool(rvalue, &b) == 0)
                nw->lldp = b ? NETWORK_LLDP_YES : NETWORK_LLDP_NO;
        else
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
        return 0;
}

static int config_parse_emit_lldp(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        bool b;

        if (strcmp(rvalue, "nearest-bridge") == 0)
                nw->emit_lldp = NETWORK_EMIT_LLDP_NEAREST_BRIDGE;
        else if (strcmp(rvalue, "non-tpmr-bridge") == 0)
                nw->emit_lldp = NETWORK_EMIT_LLDP_NON_TPMR_BRIDGE;
        else if (strcmp(rvalue, "customer-bridge") == 0)
                nw->emit_lldp = NETWORK_EMIT_LLDP_CUSTOMER_BRIDGE;
        else if (network_parse_bool(rvalue, &b) == 0)
                nw->emit_lldp = b ? NETWORK_EMIT_LLDP_NEAREST_BRIDGE : NETWORK_EMIT_LLDP_NO;
        else
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
        return 0;
}

static int config_parse_dhcp_server(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_bool_field(path, line, lvalue, rvalue, &nw->dhcp_server);
}

/* --- [DHCPv4] --- */

static int config_parse_use_dns(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_bool_field(path, line, lvalue, rvalue, &nw->dhcp_use_dns);
}

static int config_parse_use_ntp(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_bool_field(path, line, lvalue, rvalue, &nw->dhcp_use_ntp);
}

static int config_parse_use_timezone(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_bool_field(path, line, lvalue, rvalue, &nw->dhcp_use_timezone);
}

/*
 * Plain decimal only, 0..UINT32_MAX. networkd's safe_atou32() takes any base,
 * so "010" or "0x10" would mean something else there; rejecting every
 * spelling the two parsers could read differently keeps a value netd accepts
 * meaning the same to both. strtoull because unsigned long is 32 bits on
 * ARMv5; the explicit bound for the same reason as unit-parse.c's
 * parse_usec().
 */
static int parse_route_metric(const char *s, uint32_t *ret) {
        unsigned long long v;
        char *end;

        if (*s == '\0' || strspn(s, "0123456789") != strlen(s) || (s[0] == '0' && s[1] != '\0'))
                return -EINVAL;

        errno = 0;
        v = strtoull(s, &end, 10);
        if (errno == ERANGE || *end != '\0' || v > UINT32_MAX)
                return -EINVAL;

        *ret = (uint32_t) v;
        return 0;
}

/* --- [Address] and Address= --- */

/*
 * Parse state that lives only while one file is scanned. `cur` and `cur_route`
 * are the entries the open [Address] and [Route] sections fill, -1 when there
 * is none or the file is over NETWORK_ADDRESS_MAX or NETWORK_ROUTE_MAX, whose
 * entries are then ignored.
 */
typedef struct NetworkParser {
        Network *nw;
        ssize_t cur;
        ssize_t cur_route;
        bool warned_cap;
        bool warned_route_cap;

        /* The open qdisc kind section, committed when the next section or the
         * end of the file closes it: Parent= may come after other keys. */
        NetworkQdisc sec_qdisc;
        const char *sec_qdisc_name;
        unsigned sec_qdisc_line;
        bool sec_qdisc_root;
        bool sec_qdisc_keys;
} NetworkParser;

typedef int (*NetworkAddressParseFn)(
                NetworkAddress *a, const char *path, unsigned line, const char *lvalue, const char *rvalue);

typedef struct NetworkAddressConfigItem {
        const char *lvalue;
        NetworkAddressParseFn parse;
} NetworkAddressConfigItem;

/* Appends a zeroed entry, or returns -1 with one warning per file when the
 * cap is reached. -ENOMEM on allocation failure. */
static ssize_t network_address_append(NetworkParser *p, const char *path, unsigned line) {
        Network *nw = p->nw;
        NetworkAddress *grown;

        if (nw->n_addresses >= NETWORK_ADDRESS_MAX) {
                if (!p->warned_cap)
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: more than %d addresses, ignoring the rest",
                                 path,
                                 line,
                                 NETWORK_ADDRESS_MAX);
                p->warned_cap = true;
                return -1;
        }

        grown = realloc(nw->addresses, (nw->n_addresses + 1) * sizeof(*grown));
        if (!grown)
                return -ENOMEM;

        nw->addresses = grown;
        memset(&grown[nw->n_addresses], 0, sizeof(*grown));
        grown[nw->n_addresses].line = line;
        grown[nw->n_addresses].file = path;
        return (ssize_t) nw->n_addresses++;
}

/* The same for a [Route] section. */
static ssize_t network_route_append(NetworkParser *p, const char *path, unsigned line) {
        Network *nw = p->nw;
        NetworkRoute *grown;

        if (nw->n_routes >= NETWORK_ROUTE_MAX) {
                if (!p->warned_route_cap)
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: more than %d routes, ignoring the rest",
                                 path,
                                 line,
                                 NETWORK_ROUTE_MAX);
                p->warned_route_cap = true;
                return -1;
        }

        grown = realloc(nw->routes, (nw->n_routes + 1) * sizeof(*grown));
        if (!grown)
                return -ENOMEM;

        nw->routes = grown;
        memset(&grown[nw->n_routes], 0, sizeof(*grown));
        grown[nw->n_routes].line = line;
        grown[nw->n_routes].file = path;
        return (ssize_t) nw->n_routes++;
}

/* [QDisc] is not read: in networkd it holds only clsact and ingress, which
 * netd does not install. */
static const struct {
        const char *section;
        NetworkQdisc kind;
} network_qdisc_sections[] = {
        { "FairQueueingControlledDelay", NETWORK_QDISC_FQ_CODEL },
        {                "FairQueueing",       NETWORK_QDISC_FQ },
        {                        "CAKE",     NETWORK_QDISC_CAKE },
};

static const char * const network_qdisc_names[_NETWORK_QDISC_MAX] = {
        [NETWORK_QDISC_FQ_CODEL] = "fq_codel",
        [NETWORK_QDISC_FQ] = "fq",
        [NETWORK_QDISC_CAKE] = "cake",
};

const char *network_qdisc_to_string(NetworkQdisc q) {
        if (q <= NETWORK_QDISC_NONE || q >= _NETWORK_QDISC_MAX)
                return NULL;

        return network_qdisc_names[q];
}

static void network_qdisc_commit(NetworkParser *p, const char *path) {
        /* networkd creates the qdisc when a key of the section is parsed, so
         * a header alone installs nothing. */
        if (p->sec_qdisc == NETWORK_QDISC_NONE || !p->sec_qdisc_root || !p->sec_qdisc_keys)
                return;

        if (p->nw->qdisc != NETWORK_QDISC_NONE)
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: more than one root qdisc section is defined, ignoring the [%s] section",
                         path,
                         p->sec_qdisc_line,
                         p->sec_qdisc_name);
        else
                p->nw->qdisc = p->sec_qdisc;

        p->sec_qdisc = NETWORK_QDISC_NONE;
}

/* [FairQueueing] and friends, Parent=: root, the default, is the only parent
 * netd installs on. */
static int config_parse_qdisc_parent(NetworkParser *p, const char *path, unsigned line, const char *rvalue) {
        if (*rvalue == '\0') {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: invalid Parent= value '', ignoring the [%s] section",
                         path,
                         line,
                         p->sec_qdisc_name);
                p->sec_qdisc_root = false;
                return 0;
        }

        p->sec_qdisc_root = strcmp(rvalue, "root") == 0;
        if (!p->sec_qdisc_root)
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: Parent=%s is not supported, ignoring the [%s] section",
                         path,
                         line,
                         rvalue,
                         p->sec_qdisc_name);
        return 0;
}

static int network_section_handler(const char *path, unsigned line, const char *section, void *userdata) {
        NetworkParser *p = userdata;
        ssize_t i;

        network_qdisc_commit(p, path);
        p->sec_qdisc = NETWORK_QDISC_NONE;

        for (size_t k = 0; k < sizeof(network_qdisc_sections) / sizeof(network_qdisc_sections[0]); k++)
                if (strcmp(section, network_qdisc_sections[k].section) == 0) {
                        p->sec_qdisc = network_qdisc_sections[k].kind;
                        p->sec_qdisc_name = network_qdisc_sections[k].section;
                        p->sec_qdisc_line = line;
                        p->sec_qdisc_root = true;
                        p->sec_qdisc_keys = false;
                }

        p->cur = -1;
        p->cur_route = -1;

        if (strcmp(section, "Address") == 0) {
                i = network_address_append(p, path, line);
                if (i == -ENOMEM)
                        return -ENOMEM;
                p->cur = i;
        } else if (strcmp(section, "Route") == 0) {
                i = network_route_append(p, path, line);
                if (i == -ENOMEM)
                        return -ENOMEM;
                p->cur_route = i;
        }

        return 0;
}

/* [Network] Address=: its own entry per line; empty clears every entry so far. */
static int config_parse_network_address(
                NetworkParser *p, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        NetworkAddress *a;
        NetdInAddr addr;
        unsigned char plen;
        ssize_t i;
        int family, r;
        (void) lvalue;

        if (*rvalue == '\0') {
                p->nw->n_addresses = 0;
                return 0;
        }

        r = netd_prefix_parse(rvalue, &family, &addr, &plen);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid Address= value '%s', ignoring", path, line, rvalue);
                return 0;
        }

        i = network_address_append(p, path, line);
        if (i < 0)
                return i == -ENOMEM ? -ENOMEM : 0;

        a = &p->nw->addresses[i];
        a->family = (uint8_t) family;
        a->prefixlen = plen;
        a->address = addr;
        return 0;
}

static int config_parse_section_address(
                NetworkAddress *a, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        NetdInAddr addr;
        unsigned char plen;
        int family;
        (void) lvalue;

        /* An empty assignment clears both Address= and Peer=, as in networkd. */
        if (*rvalue == '\0') {
                a->family = 0;
                a->peer_family = 0;
                a->peer_set = false;
                a->prefixlen = 0;
                memset(&a->address, 0, sizeof(a->address));
                memset(&a->peer, 0, sizeof(a->peer));
                return 0;
        }

        if (netd_prefix_parse(rvalue, &family, &addr, &plen) < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid Address= value '%s', ignoring", path, line, rvalue);
                return 0;
        }

        a->family = (uint8_t) family;
        a->prefixlen = plen;
        a->address = addr;
        return 0;
}

/* Only the address of Peer= is used; the prefix length is Address='s. */
static int config_parse_section_peer(
                NetworkAddress *a, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        char buf[INET6_ADDRSTRLEN + 8];
        const char *slash = strchr(rvalue, '/');
        NetdInAddr addr;
        size_t len = slash ? (size_t) (slash - rvalue) : strlen(rvalue);
        int family;
        (void) lvalue;

        if (*rvalue == '\0') {
                a->peer_set = false;
                a->peer_family = 0;
                return 0;
        }

        if (len >= sizeof(buf)) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid Peer= value '%s', ignoring", path, line, rvalue);
                return 0;
        }
        memcpy(buf, rvalue, len);
        buf[len] = '\0';

        if (netd_addr_parse(buf, &family, &addr) < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid Peer= value '%s', ignoring", path, line, rvalue);
                return 0;
        }

        if (slash)
                pico_log(PICO_LOG_DEBUG,
                         "%s:%u: Peer= prefix length in '%s' is ignored, Address= sets it",
                         path,
                         line,
                         rvalue);

        a->peer_family = (uint8_t) family;
        a->peer = addr;
        a->peer_set = true;
        return 0;
}

static int config_parse_section_label(
                NetworkAddress *a, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        (void) lvalue;

        if (strlen(rvalue) >= sizeof(a->label)) {
                pico_log(PICO_LOG_WARNING, "%s:%u: Label= value '%s' is too long, ignoring", path, line, rvalue);
                return 0;
        }

        memcpy(a->label, rvalue, strlen(rvalue) + 1);
        return 0;
}

static int config_parse_section_route_metric(
                NetworkAddress *a, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        uint32_t v = 0;

        if (*rvalue != '\0' && parse_route_metric(rvalue, &v) < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
                return 0;
        }

        a->route_metric = v;
        return 0;
}

/* networkd takes forever, infinity, empty and 0 only. */
static int config_parse_section_preferred_lifetime(
                NetworkAddress *a, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        if (*rvalue == '\0' || strcmp(rvalue, "forever") == 0 || strcmp(rvalue, "infinity") == 0)
                a->deprecated = false;
        else if (strcmp(rvalue, "0") == 0)
                a->deprecated = true;
        else
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);

        return 0;
}

/* networkd's scope names, or a number from 0 to 255 (-EINVAL otherwise). */
static int parse_scope(const char *s, uint8_t *ret) {
        static const struct {
                const char *name;
                uint8_t scope;
        } names[] = {
                {  "global",   0 },
                {    "site", 200 },
                {    "link", 253 },
                {    "host", 254 },
                { "nowhere", 255 },
        };
        unsigned long v;

        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
                if (strcmp(s, names[i].name) == 0) {
                        *ret = names[i].scope;
                        return 0;
                }

        if (*s == '\0' || strlen(s) > 3 || strspn(s, "0123456789") != strlen(s))
                return -EINVAL;

        v = strtoul(s, NULL, 10);
        if (v > 255)
                return -EINVAL;

        *ret = (uint8_t) v;
        return 0;
}

static int config_parse_section_scope(
                NetworkAddress *a, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        uint8_t v;

        if (*rvalue == '\0') {
                a->scope_set = false;
                return 0;
        }

        if (parse_scope(rvalue, &v) < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
                return 0;
        }

        a->scope = v;
        a->scope_set = true;
        return 0;
}

/* Only the IPv6 half has an effect: there is no IPv4 address conflict
 * detection to run. The boolean spellings keep networkd's historical meaning,
 * where yes turns detection off. */
static int config_parse_section_dad(
                NetworkAddress *a, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        bool b;

        if (*rvalue == '\0') {
                a->dad_set = false;
                return 0;
        }

        if (network_parse_bool(rvalue, &b) == 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: %s=%s means %s=%s, use 'both', 'ipv4', 'ipv6' or 'none'",
                         path,
                         line,
                         lvalue,
                         rvalue,
                         lvalue,
                         b ? "none" : "both");
                a->dad = !b;
        } else if (strcmp(rvalue, "both") == 0 || strcmp(rvalue, "ipv6") == 0)
                a->dad = true;
        else if (strcmp(rvalue, "none") == 0)
                a->dad = false;
        else if (strcmp(rvalue, "ipv4") == 0) {
                pico_log(PICO_LOG_DEBUG,
                         "%s:%u: %s=ipv4 has no effect, there is no IPv4 conflict detection",
                         path,
                         line,
                         lvalue);
                a->dad = false;
        } else {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
                return 0;
        }

        a->dad_set = true;
        return 0;
}

static int config_parse_section_add_prefix_route(
                NetworkAddress *a, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        bool b;

        if (network_parse_bool(rvalue, &b) < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
                return 0;
        }

        a->no_prefix_route = !b;
        return 0;
}

static const NetworkAddressConfigItem address_config_items[] = {
        {                   "Address",            config_parse_section_address },
        {                      "Peer",               config_parse_section_peer },
        {                     "Label",              config_parse_section_label },
        {               "RouteMetric",       config_parse_section_route_metric },
        {         "PreferredLifetime", config_parse_section_preferred_lifetime },
        {                     "Scope",              config_parse_section_scope },
        { "DuplicateAddressDetection",                config_parse_section_dad },
        {            "AddPrefixRoute",   config_parse_section_add_prefix_route },
};

static bool network_address_same(const NetworkAddress *a, const NetworkAddress *b) {
        if (a->family != b->family)
                return false;

        if (!netd_addr_eq(a->family, &a->address, &b->address))
                return false;

        /* An IPv6 address is one address whatever its prefix length. */
        return a->family == AF_INET6 || a->prefixlen == b->prefixlen;
}

/* Where a later duplicate is: "line N" in the same file, else "file:N". */
static const char *network_where(char *buf, size_t size, const char *first, const char *file, unsigned line) {
        if (strcmp(first, file) == 0)
                snprintf(buf, size, "line %u", line);
        else
                snprintf(buf, size, "%s:%u", file, line);
        return buf;
}

/*
 * Drops what networkd drops and fills in the defaults, once every file is
 * read, because the keys of a section come in any order. The later of two
 * entries for one address wins, as in networkd.
 */
static void network_verify_addresses(Network *nw) {
        size_t n = 0;

        for (size_t i = 0; i < nw->n_addresses; i++) {
                NetworkAddress a = nw->addresses[i];
                char buf[INET6_ADDRSTRLEN];
                char where[PATH_MAX + 16];
                size_t k;

                if (a.family == 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: [Address] section without Address=, ignoring",
                                 a.file,
                                 a.line);
                        continue;
                }

                if (a.peer_set && a.peer_family != a.family) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: Peer= is not the same family as Address=, ignoring the address",
                                 a.file,
                                 a.line);
                        continue;
                }

                if (netd_addr_is_null(a.family, &a.address)) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: a null Address= asks for an address pool, which is not supported, ignoring",
                                 a.file,
                                 a.line);
                        continue;
                }

                if (a.family == AF_INET6 && a.label[0] != '\0') {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: Label= has no effect on an IPv6 address, ignoring it",
                                 a.file,
                                 a.line);
                        a.label[0] = '\0';
                }

                if (!a.scope_set) {
                        if (netd_addr_is_loopback(a.family, &a.address))
                                a.scope = 254; /* RT_SCOPE_HOST */
                        else if (netd_addr_is_link_local(a.family, &a.address))
                                a.scope = 253; /* RT_SCOPE_LINK */
                }

                if (!a.dad_set)
                        a.dad = a.family == AF_INET6;

                for (k = 0; k < n; k++)
                        if (network_address_same(&nw->addresses[k], &a))
                                break;

                if (k < n) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: address %s is also set at %s, using the later one",
                                 nw->addresses[k].file,
                                 nw->addresses[k].line,
                                 netd_addr_to_string(a.family, &a.address, buf),
                                 network_where(where, sizeof(where), nw->addresses[k].file, a.file, a.line));
                        memmove(&nw->addresses[k], &nw->addresses[k + 1], (n - k - 1) * sizeof(*nw->addresses));
                        n--;
                }

                nw->addresses[n++] = a;
        }

        nw->n_addresses = n;
}

/* --- [Route] --- */

typedef int (*NetworkRouteParseFn)(
                NetworkRoute *r, const char *path, unsigned line, const char *lvalue, const char *rvalue);

typedef struct NetworkRouteConfigItem {
        const char *lvalue;
        NetworkRouteParseFn parse;
} NetworkRouteConfigItem;

static void route_warn_invalid(const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
}

/*
 * A key that changes what the route is: installing a different route than the
 * file asks for is worse than installing none, so the section goes, with one
 * warning.
 */
static void route_drop(NetworkRoute *r, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        if (r->drop)
                return;

        r->drop = true;
        pico_log(PICO_LOG_WARNING,
                 "%s:%u: %s=%s is not supported, ignoring the [Route] section",
                 path,
                 line,
                 lvalue,
                 rvalue);
}

/* A prefix, or a bare address for a host route. */
static int route_destination_parse(const char *s, int *family, NetdInAddr *a, unsigned char *plen) {
        int r;

        if (strchr(s, '/'))
                return netd_prefix_parse(s, family, a, plen);

        r = netd_addr_parse(s, family, a);
        if (r < 0)
                return r;

        *plen = *family == AF_INET ? 32 : 128;
        return 0;
}

static int config_parse_route_destination(
                NetworkRoute *r, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        NetdInAddr a;
        unsigned char plen;
        int family;

        if (route_destination_parse(rvalue, &family, &a, &plen) < 0) {
                route_warn_invalid(path, line, lvalue, rvalue);
                return 0;
        }

        netd_addr_mask(family, &a, plen);
        r->dst_family = (uint8_t) family;
        r->dst = a;
        r->dst_len = plen;
        return 0;
}

static int config_parse_route_gateway(
                NetworkRoute *r, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        NetdInAddr a;
        int family;

        if (*rvalue == '\0') {
                r->gw_family = 0;
                memset(&r->gw, 0, sizeof(r->gw));
                return 0;
        }

        if (strcmp(rvalue, "_dhcp4") == 0 || strcmp(rvalue, "_ipv6ra") == 0 || strcmp(rvalue, "_dhcp") == 0) {
                route_drop(r, path, line, lvalue, rvalue);
                return 0;
        }

        if (netd_addr_parse(rvalue, &family, &a) < 0 || netd_addr_is_null(family, &a)) {
                route_warn_invalid(path, line, lvalue, rvalue);
                return 0;
        }

        r->gw_family = (uint8_t) family;
        r->gw = a;
        return 0;
}

static int config_parse_route_metric(
                NetworkRoute *r, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        uint32_t v;

        if (parse_route_metric(rvalue, &v) < 0) {
                route_warn_invalid(path, line, lvalue, rvalue);
                return 0;
        }

        r->metric = v;
        return 0;
}

static int config_parse_route_onlink(
                NetworkRoute *r, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        bool b;

        if (*rvalue == '\0') {
                r->onlink_set = false;
                return 0;
        }

        if (network_parse_bool(rvalue, &b) < 0) {
                route_warn_invalid(path, line, lvalue, rvalue);
                return 0;
        }

        r->onlink = b;
        r->onlink_set = true;
        return 0;
}

/* "no" is networkd's way of refusing a source taken from a lease, which netd
 * has none of; it leaves the key unset. */
static int config_parse_route_prefsrc(
                NetworkRoute *r, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        NetdInAddr a;
        bool b;
        int family;

        if (*rvalue == '\0' || (network_parse_bool(rvalue, &b) == 0 && !b)) {
                r->prefsrc_family = 0;
                memset(&r->prefsrc, 0, sizeof(r->prefsrc));
                return 0;
        }

        if (netd_addr_parse(rvalue, &family, &a) < 0 || netd_addr_is_null(family, &a)) {
                route_warn_invalid(path, line, lvalue, rvalue);
                return 0;
        }

        r->prefsrc_family = (uint8_t) family;
        r->prefsrc = a;
        return 0;
}

static int config_parse_route_scope(
                NetworkRoute *r, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        uint8_t v;

        if (parse_scope(rvalue, &v) < 0) {
                route_warn_invalid(path, line, lvalue, rvalue);
                return 0;
        }

        r->scope = v;
        r->scope_set = true;
        return 0;
}

/* The main table and the unicast type are what every route gets anyway. */
static int config_parse_route_table(
                NetworkRoute *r, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        if (*rvalue != '\0' && strcmp(rvalue, "main") != 0 && strcmp(rvalue, "254") != 0)
                route_drop(r, path, line, lvalue, rvalue);

        return 0;
}

static int config_parse_route_type(
                NetworkRoute *r, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        if (*rvalue != '\0' && strcmp(rvalue, "unicast") != 0)
                route_drop(r, path, line, lvalue, rvalue);

        return 0;
}

static int config_parse_route_unsupported(
                NetworkRoute *r, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        if (*rvalue != '\0')
                route_drop(r, path, line, lvalue, rvalue);

        return 0;
}

static const NetworkRouteConfigItem route_config_items[] = {
        {     "Destination", config_parse_route_destination },
        {         "Gateway",     config_parse_route_gateway },
        {          "Metric",      config_parse_route_metric },
        {   "GatewayOnLink",      config_parse_route_onlink },
        { "PreferredSource",     config_parse_route_prefsrc },
        {           "Scope",       config_parse_route_scope },
        {           "Table",       config_parse_route_table },
        {            "Type",        config_parse_route_type },
        {          "Source", config_parse_route_unsupported },
        {  "MultiPathRoute", config_parse_route_unsupported },
        {         "NextHop", config_parse_route_unsupported },
};

static bool network_route_same(const NetworkRoute *a, const NetworkRoute *b) {
        return a->family == b->family && a->dst_len == b->dst_len && a->scope == b->scope &&
                        a->metric == b->metric && a->onlink == b->onlink &&
                        (a->gw_family != 0) == (b->gw_family != 0) &&
                        (a->prefsrc_family != 0) == (b->prefsrc_family != 0) &&
                        memcmp(a->dst.bytes, b->dst.bytes, sizeof(a->dst.bytes)) == 0 &&
                        memcmp(a->gw.bytes, b->gw.bytes, sizeof(a->gw.bytes)) == 0 &&
                        memcmp(a->prefsrc.bytes, b->prefsrc.bytes, sizeof(a->prefsrc.bytes)) == 0;
}

/*
 * Drops what networkd drops and fills in the defaults, once the whole file is
 * read. A section without any of Gateway=, Destination= or PreferredSource=
 * has no family and goes, so the `Metric=` line of a console image's [Route]
 * is a warned no-op and never a metric on some route. The later of two
 * identical routes wins.
 */
static void network_verify_routes(Network *nw) {
        size_t n = 0;

        for (size_t i = 0; i < nw->n_routes; i++) {
                NetworkRoute r = nw->routes[i];
                char where[PATH_MAX + 16];
                size_t k;

                if (r.drop)
                        continue;

                r.family = r.dst_family ? r.dst_family : (r.gw_family ? r.gw_family : r.prefsrc_family);
                if (r.family == 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: [Route] section without Gateway=, Destination=, Source=, or PreferredSource= field configured, ignoring",
                                 r.file,
                                 r.line);
                        continue;
                }

                if ((r.dst_family && r.dst_family != r.family) || (r.gw_family && r.gw_family != r.family) ||
                    (r.prefsrc_family && r.prefsrc_family != r.family)) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: Destination=, Gateway= and PreferredSource= are not all IPv4 or all IPv6, ignoring the [Route] section",
                                 r.file,
                                 r.line);
                        continue;
                }

                if (r.family == AF_INET6) {
                        if (r.scope_set && r.scope != RT_SCOPE_UNIVERSE)
                                pico_log(PICO_LOG_WARNING,
                                         "%s:%u: Scope= is specified for an IPv6 route, ignoring it",
                                         r.file,
                                         r.line);

                        r.scope = RT_SCOPE_UNIVERSE;
                        /* The kernel's own default for a user route; recording it
                         * keeps the delete and the comparison on the same value. */
                        if (r.metric == 0)
                                r.metric = 1024;
                } else if (!r.scope_set)
                        r.scope = r.gw_family ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;

                if (!r.onlink_set && r.gw_family && nw->n_addresses == 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: Gateway= without a static address configured, enabling GatewayOnLink=",
                                 r.file,
                                 r.line);
                        r.onlink = true;
                }

                for (k = 0; k < n; k++)
                        if (network_route_same(&nw->routes[k], &r))
                                break;

                if (k < n) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: the same route is set at %s, using the later one",
                                 nw->routes[k].file,
                                 nw->routes[k].line,
                                 network_where(where, sizeof(where), nw->routes[k].file, r.file, r.line));
                        memmove(&nw->routes[k], &nw->routes[k + 1], (n - k - 1) * sizeof(*nw->routes));
                        n--;
                }

                nw->routes[n++] = r;
        }

        nw->n_routes = n;
}

/* A rejected value, the empty one included, keeps any earlier value: networkd
 * logs and ignores it too, rather than resetting. */
static int config_parse_dhcp4_route_metric(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        uint32_t v;

        if (parse_route_metric(rvalue, &v) < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
                return 0;
        }

        nw->dhcp_route_metric = v;
        nw->dhcp_route_metric_set = true;
        nw->dhcp_route_metric_v4 = true;
        return 0;
}

/* [DHCP] RouteMetric=: networkd's config_parse_dhcp_route_metric() lets it
 * apply only while no [DHCPv4] value has been seen. */
static int config_parse_dhcp_legacy_route_metric(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        uint32_t v;

        if (parse_route_metric(rvalue, &v) < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
                return 0;
        }

        if (nw->dhcp_route_metric_v4)
                return 0;

        nw->dhcp_route_metric = v;
        nw->dhcp_route_metric_set = true;
        return 0;
}

/* --- [IPv6AcceptRA] --- */

static int config_parse_ipv6_accept_ra(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        bool b;

        if (*rvalue == '\0') {
                nw->ipv6_accept_ra = -1;
                return 0;
        }

        if (network_parse_bool(rvalue, &b) < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
                return 0;
        }

        nw->ipv6_accept_ra = b;
        return 0;
}

static int config_parse_ra_use_gateway(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_bool_field(path, line, lvalue, rvalue, &nw->ra_use_gateway);
}

static int config_parse_ra_use_onlink_prefix(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_bool_field(path, line, lvalue, rvalue, &nw->ra_use_onlink_prefix);
}

static int config_parse_ra_use_autonomous_prefix(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_bool_field(path, line, lvalue, rvalue, &nw->ra_use_autonomous_prefix);
}

static int config_parse_ra_use_dns(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_bool_field(path, line, lvalue, rvalue, &nw->ra_use_dns);
}

static int config_parse_ra_use_mtu(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_bool_field(path, line, lvalue, rvalue, &nw->ra_use_mtu);
}

/* networkd's "route" puts the domains on resolved's routing list only, which
 * resolv.conf cannot express: here it is the same as no. */
static int config_parse_ra_use_domains(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        if (strcmp(rvalue, "route") == 0) {
                pico_log(PICO_LOG_DEBUG,
                         "%s:%u: %s=route has no resolv.conf equivalent, treating it as no",
                         path,
                         line,
                         lvalue);
                nw->ra_use_domains = false;
                return 0;
        }

        return config_parse_bool_field(path, line, lvalue, rvalue, &nw->ra_use_domains);
}

/* "N" for all three, or "high:medium:low" strictly increasing, as networkd's
 * config_parse_ndisc_route_metric(). A rejected value keeps the previous one. */
static int config_parse_ra_route_metric(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        uint32_t m[3];
        char buf[3 * 11 + 3];
        char *p = buf;

        if (parse_route_metric(rvalue, &m[0]) == 0) {
                m[1] = m[2] = m[0];
                goto set;
        }

        if (strlen(rvalue) >= sizeof(buf))
                goto invalid;
        memcpy(buf, rvalue, strlen(rvalue) + 1);

        for (unsigned i = 0; i < 3; i++) {
                char *colon = strchr(p, ':');

                if ((i < 2) != (colon != NULL))
                        goto invalid;
                if (colon)
                        *colon = '\0';
                if (parse_route_metric(p, &m[i]) < 0)
                        goto invalid;
                p = colon ? colon + 1 : p;
        }

        if (m[0] >= m[1] || m[1] >= m[2])
                goto invalid;

set:
        memcpy(nw->ra_route_metric, m, sizeof(m));
        return 0;

invalid:
        pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
        return 0;
}

/*
 * eui64, prefixstable, or static:ADDRESS (a bare address also means static),
 * whose low 64 bits are the identifier. networkd collects several tokens per
 * link; netd keeps one, the last. The prefixstable forms with a prefix filter
 * or a secret key are not supported and are ignored.
 */
static int config_parse_ra_token(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        struct in6_addr a;
        const char *addr;

        if (*rvalue == '\0') {
                nw->ra_token = NETWORK_RA_TOKEN_DEFAULT;
                return 0;
        }

        if (strcmp(rvalue, "eui64") == 0) {
                nw->ra_token = NETWORK_RA_TOKEN_EUI64;
                return 0;
        }

        if (strcmp(rvalue, "prefixstable") == 0) {
                nw->ra_token = NETWORK_RA_TOKEN_PREFIXSTABLE;
                return 0;
        }

        if (strncmp(rvalue, "prefixstable", strlen("prefixstable")) == 0) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: %s=%s: a prefix or secret key with prefixstable is not supported, ignoring",
                         path,
                         line,
                         lvalue,
                         rvalue);
                return 0;
        }

        addr = strncmp(rvalue, "static:", strlen("static:")) == 0 ? rvalue + strlen("static:") : rvalue;

        if (inet_pton(AF_INET6, addr, &a) != 1) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid %s= value '%s', ignoring", path, line, lvalue, rvalue);
                return 0;
        }

        memset(a.s6_addr, 0, 8);
        if (IN6_IS_ADDR_UNSPECIFIED(&a)) {
                pico_log(PICO_LOG_WARNING,
                         "%s:%u: %s=%s has no interface identifier in its low 64 bits, ignoring",
                         path,
                         line,
                         lvalue,
                         rvalue);
                return 0;
        }

        nw->ra_token = NETWORK_RA_TOKEN_STATIC;
        nw->ra_token_addr = a;
        return 0;
}

typedef int (*NetworkParseFn)(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue);

typedef struct NetworkConfigItem {
        const char *section;
        const char *lvalue;
        NetworkParseFn parse;
} NetworkConfigItem;

static const NetworkConfigItem network_config_items[] = {
        {        "Match",                "Name",               config_parse_match_name },
        {      "Network",                "DHCP",                     config_parse_dhcp },
        {      "Network",             "Gateway",                  config_parse_gateway },
        {      "Network",                 "DNS",                      config_parse_dns },
        {      "Network",                 "NTP",                      config_parse_ntp },
        {      "Network",          "DHCPServer",              config_parse_dhcp_server },
        {      "Network",                "LLDP",                     config_parse_lldp },
        {      "Network",            "EmitLLDP",                config_parse_emit_lldp },
        {       "DHCPv4",              "UseDNS",                  config_parse_use_dns },
        {       "DHCPv4",              "UseNTP",                  config_parse_use_ntp },
        {       "DHCPv4",         "UseTimezone",             config_parse_use_timezone },
        {       "DHCPv4",         "RouteMetric",       config_parse_dhcp4_route_metric },
        {         "DHCP",         "RouteMetric", config_parse_dhcp_legacy_route_metric },
        {      "Network",        "IPv6AcceptRA",           config_parse_ipv6_accept_ra },
        {      "Network",           "IPv6Token",                 config_parse_ra_token },
        { "IPv6AcceptRA",          "UseGateway",           config_parse_ra_use_gateway },
        { "IPv6AcceptRA",     "UseOnLinkPrefix",     config_parse_ra_use_onlink_prefix },
        { "IPv6AcceptRA", "UseAutonomousPrefix", config_parse_ra_use_autonomous_prefix },
        { "IPv6AcceptRA",              "UseDNS",               config_parse_ra_use_dns },
        { "IPv6AcceptRA",          "UseDomains",           config_parse_ra_use_domains },
        { "IPv6AcceptRA",              "UseMTU",               config_parse_ra_use_mtu },
        { "IPv6AcceptRA",         "RouteMetric",          config_parse_ra_route_metric },
        { "IPv6AcceptRA",               "Token",                 config_parse_ra_token },
};

/*
 * The conf-scan.h handler: dispatches one already-scanned assignment through
 * network_config_items[], and logs-and-drops anything not in it -- the same
 * drop-in tolerance rule unit-parse.c's own handler applies (see that file),
 * so a section this parser has never heard of simply never matches a row here
 * and falls straight to the debug log below. [DHCP] has a row for
 * RouteMetric= only; its other keys take the same path, as do the
 * [IPv6AcceptRA] keys netd does not implement.
 */
static int network_conf_handler(
                const char *path,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *userdata) {
        NetworkParser *p = userdata;
        Network *nw = p->nw;
        size_t i;

        if (!section) {
                pico_log(PICO_LOG_WARNING, "%s:%u: assignment outside any section, ignoring", path, line);
                return 0;
        }

        if (strcmp(section, "Network") == 0 && strcmp(lvalue, "Address") == 0)
                return config_parse_network_address(p, path, line, lvalue, rvalue);

        if (p->sec_qdisc != NETWORK_QDISC_NONE) {
                p->sec_qdisc_keys = true;
                if (strcmp(lvalue, "Parent") == 0)
                        return config_parse_qdisc_parent(p, path, line, rvalue);
        }

        if (strcmp(section, "Address") == 0) {
                if (p->cur < 0)
                        return 0;

                for (i = 0; i < sizeof(address_config_items) / sizeof(address_config_items[0]); i++)
                        if (strcmp(address_config_items[i].lvalue, lvalue) == 0)
                                return address_config_items[i].parse(
                                                &nw->addresses[p->cur], path, line, lvalue, rvalue);

                pico_log(PICO_LOG_DEBUG,
                         "%s:%u: unknown directive %s= in [%s], ignoring",
                         path,
                         line,
                         lvalue,
                         section);
                return 0;
        }

        if (strcmp(section, "Route") == 0) {
                if (p->cur_route < 0)
                        return 0;

                for (i = 0; i < sizeof(route_config_items) / sizeof(route_config_items[0]); i++)
                        if (strcmp(route_config_items[i].lvalue, lvalue) == 0)
                                return route_config_items[i].parse(
                                                &nw->routes[p->cur_route], path, line, lvalue, rvalue);

                pico_log(PICO_LOG_DEBUG,
                         "%s:%u: unknown directive %s= in [%s], ignoring",
                         path,
                         line,
                         lvalue,
                         section);
                return 0;
        }

        for (i = 0; i < sizeof(network_config_items) / sizeof(network_config_items[0]); i++)
                if (strcmp(network_config_items[i].section, section) == 0 &&
                    strcmp(network_config_items[i].lvalue, lvalue) == 0)
                        return network_config_items[i].parse(nw, path, line, lvalue, rvalue);

        pico_log(PICO_LOG_DEBUG, "%s:%u: unknown directive %s= in [%s], ignoring", path, line, lvalue, section);
        return 0;
}

static char *path_basename_dup(const char *path) {
        const char *slash = strrchr(path, '/');

        return pico_strdup(slash ? slash + 1 : path);
}

/* Scan one file with the parser state of a fresh file. The resets are
 * defensive: a key before the first section is refused before they matter. */
static int network_scan_file(NetworkParser *parser, const char *path) {
        int r;

        parser->cur = -1;
        parser->cur_route = -1;
        parser->warned_cap = false;
        parser->warned_route_cap = false;
        parser->sec_qdisc = NETWORK_QDISC_NONE;

        r = pico_conf_scan_full(path, network_conf_handler, network_section_handler, parser);
        network_qdisc_commit(parser, path);
        return r;
}

/* As network_parse_files(), taking ownership of `dropins` on success and failure. */
static int network_parse_owned(const char *path, char **dropins, Network **ret) {
        NetworkParser parser = { 0 };
        Network *nw = NULL;
        int r;

        r = network_new(&nw);
        if (r < 0) {
                pico_strv_free(dropins);
                return r;
        }

        nw->dropins = dropins;

        nw->filename = pico_strdup(path);
        nw->basename = path_basename_dup(path);
        if (!nw->filename || !nw->basename) {
                network_free(nw);
                return -ENOMEM;
        }

        parser.nw = nw;

        r = network_scan_file(&parser, nw->filename);
        if (r < 0) {
                network_free(nw);
                return r;
        }

        /* A drop-in that is gone or unreadable costs that file only, as for
         * unit drop-ins. */
        for (char * const *d = nw->dropins; d && *d; d++) {
                int dr = network_scan_file(&parser, *d);

                if (dr < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "%s: failed to read drop-in '%s': %s",
                                 nw->filename,
                                 *d,
                                 strerror(-dr));
        }

        network_verify_addresses(nw);
        network_verify_routes(nw);

        *ret = nw;
        return 0;
}

int network_parse_files(const char *path, char * const *dropins, Network **ret) {
        char **copy = NULL;

        if (!path || !ret)
                return -EINVAL;

        for (; dropins && *dropins; dropins++)
                if (pico_strv_extend(&copy, *dropins) < 0) {
                        pico_strv_free(copy);
                        return -ENOMEM;
                }

        return network_parse_owned(path, copy, ret);
}

int network_parse_file(const char *path, Network **ret) {
        return network_parse_files(path, NULL, ret);
}

/* --- discovery: search-path walk, shadowing, ordering --- */

/* One *.network file resolved to the single directory that wins for it (the
 * earliest entry in n->network_path that has a file of this basename) --
 * same shape as unit-enable.c's PresetEntry, for the same reason. */
typedef struct NetworkEntry {
        char *basename;
        char *path;     /* dir/basename */
        char **dropins; /* the drop-in files that apply, in order; NULL for none */
} NetworkEntry;

static void network_entries_free(NetworkEntry *entries, size_t n) {
        for (size_t i = 0; i < n; i++) {
                free(entries[i].basename);
                free(entries[i].path);
                pico_strv_free(entries[i].dropins);
        }
        free(entries);
}

static void network_dirlists_free(PicoDropinDirList *lists, size_t n) {
        for (size_t i = 0; i < n; i++)
                pico_dropin_dirlist_clear(&lists[i]);
        free(lists);
}

static int network_entry_cmp(const void *a, const void *b) {
        const NetworkEntry *ea = a;
        const NetworkEntry *eb = b;

        return strcmp(ea->basename, eb->basename);
}

static bool has_network_suffix(const char *name) {
        static const char suffix[] = NETWORK_FILE_SUFFIX;
        size_t slen = sizeof(suffix) - 1;
        size_t len = strlen(name);

        return len > slen && strcmp(name + len - slen, suffix) == 0;
}

/*
 * Collect one NetworkEntry per distinct *.network basename across the whole
 * search path, in directory order -- so a basename already recorded from an
 * earlier (higher-priority) directory shadows the same name turning up in a
 * later one, and the lower-priority file is never even opened. The caller
 * sorts the result by basename to get the real cross-directory file order.
 *
 * The same pass over each directory records its "*.network.d" directories in
 * `*ret_dirs`, one list per search-path entry, so finding the drop-ins of a
 * file needs no further listing.
 */
static int collect_network_entries(Netd *n, NetworkEntry **ret, size_t *ret_n, PicoDropinDirList **ret_dirs) {
        PicoDropinDirList *dirs = NULL;
        NetworkEntry *entries = NULL;
        size_t n_alloc = 0;
        size_t n_entries = 0;
        size_t n_dirs = n->network_path ? pico_strv_length(n->network_path) : 0;
        int rc = 0;

        dirs = calloc(n_dirs ? n_dirs : 1, sizeof(*dirs));
        if (!dirs)
                return -ENOMEM;

        for (size_t i = 0; n->network_path && n->network_path[i]; i++) {
                const char *dir = n->network_path[i];
                struct dirent *de;
                DIR *d;

                d = opendir(dir);
                if (!d) {
                        if (errno == ENOENT)
                                continue;
                        rc = -errno;
                        goto fail;
                }

                while ((de = readdir(d))) {
                        char path[PATH_MAX];
                        bool shadowed = false;
                        int written;

                        if (pico_dropin_dirlist_add(&dirs[i], de, NETWORK_FILE_SUFFIX ".d") < 0) {
                                rc = -ENOMEM;
                                closedir(d);
                                goto fail;
                        }

                        if (!has_network_suffix(de->d_name))
                                continue;

                        for (size_t j = 0; j < n_entries; j++)
                                if (strcmp(entries[j].basename, de->d_name) == 0) {
                                        shadowed = true;
                                        break;
                                }

                        if (shadowed)
                                continue;

                        written = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
                        if (written < 0 || (size_t) written >= sizeof(path))
                                continue; /* unusable path, drop this one file */

                        if (n_entries == n_alloc) {
                                NetworkEntry *grown;
                                size_t new_alloc = n_alloc ? n_alloc * 2 : 8;

                                grown = realloc(entries, new_alloc * sizeof(*entries));
                                if (!grown) {
                                        rc = -ENOMEM;
                                        closedir(d);
                                        goto fail;
                                }
                                entries = grown;
                                n_alloc = new_alloc;
                        }

                        entries[n_entries].dropins = NULL;
                        entries[n_entries].basename = pico_strdup(de->d_name);
                        entries[n_entries].path = pico_strdup(path);
                        if (!entries[n_entries].basename || !entries[n_entries].path) {
                                free(entries[n_entries].basename);
                                free(entries[n_entries].path);
                                rc = -ENOMEM;
                                closedir(d);
                                goto fail;
                        }
                        n_entries++;
                }

                closedir(d);
                pico_dropin_dirlist_sort(&dirs[i]);
        }

        qsort(entries, n_entries, sizeof(*entries), network_entry_cmp);

        *ret = entries;
        *ret_n = n_entries;
        *ret_dirs = dirs;
        return 0;

fail:
        network_entries_free(entries, n_entries);
        network_dirlists_free(dirs, n_dirs);
        return rc;
}

/*
 * The drop-ins of "foo.network" are the files of "foo.network.d" in every
 * search-path directory, as networkd reads them (network_load_one() in
 * networkd-network.c): no type-level or dash-truncated directory, and a file
 * name in an earlier directory hides the same name in a later one. They apply
 * wherever the .network file itself was found.
 */
static int network_find_dropins(Netd *n, const PicoDropinDirList *lists, const char *basename, char ***ret) {
        char **dirs = NULL;
        char dirname[NAME_MAX + 1];
        int r;

        if (snprintf(dirname, sizeof(dirname), "%s.d", basename) >= (int) sizeof(dirname))
                return 0;

        for (size_t i = 0; n->network_path && n->network_path[i]; i++) {
                char path[PATH_MAX];

                if (!pico_dropin_dirlist_has(&lists[i], dirname))
                        continue;
                if (snprintf(path, sizeof(path), "%s/%s", n->network_path[i], dirname) >= (int) sizeof(path)) {
                        pico_log(PICO_LOG_WARNING, "drop-ins: path of '%s' too long, skipping", dirname);
                        continue;
                }

                r = pico_strv_extend(&dirs, path);
                if (r < 0) {
                        pico_strv_free(dirs);
                        return r;
                }
        }

        if (!dirs)
                return 0;

        r = pico_dropin_files(dirs, ret);
        pico_strv_free(dirs);
        return r;
}

/* Like networkd's null_or_empty(): any character device or an empty file. */
static bool network_file_masked(const char *path) {
        struct stat st;

        if (stat(path, &st) < 0)
                return false;

        return S_ISCHR(st.st_mode) || (S_ISREG(st.st_mode) && st.st_size == 0);
}

int network_load_all(Netd *n) {
        PicoDropinDirList *dirlists = NULL;
        size_t n_dirs;
        NetworkEntry *entries = NULL;
        size_t n_entries = 0;
        Network **networks = NULL;
        size_t n_networks = 0;
        int loaded = 0;
        int r;

        if (!n)
                return -EINVAL;

        n_dirs = n->network_path ? pico_strv_length(n->network_path) : 0;

        r = collect_network_entries(n, &entries, &n_entries, &dirlists);
        if (r < 0)
                return r;

        for (size_t i = 0; i < n_entries; i++) {
                Network *nw = NULL;
                Network **grown;

                if (network_file_masked(entries[i].path)) {
                        pico_log(PICO_LOG_DEBUG, "%s: empty or masked, skipping", entries[i].path);
                        continue;
                }

                r = network_find_dropins(n, dirlists, entries[i].basename, &entries[i].dropins);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: cannot list drop-ins (%s), skipping",
                                 entries[i].path,
                                 strerror(-r));
                        continue;
                }

                /*
                 * A parse failure in one file does not abort the load: the
                 * running configuration is only replaced once the new set is
                 * complete (netd-network.h), and one malformed file must not
                 * cost every other interface its configuration.
                 */
                r = network_parse_owned(entries[i].path, entries[i].dropins, &nw);
                entries[i].dropins = NULL;
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: failed to parse (%s), skipping",
                                 entries[i].path,
                                 strerror(-r));
                        continue;
                }

                grown = realloc(networks, (n_networks + 1) * sizeof(*grown));
                if (!grown) {
                        network_free(nw);
                        for (size_t j = 0; j < n_networks; j++)
                                network_free(networks[j]);
                        free(networks);
                        network_entries_free(entries, n_entries);
                        network_dirlists_free(dirlists, n_dirs);
                        return -ENOMEM;
                }
                networks = grown;
                networks[n_networks++] = nw;
                loaded++;
        }

        network_entries_free(entries, n_entries);
        network_dirlists_free(dirlists, n_dirs);

        /* replace only once the new set is complete */
        network_free_all(n);
        n->networks = networks;
        n->n_networks = n_networks;

        return loaded;
}

bool network_matches(const Network *nw, const char *ifname) {
        bool matched = false, has_positive = false;

        if (!nw || !ifname || !nw->match_name)
                return false;

        for (char * const *p = nw->match_name; *p; p++)
                if (**p != '!')
                        has_positive = true;

        /* A matching "!pattern" vetoes the file; a list of only negations
         * matches every other name. */
        for (char * const *p = nw->match_name; *p; p++) {
                bool negated = **p == '!';

                if (fnmatch(*p + negated, ifname, 0) != 0)
                        continue;
                if (negated)
                        return false;
                matched = true;
        }

        return matched || !has_positive;
}

Network *network_find(Netd *n, const char *ifname) {
        if (!n || !ifname)
                return NULL;

        for (size_t i = 0; i < n->n_networks; i++)
                if (network_matches(n->networks[i], ifname))
                        return n->networks[i];

        return NULL;
}

/*
 * Value spellings. This table holds the address-family words and the plain
 * yes/no; every other boolean spelling goes through network_parse_bool().
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
        bool b;

        if (!s)
                return _NETWORK_DHCP_INVALID;

        /* Case-insensitive like every boolean key in this file. */
        for (NetworkDHCP d = 0; d < _NETWORK_DHCP_MAX; d++)
                if (strcasecmp(s, network_dhcp_table[d]) == 0)
                        return d;

        if (network_parse_bool(s, &b) == 0)
                return b ? NETWORK_DHCP_YES : NETWORK_DHCP_NO;

        return _NETWORK_DHCP_INVALID;
}
