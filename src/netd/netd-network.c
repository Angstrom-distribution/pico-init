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

#include "../conf-scan.h"
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
 * DNS=/NTP=: a space-separated list of address literals -- netd has no
 * resolver, so a hostname here is a parse error for that one token, not a
 * lookup. A bad token is dropped with a warning; the rest of the line still
 * lands, the same per-directive tolerance the rest of this project uses.
 */
static int config_parse_addr_list(
                const char *path,
                unsigned line,
                const char *lvalue,
                const char *rvalue,
                struct in_addr **list,
                size_t *n) {
        char *copy, *saveptr = NULL, *tok;

        /* An empty assignment resets the list, as in systemd. */
        if (*rvalue == '\0') {
                free(*list);
                *list = NULL;
                *n = 0;
                return 0;
        }

        copy = pico_strdup(rvalue);
        if (!copy)
                return -ENOMEM;

        for (tok = strtok_r(copy, " \t", &saveptr); tok; tok = strtok_r(NULL, " \t", &saveptr)) {
                struct in_addr a, *grown;

                if (*n >= NETWORK_ADDR_LIST_MAX) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: %s= holds more than %d entries, ignoring the rest",
                                 path,
                                 line,
                                 lvalue,
                                 NETWORK_ADDR_LIST_MAX);
                        break;
                }

                if (inet_pton(AF_INET, tok, &a) != 1) {
                        struct in6_addr a6;

                        if (inet_pton(AF_INET6, tok, &a6) == 1)
                                pico_log(PICO_LOG_WARNING,
                                         "%s:%u: %s= value '%s' is IPv6, which the SNTP client does not speak, ignoring",
                                         path,
                                         line,
                                         lvalue,
                                         tok);
                        else
                                pico_log(PICO_LOG_WARNING,
                                         "%s:%u: %s= value '%s' is not an address literal, ignoring",
                                         path,
                                         line,
                                         lvalue,
                                         tok);
                        continue;
                }

                grown = realloc(*list, (*n + 1) * sizeof(**list));
                if (!grown) {
                        pico_mfree(copy);
                        return -ENOMEM;
                }
                *list = grown;
                (*list)[(*n)++] = a;
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

static int config_parse_ntp(Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_addr_list(path, line, lvalue, rvalue, &nw->ntp, &nw->n_ntp);
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
        return (ssize_t) nw->n_routes++;
}

static int network_section_handler(const char *path, unsigned line, const char *section, void *userdata) {
        NetworkParser *p = userdata;
        ssize_t i;

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

/*
 * Drops what networkd drops and fills in the defaults, once the whole file is
 * read, because the keys of a section come in any order. The later of two
 * entries for one address wins, as in networkd.
 */
static void network_verify_addresses(Network *nw, const char *path) {
        size_t n = 0;

        for (size_t i = 0; i < nw->n_addresses; i++) {
                NetworkAddress a = nw->addresses[i];
                char buf[INET6_ADDRSTRLEN];
                size_t k;

                if (a.family == 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: [Address] section without Address=, ignoring",
                                 path,
                                 a.line);
                        continue;
                }

                if (a.peer_set && a.peer_family != a.family) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: Peer= is not the same family as Address=, ignoring the address",
                                 path,
                                 a.line);
                        continue;
                }

                if (netd_addr_is_null(a.family, &a.address)) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: a null Address= asks for an address pool, which is not supported, ignoring",
                                 path,
                                 a.line);
                        continue;
                }

                if (a.family == AF_INET6 && a.label[0] != '\0') {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: Label= has no effect on an IPv6 address, ignoring it",
                                 path,
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
                                 "%s:%u: address %s is also set at line %u, using the later one",
                                 path,
                                 nw->addresses[k].line,
                                 netd_addr_to_string(a.family, &a.address, buf),
                                 a.line);
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
static void network_verify_routes(Network *nw, const char *path) {
        size_t n = 0;

        for (size_t i = 0; i < nw->n_routes; i++) {
                NetworkRoute r = nw->routes[i];
                size_t k;

                if (r.drop)
                        continue;

                r.family = r.dst_family ? r.dst_family : (r.gw_family ? r.gw_family : r.prefsrc_family);
                if (r.family == 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: [Route] section without Gateway=, Destination=, Source=, or PreferredSource= field configured, ignoring",
                                 path,
                                 r.line);
                        continue;
                }

                if ((r.dst_family && r.dst_family != r.family) || (r.gw_family && r.gw_family != r.family) ||
                    (r.prefsrc_family && r.prefsrc_family != r.family)) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: Destination=, Gateway= and PreferredSource= are not all IPv4 or all IPv6, ignoring the [Route] section",
                                 path,
                                 r.line);
                        continue;
                }

                if (r.family == AF_INET6) {
                        if (r.scope_set && r.scope != RT_SCOPE_UNIVERSE)
                                pico_log(PICO_LOG_WARNING,
                                         "%s:%u: Scope= is specified for an IPv6 route, ignoring it",
                                         path,
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
                                 path,
                                 r.line);
                        r.onlink = true;
                }

                for (k = 0; k < n; k++)
                        if (network_route_same(&nw->routes[k], &r))
                                break;

                if (k < n) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s:%u: the same route is set at line %u, using the later one",
                                 path,
                                 nw->routes[k].line,
                                 r.line);
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

typedef int (*NetworkParseFn)(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue);

typedef struct NetworkConfigItem {
        const char *section;
        const char *lvalue;
        NetworkParseFn parse;
} NetworkConfigItem;

static const NetworkConfigItem network_config_items[] = {
        {   "Match",        "Name",               config_parse_match_name },
        { "Network",        "DHCP",                     config_parse_dhcp },
        { "Network",     "Gateway",                  config_parse_gateway },
        { "Network",         "DNS",                      config_parse_dns },
        { "Network",         "NTP",                      config_parse_ntp },
        { "Network",  "DHCPServer",              config_parse_dhcp_server },
        { "Network",        "LLDP",                     config_parse_lldp },
        { "Network",    "EmitLLDP",                config_parse_emit_lldp },
        {  "DHCPv4",      "UseDNS",                  config_parse_use_dns },
        {  "DHCPv4",      "UseNTP",                  config_parse_use_ntp },
        {  "DHCPv4", "UseTimezone",             config_parse_use_timezone },
        {  "DHCPv4", "RouteMetric",       config_parse_dhcp4_route_metric },
        {    "DHCP", "RouteMetric", config_parse_dhcp_legacy_route_metric },
};

/*
 * The conf-scan.h handler: dispatches one already-scanned assignment through
 * network_config_items[], and logs-and-drops anything not in it -- the same
 * drop-in tolerance rule unit-parse.c's own handler applies (see that file),
 * so a section this parser has never heard of (e.g. [IPv6AcceptRA]) simply
 * never matches a row here and falls straight to the debug log below. [DHCP]
 * has a row for RouteMetric= only; its other keys take the same path.
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

int network_parse_file(const char *path, Network **ret) {
        NetworkParser parser = { 0 };
        Network *nw = NULL;
        int r;

        if (!path || !ret)
                return -EINVAL;

        r = network_new(&nw);
        if (r < 0)
                return r;

        nw->filename = pico_strdup(path);
        nw->basename = path_basename_dup(path);
        if (!nw->filename || !nw->basename) {
                network_free(nw);
                return -ENOMEM;
        }

        parser.nw = nw;
        parser.cur = -1;
        parser.cur_route = -1;

        r = pico_conf_scan_full(path, network_conf_handler, network_section_handler, &parser);
        if (r < 0) {
                network_free(nw);
                return r;
        }

        network_verify_addresses(nw, path);
        network_verify_routes(nw, path);

        *ret = nw;
        return 0;
}

/* --- discovery: search-path walk, shadowing, ordering --- */

/* One *.network file resolved to the single directory that wins for it (the
 * earliest entry in n->network_path that has a file of this basename) --
 * same shape as unit-enable.c's PresetEntry, for the same reason. */
typedef struct NetworkEntry {
        char *basename;
        char *path; /* dir/basename */
} NetworkEntry;

static void network_entries_free(NetworkEntry *entries, size_t n) {
        for (size_t i = 0; i < n; i++) {
                free(entries[i].basename);
                free(entries[i].path);
        }
        free(entries);
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
 */
static int collect_network_entries(Netd *n, NetworkEntry **ret, size_t *ret_n) {
        NetworkEntry *entries = NULL;
        size_t n_alloc = 0;
        size_t n_entries = 0;
        int rc = 0;

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
        }

        qsort(entries, n_entries, sizeof(*entries), network_entry_cmp);

        *ret = entries;
        *ret_n = n_entries;
        return 0;

fail:
        network_entries_free(entries, n_entries);
        return rc;
}

int network_load_all(Netd *n) {
        NetworkEntry *entries = NULL;
        size_t n_entries = 0;
        Network **networks = NULL;
        size_t n_networks = 0;
        int loaded = 0;
        int r;

        if (!n)
                return -EINVAL;

        r = collect_network_entries(n, &entries, &n_entries);
        if (r < 0)
                return r;

        for (size_t i = 0; i < n_entries; i++) {
                Network *nw = NULL;
                Network **grown;

                /*
                 * A parse failure in one file does not abort the load: the
                 * running configuration is only replaced once the new set is
                 * complete (netd-network.h), and one malformed file must not
                 * cost every other interface its configuration.
                 */
                r = network_parse_file(entries[i].path, &nw);
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
                        return -ENOMEM;
                }
                networks = grown;
                networks[n_networks++] = nw;
                loaded++;
        }

        network_entries_free(entries, n_entries);

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
