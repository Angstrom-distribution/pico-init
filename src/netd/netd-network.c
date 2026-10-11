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

/* "a.b.c.d/nn": split and validate. 0 or -EINVAL -- Address= is documented as
 * a CIDR literal (netd-network.h), so a bare address with no prefix is
 * rejected rather than guessed at. */
static int parse_cidr(const char *s, NetworkAddress *ret) {
        char *copy, *slash, *end;
        unsigned long v;
        int r = -EINVAL;

        copy = pico_strdup(s);
        if (!copy)
                return -ENOMEM;

        slash = strchr(copy, '/');
        if (!slash)
                goto out;
        *slash = '\0';

        v = strtoul(slash + 1, &end, 10);
        if (end == slash + 1 || *end != '\0' || v > 32)
                goto out;

        if (inet_pton(AF_INET, copy, &ret->address) != 1)
                goto out;

        ret->prefixlen = (unsigned char) v;
        r = 0;

out:
        free(copy);
        return r;
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

static int config_parse_address(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        NetworkAddress addr, *grown;
        (void) lvalue;

        if (parse_cidr(rvalue, &addr) < 0) {
                pico_log(PICO_LOG_WARNING, "%s:%u: invalid Address= value '%s', ignoring", path, line, rvalue);
                return 0;
        }

        grown = realloc(nw->addresses, (nw->n_addresses + 1) * sizeof(*grown));
        if (!grown)
                return -ENOMEM;

        nw->addresses = grown;
        nw->addresses[nw->n_addresses++] = addr;
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

        copy = pico_strdup(rvalue);
        if (!copy)
                return -ENOMEM;

        for (tok = strtok_r(copy, " \t", &saveptr); tok; tok = strtok_r(NULL, " \t", &saveptr)) {
                struct in_addr a, *grown;

                if (inet_pton(AF_INET, tok, &a) != 1) {
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

static int config_parse_dns(Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue) {
        return config_parse_addr_list(path, line, lvalue, rvalue, &nw->dns, &nw->n_dns);
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

typedef int (*NetworkParseFn)(
                Network *nw, const char *path, unsigned line, const char *lvalue, const char *rvalue);

typedef struct NetworkConfigItem {
        const char *section;
        const char *lvalue;
        NetworkParseFn parse;
} NetworkConfigItem;

static const NetworkConfigItem network_config_items[] = {
        {   "Match",        "Name",   config_parse_match_name },
        { "Network",        "DHCP",         config_parse_dhcp },
        { "Network",     "Address",      config_parse_address },
        { "Network",     "Gateway",      config_parse_gateway },
        { "Network",         "DNS",          config_parse_dns },
        { "Network",         "NTP",          config_parse_ntp },
        { "Network",  "DHCPServer",  config_parse_dhcp_server },
        { "Network",        "LLDP",         config_parse_lldp },
        { "Network",    "EmitLLDP",    config_parse_emit_lldp },
        {  "DHCPv4",      "UseDNS",      config_parse_use_dns },
        {  "DHCPv4",      "UseNTP",      config_parse_use_ntp },
        {  "DHCPv4", "UseTimezone", config_parse_use_timezone },
};

/*
 * The conf-scan.h handler: dispatches one already-scanned assignment through
 * network_config_items[], and logs-and-drops anything not in it -- the same
 * drop-in tolerance rule unit-parse.c's own handler applies (see that file),
 * so a section this parser has never heard of (e.g. [IPv6AcceptRA]) simply
 * never matches a row here and falls straight to the debug log below.
 */
static int network_conf_handler(
                const char *path,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *userdata) {
        Network *nw = userdata;
        size_t i;

        if (!section) {
                pico_log(PICO_LOG_WARNING, "%s:%u: assignment outside any section, ignoring", path, line);
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

        r = pico_conf_scan(path, network_conf_handler, nw);
        if (r < 0) {
                network_free(nw);
                return r;
        }

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
        if (!nw || !ifname || !nw->match_name)
                return false;

        for (char * const *p = nw->match_name; *p; p++)
                if (fnmatch(*p, ifname, 0) == 0)
                        return true;

        return false;
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
