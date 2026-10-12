/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The .network parser.
 *
 * Covers: the [DHCPv4] defaults (in particular UseTimezone=yes, netd's
 * divergence from networkd); usb0.network and usb0-server.network fixtures
 * for a USB gadget link; fixtures using directives outside netd's subset
 * ([IPv6AcceptRA], [Route], RouteMetric=); the three-directory search path
 * with basename shadowing and lexicographic union ordering; [Match] Name=
 * glob matching, including the "no [Match] Name= matches nothing" rule; and
 * unknown-section/directive tolerance. It also holds a regression for the
 * stack-overflow-class bug a VLA sized by an unbounded, attacker-controlled
 * line length used to cause (see conf-scan.c and unit-parse.c).
 */

#include <arpa/inet.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "../util.h"
#include "netd-network.h"
#include "netd.h"

static char *join_path(const char *dir, const char *name) {
        size_t len = strlen(dir) + 1 + strlen(name) + 1;
        char *p = malloc(len);

        ASSERT_TRUE(p != NULL);
        snprintf(p, len, "%s/%s", dir, name);
        return p;
}

/* A .network that sets nothing must still come back with netd's defaults --
 * in particular UseTimezone=yes, which is where netd parts company with
 * networkd. */
static void test_defaults(void) {
        Network *nw = NULL;

        ASSERT_EQ_INT(network_new(&nw), 0);
        ASSERT_TRUE(nw != NULL);

        ASSERT_EQ_INT(nw->dhcp, NETWORK_DHCP_NO);
        ASSERT_TRUE(!nw->dhcp_server);
        ASSERT_EQ_INT(nw->n_addresses, 0);

        ASSERT_TRUE(nw->dhcp_use_dns);
        ASSERT_TRUE(nw->dhcp_use_ntp);
        ASSERT_TRUE(nw->dhcp_use_timezone);

        ASSERT_TRUE(network_free(nw) == NULL);
}

/* DHCP= is an address-family selector upstream, not a boolean, and netd
 * parses the whole set so a file written for networkd keeps its meaning. */
static void test_dhcp_spellings(void) {
        ASSERT_EQ_INT(network_dhcp_from_string("yes"), NETWORK_DHCP_YES);
        ASSERT_EQ_INT(network_dhcp_from_string("true"), NETWORK_DHCP_YES);
        ASSERT_EQ_INT(network_dhcp_from_string("1"), NETWORK_DHCP_YES);
        ASSERT_EQ_INT(network_dhcp_from_string("ipv4"), NETWORK_DHCP_IPV4);
        ASSERT_EQ_INT(network_dhcp_from_string("ipv6"), NETWORK_DHCP_IPV6);
        ASSERT_EQ_INT(network_dhcp_from_string("no"), NETWORK_DHCP_NO);
        ASSERT_EQ_INT(network_dhcp_from_string("off"), NETWORK_DHCP_NO);
        ASSERT_EQ_INT(network_dhcp_from_string("maybe"), _NETWORK_DHCP_INVALID);

        /* networkd reads DHCP= with parse_boolean(): case-insensitive, with
         * the one-letter forms. */
        ASSERT_EQ_INT(network_dhcp_from_string("Yes"), NETWORK_DHCP_YES);
        ASSERT_EQ_INT(network_dhcp_from_string("y"), NETWORK_DHCP_YES);
        ASSERT_EQ_INT(network_dhcp_from_string("T"), NETWORK_DHCP_YES);
        ASSERT_EQ_INT(network_dhcp_from_string("n"), NETWORK_DHCP_NO);
        ASSERT_EQ_INT(network_dhcp_from_string("OFF"), NETWORK_DHCP_NO);
        ASSERT_EQ_INT(network_dhcp_from_string("IPv4"), NETWORK_DHCP_IPV4);

        ASSERT_STREQ(network_dhcp_to_string(NETWORK_DHCP_IPV4), "ipv4");
}

/* Only YES and IPV4 arm the v4 client. An IPv6-only file parses and does
 * nothing, rather than being rejected (IPv6 is not implemented). */
static void test_dhcp4_enabled(void) {
        Network *nw = NULL;

        ASSERT_EQ_INT(network_new(&nw), 0);

        nw->dhcp = NETWORK_DHCP_NO;
        ASSERT_TRUE(!network_dhcp4_enabled(nw));
        nw->dhcp = NETWORK_DHCP_IPV6;
        ASSERT_TRUE(!network_dhcp4_enabled(nw));
        nw->dhcp = NETWORK_DHCP_IPV4;
        ASSERT_TRUE(network_dhcp4_enabled(nw));
        nw->dhcp = NETWORK_DHCP_YES;
        ASSERT_TRUE(network_dhcp4_enabled(nw));

        ASSERT_TRUE(!network_dhcp4_enabled(NULL));

        network_free(nw);
}

/* [Match] Name= is a space-separated list of fnmatch(3) globs; a file with
 * none at all matches *nothing* -- an unconditional catch-all would be a far
 * worse failure mode than a file that silently does nothing. */
static void test_match_glob_and_no_match_matches_nothing(void) {
        Network *nw = NULL;
        Network *bare = NULL;

        ASSERT_EQ_INT(network_new(&nw), 0);
        ASSERT_EQ_INT(pico_strv_extend(&nw->match_name, "usb*"), 0);
        ASSERT_EQ_INT(pico_strv_extend(&nw->match_name, "eth0"), 0);

        ASSERT_TRUE(network_matches(nw, "usb0"));
        ASSERT_TRUE(network_matches(nw, "usb1"));
        ASSERT_TRUE(network_matches(nw, "eth0"));
        ASSERT_TRUE(!network_matches(nw, "eth1"));
        ASSERT_TRUE(!network_matches(nw, "wlan0"));
        network_free(nw);

        ASSERT_EQ_INT(network_new(&bare), 0);
        ASSERT_TRUE(!network_matches(bare, "usb0"));
        ASSERT_TRUE(!network_matches(bare, "anything"));
        network_free(bare);
}

/* A leading '!' excludes; a list of only exclusions matches everything else. */
static void test_match_negation(void) {
        Network *nw = NULL;

        ASSERT_EQ_INT(network_new(&nw), 0);
        ASSERT_EQ_INT(pico_strv_extend(&nw->match_name, "!lo"), 0);
        ASSERT_EQ_INT(pico_strv_extend(&nw->match_name, "!veth*"), 0);

        ASSERT_TRUE(network_matches(nw, "eth0"));
        ASSERT_TRUE(!network_matches(nw, "lo"));
        ASSERT_TRUE(!network_matches(nw, "veth3"));
        network_free(nw);

        ASSERT_EQ_INT(network_new(&nw), 0);
        ASSERT_EQ_INT(pico_strv_extend(&nw->match_name, "eth*"), 0);
        ASSERT_EQ_INT(pico_strv_extend(&nw->match_name, "!eth1"), 0);

        ASSERT_TRUE(network_matches(nw, "eth0"));
        ASSERT_TRUE(!network_matches(nw, "eth1"));
        ASSERT_TRUE(!network_matches(nw, "usb0"));
        network_free(nw);
}

/* An empty Name=/DNS=/NTP= assignment resets what earlier lines gave. */
static void test_empty_assignment_resets(void) {
        char *dir, *path;
        Network *nw = NULL;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "reset.network",
                                      "[Match]\nName=eth0\nName=\nName=usb0\n\n"
                                      "[Network]\nDNS=10.0.0.1\nDNS=\nDNS=10.0.0.2\n"
                                      "NTP=10.0.0.3\nNTP=\n"),
                      0);
        path = join_path(dir, "reset.network");

        ASSERT_EQ_INT(network_parse_file(path, &nw), 0);
        ASSERT_TRUE(!network_matches(nw, "eth0"));
        ASSERT_TRUE(network_matches(nw, "usb0"));
        ASSERT_EQ_INT(nw->n_dns, 1);
        ASSERT_EQ_INT(nw->dns[0].s_addr, htonl(0x0a000002));
        ASSERT_EQ_INT(nw->n_ntp, 0);

        network_free(nw);
        free(path);
        test_rm_rf(dir);
        free(dir);
}

/* A runaway NTP= list is cut off at 128 servers. */
static void test_addr_list_is_bounded(void) {
        char *dir, *path;
        char content[4096];
        size_t len;
        Network *nw = NULL;

        len = (size_t) snprintf(content, sizeof(content), "[Network]\nNTP=");
        for (int i = 0; i < 200; i++)
                len += (size_t) snprintf(
                                content + len, sizeof(content) - len, "10.1.%d.%d ", i / 250, i % 250 + 1);

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "many.network", content), 0);
        path = join_path(dir, "many.network");

        ASSERT_EQ_INT(network_parse_file(path, &nw), 0);
        ASSERT_EQ_INT(nw->n_ntp, 128);

        network_free(nw);
        free(path);
        test_rm_rf(dir);
        free(dir);
}

/* A USB gadget link configured as a DHCP client. */
static const char *usb0_network_fixture =
                "[Match]\n"
                "Name=usb0\n"
                "\n"
                "[Network]\n"
                "DHCP=yes\n";

static void test_real_usb0_network_parses(void) {
        char *dir, *path;
        Network *nw = NULL;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "usb0.network", usb0_network_fixture), 0);
        path = join_path(dir, "usb0.network");

        ASSERT_EQ_INT(network_parse_file(path, &nw), 0);
        ASSERT_TRUE(nw != NULL);
        ASSERT_STREQ(nw->basename, "usb0.network");

        ASSERT_TRUE(network_matches(nw, "usb0"));
        ASSERT_TRUE(!network_matches(nw, "usb1"));
        ASSERT_EQ_INT(nw->dhcp, NETWORK_DHCP_YES);
        ASSERT_TRUE(network_dhcp4_enabled(nw));
        ASSERT_EQ_INT(nw->n_addresses, 0);
        ASSERT_TRUE(!nw->dhcp_server);
        /* untouched [DHCPv4] defaults still apply */
        ASSERT_TRUE(nw->dhcp_use_timezone);

        network_free(nw);
        free(path);
        test_rm_rf(dir);
        free(dir);
}

/* A USB gadget link serving DHCP. */
static const char *usb0_server_network_fixture =
                "[Match]\n"
                "Name=usb0\n"
                "\n"
                "[Network]\n"
                "Address=192.168.7.2/24\n"
                "DHCPServer=yes\n";

static void test_real_usb0_server_network_parses(void) {
        char *dir, *path;
        Network *nw = NULL;
        char buf[INET_ADDRSTRLEN];

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "usb0-server.network", usb0_server_network_fixture), 0);
        path = join_path(dir, "usb0-server.network");

        ASSERT_EQ_INT(network_parse_file(path, &nw), 0);
        ASSERT_TRUE(nw != NULL);

        ASSERT_TRUE(network_matches(nw, "usb0"));
        ASSERT_EQ_INT(nw->dhcp, NETWORK_DHCP_NO);
        ASSERT_TRUE(nw->dhcp_server);
        ASSERT_EQ_INT(nw->n_addresses, 1);
        ASSERT_EQ_INT(nw->addresses[0].prefixlen, 24);
        ASSERT_TRUE(inet_ntop(AF_INET, &nw->addresses[0].address, buf, sizeof(buf)) != NULL);
        ASSERT_STREQ(buf, "192.168.7.2");

        network_free(nw);
        free(path);
        test_rm_rf(dir);
        free(dir);
}

/*
 * Typical console-image .network files, exercising directives well outside
 * netd's subset: RouteMetric=, and whole sections ([IPv6AcceptRA], [Route])
 * netd has no fields for at all. A parse failure would otherwise only be
 * found at boot.
 */
static const char *console_10_en_network =
                "[Match]\n"
                "Name=en*\n"
                "\n"
                "[Network]\n"
                "DHCP=yes\n"
                "LLDP=yes\n"
                "EmitLLDP=yes\n"
                "\n"
                "[DHCPv4]\n"
                "UseTimezone=yes\n"
                "RouteMetric=10\n"
                "\n"
                "[IPv6AcceptRA]\n"
                "RouteMetric=10\n"
                "\n"
                "[Route]\n"
                "Metric=10\n";

static const char *console_11_eth_network =
                "[Match]\n"
                "Name=eth*\n"
                "\n"
                "[Network]\n"
                "DHCP=yes\n"
                "LLDP=yes\n"
                "EmitLLDP=yes\n"
                "\n"
                "[DHCPv4]\n"
                "UseTimezone=yes\n"
                "RouteMetric=10\n"
                "\n"
                "[IPv6AcceptRA]\n"
                "RouteMetric=10\n"
                "\n"
                "[Route]\n"
                "Metric=10\n";

static const char *console_12_wlan_network =
                "[Match]\n"
                "Name=wlan*\n"
                "\n"
                "[Network]\n"
                "DHCP=yes\n"
                "LLDP=yes\n"
                "EmitLLDP=yes\n"
                "\n"
                "[DHCPv4]\n"
                "UseTimezone=yes\n"
                "RouteMetric=100\n"
                "\n"
                "[IPv6AcceptRA]\n"
                "RouteMetric=100\n"
                "\n"
                "[Route]\n"
                "Metric=100\n";

static void assert_console_fixture_parses(
                const char *name, const char *content, const char *glob_hit, const char *glob_miss) {
        char *dir, *path;
        Network *nw = NULL;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, name, content), 0);
        path = join_path(dir, name);

        ASSERT_EQ_INT(network_parse_file(path, &nw), 0);
        ASSERT_TRUE(nw != NULL);

        ASSERT_TRUE(network_matches(nw, glob_hit));
        ASSERT_TRUE(!network_matches(nw, glob_miss));
        ASSERT_EQ_INT(nw->dhcp, NETWORK_DHCP_YES);
        ASSERT_TRUE(network_dhcp4_enabled(nw));
        ASSERT_TRUE(nw->dhcp_use_timezone); /* the file says so explicitly */
        ASSERT_TRUE(nw->dhcp_use_dns);      /* untouched, still defaults yes */
        ASSERT_EQ_INT(nw->n_addresses, 0);
        ASSERT_TRUE(!nw->gateway_set);
        ASSERT_EQ_INT(nw->n_dns, 0);
        ASSERT_EQ_INT(nw->n_ntp, 0);

        network_free(nw);
        free(path);
        test_rm_rf(dir);
        free(dir);
}

static void test_console_base_image_fixtures_parse(void) {
        assert_console_fixture_parses("10-en.network", console_10_en_network, "en0", "eth0");
        assert_console_fixture_parses("11-eth.network", console_11_eth_network, "eth0", "wlan0");
        assert_console_fixture_parses("12-wlan.network", console_12_wlan_network, "wlan0", "en0");
}

/* An unrecognized section and unrecognized directives inside a recognized
 * one are valid syntax, dropped at debug level -- the same drop-in tolerance
 * rule unit-parse.c applies to unit files. */
static const char *tolerant_fixture =
                "[Match]\n"
                "Name=usb0\n"
                "MACAddress=00:11:22:33:44:55\n" /* [Match] beyond Name= is not supported */
                "\n"
                "[Network]\n"
                "DHCP=yes\n"
                "LLDP=yes\n"
                "\n"
                "[SomeFutureSection]\n"
                "Whatever=goes-here\n"
                "\n"
                "[DHCPv4]\n"
                "UseDNS=no\n"
                "RouteMetric=10\n"; /* not implemented */

static void test_lldp_directives(void) {
        static const struct {
                const char *rx, *tx;
                NetworkLldp want_rx;
                NetworkEmitLldp want_tx;
        } cases[] = {
                {          "yes",             "yes",          NETWORK_LLDP_YES,  NETWORK_EMIT_LLDP_NEAREST_BRIDGE },
                {           "no",              "no",           NETWORK_LLDP_NO,              NETWORK_EMIT_LLDP_NO },
                { "routers-only",  "nearest-bridge", NETWORK_LLDP_ROUTERS_ONLY,  NETWORK_EMIT_LLDP_NEAREST_BRIDGE },
                {         "true", "non-tpmr-bridge",          NETWORK_LLDP_YES, NETWORK_EMIT_LLDP_NON_TPMR_BRIDGE },
                {            "0", "customer-bridge",           NETWORK_LLDP_NO, NETWORK_EMIT_LLDP_CUSTOMER_BRIDGE },
                {        "bogus",           "bogus",           NETWORK_LLDP_NO,              NETWORK_EMIT_LLDP_NO }, /* ignored: the default stays */
        };
        char *dir = test_tmpdir_new();
        size_t i;

        ASSERT_TRUE(dir != NULL);
        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                char body[160], *path;
                Network *nw = NULL;

                snprintf(body,
                         sizeof(body),
                         "[Match]\nName=x\n\n[Network]\nLLDP=%s\nEmitLLDP=%s\n",
                         cases[i].rx,
                         cases[i].tx);
                ASSERT_EQ_INT(test_write_file(dir, "lldp.network", body), 0);
                path = join_path(dir, "lldp.network");
                ASSERT_EQ_INT(network_parse_file(path, &nw), 0);
                ASSERT_EQ_INT(nw->lldp, cases[i].want_rx);
                ASSERT_EQ_INT(nw->emit_lldp, cases[i].want_tx);
                network_free(nw);
                free(path);
        }

        /* Absent: both off. */
        {
                Network *nw = NULL;
                char *path;

                ASSERT_EQ_INT(test_write_file(dir, "none.network", "[Match]\nName=x\n"), 0);
                path = join_path(dir, "none.network");
                ASSERT_EQ_INT(network_parse_file(path, &nw), 0);
                ASSERT_EQ_INT(nw->lldp, NETWORK_LLDP_NO);
                ASSERT_EQ_INT(nw->emit_lldp, NETWORK_EMIT_LLDP_NO);
                network_free(nw);
                free(path);
        }
        test_rm_rf(dir);
        free(dir);
}

static void test_unknown_directive_tolerance(void) {
        char *dir, *path;
        Network *nw = NULL;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "tolerant.network", tolerant_fixture), 0);
        path = join_path(dir, "tolerant.network");

        ASSERT_EQ_INT(network_parse_file(path, &nw), 0);
        ASSERT_TRUE(nw != NULL);

        ASSERT_TRUE(network_matches(nw, "usb0"));
        ASSERT_EQ_INT(nw->dhcp, NETWORK_DHCP_YES);
        ASSERT_TRUE(!nw->dhcp_use_dns); /* explicit UseDNS=no honoured */
        ASSERT_TRUE(nw->dhcp_use_ntp);  /* untouched directive keeps its default */
        ASSERT_TRUE(nw->dhcp_use_timezone);

        network_free(nw);
        free(path);
        test_rm_rf(dir);
        free(dir);
}

/*
 * The full search-path contract in one test: three directories, a basename
 * shadowed by the highest-priority one (its DHCP=yes wins over the other
 * two's DHCP=no, and those two files' bodies are never even consulted), and
 * a distinct basename that only the lowest-priority directory has, proving
 * the union collection reaches every directory and the ordering is the
 * lexicographic basename sort, not directory-scan order.
 */
static void test_search_path_shadowing_and_order(void) {
        char *etc_dir, *run_dir, *usr_dir;
        char **path = NULL;
        Netd n;
        Network *found;
        int loaded;

        etc_dir = test_tmpdir_new();
        run_dir = test_tmpdir_new();
        usr_dir = test_tmpdir_new();
        ASSERT_TRUE(etc_dir && run_dir && usr_dir);

        ASSERT_EQ_INT(test_write_file(etc_dir, "10-usb0.network", "[Match]\nName=usb0\n[Network]\nDHCP=yes\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(run_dir, "10-usb0.network", "[Match]\nName=usb0\n[Network]\nDHCP=no\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(usr_dir, "10-usb0.network", "[Match]\nName=usb0\n[Network]\nDHCP=no\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(usr_dir, "05-eth0.network", "[Match]\nName=eth0\n"), 0);

        ASSERT_EQ_INT(pico_strv_extend(&path, etc_dir), 0);
        ASSERT_EQ_INT(pico_strv_extend(&path, run_dir), 0);
        ASSERT_EQ_INT(pico_strv_extend(&path, usr_dir), 0);

        memset(&n, 0, sizeof(n));
        n.network_path = path;

        loaded = network_load_all(&n);
        ASSERT_EQ_INT(loaded, 2);
        ASSERT_EQ_INT(n.n_networks, 2);

        ASSERT_STREQ(n.networks[0]->basename, "05-eth0.network");
        ASSERT_STREQ(n.networks[1]->basename, "10-usb0.network");

        found = network_find(&n, "usb0");
        ASSERT_TRUE(found != NULL);
        ASSERT_TRUE(network_dhcp4_enabled(found)); /* etc/'s DHCP=yes, not run/'s or usr/'s no */

        found = network_find(&n, "eth0");
        ASSERT_TRUE(found != NULL);
        ASSERT_STREQ(found->basename, "05-eth0.network");

        ASSERT_TRUE(network_find(&n, "wlan0") == NULL);

        network_free_all(&n);
        pico_strv_free(n.network_path);
        test_rm_rf(etc_dir);
        test_rm_rf(run_dir);
        test_rm_rf(usr_dir);
        free(etc_dir);
        free(run_dir);
        free(usr_dir);
}

/* A missing search-path directory (e.g. no /run/systemd/network on a fresh
 * image) is normal, not an error. */
static void test_missing_search_dir_is_not_an_error(void) {
        char *etc_dir, *missing_dir;
        char **path = NULL;
        Netd n;
        int loaded;

        etc_dir = test_tmpdir_new();
        ASSERT_TRUE(etc_dir != NULL);
        missing_dir = join_path(etc_dir, "does-not-exist");

        ASSERT_EQ_INT(test_write_file(etc_dir, "usb0.network", usb0_network_fixture), 0);

        ASSERT_EQ_INT(pico_strv_extend(&path, etc_dir), 0);
        ASSERT_EQ_INT(pico_strv_extend(&path, missing_dir), 0);

        memset(&n, 0, sizeof(n));
        n.network_path = path;

        loaded = network_load_all(&n);
        ASSERT_EQ_INT(loaded, 1);
        ASSERT_EQ_INT(n.n_networks, 1);

        network_free_all(&n);
        pico_strv_free(n.network_path);
        test_rm_rf(etc_dir);
        free(etc_dir);
        free(missing_dir);
}

/*
 * Regression for a stack-overflow-class bug: a VLA sized by an unbounded,
 * attacker-controlled line length, originally reproduced with a 30MB
 * Requires= line in a unit file and fixed by switching to a heap buffer
 * (unit-parse.c's config_parse_unit_deps()). conf-scan.c's getline()/
 * realloc()-based line handling never used a VLA either, and neither does
 * this file's config_parse_match_name(); both are exercised here by a 30MB
 * single-token Name= line.
 */
static void test_huge_line_does_not_crash(void) {
        char *dir;
        char path[PATH_MAX];
        FILE *f;
        char chunk[65536];
        size_t huge_len = 30 * 1024 * 1024;
        size_t remaining;
        Network *nw = NULL;

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);
        snprintf(path, sizeof(path), "%s/huge.network", dir);

        f = fopen(path, "we");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fputs("[Match]\nName=", f) >= 0);

        memset(chunk, 'a', sizeof(chunk));
        remaining = huge_len;
        while (remaining > 0) {
                size_t n = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
                ASSERT_TRUE(fwrite(chunk, 1, n, f) == n);
                remaining -= n;
        }
        ASSERT_TRUE(fputs("\n", f) >= 0);
        ASSERT_TRUE(fclose(f) == 0);

        ASSERT_EQ_INT(network_parse_file(path, &nw), 0);
        ASSERT_TRUE(nw != NULL);
        ASSERT_TRUE(nw->match_name != NULL);
        ASSERT_EQ_INT(strlen(nw->match_name[0]), huge_len);

        network_free(nw);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        test_defaults();
        test_dhcp_spellings();
        test_dhcp4_enabled();
        test_match_glob_and_no_match_matches_nothing();
        test_match_negation();
        test_empty_assignment_resets();
        test_addr_list_is_bounded();
        test_real_usb0_network_parses();
        test_real_usb0_server_network_parses();
        test_console_base_image_fixtures_parse();
        test_lldp_directives();
        test_unknown_directive_tolerance();
        test_search_path_shadowing_and_order();
        test_missing_search_dir_is_not_an_error();
        test_huge_line_does_not_crash();

        printf("test-netd-network: ok\n");
        return EXIT_SUCCESS;
}
