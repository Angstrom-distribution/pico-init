/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Everything in sd-network.h that is not the resolv.conf family
 * (network-resolv.c) or the monitor (network-monitor.c).
 *
 * This shim uses two different -EOPNOTSUPP flavours here, and the
 * distinction is deliberate (see network-internal.h's header and the
 * design note this family shipped with): a "defer" function names a real
 * netd publisher that does not exist YET (netd computes the data
 * in-memory and simply never writes it anywhere) and graduates to real
 * once that publisher lands; a "honest_failure" function names a netd.
 * directive or resolver feature that plain does not exist in netd's
 * parser at all, so there is no truthful value even in principle -- both
 * return the same -EOPNOTSUPP today, but the comment at each tells a
 * reader which kind of gap they hit and whether it is worth waiting for.
 *
 * -EOPNOTSUPP itself (rather than the real library's usual -ENODATA) is
 * the point: sd-network's -ENODATA means "networkd is not aware of this
 * link (yet)", which every real caller (systemd-networkd-wait-online
 * included) treats as transient and retries. A code sd-network is
 * documented to never return gives callers a positive, truthful "this is
 * not systemd-networkd" signal instead of an infinite retry loop.
 *
 * Every per-link function still validates ifindex for real: a caller bug
 * (ifindex <= 0) must surface as -EINVAL regardless of how much of the
 * rest of this shim exists yet.
 */

#include "sd-network.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>

#include "network-internal.h"

static int check_ifindex(int ifindex) {
        return ifindex > 0 ? 0 : -EINVAL;
}

/* --- global state: netd computes it, but publishes no state file at all
 * (§2.9 excludes every IPC channel) --- */

int sd_network_get_operational_state(char **ret) {
        return ret ? -EOPNOTSUPP : -EINVAL;
}
int sd_network_get_carrier_state(char **ret) {
        return ret ? -EOPNOTSUPP : -EINVAL;
}
int sd_network_get_address_state(char **ret) {
        return ret ? -EOPNOTSUPP : -EINVAL;
}
int sd_network_get_ipv4_address_state(char **ret) {
        return ret ? -EOPNOTSUPP : -EINVAL;
}
int sd_network_get_ipv6_address_state(char **ret) {
        return ret ? -EOPNOTSUPP : -EINVAL;
}
int sd_network_get_online_state(char **ret) {
        return ret ? -EOPNOTSUPP : -EINVAL;
}

/* --- per-link state: same publisher gap, per-link flavour (netd-link.h's
 * LinkState is exactly the data; it is just never written to disk) --- */

int sd_network_link_get_setup_state(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_operational_state(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_carrier_state(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_address_state(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_ipv4_address_state(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_ipv6_address_state(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_online_state(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}

/* --- per-link EFFECTIVE dns/ntp/search: the lease file has the DHCP
 * server's offer, not netd's UseDNS=/UseNTP=-gated decision; serving the
 * offer as if it were effective is exactly the misleading-partial this
 * family's design refuses to do --- */

int sd_network_link_get_dns(int ifindex, char ***ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_ntp(int ifindex, char ***ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_search_domains(int ifindex, char ***ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}

/* --- which .network file matched: netd knows (Netd.networks' match walk)
 * but never publishes it --- */

int sd_network_link_get_network_file(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_network_file_dropins(int ifindex, char ***ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}

/* --- directives netd's parser does not have at all: RequiredForOnline=,
 * ActivationPolicy= (netd-network.h has neither field) --- */

int sd_network_link_get_required_for_online(int ifindex) {
        return check_ifindex(ifindex) < 0 ? -EINVAL : -EOPNOTSUPP;
}
int sd_network_link_get_required_operstate_for_online(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_required_family_for_online(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_activation_policy(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}

/* --- .netdev files, DHCP options netd's client never requests, and
 * resolver feature flags with no resolver on pico (pico-resolv is a
 * static file mechanism, not a running service with these controls) --- */

int sd_network_link_get_netdev_file(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_netdev_file_dropins(int ifindex, char ***ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_sip(int ifindex, char ***ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_captive_portal(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_llmnr(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_mdns(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_dns_over_tls(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_dnssec(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_dnssec_negative_trust_anchors(int ifindex, char ***ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
/*
 * Per-link route_domains gets -EOPNOTSUPP rather than the global
 * sd_network_get_route_domains()'s empty-success: the header ties the
 * per-link calls to "-ENODATA: networkd is not aware of the link"
 * semantics this shim cannot evaluate without real per-link state, and a
 * positive empty answer here would falsely assert netd manages this
 * ifindex at all.
 */
int sd_network_link_get_route_domains(int ifindex, char ***ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_dns_default_route(int ifindex) {
        return check_ifindex(ifindex) < 0 ? -EINVAL : -EOPNOTSUPP;
}
int sd_network_link_get_carrier_bound_to(int ifindex, int **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_carrier_bound_by(int ifindex, int **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
/* netd is DHCPv4-only by explicit scope (netd-network.h, §2.9: all of
 * IPv6 out of scope), so there is no DHCPv6 client to have an IAID/DUID. */
int sd_network_link_get_dhcp6_client_iaid_string(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_dhcp6_client_duid_string(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}

/*
 * Real: netd's lease file is, today, the only per-link state file netd
 * has at all, so stat()ing it is a genuine (if narrow) answer -- -ENOENT
 * is the API's own truthful "no state recorded for this link" signal.
 * When the link-state publisher named throughout this file lands, this
 * retargets to /run/netd/links/<ifindex> instead.
 */
int sd_network_link_get_stat(int ifindex, struct stat *ret) {
        char path[PATH_MAX], suffix[32];
        int r;

        if (check_ifindex(ifindex) < 0 || !ret)
                return -EINVAL;

        (void) snprintf(suffix, sizeof(suffix), "/run/netd/leases/%d", ifindex);
        r = network_path(path, sizeof(path), suffix);
        if (r < 0)
                return r;

        return stat(path, ret) == 0 ? 0 : -errno;
}
