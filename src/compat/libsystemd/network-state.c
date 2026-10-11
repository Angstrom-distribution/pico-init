/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Everything in sd-network.h that is not the resolv.conf family
 * (network-resolv.c) or the monitor (network-monitor.c).
 *
 * Everything here returns -EOPNOTSUPP except sd_network_link_get_stat(),
 * which is implemented. Some functions name data netd
 * computes in memory but publishes nowhere; others name directives or
 * features netd's parser does not have, so no truthful value exists. The
 * comment at each group says which.
 *
 * -EOPNOTSUPP rather than the usual -ENODATA: sd-network's -ENODATA means
 * "networkd is not aware of this link (yet)", which callers such as
 * systemd-networkd-wait-online treat as transient and retry forever.
 * -EOPNOTSUPP tells them this is not systemd-networkd.
 *
 * Per-link functions still validate ifindex: ifindex <= 0 gives -EINVAL.
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

/* --- global state: netd computes it but publishes no state file --- */

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

/* --- per-link effective dns/ntp/search: the lease file holds the DHCP
 * server's offer, not the result of netd's UseDNS=/UseNTP= gating, so
 * serving it would be misleading --- */

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
 * resolver feature flags (there is no resolver service) --- */

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
/* netd has no DHCPv6 client (netd-network.h), so no IAID/DUID. */
int sd_network_link_get_dhcp6_client_iaid_string(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}
int sd_network_link_get_dhcp6_client_duid_string(int ifindex, char **ret) {
        int r = check_ifindex(ifindex);
        return r < 0 ? r : (ret ? -EOPNOTSUPP : -EINVAL);
}

/*
 * Implemented: netd's lease file is its only per-link state file, so
 * stat()ing it is a narrow but truthful answer; -ENOENT is the API's own
 * "no state recorded for this link".
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
