/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-init's own implementation of the sd-network public API surface.
 *
 * Function signatures and documented error conventions match systemd's
 * sd-network.h.
 *
 * The real library reads systemd-networkd's /run/systemd/netif state files,
 * which do not exist here; this shim reads netd's /run/netd state instead
 * (netd.h, netd-resolv.h). Getters for state netd computes but does not
 * publish return -EOPNOTSUPP, with a comment at the call site naming the
 * missing publisher. See network-state.c's top comment for the -ENODATA vs
 * -EOPNOTSUPP rule.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stat;

/* --- global (all-links) state --- */

int sd_network_get_operational_state(char **ret);
int sd_network_get_carrier_state(char **ret);
int sd_network_get_address_state(char **ret);
int sd_network_get_ipv4_address_state(char **ret);
int sd_network_get_ipv6_address_state(char **ret);
int sd_network_get_online_state(char **ret);

int sd_network_get_dns(char ***ret);
int sd_network_get_ntp(char ***ret);
int sd_network_get_search_domains(char ***ret);
int sd_network_get_route_domains(char ***ret);

/* --- per-link state --- */

int sd_network_link_get_setup_state(int ifindex, char **ret);
int sd_network_link_get_operational_state(int ifindex, char **ret);
int sd_network_link_get_required_operstate_for_online(int ifindex, char **ret);
int sd_network_link_get_required_family_for_online(int ifindex, char **ret);
int sd_network_link_get_carrier_state(int ifindex, char **ret);
int sd_network_link_get_address_state(int ifindex, char **ret);
int sd_network_link_get_ipv4_address_state(int ifindex, char **ret);
int sd_network_link_get_ipv6_address_state(int ifindex, char **ret);
int sd_network_link_get_online_state(int ifindex, char **ret);

int sd_network_link_get_required_for_online(int ifindex);
int sd_network_link_get_activation_policy(int ifindex, char **ret);

int sd_network_link_get_network_file(int ifindex, char **ret);
int sd_network_link_get_network_file_dropins(int ifindex, char ***ret);
int sd_network_link_get_netdev_file(int ifindex, char **ret);
int sd_network_link_get_netdev_file_dropins(int ifindex, char ***ret);

int sd_network_link_get_dns(int ifindex, char ***ret);
int sd_network_link_get_ntp(int ifindex, char ***ret);
int sd_network_link_get_sip(int ifindex, char ***ret);
int sd_network_link_get_captive_portal(int ifindex, char **ret);

int sd_network_link_get_llmnr(int ifindex, char **ret);
int sd_network_link_get_mdns(int ifindex, char **ret);
int sd_network_link_get_dns_over_tls(int ifindex, char **ret);
int sd_network_link_get_dnssec(int ifindex, char **ret);
int sd_network_link_get_dnssec_negative_trust_anchors(int ifindex, char ***ret);
int sd_network_link_get_search_domains(int ifindex, char ***ret);
int sd_network_link_get_route_domains(int ifindex, char ***ret);
int sd_network_link_get_dns_default_route(int ifindex);

int sd_network_link_get_carrier_bound_to(int ifindex, int **ret);
int sd_network_link_get_carrier_bound_by(int ifindex, int **ret);

int sd_network_link_get_dhcp6_client_iaid_string(int ifindex, char **ret);
int sd_network_link_get_dhcp6_client_duid_string(int ifindex, char **ret);

int sd_network_link_get_stat(int ifindex, struct stat *ret);

/* --- monitor --- */

typedef struct sd_network_monitor sd_network_monitor;

int sd_network_monitor_new(sd_network_monitor **ret, const char *category);
sd_network_monitor *sd_network_monitor_unref(sd_network_monitor *m);

static inline void sd_network_monitor_unrefp(sd_network_monitor **p) {
        if (*p)
                sd_network_monitor_unref(*p);
}

int sd_network_monitor_flush(sd_network_monitor *m);
int sd_network_monitor_get_fd(sd_network_monitor *m);
int sd_network_monitor_get_events(sd_network_monitor *m);
int sd_network_monitor_get_timeout(sd_network_monitor *m, uint64_t *ret_usec);

#ifdef __cplusplus
}
#endif
