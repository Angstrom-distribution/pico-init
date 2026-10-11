/* SPDX-FileCopyrightText: 2013 Intel Corporation */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/dhcp-server-internal.h
 * and dhcp-server-request.h (folded in here, so DHCPRequest and the
 * process_*() declarations live in one header).
 *
 * The lease table is the one structural rewrite: upstream keeps four
 * Hashmaps (bound/static x by-client-id/by-address). Here DhcpServer.leases
 * is a flat array allocated with one slot per pool address in
 * dhcp_server_configure_pool() and indexed by (address - pool start); see
 * dhcp-server-lease-internal.h and dhcp-server-lease.c.
 *
 * Cut, for a deployment of one netd DHCP server per link (a usb-gadget
 * point-to-point link or a small LAN):
 *
 *  - Lease-file persistence (dhcp_server_save_leases()/_load_leases(), the
 *    lease_dir_fd/lease_file fields): it needs sd-json. Leases live in
 *    memory and do not survive a netd restart; a client whose lease is
 *    forgotten simply DISCOVERs again.
 *  - Static leases (sd_dhcp_server_set_static_lease(), the static_leases_by_*
 *    hashmaps): no `.network` directive configures one. Every request is
 *    checked against the dynamic pool only.
 *  - DHCP relay (giaddr forwarding, the Relay Agent Information sub-TLV echo
 *    in dhcp-server-send.c, the pktinfo/agent-flags handling in
 *    server_guess_client_state()). A nonzero giaddr is rejected as malformed.
 *  - The RENEWING-vs-REBINDING split, even without relay: upstream draws it
 *    (via IP_PKTINFO) so a NAK from a non-authoritative server on a
 *    multi-server subnet does not clobber another server's reply. With one
 *    authoritative server per link, every mismatched DHCPREQUEST is NAKed
 *    uniformly (see dhcp-server-request.c).
 *  - Boot server address/name/filename (BOOTP siaddr/sname/file) and the
 *    vendor-options/extra-options raw TLV passthrough.
 *  - IPv6-only-preferred (option 108): netd carries no IPv6.
 *  - sd_dhcp_server_forcerenew() / DHCP_FORCERENEW: no caller.
 *  - POP3/SMTP/LPR server options: DhcpLeaseServerType (dhcp-lease-internal.h)
 *    only defines DNS/NTP/SIP, and option_map in dhcp-server-send.c matches.
 *
 * Upstream's sd-dhcp-server.c has no DONT_DESTROY ref guard, unlike
 * sd-dhcp-client.c. In netd SIGHUP reconfigures every interface and lease
 * application is a direct function call, so a callback that reacts to a
 * lease change by tearing down and reconfiguring its own link would reach
 * back into this object's call stack. DHCP_SERVER_DONT_DESTROY below is
 * netd's own addition, applied in dhcp_server_on_lease_change(),
 * dhcp_server_process_message() and dhcp_server_stop().
 */

#pragma once

/* Self-sufficient: needs bool/usec_t/macros from netd-compat.h. */
#include "netd-compat.h"

#include "dhcp-client-id-internal.h"
#include "dhcp-lease-internal.h" /* DhcpLeaseServerType/DhcpLeaseServerData, shared with the client's lease object */
#include "dhcp-message.h"
#include "netd-loop.h" /* struct netd_epoll_tag, Netd, netd_io_callback_t -- this file's sd-event.h equivalent */

/* netd's name for upstream's sd_dhcp_server. */
typedef struct DhcpServer DhcpServer;

/* Forward-declared: the full definition is dhcp-server-lease-internal.h's.
 * DhcpServer only ever holds a pointer to the array, so a forward
 * declaration is enough here and avoids a circular include (that header
 * includes this one, for DhcpServer and DHCPRequest). */
typedef struct DhcpServerLease DhcpServerLease;

typedef enum DhcpServerEvent {
        DHCP_SERVER_EVENT_LEASE_CHANGED,
} DhcpServerEvent;

typedef void (*DhcpServerCallback)(DhcpServer *server, DhcpServerEvent event, void *userdata);

struct DhcpServer {
        unsigned n_ref;

        /* Not owned; used only to (de)register io_tag at start/stop
         * (netd-loop.h's "sources are dynamic... own their fd end to end"). */
        Netd *netd;
        struct netd_epoll_tag io_tag;
        int socket_fd;

        int ifindex;
        char *ifname; /* owned; SO_BINDTODEVICE needs the name, not just the index */

        be32_t address;
        be32_t netmask;
        be32_t subnet;
        uint32_t pool_offset;
        uint32_t pool_size;

        /* pool_size slots, index i == address (subnet | (pool_offset + i)).
         * NULL until dhcp_server_configure_pool() succeeds. */
        DhcpServerLease *leases;

        bool emit_router;
        struct in_addr router_address;

        DhcpLeaseServerData servers[_DHCP_LEASE_SERVER_TYPE_MAX];

        char *domain_name;
        char *timezone;

        usec_t default_lease_time;
        usec_t max_lease_time;

        bool rapid_commit;

        uint8_t ip_service_type;

        DhcpServerCallback callback;
        void *callback_userdata;
};

/* If we are invoking the callback (or anything that transitively might),
 * ensure the caller unreffing/stopping the server from inside it doesn't
 * free the object this function is still using. */
#define DHCP_SERVER_DONT_DESTROY(server) \
        _cleanup_(dhcp_server_unrefp) _unused_ DhcpServer *_dont_destroy_##server = dhcp_server_ref(server)

DhcpServer *dhcp_server_ref(DhcpServer *p);
DhcpServer *dhcp_server_unref(DhcpServer *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(DhcpServer *, dhcp_server_unref);

/* --- dhcp-server.c: lifecycle and configuration --- */

int dhcp_server_new(Netd *n, int ifindex, const char *ifname, DhcpServer **ret);

/* See dhcp-server.c's header for the 7bd9f0f805 backport this carries. */
int dhcp_server_configure_pool(
                DhcpServer *server,
                const struct in_addr *address,
                unsigned char prefixlen,
                uint32_t offset,
                uint32_t size);

int dhcp_server_set_router(DhcpServer *server, const struct in_addr *router);
int dhcp_server_set_dns(DhcpServer *server, const struct in_addr dns[], size_t n);
int dhcp_server_set_ntp(DhcpServer *server, const struct in_addr ntp[], size_t n);
int dhcp_server_set_domain_name(DhcpServer *server, const char *domain_name);
int dhcp_server_set_timezone(DhcpServer *server, const char *tz);
int dhcp_server_set_lease_times(DhcpServer *server, usec_t default_lease_time, usec_t max_lease_time);
int dhcp_server_set_rapid_commit(DhcpServer *server, bool enabled);
int dhcp_server_set_callback(DhcpServer *server, DhcpServerCallback cb, void *userdata);

bool dhcp_server_is_running(DhcpServer *server);
int dhcp_server_start(DhcpServer *server);
int dhcp_server_stop(DhcpServer *server);

void dhcp_server_on_lease_change(DhcpServer *server);
bool dhcp_server_address_is_in_pool(DhcpServer *server, be32_t address);
bool dhcp_server_address_available(DhcpServer *server, be32_t address);

/* --- one in-flight request's parsed/working state (dhcp-server-request.h's role) --- */

typedef struct DHCPRequest {
        DhcpMessage *message; /* ref'd */

        struct hw_addr_data hw_addr;
        DhcpClientId client_id; /* from option 61, or synthesized from chaddr */
        DhcpClientId client_id_by_header; /* the chaddr-synthesized one specifically, for the static-lease-less fallback */

        uint8_t type;          /* DHCPMessageType */
        be32_t server_address; /* option 54; INADDR_ANY if absent */
        be32_t address;        /* the address this transaction assigns/confirms; INADDR_ANY until chosen */
        usec_t lifetime;
        uint16_t max_message_size;

        NetdU8Set parameter_request_list;
} DHCPRequest;

/* --- dhcp-server-request.c --- */

int dhcp_server_process_message(DhcpServer *server, const struct iovec *iov);

/* The server's single io event source. Registers via netd_loop_add_io() under
 * NETD_EPOLL_DHCP_SERVER; matches netd_io_callback_t's signature. */
int dhcp_server_io_callback(Netd *n, struct netd_epoll_tag *tag, uint32_t revents);

int dhcp_server_open_socket(DhcpServer *server);

/* --- dhcp-server-send.c --- */

int dhcp_server_send_reply(DhcpServer *server, DHCPRequest *req, uint8_t type);
