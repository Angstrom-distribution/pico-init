/* SPDX-FileCopyrightText: 2013 Intel Corporation */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from src/libsystemd-network/dhcp-server-internal.h (82 lines) and
 * src/libsystemd-network/dhcp-server-request.h (23 lines, folded in here:
 * this milestone's exclusive file list has no separate dhcp-server-request.h
 * registered, so DHCPRequest and the process_*() declarations live where
 * dhcp-server-request.c's own callers can already reach them). Carries a
 * real 2013 Intel copyright line -- verified against the real v261.2 file,
 * which still has it.
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. History review
 * (4925d9f07f..main, plan §2.2): no fix in the 26-commit lift-set window
 * touches dhcp-server-internal.h. That window's one backport-worthy commit,
 * 7bd9f0f805 ("dhcp-server: reject pool offsets beyond the subnet"), touches
 * sd-dhcp-server.c's sd_dhcp_server_configure_pool() -- applied in
 * dhcp-server.c, not here; see that file's header for the fix itself and the
 * latency record plan §2's quarry table calls for.
 *
 * The lease table is the one structural rewrite (plan §2.1/§2.2): upstream
 * keeps four Hashmaps (bound/static x by-client-id/by-address). At embedded
 * pool scale a flat array is smaller, allocation-free per lookup, and
 * strictly simpler to reason about. DhcpServer.leases is allocated with one
 * slot per pool address at dhcp_server_configure_pool() time and indexed
 * directly by (address - pool start) -- see dhcp-server-lease-internal.h and
 * dhcp-server-lease.c. This also means the two per-key hash-ops pairs
 * upstream needs (client_id_hash_func()/_compare_func(), both cut from
 * dhcp-client-id-internal.h -- see that file's own header) are simply not
 * needed: an array has no hash function to plug in.
 *
 * Cut on the way in, and why each is safe to cut for netd's actual
 * deployment (a usb-gadget point-to-point link or a small LAN, exactly one
 * netd DHCP server per link, no other implementation sharing the subnet):
 *
 *  - Lease-file persistence (dhcp_server_save_leases()/_load_leases(), the
 *    lease_dir_fd/lease_file fields) -- the single biggest hidden-depth
 *    surprise in the whole netd plan (plan §2.1): it pulls in 10,346 LOC of
 *    sd-json to write a lease file. Dropped entirely, not ported; leases
 *    live in memory only and do not survive a netd restart. A client whose
 *    lease is forgotten simply DISCOVERs again.
 *  - Static leases (sd_dhcp_server_set_static_lease(), the
 *    static_leases_by_* hashmaps) -- no `.network` directive configures one
 *    (netd-network.h's Network struct has no such field), so this would be
 *    dead API surface, not a real port. dhcp_server_get_static_lease()
 *    correspondingly does not exist here; every request is checked against
 *    the dynamic pool only.
 *  - DHCP relay (giaddr-forwarding replies, the Relay Agent Information
 *    sub-TLV echo in dhcp-server-send.c, the RTM_NEWLINK-style
 *    pktinfo/agent-flags RENEWING-vs-REBINDING distinction in
 *    server_guess_client_state()) -- out of scope per plan §2.9. netd
 *    requires giaddr == 0 and rejects a nonzero one as malformed rather than
 *    silently misrouting a reply nothing here builds correctly.
 *  - The RENEWING-vs-REBINDING split itself, even for the non-relay case --
 *    upstream draws it (via IP_PKTINFO) purely so a NAK from an
 *    unauthoritative server on a multi-server subnet doesn't clobber another
 *    server's reply. netd's deployment model is one authoritative server
 *    per link, so there is no other server to protect; every mismatched
 *    DHCPREQUEST is NAKed uniformly. See dhcp-server-request.c for where
 *    this collapses upstream's server_guess_client_state().
 *  - Boot server address/name/filename (BOOTP siaddr/sname/file passthrough)
 *    and the vendor-options/extra-options raw TLV passthrough -- no
 *    `.network` directive configures either, and PXE/BOOTP chaining is not
 *    a pico-init use case.
 *  - IPv6-only-preferred (option 108) -- netd carries no IPv6 (plan §2.9,
 *    "all of IPv6"); the option constant survives in dhcp-protocol.h for API
 *    completeness (that file's own header explains why) but nothing here
 *    ever sets or emits it.
 *  - sd_dhcp_server_forcerenew() / DHCP_FORCERENEW -- no caller anywhere in
 *    netd's design (plan §2.5's SIGHUP reload reconfigures links, it does
 *    not force-renew existing DHCP clients), so this is unused API surface
 *    upstream itself only expects networkd's D-Bus layer to call.
 *  - POP3/SMTP/LPR server options -- DhcpLeaseServerType (dhcp-lease-
 *    internal.h, shared with the client side of this lift) only defines
 *    DNS/NTP/SIP; that enum already made this cut for the whole lift set,
 *    not just here, and dhcp-server-send.c's option_map below matches it.
 *
 * MISSING DEFECT UPSTREAM DOES NOT FIX: sd-dhcp-server.c has no
 * DONT_DESTROY ref-guard anywhere, unlike sd-dhcp-client.c's nine
 * (dhcp-client-internal.h:96, DHCP_CLIENT_DONT_DESTROY) -- the same defect
 * upstream itself fixed in sd-lldp-rx as a762c92a7c, still live here.
 * dhcp_server_on_lease_change() (sd-dhcp-server.c:36-37) calls
 * server->callback(...) with no ref held. It matters more in netd than
 * upstream: SIGHUP reconfigures every interface and lease application is a
 * direct function call (no D-Bus indirection to absorb reentrancy), so a
 * user callback that reacts to a lease change by tearing down and
 * reconfiguring its own link reaches straight back into this object's own
 * call stack. DHCP_SERVER_DONT_DESTROY below is netd's own addition -- a
 * real fix upstream does not have, not a carried one -- applied at
 * dhcp_server_on_lease_change() itself (the exact function the plan
 * identifies) and at dhcp_server_process_message() and dhcp_server_stop()
 * (mirroring which functions sd-dhcp-client.c guards: client_handle_message
 * for the receive path, sd_dhcp_client_stop() for the public stop entry
 * point).
 */

#pragma once

/* Self-sufficient regardless of what a consumer includes first -- see any
 * lifted header's near-identical note for why (a real cross-agent bug this
 * project hit once already). */
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
 * free the object this function is still using. See this file's header --
 * upstream has no equivalent of this macro for the server at all. */
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

/* The single io event source (plan §2.1: "11.3% event-coupled, exactly one
 * io event source" -- this is it). Registers via netd_loop_add_io() under
 * NETD_EPOLL_DHCP_SERVER; matches netd_io_callback_t's signature. */
int dhcp_server_io_callback(Netd *n, struct netd_epoll_tag *tag, uint32_t revents);

int dhcp_server_open_socket(DhcpServer *server);

/* --- dhcp-server-send.c --- */

int dhcp_server_send_reply(DhcpServer *server, DHCPRequest *req, uint8_t type);
