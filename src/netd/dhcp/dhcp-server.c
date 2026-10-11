/* SPDX-FileCopyrightText: 2013 Intel Corporation */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/sd-dhcp-server.c. The
 * server object's lifecycle: construction, pool configuration, the option
 * setters a `.network`-driven DHCPServer=yes needs
 * (address/router/dns/ntp/domain/timezone, plus the lease-time and
 * rapid-commit defaults), and start/stop over netd-loop.h instead of
 * sd-event. See dhcp-server-internal.h for what was cut.
 *
 * Backport: systemd 7bd9f0f805 ("network/dhcp-server: fix pool size
 * calculation overflow"). v261.2's dhcp_server_configure_pool() computes
 * size_max in uint32_t before validating that offset is inside the subnet:
 *
 *   size_max = (broadcast_off + 1) - offset - 1;
 *   assert_return(size_max >= 1, -ERANGE);
 *
 * When offset > broadcast_off this underflows to near-UINT32_MAX, passes the
 * >= 1 check, and the server hands out addresses outside its subnet. The fix
 * checks the offset first and drops the subtraction that could underflow:
 *
 *   assert_return(offset < broadcast_off, -ERANGE);
 *   size_max = broadcast_off - offset;
 *
 * Currently unreachable: netd-network.h has no PoolOffset=/PoolSize= fields,
 * so offset is always 0 and becomes 1 before the arithmetic runs. It
 * becomes reachable if `.network` gains those directives.
 *
 * DHCP_SERVER_DONT_DESTROY is netd's own addition, applied in
 * dhcp_server_stop() and dhcp_server_on_lease_change(); see
 * dhcp-server-internal.h.
 */

#include "dhcp-server-lease-internal.h"

#include <sys/epoll.h>

#include "../util.h"
#include "dns-name.h"

#define DHCP_SERVER_DEFAULT_LEASE_TIME_USEC USEC_PER_HOUR
#define DHCP_SERVER_MAX_LEASE_TIME_USEC (USEC_PER_HOUR * 12)

/* Local because util.h has no free_and_strdup() and this is its only user. */
static int free_and_strdup_local(char **p, const char *s) {
        char *n = NULL;

        assert(p);

        if (s) {
                n = pico_strdup(s);
                if (!n)
                        return -ENOMEM;
        }

        pico_mfree(*p);
        *p = n;
        return 0;
}

void dhcp_server_on_lease_change(DhcpServer *server) {
        assert(server);
        DHCP_SERVER_DONT_DESTROY(server);

        if (server->callback)
                server->callback(server, DHCP_SERVER_EVENT_LEASE_CHANGED, server->callback_userdata);
}

int dhcp_server_configure_pool(
                DhcpServer *server,
                const struct in_addr *address,
                unsigned char prefixlen,
                uint32_t offset,
                uint32_t size) {

        struct in_addr netmask_addr;
        be32_t netmask;
        uint32_t server_off, broadcast_off, size_max;
        int r;

        assert_return(server, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(address->s_addr != htobe32(INADDR_ANY), -EINVAL);
        assert_return(prefixlen <= 32, -ERANGE);

        r = in4_addr_prefixlen_to_netmask(&netmask_addr, prefixlen);
        assert(r == 0); /* internal invariant: prefixlen was just bounds-checked above */
        netmask = netmask_addr.s_addr;

        server_off = be32toh(address->s_addr & ~netmask);
        broadcast_off = be32toh(~netmask);

        /* the server address cannot be the subnet address */
        assert_return(server_off != 0, -ERANGE);

        /* nor the broadcast address */
        assert_return(server_off != broadcast_off, -ERANGE);

        /* 0 offset means we should set a default, we skip the first (subnet) address
           and take the next one */
        if (offset == 0)
                offset = 1;

        /* 7bd9f0f805: check offset is inside the subnet before computing a
         * pool size from it (see this file's header). */
        assert_return(offset < broadcast_off, -ERANGE);
        size_max = broadcast_off - offset; /* excludes the broadcast address */

        if (size != 0)
                assert_return(size <= size_max, -ERANGE);
        else
                size = size_max;

        if (server->address != address->s_addr || server->netmask != netmask || server->pool_size != size ||
            server->pool_offset != offset) {

                _cleanup_free_ DhcpServerLease *leases = new0(DhcpServerLease, size);
                if (!leases)
                        return -ENOMEM;

                /* The old pool's leases do not carry over: their slot indices
                 * are meaningless against a different offset/size. Each old
                 * slot's hostname is heap-owned and freed individually
                 * before the array goes. */
                if (server->leases)
                        FOREACH_ARRAY(lease, server->leases, server->pool_size)
                dhcp_server_lease_clear(lease);
                pico_mfree(server->leases);
                server->leases = TAKE_PTR(leases);

                server->pool_offset = offset;
                server->pool_size = size;

                server->address = address->s_addr;
                server->netmask = netmask;
                server->subnet = address->s_addr & netmask;
        }

        return 0;
}

bool dhcp_server_address_is_in_pool(DhcpServer *server, be32_t address) {
        assert(server);

        if (server->pool_size == 0)
                return false;

        if (address == server->address)
                return false;

        if (be32toh(address) < (be32toh(server->subnet) | server->pool_offset) ||
            be32toh(address) >= (be32toh(server->subnet) | (server->pool_offset + server->pool_size)))
                return false;

        return true;
}

bool dhcp_server_address_available(DhcpServer *server, be32_t address) {
        assert(server);

        if (address == server->address)
                return false;

        return dhcp_server_get_lease_by_address(server, address) == NULL;
}

static void dhcp_server_update_lease_servers(DhcpServer *server) {
        assert(server);
        assert(server->address != htobe32(INADDR_ANY));

        /* Convert null address -> server address, matching upstream. */
        for (DhcpLeaseServerType k = 0; k < _DHCP_LEASE_SERVER_TYPE_MAX; k++) {
                if (server->servers[k].size == 0)
                        continue;

                FOREACH_ARRAY(a, server->servers[k].addr, server->servers[k].size)
                if (in4_addr_is_null(a))
                        a->s_addr = server->address;
        }
}

int dhcp_server_set_router(DhcpServer *server, const struct in_addr *router) {
        assert_return(server, -EINVAL);

        /* router == NULL: no router option is emitted.
         * router == 0.0.0.0: the server's own address is used.
         * otherwise: the given address is used. */
        server->emit_router = router != NULL;
        if (router)
                server->router_address = *router;

        return 0;
}

static int dhcp_server_set_servers(
                DhcpServer *server,
                DhcpLeaseServerType what,
                const struct in_addr addresses[],
                size_t n_addresses) {

        struct in_addr *c = NULL;

        assert_return(server, -EINVAL);
        assert_return(addresses || n_addresses == 0, -EINVAL);
        assert_return(what >= 0 && what < _DHCP_LEASE_SERVER_TYPE_MAX, -EINVAL);

        if (n_addresses > 0) {
                c = newdup(struct in_addr, addresses, n_addresses);
                if (!c)
                        return -ENOMEM;
        }

        pico_mfree(server->servers[what].addr);
        server->servers[what].addr = c;
        server->servers[what].size = n_addresses;
        return 0;
}

int dhcp_server_set_dns(DhcpServer *server, const struct in_addr dns[], size_t n) {
        return dhcp_server_set_servers(server, DHCP_LEASE_DNS, dns, n);
}

int dhcp_server_set_ntp(DhcpServer *server, const struct in_addr ntp[], size_t n) {
        return dhcp_server_set_servers(server, DHCP_LEASE_NTP, ntp, n);
}

int dhcp_server_set_domain_name(DhcpServer *server, const char *domain_name) {
        int r;

        assert_return(server, -EINVAL);

        if (domain_name) {
                r = dns_name_is_valid(domain_name);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL;
        }

        return free_and_strdup_local(&server->domain_name, domain_name);
}

/* Light syntactic check only; the zoneinfo lookup is netd-time.c's job when
 * a received timezone is applied. */
static bool timezone_looks_valid(const char *tz) {
        if (isempty(tz) || strlen(tz) > 255)
                return false;

        for (const char *p = tz; *p; p++)
                if (*p < 0x20 || *p == 0x7f)
                        return false;

        return true;
}

int dhcp_server_set_timezone(DhcpServer *server, const char *tz) {
        assert_return(server, -EINVAL);
        assert_return(!tz || timezone_looks_valid(tz), -EINVAL);

        return free_and_strdup_local(&server->timezone, tz);
}

int dhcp_server_set_lease_times(DhcpServer *server, usec_t default_lease_time, usec_t max_lease_time) {
        assert_return(server, -EINVAL);

        if (default_lease_time > 0)
                server->default_lease_time = default_lease_time;
        if (max_lease_time > 0)
                server->max_lease_time = max_lease_time;

        return 0;
}

int dhcp_server_set_rapid_commit(DhcpServer *server, bool enabled) {
        assert_return(server, -EINVAL);

        server->rapid_commit = enabled;
        return 0;
}

int dhcp_server_set_callback(DhcpServer *server, DhcpServerCallback cb, void *userdata) {
        assert_return(server, -EINVAL);

        server->callback = cb;
        server->callback_userdata = userdata;
        return 0;
}

bool dhcp_server_is_running(DhcpServer *server) {
        return server && server->io_tag.registered;
}

/* Teardown shared by dhcp_server_stop() and dhcp_server_free(). free() must
 * not go through the DONT_DESTROY-guarded dhcp_server_stop(): n_ref is
 * already 0 there and dhcp_server_ref() asserts n_ref > 0. */
static int dhcp_server_stop_internal(DhcpServer *server) {
        bool running;

        assert(server);

        running = dhcp_server_is_running(server);

        (void) netd_loop_remove_io(server->netd, &server->io_tag);
        if (server->socket_fd >= 0)
                (void) close(server->socket_fd);
        server->socket_fd = -1;

        if (running)
                pico_log(PICO_LOG_INFO, "netd: dhcp-server: %s: STOPPED", server->ifname ? server->ifname : "?");

        return 0;
}

static DhcpServer *dhcp_server_free(DhcpServer *server) {
        assert(server);

        /* Idempotent; the unguarded form, see dhcp_server_stop_internal(). */
        (void) dhcp_server_stop_internal(server);

        for (DhcpLeaseServerType k = 0; k < _DHCP_LEASE_SERVER_TYPE_MAX; k++)
                pico_mfree(server->servers[k].addr);

        if (server->leases)
                FOREACH_ARRAY(lease, server->leases, server->pool_size)
        dhcp_server_lease_clear(lease);
        pico_mfree(server->leases);

        pico_mfree(server->domain_name);
        pico_mfree(server->timezone);
        pico_mfree(server->ifname);
        return pico_mfree(server);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DhcpServer, dhcp_server, dhcp_server_free);

int dhcp_server_new(Netd *n, int ifindex, const char *ifname, DhcpServer **ret) {
        _cleanup_(dhcp_server_unrefp) DhcpServer *server = NULL;

        assert_return(n, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        server = new (DhcpServer, 1);
        if (!server)
                return -ENOMEM;

        *server = (DhcpServer){
                .n_ref = 1,
                .netd = n,
                .socket_fd = -1,
                .ifindex = ifindex,
                .ip_service_type = 0,
                .default_lease_time = DHCP_SERVER_DEFAULT_LEASE_TIME_USEC,
                .max_lease_time = DHCP_SERVER_MAX_LEASE_TIME_USEC,
                .rapid_commit = true,
        };
        server->io_tag.fd = -1;

        if (ifname) {
                server->ifname = pico_strdup(ifname);
                if (!server->ifname)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(server);
        return 0;
}

int dhcp_server_start(DhcpServer *server) {
        int r, fd;

        assert_return(server, -EINVAL);
        assert_return(server->address != htobe32(INADDR_ANY), -EUNATCH);

        if (dhcp_server_is_running(server))
                return 0;

        dhcp_server_update_lease_servers(server);

        fd = dhcp_server_open_socket(server);
        if (fd < 0)
                return fd;

        r = netd_loop_add_io(
                        server->netd,
                        &server->io_tag,
                        fd,
                        EPOLLIN,
                        NETD_EPOLL_DHCP_SERVER,
                        dhcp_server_io_callback,
                        server);
        if (r < 0) {
                (void) close(fd);
                return r;
        }

        server->socket_fd = fd;
        pico_log(PICO_LOG_INFO, "netd: dhcp-server: %s: STARTED", server->ifname ? server->ifname : "?");
        return 0;
}

int dhcp_server_stop(DhcpServer *server) {
        if (!server)
                return 0;
        DHCP_SERVER_DONT_DESTROY(server);

        return dhcp_server_stop_internal(server);
}
