/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from src/libsystemd-network/dhcp-server-request.c (671 lines). The
 * dhcp_server_process_{discover,request,decline,release}() handlers --
 * synchronous request -> reply functions, which is exactly why the server
 * ports so much more cleanly than the client (plan §2.1). No real
 * copyright line upstream.
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. History review
 * (4925d9f07f..main, plan §2.2): no fix in the 26-commit lift-set window
 * touches dhcp-server-request.c.
 *
 * ONE THING THE PLAN GOT WRONG, WORTH RECORDING: plan §2 repeatedly names
 * "dhcp_server_process_{discover,request,decline,release,inform}()" as the
 * five handlers this milestone ports. The real v261.2 source has no
 * dhcp_server_process_inform() at all -- DHCPINFORM falls through
 * dhcp_server_process_message()'s switch to `default: return 0` (ignored),
 * same as every other unhandled type. This file matches the real source,
 * not the plan's prose: four handlers, not five. Flagged in the final
 * report rather than silently "fixed" by inventing a fifth handler nothing
 * upstream has.
 *
 * Structural changes from upstream, all consequences of decisions recorded
 * in dhcp-server-internal.h's header (read that first):
 *
 *  - No relay. dhcp_server_parse_message() requires giaddr == INADDR_ANY and
 *    rejects a nonzero one with -EBADMSG (upstream instead treats
 *    giaddr == server->address specifically as a malicious-message signal
 *    and otherwise forwards through it -- relay is out of scope here, so
 *    any giaddr at all means a device this server was never meant to talk
 *    to is on the wire).
 *  - server_guess_client_state() collapses upstream's SELECTING /
 *    RENEWING / REBINDING / INIT_REBOOT four-way (the middle two split by
 *    IP_PKTINFO destination-address inspection, itself only there to avoid
 *    a NAK disturbing a *different* DHCP server on a shared subnet) into
 *    SELECTING / RENEW-OR-REBIND / INIT_REBOOT. netd's deployment model is
 *    exactly one authoritative server per link (a usb-gadget point-to-point
 *    link or a small LAN this server itself owns), so there is no other
 *    server a NAK could disturb, and the collapsed state still NAKs every
 *    mismatch and ignores nothing.
 *  - No static-lease path (dhcp_server_get_static_lease() does not exist
 *    here) -- every DISCOVER/REQUEST is resolved against the dynamic pool
 *    only.
 *  - dhcp_server_process_discover()'s siphash-offset trick is kept in full
 *    (plan calls out this exact mechanism as worth carrying): even with no
 *    persistence, hashing the client-id into an offset into the pool means
 *    a client that DISCOVERs twice is likely offered the same address both
 *    times, without needing to remember anything. siphash24() (netd's
 *    trimmed dhcp/siphash24.h) replaces the incremental
 *    init/compress/finalize dance upstream uses for a single 16-byte input.
 */

#include "dhcp-server-lease-internal.h"

#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "../util.h"
#include "siphash24.h"

/* RFC 2132 section 9.10: the minimum legal Maximum Message Size is 576
 * octets, and it is also req->max_message_size's default when the option is
 * absent. */
#define DHCP_MIN_MESSAGE_SIZE 576

/* Generous ceiling for one incoming datagram: real DHCP packets are a few
 * hundred bytes; this is larger than any max_message_size a sane client
 * would request, so a legitimate packet is never truncated, and an
 * over-large one is simply dropped (MSG_TRUNC) rather than parsed partially. */
#define DHCP_SERVER_RECV_BUF_SIZE 2048

static DHCPRequest *dhcp_request_free(DHCPRequest *req) {
        if (!req)
                return NULL;

        dhcp_message_unref(req->message);
        return pico_mfree(req);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DHCPRequest *, dhcp_request_free);

static int dhcp_request_set_client_id(DHCPRequest *req) {
        assert(req);
        assert(req->message);

        /* Genuine client ID from option 61. May be absent. */
        (void) dhcp_message_get_option_client_id(req->message, &req->client_id);

        /* Fake client ID synthesized from the DHCP header. Types 0 and 255
         * are reserved (RFC 2132 9.14 / RFC 4361), so a chaddr-derived id
         * never collides with either; hardware types 0/255 (rare, e.g.
         * loopback) have no usable chaddr and are skipped. */
        if (!IN_SET(req->message->header.htype, 0, UINT8_MAX))
                (void) dhcp_client_id_set(
                                &req->client_id_by_header,
                                req->message->header.htype,
                                req->message->header.chaddr,
                                req->message->header.hlen);

        if (!dhcp_client_id_is_set(&req->client_id))
                req->client_id = req->client_id_by_header;

        /* Leases are keyed by client-id; at least one form is mandatory. */
        netd_validate(dhcp_client_id_is_set(&req->client_id), -EBADMSG);

        return 0;
}

static int dhcp_request_set_server_identifier(DHCPRequest *req) {
        bool mandatory;
        be32_t a;
        int r;

        assert(req);
        assert(req->message);

        mandatory = IN_SET(req->type, DHCP_RELEASE, DHCP_DECLINE);

        r = dhcp_message_get_option_be32(req->message, SD_DHCP_OPTION_SERVER_IDENTIFIER, &a);
        if (r < 0)
                return mandatory ? r : 0;

        req->server_address = a;
        return 0;
}

static void dhcp_request_set_lifetime(DHCPRequest *req, DhcpServer *server) {
        assert(req);
        assert(req->message);
        assert(server);

        (void) dhcp_message_get_option_sec(
                        req->message,
                        SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
                        /* max_as_infinity= */ true,
                        &req->lifetime);

        if (req->lifetime <= 0)
                req->lifetime = server->default_lease_time > 30 * USEC_PER_SEC ? server->default_lease_time :
                                                                                 30 * USEC_PER_SEC;

        if (server->max_lease_time > 0 && req->lifetime > server->max_lease_time)
                req->lifetime = server->max_lease_time;
}

static int dhcp_server_parse_message(DhcpServer *server, const struct iovec *iov, DHCPRequest **ret) {
        _cleanup_(dhcp_message_unrefp) DhcpMessage *message = NULL;
        _cleanup_(dhcp_request_freep) DHCPRequest *req = NULL;
        int r;

        assert(server);
        assert(iov);
        assert(ret);

        r = dhcp_message_parse(iov, BOOTREQUEST, /* xid= */ NULL, ARPHRD_NONE, /* hw_addr= */ NULL, &message);
        if (r < 0)
                return r;

        /* No relay support (dhcp-server-internal.h's header) -- any giaddr
         * at all means this packet came via, or claims to come via, a relay
         * agent this server does not implement forwarding for. */
        netd_validate(message->header.giaddr == htobe32(INADDR_ANY), -EBADMSG);

        req = new0(DHCPRequest, 1);
        if (!req)
                return -ENOMEM;

        req->message = TAKE_PTR(message);
        req->max_message_size = DHCP_MIN_MESSAGE_SIZE;

        /* hlen/chaddr may be unset for a non-Ethernet interface (RFC 2131
         * 4.1); dhcp_message_get_hw_addr() already validates hlen's bound
         * against a real -EBADMSG (netd's codec layer, not this file). */
        r = dhcp_message_get_hw_addr(req->message, &req->hw_addr);
        if (r < 0)
                return r;

        r = dhcp_message_get_option_u8(req->message, SD_DHCP_OPTION_MESSAGE_TYPE, &req->type);
        if (r < 0)
                return r; /* mandatory */

        r = dhcp_request_set_client_id(req);
        if (r < 0)
                return r;

        r = dhcp_request_set_server_identifier(req);
        if (r < 0)
                return r;

        uint16_t max_size;
        if (dhcp_message_get_option_u16(req->message, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, &max_size) >= 0 &&
            max_size >= DHCP_MIN_MESSAGE_SIZE)
                req->max_message_size = max_size;

        dhcp_request_set_lifetime(req, server);

        (void) dhcp_message_get_option_parameter_request_list(req->message, &req->parameter_request_list);

        *ret = TAKE_PTR(req);
        return 0;
}

static int dhcp_server_ack(DhcpServer *server, DHCPRequest *req) {
        int r;

        assert(server);
        assert(req);
        assert(req->address != htobe32(INADDR_ANY));

        r = dhcp_server_set_lease(server, req);
        if (r < 0)
                return r;

        r = dhcp_server_send_reply(server, req, DHCP_ACK);
        if (r < 0)
                return r;

        dhcp_server_on_lease_change(server);
        return r;
}

static int dhcp_server_process_discover(DhcpServer *server, DHCPRequest *req) {
        DhcpServerLease *existing_lease;

        assert(server);
        assert(req);

        existing_lease = dhcp_server_get_lease_by_client_id(server, &req->client_id);

        pico_log(PICO_LOG_DEBUG, "netd: dhcp-server: DISCOVER (0x%x)", be32toh(req->message->header.xid));

        if (existing_lease) {
                /* The lease's own slot index *is* the address (dhcp-server-
                 * lease-internal.h's design) -- reuse it directly rather
                 * than re-deriving from a stored address field. */
                ssize_t idx = existing_lease - server->leases;
                be32_t candidate = htobe32(be32toh(server->subnet) | (server->pool_offset + (uint32_t) idx));
                if (dhcp_server_address_is_in_pool(server, candidate))
                        req->address = candidate;
        }

        if (req->address == htobe32(INADDR_ANY) && server->pool_size > 0) {
                uint64_t hash = siphash24(
                                req->client_id.raw,
                                req->client_id.size,
                                (const uint8_t[16]){ 0x0d,
                                                     0x1d,
                                                     0xfe,
                                                     0xbd,
                                                     0xf1,
                                                     0x24,
                                                     0xbd,
                                                     0xb3,
                                                     0x47,
                                                     0xf1,
                                                     0xdd,
                                                     0x6e,
                                                     0x73,
                                                     0x21,
                                                     0x93,
                                                     0x30 });

                for (uint32_t i = 0; i < server->pool_size; i++) {
                        uint32_t off = (uint32_t) ((hash + i) % server->pool_size);
                        be32_t a = htobe32(be32toh(server->subnet) | (server->pool_offset + off));

                        if (dhcp_server_address_available(server, a)) {
                                req->address = a;
                                break;
                        }
                }
        }

        if (req->address == htobe32(INADDR_ANY))
                return -EADDRNOTAVAIL; /* pool exhausted */

        if (server->rapid_commit &&
            dhcp_message_get_option_flag(req->message, SD_DHCP_OPTION_RAPID_COMMIT) >= 0)
                return dhcp_server_ack(server, req);

        return dhcp_server_send_reply(server, req, DHCP_OFFER);
}

/* Collapsed RENEW-OR-REBIND state -- see this file's header for why the
 * upstream RENEWING/REBINDING split does not apply here. */
typedef enum RequestState {
        REQUEST_SELECTING,
        REQUEST_RENEW_OR_REBIND,
        REQUEST_INIT_REBOOT,
} RequestState;

static int dhcp_server_process_request(DhcpServer *server, DHCPRequest *req) {
        DhcpServerLease *existing_lease;
        RequestState state;
        be32_t address;
        int r;

        assert(server);
        assert(req);

        existing_lease = dhcp_server_get_lease_by_client_id(server, &req->client_id);

        /* RFC 2131 section 4.3.2. */
        if (req->server_address != htobe32(INADDR_ANY)) {
                state = REQUEST_SELECTING;

                if (req->server_address != server->address)
                        return 0; /* not addressed to us */

                netd_validate(req->message->header.ciaddr == htobe32(INADDR_ANY), -EBADMSG);

                r = dhcp_message_get_option_be32(req->message, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &address);
                if (r < 0)
                        return r;
                netd_validate(address != htobe32(INADDR_ANY), -EBADMSG);

        } else if (req->message->header.ciaddr != htobe32(INADDR_ANY)) {
                state = REQUEST_RENEW_OR_REBIND;

                /* This MUST NOT be filled per RFC 2131 4.3.2. */
                netd_validate(dhcp_message_get_option_be32(
                                              req->message, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, NULL) < 0,
                              -EBADMSG);

                address = req->message->header.ciaddr;

        } else {
                state = REQUEST_INIT_REBOOT;

                r = dhcp_message_get_option_be32(req->message, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &address);
                if (r < 0)
                        return r;
                netd_validate(address != htobe32(INADDR_ANY), -EBADMSG);
        }

        pico_log(PICO_LOG_DEBUG,
                 "netd: dhcp-server: REQUEST (%s) (0x%x)",
                 state == REQUEST_SELECTING                   ? "selecting" :
                                 state == REQUEST_INIT_REBOOT ? "init-reboot" :
                                                                "renew-or-rebind",
                 be32toh(req->message->header.xid));

        /* Every mismatch NAKs -- no REBINDING-silently-ignore case, see this
         * file's header for why that split does not apply to netd's
         * one-server-per-link deployment. */

        DhcpServerLease *held = dhcp_server_get_lease_by_address(server, address);
        if (held && held != existing_lease)
                return dhcp_server_send_reply(server, req, DHCP_NAK);

        if (dhcp_server_address_is_in_pool(server, address)) {
                req->address = address;
                return dhcp_server_ack(server, req);
        }

        return dhcp_server_send_reply(server, req, DHCP_NAK);
}

static int dhcp_server_process_decline(DhcpServer *server, DHCPRequest *req) {
        _cleanup_free_ char *e = NULL;

        assert(server);
        assert(req);

        if (req->server_address != server->address)
                return 0;

        (void) dhcp_message_get_option_string(req->message, SD_DHCP_OPTION_ERROR_MESSAGE, &e);
        pico_log(PICO_LOG_DEBUG,
                 "netd: dhcp-server: DECLINE (0x%x): %s",
                 be32toh(req->message->header.xid),
                 e ? e : "");
        return 0;
}

static int dhcp_server_process_release(DhcpServer *server, DHCPRequest *req) {
        DhcpServerLease *existing_lease;

        assert(server);
        assert(req);

        if (req->server_address != server->address)
                return 0;

        existing_lease = dhcp_server_get_lease_by_client_id(server, &req->client_id);
        if (!existing_lease)
                return 0;

        ssize_t idx = existing_lease - server->leases;
        be32_t leased_addr = htobe32(be32toh(server->subnet) | (server->pool_offset + (uint32_t) idx));
        netd_validate(leased_addr == req->message->header.ciaddr, -EBADMSG);

        dhcp_server_lease_clear(existing_lease);
        dhcp_server_on_lease_change(server);

        pico_log(PICO_LOG_DEBUG, "netd: dhcp-server: RELEASE (0x%x)", be32toh(req->message->header.xid));
        return 0;
}

int dhcp_server_process_message(DhcpServer *server, const struct iovec *iov) {
        _cleanup_(dhcp_request_freep) DHCPRequest *req = NULL;
        int r;

        assert(server);
        assert(iov);
        DHCP_SERVER_DONT_DESTROY(server);

        r = dhcp_server_parse_message(server, iov, &req);
        if (r < 0)
                return r;

        dhcp_server_cleanup_expired_leases(server);

        switch (req->type) {
        case DHCP_DISCOVER:
                return dhcp_server_process_discover(server, req);
        case DHCP_REQUEST:
                return dhcp_server_process_request(server, req);
        case DHCP_DECLINE:
                return dhcp_server_process_decline(server, req);
        case DHCP_RELEASE:
                return dhcp_server_process_release(server, req);
        default:
                /* Includes DHCPINFORM, which upstream also does not handle
                 * (see this file's header) -- and any type this milestone
                 * simply does not implement (FORCERENEW has no caller,
                 * dhcp-server-internal.h's header). */
                return 0;
        }
}

int dhcp_server_io_callback(Netd *n, struct netd_epoll_tag *tag, uint32_t revents) {
        DhcpServer *server;
        uint8_t buf[DHCP_SERVER_RECV_BUF_SIZE];
        ssize_t len;
        int r;

        assert(tag);
        server = ASSERT_PTR(tag->userdata);
        (void) n;
        (void) revents;

        len = recv(server->socket_fd, buf, sizeof(buf), MSG_TRUNC);
        if (len < 0) {
                r = -errno;
                if (ERRNO_IS_NEG_TRANSIENT(r) || ERRNO_IS_NEG_DISCONNECT(r))
                        return 0;
                /* Not "%m": pico_log_internal() is declared with the ISO
                 * "printf" format archetype, and -Wpedantic rejects glibc's
                 * %m extension against it (netd-time.c hit and documented
                 * the same thing first). */
                log_dhcp_server_errno(server, r, "netd: dhcp-server: recv: %s", strerror(-r));
                return 0;
        }

        if ((size_t) len > sizeof(buf)) {
                /* MSG_TRUNC: kernel reports the true datagram length even
                 * when it exceeds the buffer -- a real, oversized wire
                 * packet, not netd's own bug. Drop it. */
                pico_log(PICO_LOG_DEBUG,
                         "netd: dhcp-server: %s: oversized datagram (%zd bytes), dropped",
                         server->ifname ? server->ifname : "?",
                         len);
                return 0;
        }

        struct iovec iov = { .iov_base = buf, .iov_len = (size_t) len };
        r = dhcp_server_process_message(server, &iov);
        if (r < 0)
                log_dhcp_server_errno(
                                server,
                                r,
                                "netd: dhcp-server: %s: couldn't process message: %s",
                                server->ifname ? server->ifname : "?",
                                strerror(-r));

        return 0;
}

int dhcp_server_open_socket(DhcpServer *server) {
        _cleanup_close_ int fd = -1;
        int one = 1;
        int r;

        assert(server);

        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
                return -errno;

        if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) < 0)
                return -errno;

        if (server->ifname) {
                r = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, server->ifname, strlen(server->ifname) + 1);
                if (r < 0)
                        return -errno;
        }

        struct sockaddr_in sa = {
                .sin_family = AF_INET,
                .sin_port = htobe16(DHCP_PORT_SERVER),
                .sin_addr.s_addr = htobe32(INADDR_ANY),
        };

        if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
                return -errno;

        return TAKE_FD(fd);
}
