/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/dhcp-client-internal.h:
 * the DHCPv4 client object's layout and the internal entry points
 * dhcp-client.c and dhcp-client-send.c share.
 *
 * Upstream holds five sd_event_source pointers (timeout_resend, timeout_t1,
 * timeout_t2, timeout_expire, receive_message). netd holds four
 * PicoTimerEvent handles and one netd_epoll_tag instead. src/timer.h's
 * handle-lifetime contract applies: the queue stores the address of the
 * handle slot and clears it when the event fires or is cancelled, so a
 * handle is NULL exactly when its event no longer exists, and every arm
 * passes the address of the owning field (never a local). For that reason
 * dhcp_client_free() cancels all four before freeing anything.
 *
 * The protocol logic is kept; the control flow around the timers is
 * re-derived, and each rewritten function carries a comment naming the RFC
 * 2131 requirement its upstream event code encoded.
 *
 * DHCP_CLIENT_DONT_DESTROY (below) and the `state == DHCP_STATE_STOPPED`
 * re-check after every client_notify() are kept. SIGHUP reconfigures every
 * interface and lease application is a direct call into netd-link.c, so a
 * reconfigure reached from inside a lease callback would otherwise free the
 * client under its own stack frame.
 *
 * Cut relative to upstream:
 *  - RFC 7844 anonymize mode (`anonymize`, the anonymized parameter request
 *    list, and the last_addr/rapid-commit suppressions it drives): the
 *    `.network` subset has no Anonymize= directive.
 *  - sd_device: netd has no udev dependency, so dhcp_identifier_set_iaid()
 *    takes no device (dhcp-client-id-internal.h). See the IAID note below.
 *  - Option 108 (IPv6-Only Preferred) and the REQUESTING delay built on it:
 *    netd does not request option 108 and the lease object has no
 *    ipv6_only_preferred_usec field (dhcp-lease-internal.h).
 *  - MUD URL (161), User Class (77), Vendor Specific (43) sub-TLVs and the
 *    caller-supplied extra/vendor TLV blocks: no `.network` directive
 *    reaches them, and the sub-TLV append helpers were cut from the codec
 *    (dhcp-message.h).
 *  - The externally supplied socket fd (`socket_fd`), which exists upstream
 *    only so its tests can drive the client over a socketpair.
 *  - ARPHRD_INFINIBAND: HW_ADDR_MAX_SIZE (dhcp-protocol.h) is sized without
 *    it, so dhcp_client_set_mac() rejects it.
 *
 * IAID divergence: upstream derives the IAID in the RFC 4361 client-id from
 * a hash of the persistent interface name when an sd_device is available,
 * and from the MAC address otherwise. netd always hashes the MAC. A board
 * moved from systemd-networkd to netd therefore presents a different client
 * identifier on the same interface, and a DHCP server keyed on client-id may
 * hand it a different address.
 *
 * Clock divergence: upstream runs every DHCP timer on CLOCK_BOOTTIME, so
 * time spent suspended counts against a lease. netd's shared timer queue is
 * CLOCK_MONOTONIC (src/timer.c), as is the lease timestamp
 * (dhcp-lease-internal.h), so a lease is held across a suspend that upstream
 * would have expired. Suspend is not supported.
 */

#pragma once

/* Self-sufficient, like every other header under src/netd/dhcp/. */
#include "netd-compat.h"

#include <net/if.h>
#include <netinet/in.h>

#include "netd.h"

#include "dhcp-client-id-internal.h"
#include "dhcp-lease-internal.h"
#include "dhcp-message.h"
#include "dhcp-protocol.h"

/* netd's name for upstream's sd_dhcp_client. */
typedef struct DhcpClient DhcpClient;

/*
 * The events handed to the link layer's callback. The numeric values are
 * upstream's SD_DHCP_CLIENT_EVENT_* values unchanged, so a reader comparing
 * the two state machines side by side does not have to translate.
 */
typedef enum DhcpClientEvent {
        DHCP_CLIENT_EVENT_STOP = 0,
        DHCP_CLIENT_EVENT_IP_ACQUIRE = 1,
        DHCP_CLIENT_EVENT_IP_CHANGE = 2,
        DHCP_CLIENT_EVENT_EXPIRED = 3,
        DHCP_CLIENT_EVENT_RENEW = 4,
        DHCP_CLIENT_EVENT_SELECTING = 5,
        /* Sent once the DISCOVER retransmission count reaches
         * TRANSIENT_FAILURE_ATTEMPTS, so the link layer can fall back
         * (usb-multi-gadget's static-address fallback is exactly this case)
         * without waiting for the full retry budget. */
        DHCP_CLIENT_EVENT_TRANSIENT_FAILURE = 6,
} DhcpClientEvent;

/*
 * `event` is a DhcpClientEvent, or a negative errno when the client failed.
 * The return value is ignored for every event except
 * DHCP_CLIENT_EVENT_SELECTING, where a negative return means "reject this
 * OFFER" and the client goes on waiting for another one.
 *
 * The callback MAY stop or unref the client. Every call site guards itself
 * with DHCP_CLIENT_DONT_DESTROY and re-checks the state afterwards.
 */
typedef int (*dhcp_client_callback_t)(DhcpClient *client, int event, void *userdata);

struct DhcpClient {
        unsigned n_ref;

        Netd *netd; /* borrowed; owns the timer queue and the epoll set */

        DHCPState state;

        int ifindex;
        char ifname[IFNAMSIZ]; /* for logging only */

        /* Event sources: four timer handles and one epoll registration.
         * Every pico_timer_add() is handed the address of one of these
         * fields, per src/timer.h. */
        PicoTimerEvent *timeout_resend;
        PicoTimerEvent *timeout_t1;
        PicoTimerEvent *timeout_t2;
        PicoTimerEvent *timeout_expire;
        struct netd_epoll_tag io_tag;

        /*
         * The receive socket, owned. -1 when none is open. `fd_domain` is
         * AF_PACKET before a lease exists and AF_INET once one does;
         * upstream asks the kernel with getsockopt(SO_DOMAIN) because its fd
         * may have come from outside, which netd's does not.
         */
        int fd;
        int fd_domain;

        uint16_t port;        /* client port, 68 */
        uint16_t server_port; /* server port, 67 */

        bool request_broadcast;
        bool rapid_commit; /* RFC 4039 */
        bool bootp;        /* plain BOOTP, no DHCP options */
        bool send_release; /* send DHCPRELEASE from dhcp_client_stop() */

        NetdU8Set req_opts; /* the 256-bit bitmap, not upstream's Set* */

        be32_t last_addr; /* drives INIT-REBOOT, RFC 2131 4.4.2 */
        struct hw_addr_data hw_addr;
        struct hw_addr_data bcast_addr;
        uint16_t arp_type;
        DhcpClientId client_id;

        char *hostname;
        char *vendor_class_identifier;
        uint32_t mtu; /* advertised as Maximum Message Size (57) */
        usec_t fallback_lease_lifetime;

        uint32_t xid;
        usec_t start_time;  /* base for the 'secs' header field */
        usec_t start_delay; /* backoff before the next INIT cycle */

        /* Absolute CLOCK_MONOTONIC deadlines, derived from the lease's own
         * timestamp -- never from "whenever this code happened to run". */
        usec_t t1_time;
        usec_t t2_time;
        usec_t expire_time;

        uint64_t discover_attempt;
        uint64_t request_attempt;
        uint64_t max_discover_attempts;

        uint8_t ip_service_type;
        int socket_priority;

        DhcpLease *lease;

        dhcp_client_callback_t callback;
        void *userdata;
};

DhcpClient *dhcp_client_ref(DhcpClient *client);
DhcpClient *dhcp_client_unref(DhcpClient *client);
DEFINE_TRIVIAL_CLEANUP_FUNC(DhcpClient *, dhcp_client_unref);

/*
 * Carried from upstream unchanged in intent (dhcp-client-internal.h:96): a
 * scoped reference so that a user callback which stops or unrefs the client
 * cannot free the object the current function is still walking. Nine
 * upstream functions take it; so do their netd counterparts.
 */
#define DHCP_CLIENT_DONT_DESTROY(client) \
        _cleanup_(dhcp_client_unrefp) _unused_ DhcpClient *_dont_destroy_##client = dhcp_client_ref(client)

/* --- dhcp-client.c: construction and configuration --- */

/*
 * `ifindex` and `ifname` come straight from netd-link.c's rtnetlink
 * snapshot. The Netd is borrowed and must outlive the client -- it owns both
 * the timer queue every deadline lands in and the epoll set the receive
 * socket registers into.
 */
int dhcp_client_new(Netd *netd, int ifindex, const char *ifname, DhcpClient **ret);

int dhcp_client_set_callback(DhcpClient *client, dhcp_client_callback_t cb, void *userdata);
int dhcp_client_set_mac(
                DhcpClient *client,
                const uint8_t *hw_addr,
                const uint8_t *bcast_addr,
                size_t addr_len,
                uint16_t arp_type);
int dhcp_client_set_client_id(DhcpClient *client, uint8_t type, const uint8_t *data, size_t data_len);
int dhcp_client_get_client_id(DhcpClient *client, const DhcpClientId **ret);
int dhcp_client_set_request_option(DhcpClient *client, uint8_t option);
int dhcp_client_set_request_address(DhcpClient *client, const struct in_addr *last_addr);
int dhcp_client_set_request_broadcast(DhcpClient *client, bool broadcast);
int dhcp_client_set_hostname(DhcpClient *client, const char *hostname);
int dhcp_client_set_vendor_class_identifier(DhcpClient *client, const char *vci);
int dhcp_client_set_mtu(DhcpClient *client, uint32_t mtu);
int dhcp_client_set_max_attempts(DhcpClient *client, uint64_t max_attempts);
int dhcp_client_set_client_port(DhcpClient *client, uint16_t port);
int dhcp_client_set_server_port(DhcpClient *client, uint16_t port);
int dhcp_client_set_fallback_lease_lifetime(DhcpClient *client, usec_t fallback);
int dhcp_client_set_bootp(DhcpClient *client, bool bootp);
int dhcp_client_set_send_release(DhcpClient *client, bool enable);
int dhcp_client_set_rapid_commit(DhcpClient *client, bool rapid_commit);
int dhcp_client_set_ip_service_type(DhcpClient *client, uint8_t type);
int dhcp_client_set_socket_priority(DhcpClient *client, int priority);

/* --- dhcp-client.c: running --- */

int dhcp_client_start(DhcpClient *client);
int dhcp_client_stop(DhcpClient *client);
int dhcp_client_is_running(DhcpClient *client);
int dhcp_client_get_state(DhcpClient *client);
int dhcp_client_get_lease(DhcpClient *client, DhcpLease **ret);

/* Force an immediate RENEWING cycle from BOUND (upstream's
 * sd_dhcp_client_send_renew()). 0 when there is nothing to do. */
int dhcp_client_send_renew(DhcpClient *client);

/* RFC 2131 3.1.5: the address turned out to be in use. Sends DHCPDECLINE and
 * restarts the configuration process after the RFC's ten-second minimum
 * (see dhcp-client.c). */
int dhcp_client_send_decline(DhcpClient *client);

/* Logging with an interface-name prefix, which netd-compat.h's
 * log_dhcp_client() drops (it discards the client argument). Defined in
 * dhcp-client.c; also used from dhcp-client-send.c. */
void dhcp_client_log(DhcpClient *client, PicoLogLevel level, const char *fmt, ...) _printf_(3, 4);

#define log_client_debug(client, ...) dhcp_client_log((client), PICO_LOG_DEBUG, __VA_ARGS__)
#define log_client_info(client, ...) dhcp_client_log((client), PICO_LOG_INFO, __VA_ARGS__)
#define log_client_warning(client, ...) dhcp_client_log((client), PICO_LOG_WARNING, __VA_ARGS__)
#define log_client_error(client, ...) dhcp_client_log((client), PICO_LOG_ERR, __VA_ARGS__)

/* --- dhcp-client-send.c --- */

/* Build and transmit one message of `type`, choosing the raw or UDP path and
 * arming/tearing down the receive registration exactly as the state
 * requires. 0 or -errno. */
int dhcp_client_send_message(DhcpClient *client, uint8_t type);

/* Drop the receive registration and close the socket. Idempotent. Shared
 * with dhcp-client.c, which needs it on T2 (to stop listening for unicast
 * replies once REBINDING starts) and on every re-initialisation. */
void dhcp_client_disable_io(DhcpClient *client);

/* The epoll callback for the receive socket, exposed only so dhcp-client.c
 * can hand it to netd_loop_add_io(); nothing else should call it. */
int dhcp_client_io_callback(Netd *netd, struct netd_epoll_tag *tag, uint32_t revents);

/* Stop the client because of `error` (a negative errno), notifying the link
 * layer. Exported for dhcp-client-send.c's receive path. */
void dhcp_client_fail(DhcpClient *client, int error);

/* Called by dhcp_client_io_callback() with one received DHCP payload (the
 * UDP body, already stripped of any IP/UDP headers by the raw path).
 * Implemented in dhcp-client.c because it is state-machine work, not socket
 * work. Returns 0, or -errno for a failure that should stop the client. */
int dhcp_client_handle_message(DhcpClient *client, const struct iovec *payload);

/* --- small helpers the two .c files share --- */

/* Functions rather than upstream's MIN/MAX/CLAMP macros so nothing is
 * evaluated twice. */
static inline usec_t usec_min(usec_t a, usec_t b) {
        return a < b ? a : b;
}

static inline usec_t usec_max(usec_t a, usec_t b) {
        return a > b ? a : b;
}

static inline usec_t usec_clamp(usec_t v, usec_t low, usec_t high) {
        return v < low ? low : (v > high ? high : v);
}

/*
 * RFC 2131's 'secs' field: seconds since the client began the current
 * acquisition or renewal, rounded *up* (upstream's DIV_ROUND_UP), saturated
 * at UINT16_MAX - 1. Rounding up is what keeps a sub-second elapsed time
 * from being reported as zero.
 */
static inline be16_t usec_to_be16_sec(usec_t t) {
        if (t == USEC_INFINITY)
                return (be16_t) htobe16(UINT16_MAX);

        if (t >= (usec_t) (UINT16_MAX - 1) * USEC_PER_SEC)
                return (be16_t) htobe16(UINT16_MAX - 1);

        return (be16_t) htobe16((uint16_t) ((t + USEC_PER_SEC - 1) / USEC_PER_SEC));
}
