/* SPDX-FileCopyrightText: 2013 Intel Corporation */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported from systemd v261.2 src/libsystemd-network/sd-dhcp-client.c, whose
 * Intel copyright line is carried above.
 *
 * The DHCPv4 client state machine: INIT -> SELECTING -> REQUESTING -> BOUND,
 * with RENEWING/REBINDING off T1/T2, expiry, INIT-REBOOT, DECLINE and NAK.
 *
 * Upstream's sd_event plumbing is re-derived against src/timer.c's shared
 * deadline queue. Each rewritten function keeps a comment naming the RFC
 * 2131 requirement the original encoded:
 *
 *   client_timeout_resend()      §4.1 backoff, §3.1.5 restart, §4.4.5 halving
 *   client_timeout_t1()          §4.4.5 BOUND -> RENEWING, unicast
 *   client_timeout_t2()          §4.4.5 RENEWING -> REBINDING, broadcast
 *   client_timeout_expire()      §4.4.5 lease end -> INIT
 *   client_set_lease_timeouts()  §4.4.5 T1/T2 fuzz, derived from lease times
 *   client_enter_requesting()    §3.1/4.3.2 OFFER accepted, REQUEST armed
 *   client_enter_bound()         §4.4.5 timers rebuilt from the new lease
 *   client_start_delayed()       §4.1 new xid + 'secs' base per cycle
 *   client_restart()             §3.1.5 revert to INIT after NAK/no reply
 *
 * Timer handles: src/timer.h stores the address of the handle slot and NULLs
 * it when the event fires or is cancelled, so a non-NULL handle means a live
 * event. Every arm passes &client->timeout_*, never a local.
 * client_disable_timers() cancels whatever may be armed, and
 * dhcp_client_free() calls it first, because the queue would otherwise write
 * a NULL into freed memory when a still-queued event fired.
 *
 * DHCP_CLIENT_DONT_DESTROY is taken where upstream takes it, and every
 * client_notify() that is not the last statement of its function is followed
 * by `if (client->state == DHCP_STATE_STOPPED) return ...`. Lease
 * application is a direct call into netd-link.c and SIGHUP reconfigures
 * every interface, so a reconfigure reached from inside a lease callback
 * would free this object while the callback's frame is still running.
 * Timer callbacks return void here, so where upstream propagated an error
 * into the event loop, these stop the client and return.
 *
 * Divergences from upstream (each argued at its call site):
 *  - The 'secs' field is re-based when a renewal begins, not only when an
 *    acquisition does. See client_timeout_t1().
 *  - DHCPDECLINE restarts after RFC 2131 §3.1.5's ten-second minimum rather
 *    than upstream's one second. See dhcp_client_send_decline().
 *  - A missing or unreadable /etc/machine-id falls back to DUID-LL instead
 *    of failing the start. See client_ensure_client_id().
 * The clock, IAID and cut-feature divergences are in dhcp-client-internal.h.
 */

#include "dhcp-client-internal.h"

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <sys/random.h>

#include "dns-name.h"

/* RFC 791: the smallest MTU every IPv4 host must handle. */
#define IPV4_MIN_MTU 68

/* Linux TC_PRIO_CONTROL (<linux/pkt_sched.h>): what upstream's
 * tos_to_priority() yields for IPTOS_CLASS_CS6, the class DHCP uses. */
#define NETD_TC_PRIO_CONTROL 7

/*
 * RFC 2131 3.1.5: after a DHCPNAK, or after exhausting the retransmission
 * budget, the client reverts to INIT. Upstream backs that restart off
 * exponentially between one second and thirty minutes so a permanently
 * hostile or absent server does not turn into a broadcast storm.
 */
#define RESTART_AFTER_NAK_MIN_USEC (1 * USEC_PER_SEC)
#define RESTART_AFTER_NAK_MAX_USEC (30 * USEC_PER_MINUTE)

/*
 * RFC 2131 3.1.5: "The client SHOULD wait a minimum of ten seconds before
 * restarting the configuration process to avoid excessive network traffic in
 * case of looping." See dhcp_client_send_decline() for why netd honours this
 * where upstream does not.
 */
#define RESTART_AFTER_DECLINE_USEC (10 * USEC_PER_SEC)

/* Not RFC-specified. Upstream's own choice: two REQUEST attempts in
 * REBOOTING before falling back to a full DISCOVER cycle, so a board that
 * moved networks does not spend the whole request budget asking for an
 * address that is no longer valid. */
#define MAX_REQUEST_ATTEMPTS_ON_REBOOTING 2
#define MAX_REQUEST_ATTEMPTS 5

/* Arbitrary, and upstream's: how many DISCOVERs go unanswered before the
 * link layer is told to consider a fallback. */
#define TRANSIENT_FAILURE_ATTEMPTS 3

/*
 * Default parameter request list: upstream's five (1, 3, 6, 12, 15) plus 42
 * (NTP servers) and 101 (TZDB timezone name).
 *
 * Not option 100 (POSIX timezone string): upstream never parses it, only 101
 * is implemented in the lease object.
 *
 * The NetdU8Set bitmap emits options in ascending numeric order regardless
 * of insertion order, which makes the wire bytes reproducible.
 */
static const uint8_t default_req_opts[] = {
        SD_DHCP_OPTION_SUBNET_MASK,        /* 1 */
        SD_DHCP_OPTION_ROUTER,             /* 3 */
        SD_DHCP_OPTION_DOMAIN_NAME_SERVER, /* 6 */
        SD_DHCP_OPTION_HOST_NAME,          /* 12 */
        SD_DHCP_OPTION_DOMAIN_NAME,        /* 15 */
        SD_DHCP_OPTION_NTP_SERVER,         /* 42 */
        SD_DHCP_OPTION_TZDB_TIMEZONE,      /* 101 */
};

static void client_stop(DhcpClient *client, int error);
static int client_restart_full(DhcpClient *client, usec_t min_delay);
static int client_restart(DhcpClient *client);
static void client_timeout_resend(void *userdata, usec_t now_usec);

/* --- logging --- */

void dhcp_client_log(DhcpClient *client, PicoLogLevel level, const char *fmt, ...) {
        char buf[512];
        va_list ap;

        va_start(ap, fmt);
        (void) vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);

        pico_log(level, "netd: %s: DHCPv4 client: %s", client && client->ifname[0] ? client->ifname : "-", buf);
}

/* --- randomness --- */

/* The fallback is reached only when getrandom() fails. A predictable or
 * per-interface-identical xid lets an off-path attacker forge replies; the
 * clock/stack-address/pid mix is weak but neither constant nor zero. */
static uint64_t client_random_u64(void) {
        uint64_t v = 0;

        if (getrandom(&v, sizeof(v), 0) == (ssize_t) sizeof(v))
                return v;

        v = (uint64_t) now_monotonic();
        v ^= (uint64_t) (uintptr_t) &v << 16;
        v ^= (uint64_t) getpid() << 40;
        return v;
}

static uint32_t client_random_u32(void) {
        return (uint32_t) (client_random_u64() & UINT32_MAX);
}

/* RFC 2131 4.1: "retransmission delays should include -1 to +1 sec of random
 * 'fuzz'". Subtracted from the computed timeout (upstream's sign convention). */
static int64_t client_random_fuzz(void) {
        return (int64_t) (client_random_u64() % (2 * USEC_PER_SEC)) - (int64_t) USEC_PER_SEC;
}

/* --- timer-queue plumbing --- */

static void client_timer_disarm(DhcpClient *client, PicoTimerEvent **slot) {
        assert(client);
        assert(slot);

        /* src/timer.h: the slot is NULL exactly when no event exists, so no
         * "was it armed?" bookkeeping is needed beyond this test. */
        if (*slot)
                (void) pico_timer_cancel(client->netd->timer, *slot);
}

static int client_timer_arm(DhcpClient *client, PicoTimerEvent **slot, usec_t deadline, pico_timer_callback_t cb) {
        assert(client);
        assert(slot);
        assert(cb);

        client_timer_disarm(client, slot);

        /* pico_timer_add() refuses USEC_INFINITY; callers have already
         * handled the infinite-lease case. */
        return pico_timer_add(client->netd->timer, deadline, cb, client, slot);
}

static void client_disable_timers(DhcpClient *client) {
        assert(client);

        client_timer_disarm(client, &client->timeout_resend);
        client_timer_disarm(client, &client->timeout_t1);
        client_timer_disarm(client, &client->timeout_t2);
        client_timer_disarm(client, &client->timeout_expire);
}

/* Upstream's client_disable_event_sources(): the receive socket and all four
 * timeouts, dropped together. */
static void client_disable_event_sources(DhcpClient *client) {
        assert(client);

        dhcp_client_disable_io(client);
        client_disable_timers(client);
}

/* --- state --- */

static void client_set_state(DhcpClient *client, DHCPState state) {
        assert(client);

        if (client->state == state)
                return;

        log_client_debug(
                        client,
                        "state changed: %s -> %s",
                        dhcp_state_to_string(client->state),
                        dhcp_state_to_string(state));

        client->state = state;

        switch (state) {
        case DHCP_STATE_STOPPED:
        case DHCP_STATE_BOUND:
                /* The next DHCPDISCOVER starts a new cycle: RFC 2131 4.1's
                 * backoff schedule is per-cycle, so the counter it indexes
                 * has to be cleared here and not when the DISCOVER is sent. */
                client->discover_attempt = 0;
                break;

        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
                /* Likewise for DHCPREQUEST: entering one of these states
                 * means the next REQUEST is the first of a new exchange. */
                client->request_attempt = 0;
                break;

        default:
                /* INIT/SELECTING/INIT_REBOOT keep the counters: INIT -> SELECTING
                 * and INIT_REBOOT -> REBOOTING continue one retransmission
                 * sequence. */
                break;
        }

        /* Upstream also invokes a state_callback here, which networkd uses to
         * coordinate its DHCPv4 and DHCPv6 clients. netd has no DHCPv6 client
         * and the hook can re-enter the state machine, so it is not carried. */
}

static int client_notify(DhcpClient *client, int event) {
        assert(client);

        if (client->callback)
                return client->callback(client, event, client->userdata);

        return 0;
}

static void client_set_lease(DhcpClient *client, DhcpLease *lease) {
        assert(client);

        if (client->lease == lease)
                return;

        (void) dhcp_lease_ref(lease);
        dhcp_lease_unref(client->lease);
        client->lease = lease;
}

static void client_initialize(DhcpClient *client) {
        assert(client);

        client_disable_event_sources(client);

        client_set_state(client, DHCP_STATE_STOPPED);
        client->xid = 0;

        client_set_lease(client, NULL);
}

static void client_stop(DhcpClient *client, int error) {
        assert(client);
        DHCP_CLIENT_DONT_DESTROY(client);

        if (dhcp_client_is_running(client)) {
                if (error < 0)
                        log_client_error(client, "stopped: %s", strerror(-error));
                else if (error == DHCP_CLIENT_EVENT_STOP)
                        log_client_debug(client, "stopped");
                else
                        log_client_warning(client, "stopped on unknown event %d", error);

                (void) client_notify(client, error);
        } else if (error < 0) {
                log_client_error(client, "failed: %s", strerror(-error));
                (void) client_notify(client, error);
        }

        /* No state re-check after these notifies: client_initialize() drives
         * the client to STOPPED unconditionally. DONT_DESTROY keeps it valid
         * if the callback unreffed us. */
        client_initialize(client);
}

void dhcp_client_fail(DhcpClient *client, int error) {
        assert(client);

        client_stop(client, error);
}

/* --- RFC 2131 timing arithmetic --- */

/*
 * RFC 2131 4.1: "the client... SHOULD wait... 4 seconds... the delay before
 * the next retransmission SHOULD be 8 seconds... doubled... with a maximum
 * of 64 seconds", each randomised by -1..+1 seconds.
 *
 * Called with attempt >= 1, so the shift is 2, 3, 4, 5, 6, 6, ... giving
 * 4, 8, 16, 32, 64, 64 seconds. The clamp is on the exponent, not on the
 * product, which is what keeps the doubling from overflowing on a client
 * that is left retrying for a long time.
 */
static usec_t client_compute_request_timeout(uint64_t attempt) {
        unsigned shift = attempt + 1 < 6 ? (unsigned) (attempt + 1) : 6;
        usec_t timeout = ((usec_t) 1 << shift) * USEC_PER_SEC;

        return usec_sub_signed(timeout, client_random_fuzz());
}

/*
 * RFC 2131 4.4.5: in RENEWING the client "SHOULD wait one-half of the
 * remaining time until T2... down to a minimum of 60 seconds" before
 * retransmitting; in REBINDING, one-half of the remaining lease time on the
 * same floor.
 *
 * No fuzz: §4.4.5 asks for it on the initial T1/T2 values
 * (client_set_lease_timeouts() adds it), not on the retries.
 */
static usec_t client_compute_reacquisition_timeout(usec_t now_usec, usec_t expire) {
        return usec_max(usec_sub_unsigned(expire, now_usec) / 2, 60 * USEC_PER_SEC);
}

/* --- the resend timer: RFC 2131 4.1 backoff, 3.1.5 restart, 4.4.5 halving --- */

/*
 * Decides the next interval, reschedules itself, then transmits. The timer
 * is re-armed *before* the send, so a failed send (e.g. a transient
 * ENETDOWN) still leaves a retransmission scheduled.
 *
 * A pico_timer callback returns void, so the error paths call
 * client_stop()/client_restart() directly. DONT_DESTROY covers both, since
 * client_stop() notifies.
 */
static void client_timeout_resend(void *userdata, usec_t now_usec) {
        DhcpClient *client = ASSERT_PTR(userdata);
        DHCP_CLIENT_DONT_DESTROY(client);
        usec_t next_timeout;
        int r;

        switch (client->state) {

        case DHCP_STATE_RENEWING:
                /* RFC 2131 4.4.5: halve the time remaining to T2. */
                next_timeout = client_compute_reacquisition_timeout(now_usec, client->t2_time);
                break;

        case DHCP_STATE_REBINDING:
                /* RFC 2131 4.4.5: halve the time remaining to lease end. */
                next_timeout = client_compute_reacquisition_timeout(now_usec, client->expire_time);
                break;

        case DHCP_STATE_INIT:
                client_set_state(client, DHCP_STATE_SELECTING);
                _fallthrough_;

        case DHCP_STATE_SELECTING:
                if (client->discover_attempt >= client->max_discover_attempts) {
                        r = -ETIMEDOUT;
                        goto error;
                }

                client->discover_attempt++;
                next_timeout = client_compute_request_timeout(client->discover_attempt);
                break;

        case DHCP_STATE_INIT_REBOOT:
                client_set_state(client, DHCP_STATE_REBOOTING);
                _fallthrough_;

        case DHCP_STATE_REBOOTING:
                /* RFC 2131 4.4.2 (INIT-REBOOT) prescribes no retry interval
                 * of its own. Upstream reuses the §4.1 schedule at a quarter
                 * of the interval -- 1s then 2s -- so a board that has *not*
                 * moved networks reconfirms fast, and one that has falls
                 * through to a full DISCOVER cycle after two tries. */
                if (client->request_attempt >= MAX_REQUEST_ATTEMPTS_ON_REBOOTING)
                        goto restart;

                client->request_attempt++;
                next_timeout = client_compute_request_timeout(client->request_attempt) / 4;
                break;

        case DHCP_STATE_REQUESTING:
                if (client->request_attempt >= MAX_REQUEST_ATTEMPTS)
                        goto restart;

                client->request_attempt++;
                next_timeout = client_compute_request_timeout(client->request_attempt);
                break;

        default:
                /* Internal invariant: BOUND and STOPPED never have this timer
                 * armed, because every path into them disarms it first. Not
                 * reachable from packet input. */
                assert(false);
                return;
        }

        /* Re-arm first, transmit second -- see this function's comment. */
        r = client_timer_arm(
                        client, &client->timeout_resend, usec_add(now_usec, next_timeout), client_timeout_resend);
        if (r < 0)
                goto error;

        switch (client->state) {
        case DHCP_STATE_SELECTING:
                r = dhcp_client_send_message(client, DHCP_DISCOVER);
                if (r < 0 && client->discover_attempt >= client->max_discover_attempts)
                        goto error;

                if (client->discover_attempt >= TRANSIENT_FAILURE_ATTEMPTS) {
                        (void) client_notify(client, DHCP_CLIENT_EVENT_TRANSIENT_FAILURE);

                        /* The link layer may have given up and stopped us. */
                        if (client->state == DHCP_STATE_STOPPED)
                                return;
                }
                break;

        case DHCP_STATE_REBOOTING:
                r = dhcp_client_send_message(client, DHCP_REQUEST);
                if (r < 0 && client->request_attempt >= MAX_REQUEST_ATTEMPTS_ON_REBOOTING)
                        goto restart;
                break;

        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
                r = dhcp_client_send_message(client, DHCP_REQUEST);
                if (r < 0 && client->request_attempt >= MAX_REQUEST_ATTEMPTS)
                        goto restart;
                break;

        default:
                assert(false);
                return;
        }

        return;

restart:
        /* RFC 2131 3.1.5: "if the client receives neither a DHCPACK nor a
         * DHCPNAK message after employing the retransmission algorithm, the
         * client reverts to INIT state and restarts the initialization
         * process". Without this the REQUEST loop never terminates. */
        log_client_debug(client, "maximum REQUEST attempts reached, restarting");
        r = client_restart(client);
        if (r >= 0)
                return;

        /* Keep client_restart()'s own error: the link layer reacts
         * differently to "could not open a socket" and "timed out". */

error:
        client_stop(client, r);
}

/* --- starting, restarting --- */

/* Upstream's client_initialize_time_events(): arm the resend timer at
 * start_delay from now. Everything else about a start is state, not time. */
static int client_arm_start_timer(DhcpClient *client) {
        assert(client);

        return client_timer_arm(
                        client,
                        &client->timeout_resend,
                        usec_add(now_monotonic(), client->start_delay),
                        client_timeout_resend);
}

static int client_start_delayed(DhcpClient *client) {
        assert(client);
        DHCP_CLIENT_DONT_DESTROY(client);

        client_disable_event_sources(client);
        client_set_lease(client, NULL);

        /*
         * RFC 2131 4.1: a new xid per acquisition cycle. This is also what
         * forces the receive socket to be reopened -- the AF_PACKET BPF
         * filter in dhcp-client-send.c matches on the xid, so a stale socket
         * would silently drop every reply. client_disable_event_sources()
         * above closed it; the next send opens a new one.
         */
        client->xid = client_random_u32();

        /* The base for the 'secs' header field: "seconds elapsed since the
         * client began the address acquisition process" (RFC 2131 §2). */
        client->start_time = now_monotonic();

        if (client->state != DHCP_STATE_INIT_REBOOT)
                client_set_state(client, DHCP_STATE_INIT);

        return client_arm_start_timer(client);
}

static int client_start(DhcpClient *client) {
        assert(client);

        client->start_delay = 0;
        return client_start_delayed(client);
}

/*
 * Called on DHCPNAK, on an exhausted retransmission budget, and after
 * DHCPDECLINE. `min_delay` is 0 for the first two (upstream's behaviour) and
 * RESTART_AFTER_DECLINE_USEC for the third.
 */
static int client_restart_full(DhcpClient *client, usec_t min_delay) {
        assert(client);
        DHCP_CLIENT_DONT_DESTROY(client);

        /* If a lease was in force, the link layer has to tear it down before
         * anything else happens: from here on the address is not ours. */
        if (IN_SET(client->state, DHCP_STATE_BOUND, DHCP_STATE_RENEWING, DHCP_STATE_REBINDING)) {
                (void) client_notify(client, DHCP_CLIENT_EVENT_EXPIRED);

                /* The notify callback may have stopped the client -- and in
                 * netd it may have gone further and reconfigured the whole
                 * link. Re-check before touching anything. */
                if (client->state == DHCP_STATE_STOPPED)
                        return 0;
        }

        /* RFC 2131 4.4.2: in REBOOTING a NAK or a silent server means the
         * remembered address is simply not valid here. There is nothing to
         * back off from, so restart immediately. Skipped when a minimum
         * delay was demanded, which is the DECLINE case. */
        if (client->state == DHCP_STATE_REBOOTING && min_delay == 0)
                return client_start(client);

        client->start_delay = usec_clamp(
                        client->start_delay * 2, RESTART_AFTER_NAK_MIN_USEC, RESTART_AFTER_NAK_MAX_USEC);
        client->start_delay = usec_max(client->start_delay, min_delay);

        log_client_debug(client, "restarting in %" PRIu64 "s", (uint64_t) (client->start_delay / USEC_PER_SEC));
        return client_start_delayed(client);
}

static int client_restart(DhcpClient *client) {
        return client_restart_full(client, 0);
}

/* --- lease lifetime timers: RFC 2131 4.4.5 --- */

static void client_timeout_expire(void *userdata, usec_t now_usec) {
        DhcpClient *client = ASSERT_PTR(userdata);
        DHCP_CLIENT_DONT_DESTROY(client);
        int r;

        (void) now_usec;

        /* RFC 2131 4.4.5: "If the lease expires before the client receives a
         * DHCPACK, the client... MUST immediately stop any other network
         * processing and request network initialization parameters as if the
         * client were uninitialized." */
        log_client_info(client, "lease expired");

        (void) client_notify(client, DHCP_CLIENT_EVENT_EXPIRED);

        if (client->state == DHCP_STATE_STOPPED)
                return; /* the notify callback stopped the client */

        r = client_start(client);
        if (r < 0)
                client_stop(client, r);
}

static void client_timeout_t2(void *userdata, usec_t now_usec) {
        DhcpClient *client = ASSERT_PTR(userdata);
        DHCP_CLIENT_DONT_DESTROY(client);

        /* RFC 2131 4.4.5: at T2 the client "enters the REBINDING state and
         * sends a DHCPREQUEST message... to the 0xffffffff IP broadcast
         * address". The unicast socket is bound to the leased address and
         * connected to one server, so it is dropped here. */
        dhcp_client_disable_io(client);

        client_set_state(client, DHCP_STATE_REBINDING);

        client_timeout_resend(client, now_usec);
}

static void client_timeout_t1(void *userdata, usec_t now_usec) {
        DhcpClient *client = ASSERT_PTR(userdata);
        DHCP_CLIENT_DONT_DESTROY(client);

        /* RFC 2131 4.4.5: at T1 the client "moves to RENEWING state and
         * sends... a DHCPREQUEST message to the server currently serving the
         * lease", unicast. The unicast is dhcp_client_send_message()'s job;
         * the state is this function's. */
        client_set_state(client, DHCP_STATE_RENEWING);

        /* Divergence from upstream, toward the RFC: RFC 2131 §2 defines 'secs'
         * as "seconds elapsed since client began address acquisition *or
         * renewal* process". Upstream sets start_time only in
         * client_start_delayed(), so a renewal reports the time since the
         * original DISCOVER (saturating at 65534 on long leases). Not
         * re-based again at T2: REBINDING continues the same renewal. */
        client->start_time = now_monotonic();

        client_timeout_resend(client, now_usec);
}

/*
 * Rebuild T1, T2 and expiry from the lease. All three deadlines derive from
 * the moment the lease was acquired (the lease object stamps itself at parse
 * time, dhcp-lease-internal.h), not from "now", so a lease whose ACK sat in
 * a socket buffer still expires when the server thinks it does.
 */
static int client_set_lease_timeouts(DhcpClient *client) {
        usec_t now_usec;
        int r;

        assert(client);
        assert(client->lease);

        /* RFC 2131 3.3: a lease of 0xffffffff seconds is infinite: never
         * renewed, never expires, so nothing is armed. */
        if (client->lease->lifetime == USEC_INFINITY) {
                client_timer_disarm(client, &client->timeout_t1);
                client_timer_disarm(client, &client->timeout_t2);
                client_timer_disarm(client, &client->timeout_expire);
                return 0;
        }

        now_usec = now_monotonic();

        r = dhcp_lease_get_lifetime_timestamp(client->lease, &client->expire_time);
        if (r < 0)
                return r;
        r = dhcp_lease_get_t1_timestamp(client->lease, &client->t1_time);
        if (r < 0)
                return r;
        r = dhcp_lease_get_t2_timestamp(client->lease, &client->t2_time);
        if (r < 0)
                return r;

        /* RFC 2131 4.4.5: "Times T1 and T2 SHOULD be chosen with some random
         * 'fuzz' around a fixed value, to avoid synchronization of client
         * reacquisition." The RFC gives no amount; like upstream, use §4.1's
         * -1..+1 second. */
        client->t1_time = usec_sub_signed(client->t1_time, client_random_fuzz());
        client->t2_time = usec_sub_signed(client->t2_time, client_random_fuzz());

        /* Fuzz is applied independently to each, so it can invert them.
         * T2 < T1 would mean REBINDING before RENEWING. */
        client->t2_time = usec_max(client->t1_time, client->t2_time);

        r = client_timer_arm(client, &client->timeout_expire, client->expire_time, client_timeout_expire);
        if (r < 0)
                return r;

        /* A deadline already in the past is armed anyway (pico_timer fires it
         * on the next dispatch), but an earlier deadline that has also passed
         * is skipped, so a long-expired lease does not run through RENEWING
         * and REBINDING first. */
        if (client->expire_time <= now_usec)
                return 0;

        log_client_debug(
                        client,
                        "lease expires in %" PRIu64 "s",
                        (uint64_t) ((client->expire_time - now_usec) / USEC_PER_SEC));

        r = client_timer_arm(client, &client->timeout_t2, client->t2_time, client_timeout_t2);
        if (r < 0)
                return r;

        if (client->t2_time <= now_usec)
                return 0;

        log_client_debug(
                        client,
                        "T2 expires in %" PRIu64 "s",
                        (uint64_t) ((client->t2_time - now_usec) / USEC_PER_SEC));

        r = client_timer_arm(client, &client->timeout_t1, client->t1_time, client_timeout_t1);
        if (r < 0)
                return r;

        if (client->t1_time > now_usec)
                log_client_debug(
                                client,
                                "T1 expires in %" PRIu64 "s",
                                (uint64_t) ((client->t1_time - now_usec) / USEC_PER_SEC));

        return 0;
}

/* --- state entry --- */

/*
 * RFC 2131 3.1/4.3.2: an OFFER has been accepted, so the client moves to
 * REQUESTING and sends a DHCPREQUEST naming the chosen server.
 *
 * The resend timer is armed to fire on the next dispatch rather than
 * sending from here, so the REQUEST and all its retries come from
 * client_timeout_resend() and the retransmission counting has one
 * implementation. (Upstream also delays this by the IPv6-Only Preferred
 * interval, RFC 8925; not carried, see dhcp-client-internal.h.)
 */
static int client_enter_requesting(DhcpClient *client) {
        assert(client);
        assert(client->lease);

        client_disable_event_sources(client);

        client_set_state(client, DHCP_STATE_REQUESTING);

        return client_timer_arm(client, &client->timeout_resend, now_monotonic(), client_timeout_resend);
}

/* Whether two leases describe the same IPv4 configuration, so the link layer
 * can be told "renewed" rather than "changed" and skip re-plumbing the
 * kernel. Address, mask and router list are the fields netd-link.c actually
 * puts into the kernel; upstream compares the same three. */
static bool lease_equal(const DhcpLease *a, const DhcpLease *b) {
        assert(a);
        assert(b);

        if (a->address != b->address)
                return false;

        if (a->subnet_mask != b->subnet_mask)
                return false;

        if (a->router_size != b->router_size)
                return false;

        for (size_t i = 0; i < a->router_size; i++)
                if (a->router[i].s_addr != b->router[i].s_addr)
                        return false;

        return true;
}

static int client_enter_bound(DhcpClient *client, DhcpLease *lease) {
        int notify_event;
        int r;

        assert(client);
        assert(lease);

        /* Which event this is depends on where we came from, so it has to be
         * decided before client->lease is replaced. */
        switch (client->state) {
        case DHCP_STATE_SELECTING:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_REBOOTING:
                notify_event = DHCP_CLIENT_EVENT_IP_ACQUIRE;
                break;

        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
                assert(client->lease);
                notify_event = lease_equal(client->lease, lease) ? DHCP_CLIENT_EVENT_RENEW :
                                                                   DHCP_CLIENT_EVENT_IP_CHANGE;
                break;

        default:
                /* Internal invariant: client_parse_ack() has already refused
                 * an ACK in any other state, so packet input cannot reach
                 * this. */
                assert(false);
                return -EINVAL;
        }

        client_set_lease(client, lease);

        /* Everything armed for the previous lease is now wrong: the resend
         * timer, the old T1/T2/expiry, and the socket the exchange used. */
        client_disable_event_sources(client);

        /* A successful acquisition resets the restart backoff, so a network
         * that flaps does not accumulate a thirty-minute penalty. */
        client->start_delay = 0;

        client_set_state(client, DHCP_STATE_BOUND);

        /* RFC 2131 4.4.2: the address to ask for by name on the next
         * INIT-REBOOT. Also what netd-link.c writes to
         * /run/netd/leases/<ifindex> so a netd restart can reboot into it. */
        client->last_addr = client->lease->address;

        r = client_set_lease_timeouts(client);
        if (r < 0) {
                log_client_error(client, "failed to set lease timeouts: %s", strerror(-r));
                return r;
        }

        (void) client_notify(client, notify_event);
        return 0;
}

/* --- receiving: message-type dispatch and state validation --- */

/*
 * The half of upstream's dhcp_client_parse_message() that cannot live in the
 * lease object (which takes a DhcpLeaseParseParams, not the client): message
 * type dispatch and every "is this message legal in this state?" test. The
 * option decoding is the codec's.
 *
 * Returns the DHCP message type, or a negative errno. These are packet-input
 * checks, so they return -EBADMSG and never assert.
 */

static int client_parse_bootreply(DhcpClient *client, DhcpMessage *message, DhcpLease **ret) {
        DhcpLeaseParseParams params = {
                .bootp = true,
                .fallback_lease_lifetime = client->fallback_lease_lifetime,
        };
        _cleanup_(dhcp_lease_unrefp) DhcpLease *lease = NULL;
        int r;

        assert(client);
        assert(message);
        assert(ret);

        /* Plain BOOTP has no message type, so state is the only thing that
         * makes a reply expected. */
        if (client->state != DHCP_STATE_SELECTING) {
                log_client_debug(
                                client,
                                "unexpected BOOTREPLY in state %s, ignoring",
                                dhcp_state_to_string(client->state));
                return -EBADMSG;
        }

        r = dhcp_lease_new_from_message(&params, message, &lease);
        if (r < 0) {
                log_client_debug(client, "failed to create BOOTP lease: %s", strerror(-r));
                return r;
        }

        *ret = TAKE_PTR(lease);
        return DHCP_ACK;
}

static int client_parse_ack(DhcpClient *client, DhcpMessage *message, DhcpLease **ret) {
        DhcpLeaseParseParams params = {
                .bootp = false,
                .fallback_lease_lifetime = client->fallback_lease_lifetime,
        };
        _cleanup_(dhcp_lease_unrefp) DhcpLease *lease = NULL;
        int r;

        assert(client);
        assert(message);
        assert(ret);

        switch (client->state) {
        case DHCP_STATE_SELECTING:
                /* RFC 4039: an ACK straight after DISCOVER is only legal when
                 * we asked for Rapid Commit and the server echoed option 80;
                 * otherwise the REQUEST leg could be skipped at will. */
                if (!client->rapid_commit) {
                        log_client_debug(client, "unexpected DHCPACK in SELECTING, ignoring");
                        return -EBADMSG;
                }

                r = dhcp_message_get_option_flag(message, SD_DHCP_OPTION_RAPID_COMMIT);
                if (r < 0) {
                        log_client_debug(client, "DHCPACK in SELECTING without Rapid Commit option, ignoring");
                        return -EBADMSG;
                }
                break;

        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
                break;

        default:
                log_client_debug(
                                client,
                                "unexpected DHCPACK in state %s, ignoring",
                                dhcp_state_to_string(client->state));
                return -EBADMSG;
        }

        r = dhcp_lease_new_from_message(&params, message, &lease);
        if (r < 0) {
                log_client_debug(client, "failed to create lease from DHCPACK: %s", strerror(-r));
                return r;
        }

        *ret = TAKE_PTR(lease);
        return DHCP_ACK;
}

static int client_parse_offer(DhcpClient *client, DhcpMessage *message, DhcpLease **ret) {
        DhcpLeaseParseParams params = {
                .bootp = false,
                .fallback_lease_lifetime = client->fallback_lease_lifetime,
        };
        _cleanup_(dhcp_lease_unrefp) DhcpLease *lease = NULL;
        int r;

        assert(client);
        assert(message);
        assert(ret);

        /* RFC 2131 4.4.1: an OFFER is only meaningful while we are collecting
         * them. One arriving in REQUESTING or BOUND is a late duplicate at
         * best. */
        if (client->state != DHCP_STATE_SELECTING) {
                log_client_debug(
                                client,
                                "unexpected DHCPOFFER in state %s, ignoring",
                                dhcp_state_to_string(client->state));
                return -EBADMSG;
        }

        r = dhcp_lease_new_from_message(&params, message, &lease);
        if (r < 0) {
                log_client_debug(client, "failed to create lease from DHCPOFFER: %s", strerror(-r));
                return r;
        }

        *ret = TAKE_PTR(lease);
        return DHCP_OFFER;
}

static int client_parse_nak(DhcpClient *client, DhcpMessage *message, DhcpLease **ret) {
        struct in_addr a;
        char *e = NULL;
        int r;

        assert(client);
        assert(message);
        assert(ret);

        /* RFC 2131 4.4.5/3.1: a NAK answers a REQUEST. One arriving after a
         * DISCOVER, or when we sent nothing at all, is not ours. */
        if (!IN_SET(client->state,
                    DHCP_STATE_REBOOTING,
                    DHCP_STATE_REQUESTING,
                    DHCP_STATE_RENEWING,
                    DHCP_STATE_REBINDING)) {
                log_client_debug(
                                client,
                                "unexpected DHCPNAK in state %s, ignoring",
                                dhcp_state_to_string(client->state));
                return -EBADMSG;
        }

        /* Defence against a forged NAK, which would tear down a working lease:
         * refuse a NAK with no Server Identifier, or with one that is not the
         * server holding our lease. */
        r = dhcp_message_get_option_address(message, SD_DHCP_OPTION_SERVER_IDENTIFIER, &a);
        if (r < 0) {
                log_client_debug(client, "DHCPNAK without Server Identifier option, ignoring");
                return -EBADMSG;
        }

        if (client->lease && client->lease->server_address != a.s_addr) {
                log_client_debug(client, "DHCPNAK from unexpected server %s, ignoring", IN4_ADDR_TO_STRING(&a));
                return -EBADMSG;
        }

        (void) dhcp_message_get_option_string(message, SD_DHCP_OPTION_ERROR_MESSAGE, &e);
        log_client_info(client, "received DHCPNAK: %s", e ? e : "no message");
        free(e);

        *ret = NULL;
        return DHCP_NAK;
}

static int client_parse_message(DhcpClient *client, const struct iovec *iov, DhcpLease **ret) {
        _cleanup_(dhcp_message_unrefp) DhcpMessage *message = NULL;
        uint8_t type;
        int r;

        assert(client);
        assert(iov);
        assert(ret);

        /* The codec's correlation checks: op == BOOTREPLY, xid matches ours,
         * hardware type and chaddr match this interface. The AF_PACKET BPF
         * filter tests the same fields, but the UDP path has no filter. */
        r = dhcp_message_parse(iov, BOOTREPLY, &client->xid, client->arp_type, &client->hw_addr, &message);
        if (r < 0)
                return r;

        if (client->bootp)
                return client_parse_bootreply(client, message, ret);

        r = dhcp_message_get_option_u8(message, SD_DHCP_OPTION_MESSAGE_TYPE, &type);
        if (r < 0) {
                log_client_debug(client, "no Message Type option, ignoring");
                return -EBADMSG;
        }

        switch (type) {
        case DHCP_OFFER:
                return client_parse_offer(client, message, ret);
        case DHCP_ACK:
                return client_parse_ack(client, message, ret);
        case DHCP_NAK:
                return client_parse_nak(client, message, ret);
        default:
                log_client_debug(client, "message of unexpected type %u, ignoring", type);
                return -EBADMSG;
        }
}

int dhcp_client_handle_message(DhcpClient *client, const struct iovec *payload) {
        DHCP_CLIENT_DONT_DESTROY(client);
        _cleanup_(dhcp_lease_unrefp) DhcpLease *lease = NULL;
        int r;

        assert(client);
        assert(payload);

        r = client_parse_message(client, payload, &lease);
        if (ERRNO_IS_NEG_RESOURCE(r))
                return r; /* out of memory or descriptors: a real failure */
        if (r < 0)
                return 0; /* every parse error is ignored, per RFC 2131 4.1 */

        switch (r) {

        case DHCP_OFFER:
                /* RFC 2131 4.4.1 leaves the offer selection policy to the client.
                 * Like networkd, the first acceptable offer wins, and the link
                 * layer can veto through the SELECTING callback (a negative
                 * return means "not this server"). */
                client_set_lease(client, lease);

                if (client_notify(client, DHCP_CLIENT_EVENT_SELECTING) < 0)
                        return 0; /* the link layer refused this server */

                if (client->state == DHCP_STATE_STOPPED)
                        return 0; /* the notify callback stopped the client */

                return client_enter_requesting(client);

        case DHCP_ACK:
                return client_enter_bound(client, lease);

        case DHCP_NAK:
                /* RFC 2131 4.4.5: "the client MUST... restart the
                 * initialization process". client_restart() notifies EXPIRED
                 * first if a lease was in force. */
                return client_restart(client);

        default:
                assert(false);
                return -EINVAL;
        }
}

/* --- configuration --- */

int dhcp_client_set_callback(DhcpClient *client, dhcp_client_callback_t cb, void *userdata) {
        assert_return(client, -EINVAL);

        client->callback = cb;
        client->userdata = userdata;
        return 0;
}

int dhcp_client_set_mac(
                DhcpClient *client,
                const uint8_t *hw_addr,
                const uint8_t *bcast_addr,
                size_t addr_len,
                uint16_t arp_type) {

        static const uint8_t default_eth_hwaddr[ETH_ALEN] = { 0 };

        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        switch (arp_type) {
        case ARPHRD_ETHER:
                assert_return(addr_len == ETH_ALEN, -EINVAL);
                assert_return(hw_addr, -EINVAL);
                break;

        case ARPHRD_INFINIBAND:
                /* HW_ADDR_MAX_SIZE (dhcp-protocol.h) excludes infiniband. */
                return -EOPNOTSUPP;

        case ARPHRD_RAWIP:
        case ARPHRD_NONE:
                /* Cellular modem drivers (qmi_wwan and friends) present these
                 * in point-to-point mode. Neither is a valid DHCP hardware
                 * type, and upstream's conclusion after trying the
                 * alternatives is that pretending to be Ethernet is what
                 * actually interoperates with deployed servers. */
                arp_type = ARPHRD_ETHER;
                if (addr_len == 0) {
                        addr_len = ETH_ALEN;
                        hw_addr = default_eth_hwaddr;
                        bcast_addr = NULL;
                } else if (addr_len == ETH_ALEN) {
                        if (!hw_addr)
                                hw_addr = default_eth_hwaddr;
                } else {
                        assert_return(hw_addr, -EINVAL);
                        assert_return(bcast_addr, -EINVAL);
                }
                break;

        default:
                return -EINVAL;
        }

        if (addr_len > HW_ADDR_MAX_SIZE)
                return -EINVAL;

        client->arp_type = arp_type;

        client->hw_addr.length = addr_len;
        memcpy(client->hw_addr.bytes, hw_addr, addr_len);

        if (bcast_addr) {
                client->bcast_addr.length = addr_len;
                memcpy(client->bcast_addr.bytes, bcast_addr, addr_len);
        } else if (arp_type == ARPHRD_ETHER) {
                /* The all-ones link-layer broadcast: the raw path has no
                 * routing, so it needs a destination MAC and this is the only
                 * one a client without a lease can use. */
                client->bcast_addr.length = ETH_ALEN;
                memset(client->bcast_addr.bytes, 0xff, ETH_ALEN);
        } else
                return -EINVAL;

        return 0;
}

int dhcp_client_set_client_id(DhcpClient *client, uint8_t type, const uint8_t *data, size_t data_len) {
        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);
        assert_return(data, -EINVAL);

        return dhcp_client_id_set(&client->client_id, type, data, data_len);
}

int dhcp_client_get_client_id(DhcpClient *client, const DhcpClientId **ret) {
        assert_return(client, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!dhcp_client_id_is_set(&client->client_id))
                return -ENODATA;

        *ret = &client->client_id;
        return 0;
}

int dhcp_client_set_request_option(DhcpClient *client, uint8_t option) {
        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        /* These five are structural: 0 and 255 delimit the option area, 52
         * describes it, 53 and 55 are always emitted by the client itself.
         * Asking a server to send them back is meaningless. */
        switch (option) {
        case SD_DHCP_OPTION_PAD:
        case SD_DHCP_OPTION_OVERLOAD:
        case SD_DHCP_OPTION_MESSAGE_TYPE:
        case SD_DHCP_OPTION_PARAMETER_REQUEST_LIST:
        case SD_DHCP_OPTION_END:
                return -EINVAL;
        default:
                break;
        }

        return netd_u8set_put(&client->req_opts, option);
}

int dhcp_client_set_request_address(DhcpClient *client, const struct in_addr *last_addr) {
        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        client->last_addr = last_addr ? last_addr->s_addr : INADDR_ANY;
        return 0;
}

int dhcp_client_set_request_broadcast(DhcpClient *client, bool broadcast) {
        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        client->request_broadcast = broadcast;
        return 0;
}

int dhcp_client_set_hostname(DhcpClient *client, const char *hostname) {
        char *copy;

        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        /* Option 12 carries a single label here (FQDN, 81, is cut); catch
         * anything else now rather than on the first DISCOVER. */
        if (hostname && (dns_name_is_valid(hostname) <= 0 || !dns_name_is_single_label(hostname)))
                return -EINVAL;

        copy = hostname ? pico_strdup(hostname) : NULL;
        if (hostname && !copy)
                return -ENOMEM;

        free(client->hostname);
        client->hostname = copy;
        return 0;
}

int dhcp_client_set_vendor_class_identifier(DhcpClient *client, const char *vci) {
        char *copy;

        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        copy = vci ? pico_strdup(vci) : NULL;
        if (vci && !copy)
                return -ENOMEM;

        free(client->vendor_class_identifier);
        client->vendor_class_identifier = copy;
        return 0;
}

int dhcp_client_set_mtu(DhcpClient *client, uint32_t mtu) {
        assert_return(client, -EINVAL);

        /* Callable while running: an acquired lease may change the MTU. */
        if (mtu < IPV4_MIN_MTU)
                return -ERANGE;

        client->mtu = mtu;
        return 0;
}

int dhcp_client_set_max_attempts(DhcpClient *client, uint64_t max_attempts) {
        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        client->max_discover_attempts = max_attempts;
        return 0;
}

int dhcp_client_set_client_port(DhcpClient *client, uint16_t port) {
        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        client->port = port;
        return 0;
}

int dhcp_client_set_server_port(DhcpClient *client, uint16_t port) {
        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        client->server_port = port;
        return 0;
}

int dhcp_client_set_fallback_lease_lifetime(DhcpClient *client, usec_t fallback) {
        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);
        assert_return(fallback > 0, -EINVAL);

        client->fallback_lease_lifetime = fallback;
        return 0;
}

int dhcp_client_set_bootp(DhcpClient *client, bool bootp) {
        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        client->bootp = bootp;
        return 0;
}

int dhcp_client_set_send_release(DhcpClient *client, bool enable) {
        assert_return(client, -EINVAL);

        client->send_release = enable;
        return 0;
}

int dhcp_client_set_rapid_commit(DhcpClient *client, bool rapid_commit) {
        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        client->rapid_commit = rapid_commit;
        return 0;
}

int dhcp_client_set_ip_service_type(DhcpClient *client, uint8_t type) {
        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        client->ip_service_type = type;
        return 0;
}

int dhcp_client_set_socket_priority(DhcpClient *client, int priority) {
        assert_return(client, -EINVAL);
        assert_return(!dhcp_client_is_running(client), -EBUSY);

        client->socket_priority = priority;
        return 0;
}

/* --- identity --- */

/*
 * Upstream's sd_dhcp_client_start() builds an RFC 4361 client-id from a
 * DUID-EN derived from the machine ID and fails the start if /etc/machine-id
 * is absent or unreadable (read-only rootfs, first boot). Here the fallback
 * ladder is:
 *   1. DUID-EN over the machine ID (upstream's, and the stable choice);
 *   2. DUID-LL over the interface's own MAC (RFC 8415 11.4, intended for
 *      devices with a permanently attached interface and no stable storage);
 *   3. an RFC 2132 §9.14 hardware-type client-id.
 * Only a client with no hardware address can still fail, and
 * dhcp_client_set_mac() refuses that. The identifier presented on a board's
 * first boot therefore differs from later boots, so a server may offer a
 * different address once.
 */
static int client_ensure_client_id(DhcpClient *client) {
        DhcpDuid duid;
        uint32_t iaid;
        int r;

        assert(client);

        if (dhcp_client_id_is_set(&client->client_id))
                return 0;

        r = dhcp_duid_set_en(&duid);
        if (r < 0) {
                log_client_info(client,
                                "no usable machine ID (%s), falling back to a MAC-derived DUID-LL",
                                strerror(-r));

                r = dhcp_duid_set_ll(&duid, client->hw_addr.bytes, client->hw_addr.length, client->arp_type);
        }

        if (r >= 0) {
                r = dhcp_identifier_set_iaid(&client->hw_addr, /* legacy_unstable_byteorder= */ true, &iaid);
                if (r >= 0)
                        r = dhcp_client_id_set_iaid_duid(&client->client_id, be32toh(iaid), &duid);
        }

        if (r < 0) {
                log_client_warning(
                                client,
                                "could not build an RFC 4361 client identifier (%s), "
                                "using a plain hardware-type one",
                                strerror(-r));

                return dhcp_client_id_set(
                                &client->client_id,
                                (uint8_t) client->arp_type,
                                client->hw_addr.bytes,
                                client->hw_addr.length);
        }

        return 0;
}

/* --- running --- */

int dhcp_client_is_running(DhcpClient *client) {
        if (!client)
                return 0;

        return client->state != DHCP_STATE_STOPPED;
}

int dhcp_client_get_state(DhcpClient *client) {
        assert_return(client, -EINVAL);

        return client->state;
}

int dhcp_client_get_lease(DhcpClient *client, DhcpLease **ret) {
        assert_return(client, -EINVAL);

        if (!client->lease)
                return -EADDRNOTAVAIL;

        if (ret)
                *ret = client->lease;

        return 0;
}

int dhcp_client_start(DhcpClient *client) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(client->netd, -EINVAL);
        assert_return(client->ifindex > 0, -EINVAL);
        assert_return(client->hw_addr.length > 0, -EINVAL);
        assert_return(client->bcast_addr.length > 0, -EINVAL);

        r = client_ensure_client_id(client);
        if (r < 0)
                return r;

        /* RFC 2131 4.4.2 (INIT-REBOOT): a client that remembers its address
         * may skip DISCOVER and ask for it directly. netd-link.c supplies it
         * from /run/netd/leases/<ifindex>, so a netd restart reconfirms the
         * lease instead of renumbering. Not in BOOTP mode: no REQUEST. */
        if (client->last_addr != INADDR_ANY && !client->bootp)
                client_set_state(client, DHCP_STATE_INIT_REBOOT);

        /* Not implemented (nor upstream): RFC 2131 4.4.1's random one-to-ten
         * second wait to desynchronise DHCP at startup. */
        r = client_start(client);
        if (r >= 0)
                log_client_debug(client, "started on ifindex %i", client->ifindex);

        return r;
}

static int client_send_release(DhcpClient *client) {
        assert(client);

        if (!client->send_release)
                return 0;

        /* RFC 2131 4.4.6: DHCPRELEASE requires a lease to release and a
         * configured source address to send it from; BOOTP has no release. */
        if (!dhcp_client_is_running(client) || !client->lease || client->bootp)
                return 0;

        return dhcp_client_send_message(client, DHCP_RELEASE);
}

int dhcp_client_stop(DhcpClient *client) {
        if (!client)
                return 0;

        DHCP_CLIENT_DONT_DESTROY(client);

        (void) client_send_release(client);

        client_stop(client, DHCP_CLIENT_EVENT_STOP);
        return 0;
}

int dhcp_client_send_renew(DhcpClient *client) {
        assert_return(client, -EINVAL);

        /* Only meaningful from BOUND: RENEWING already has a resend timer
         * running, and BOOTP has no renewal. */
        if (!dhcp_client_is_running(client) || client->state != DHCP_STATE_BOUND || client->bootp)
                return 0;

        client_set_state(client, DHCP_STATE_RENEWING);

        /* Same re-basing as client_timeout_t1(): a forced renewal is the
         * start of a renewal process, so 'secs' counts from here. */
        client->start_time = now_monotonic();
        client->start_delay = 0;

        return client_arm_start_timer(client);
}

int dhcp_client_send_decline(DhcpClient *client) {
        int r;

        assert_return(client, -EINVAL);

        /* RFC 2131 4.4.4: DECLINE names the address being refused, so there
         * has to be a lease; BOOTP has no DECLINE. */
        if (!dhcp_client_is_running(client) || !client->lease || client->bootp)
                return 0;

        r = dhcp_client_send_message(client, DHCP_DECLINE);
        if (r < 0)
                return r;

        /* Divergence from upstream, toward the RFC. RFC 2131 3.1.5: "The
         * client SHOULD wait a minimum of ten seconds before restarting the
         * configuration process to avoid excessive network traffic in case of
         * looping." Upstream restarts through client_restart(), whose backoff
         * starts at one second; here the ten-second floor is passed
         * explicitly. There is no caller yet (no address-conflict detection). */
        return client_restart_full(client, RESTART_AFTER_DECLINE_USEC);
}

/* --- construction --- */

static DhcpClient *dhcp_client_free(DhcpClient *client) {
        if (!client)
                return NULL;

        /* The queue holds the address of each timeout_* field, so an event
         * still queued when this memory goes away would write a NULL into
         * freed storage. client_initialize() cancels all four and drops the
         * socket registration. */
        client_initialize(client);

        free(client->hostname);
        free(client->vendor_class_identifier);

        return pico_mfree(client);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DhcpClient, dhcp_client, dhcp_client_free);

int dhcp_client_new(Netd *netd, int ifindex, const char *ifname, DhcpClient **ret) {
        _cleanup_(dhcp_client_unrefp) DhcpClient *client = NULL;
        int r;

        assert_return(netd, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        client = new0(DhcpClient, 1);
        if (!client)
                return -ENOMEM;

        client->n_ref = 1;
        client->netd = netd;
        client->state = DHCP_STATE_STOPPED;
        client->ifindex = ifindex;
        client->fd = -1;
        client->fd_domain = AF_UNSPEC;
        client->port = DHCP_PORT_CLIENT;
        client->server_port = DHCP_PORT_SERVER;
        client->max_discover_attempts = UINT64_MAX;

        /* IPTOS_CLASS_CS6, "Internetwork Control" -- the class DHCP traffic
         * belongs to -- and the socket priority the kernel's own precedence
         * mapping pairs with it. */
        client->ip_service_type = IPTOS_CLASS_CS6;
        client->socket_priority = NETD_TC_PRIO_CONTROL;

        /* netd-loop.h keys tag liveness off `registered`, whose initial value
         * is calloc()'s zero. `fd` is for logging only; -1 means none. */
        client->io_tag.fd = -1;

        if (ifname) {
                strncpy(client->ifname, ifname, sizeof(client->ifname) - 1);
                client->ifname[sizeof(client->ifname) - 1] = '\0';
        }

        netd_u8set_clear(&client->req_opts);
        FOREACH_ELEMENT(opt, default_req_opts) {
                r = dhcp_client_set_request_option(client, *opt);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(client);
        return 0;
}
