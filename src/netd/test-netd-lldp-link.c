/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * LLDP on a real veth pair in a fresh network namespace (the mechanism of
 * test-netd-dhcp.c): one end transmits, the other receives, and the
 * neighbours the receiver publishes in its state file are read back.
 *
 * Covered: a transmitted frame arriving and being published, the TTL 0
 * shutdown frame on stop, a flood of 40 distinct neighbours capped at the
 * table size with the first ones kept, junk frames ignored, carrier loss
 * forgetting everything, and routers-only filtering.
 */

/* unshare()/CLONE_NEWUSER/CLONE_NEWNET need __USE_GNU; must be first. */
#define _GNU_SOURCE

#include <errno.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../test-util.h"
#include "lldp/lldp-link.h"
#include "lldp/lldp-table.h"
#include "netd-loop.h"
#include "netd.h"

static void die(const char *what) {
        fprintf(stderr, "test-netd-lldp-link: %s: %s\n", what, strerror(errno));
        exit(1);
}

static void write_proc_file(const char *path, const char *content) {
        FILE *f = fopen(path, "we");

        if (!f)
                die(path);
        fputs(content, f);
        if (fclose(f) != 0)
                die(path);
}

/* The same isolation as test-netd-dhcp.c; a test that cannot prove it must fail, not skip. */
static void enter_test_netns(void) {
        uid_t uid = getuid();
        gid_t gid = getgid();
        char buf[64];

        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
                die("unshare(CLONE_NEWUSER|CLONE_NEWNET)");
        write_proc_file("/proc/self/setgroups", "deny");
        snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned) uid);
        write_proc_file("/proc/self/uid_map", buf);
        snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned) gid);
        write_proc_file("/proc/self/gid_map", buf);
}

static void run_ip(const char *args) {
        char cmd[256];

        snprintf(cmd, sizeof(cmd), "ip %s >/dev/null 2>&1", args);
        if (system(cmd) != 0) {
                fprintf(stderr, "test-netd-lldp-link: `%s` failed\n", cmd);
                exit(1);
        }
}

static const uint8_t mac_a[6] = { 0x02, 0, 0, 0, 0x0a, 0x01 };
static const uint8_t mac_b[6] = { 0x02, 0, 0, 0, 0x0b, 0x01 };
static const uint8_t machine_id[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

/* --- driving the loop by hand, the way netd_loop_run() dispatches --- */

static void pump_once(Netd *n, int timeout_ms) {
        struct epoll_event events[16];
        int k = epoll_wait(n->epoll_fd, events, 16, timeout_ms), i;

        for (i = 0; i < k; i++) {
                struct netd_epoll_tag *tag = events[i].data.ptr;

                if (tag && tag->callback && tag->registered)
                        (void) tag->callback(n, tag, events[i].events);
        }
}

/* Runs the loop for `ms` milliseconds regardless of events. */
static void pump_for(Netd *n, int ms) {
        int left = ms;

        while (left > 0) {
                pump_once(n, 50);
                left -= 50;
        }
}

static char state_path[256];
static char state_text[8192];

/* The state file's contents into state_text; false when there is none. */
static bool read_state(void) {
        FILE *f = fopen(state_path, "re");
        size_t n;

        if (!f)
                return false;
        n = fread(state_text, 1, sizeof(state_text) - 1, f);
        fclose(f);
        state_text[n] = '\0';
        return true;
}

static unsigned count_neighbours(void) {
        const char *p;
        unsigned c = 0;

        if (!read_state())
                return 0;
        for (p = state_text; (p = strstr(p, "\nN ")) != NULL; p++)
                c++;
        if (strncmp(state_text, "N ", 2) == 0)
                c++;
        return c;
}

/* Pumps until the file holds `want` neighbours, for at most `ms`. */
static bool pump_until_count(Netd *n, unsigned want, int ms) {
        int left = ms;

        while (left > 0) {
                if (count_neighbours() == want)
                        return true;
                pump_once(n, 50);
                left -= 50;
        }
        return count_neighbours() == want;
}

/* --- injecting frames from the far end --- */

static int open_injector(const char *ifname) {
        struct sockaddr_ll sa = { .sll_family = AF_PACKET,
                                  .sll_protocol = htons(LLDP_ETHERTYPE),
                                  .sll_ifindex = (int) if_nametoindex(ifname) };
        int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(LLDP_ETHERTYPE));

        if (fd < 0)
                die("injector socket");
        if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
                die("injector bind");
        return fd;
}

static void inject(int fd, unsigned id, uint16_t caps, size_t cut) {
        uint8_t chassis[2] = { (uint8_t) (id >> 8), (uint8_t) id };
        uint8_t buf[LLDP_FRAME_MAX];
        LldpBuild b = {
                .src = { 0x02, 0, 0, 0, 0x0c, (uint8_t) id },
                .scope = LLDP_SCOPE_CUSTOMER_BRIDGE,
                .chassis_subtype = LLDP_CHASSIS_SUBTYPE_LOCAL,
                .chassis = chassis,
                .chassis_len = 2,
                .port_subtype = LLDP_PORT_SUBTYPE_LOCAL,
                .port = (const uint8_t *) "q",
                .port_len = 1,
                .ttl = 100,
                .system_name = "injected",
                .has_capabilities = caps != 0,
                .capabilities = caps,
                .enabled_capabilities = caps,
        };
        size_t len = 0;

        ASSERT_EQ_INT(lldp_frame_build(buf, sizeof(buf), &b, &len), 0);
        if (cut && cut < len)
                len = cut;
        ASSERT_TRUE(send(fd, buf, len, 0) == (ssize_t) len);
}

int main(void) {
        LldpLinkConfig tx_cfg = { .tx = true, .tx_scope = LLDP_SCOPE_NEAREST_BRIDGE };
        LldpLinkConfig rx_cfg = { .rx = true };
        char dir_template[] = "/tmp/test-netd-lldp-XXXXXX";
        LldpLink *a = NULL, *b = NULL;
        Netd *n = NULL;
        char *dir;
        int injector;
        unsigned idx_b, i;

        enter_test_netns();
        run_ip("link add name la0 address 02:00:00:00:0a:01 type veth peer name lb0 address 02:00:00:00:0b:01");
        run_ip("link set la0 up");
        run_ip("link set lb0 up");

        dir = mkdtemp(dir_template);
        if (!dir)
                die("mkdtemp");
        ASSERT_EQ_INT(netd_new(&n), 0);
        ASSERT_EQ_INT(netd_set_runtime_dir(n, dir), 0);

        idx_b = if_nametoindex("lb0");
        snprintf(state_path, sizeof(state_path), "%s/lldp/%u", dir, idx_b);

        ASSERT_EQ_INT(lldp_link_new(n, (int) if_nametoindex("la0"), "la0", &a), 0);
        ASSERT_EQ_INT(lldp_link_new(n, (int) idx_b, "lb0", &b), 0);

        /* --- a transmitted frame arrives and is published --- */
        ASSERT_EQ_INT(lldp_link_configure(b, &rx_cfg, mac_b, machine_id), 0);
        ASSERT_EQ_INT(lldp_link_configure(a, &tx_cfg, mac_a, machine_id), 0);
        lldp_link_set_address(a, true, (struct in_addr){ .s_addr = htonl(0xc0a80702) });
        lldp_link_set_carrier(b, true);
        lldp_link_set_carrier(a, true);
        ASSERT_TRUE(pump_until_count(n, 1, 3000));
        ASSERT_TRUE(strstr(state_text, "IFNAME=lb0\n") != NULL);
        ASSERT_TRUE(strstr(state_text, " src=02:00:00:00:0a:01") != NULL);
        ASSERT_TRUE(strstr(state_text, " scope=nearest-bridge") != NULL);
        ASSERT_TRUE(strstr(state_text, " port=5:la0") != NULL);
        ASSERT_TRUE(strstr(state_text, " chassis=7:") != NULL);
        ASSERT_TRUE(strstr(state_text, " name=") != NULL);
        ASSERT_TRUE(strstr(state_text, " mgmt=192.168.7.2") != NULL);
        ASSERT_TRUE(strstr(state_text, " caps=0090 ") != NULL); /* station and router capable */

        /* The fast burst: four frames in the first seconds, all the same neighbour. */
        pump_for(n, 3500);
        ASSERT_EQ_INT(count_neighbours(), 1);

        /* --- stopping sends the shutdown frame, so the neighbour goes at once --- */
        lldp_link_stop(a);
        ASSERT_TRUE(pump_until_count(n, 0, 2000));
        ASSERT_TRUE(!read_state());

        /* --- a flood of distinct neighbours is capped; the first ones stay --- */
        injector = open_injector("la0");
        for (i = 1; i <= 40; i++)
                inject(injector, i, LLDP_CAP_STATION, 0);
        pump_for(n, 500);
        ASSERT_EQ_INT(count_neighbours(), LLDP_TABLE_MAX);
        ASSERT_TRUE(strstr(state_text, " chassis=7:%00%01 ") != NULL);
        ASSERT_TRUE(strstr(state_text, " chassis=7:%00%08 ") != NULL);
        ASSERT_TRUE(strstr(state_text, " chassis=7:%00%09 ") == NULL);

        /* --- truncated and garbage frames change nothing and do not crash --- */
        for (i = 0; i < 20; i++)
                inject(injector, 100 + i, LLDP_CAP_STATION, 14 + i);
        {
                uint8_t junk[64] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x02,
                                     0,    0,    0,    0x0c, 0x77, 0x88, 0xcc };

                memset(junk + 14, 0xff, sizeof(junk) - 14);
                ASSERT_TRUE(send(injector, junk, sizeof(junk), 0) == (ssize_t) sizeof(junk));
        }
        pump_for(n, 300);
        ASSERT_EQ_INT(count_neighbours(), LLDP_TABLE_MAX);

        /* --- losing carrier forgets every neighbour --- */
        lldp_link_set_carrier(b, false);
        ASSERT_EQ_INT(count_neighbours(), 0);
        lldp_link_set_carrier(b, true);

        /* --- routers-only: a station is ignored, a router is kept --- */
        rx_cfg.routers_only = true;
        ASSERT_EQ_INT(lldp_link_configure(b, &rx_cfg, mac_b, machine_id), 0);
        lldp_link_set_carrier(b, true);
        inject(injector, 200, LLDP_CAP_STATION, 0);
        pump_for(n, 300);
        ASSERT_EQ_INT(count_neighbours(), 0);
        inject(injector, 201, LLDP_CAP_ROUTER, 0);
        ASSERT_TRUE(pump_until_count(n, 1, 1000));

        /* --- turning LLDP off removes the socket and the state --- */
        rx_cfg.rx = false;
        ASSERT_EQ_INT(lldp_link_configure(b, &rx_cfg, mac_b, machine_id), 0);
        ASSERT_TRUE(!lldp_link_is_active(b));
        ASSERT_TRUE(!read_state());

        close(injector);
        lldp_link_free(a);
        lldp_link_free(b);
        printf("test-netd-lldp-link: ok\n");
        return EXIT_SUCCESS;
}
