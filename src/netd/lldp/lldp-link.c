/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* See lldp-link.h. */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../util.h"
#include "dhcp/siphash24.h"
#include "lldp-link.h"
#include "lldp-table.h"
#include "netd-loop.h"
#include "netd.h"

#define USEC_PER_SEC_L 1000000ull
#define TX_JITTER_USEC 400000ull
#define TX_FAST_INTERVAL_USEC USEC_PER_SEC_L
#define RX_SOCKET_BUFFER 16384

struct LldpLink {
        Netd *netd;
        int ifindex;
        char ifname[IFNAMSIZ];

        LldpLinkConfig cfg;
        bool active; /* a socket is open */
        int fd;
        struct netd_epoll_tag io_tag;

        uint8_t hw[6];
        bool have_hw;
        bool have_machine_id;
        uint8_t machine_id[16];
        bool carrier;
        bool have_address;
        struct in_addr address;

        LldpTable table;
        PicoTimerEvent *tx_timer;
        PicoTimerEvent *expire_timer;
        uint64_t expire_deadline;
        unsigned fast_left;
};

/* --- small helpers --- */

/* Printable ASCII only, for log lines; anything else (a neighbour chooses these bytes) becomes '?'. */
static void printable(char *out, size_t size, const uint8_t *data, size_t len) {
        size_t i, n = len < size - 1 ? len : size - 1;

        for (i = 0; i < n; i++)
                out[i] = data[i] >= 0x20 && data[i] < 0x7f ? (char) data[i] : '?';
        out[n] = '\0';
}

static void neighbour_label(const LldpNeighbor *n, char *out, size_t size) {
        LldpSlice s = n->f.system_name.len ? n->f.system_name : n->f.port;

        printable(out, size, n->frame + s.off, s.len);
}

static uint64_t random_below(uint64_t limit) {
        uint32_t r = 0;

        if (getrandom(&r, sizeof(r), 0) != (ssize_t) sizeof(r))
                return 0;
        return r % limit;
}

/* --- publishing neighbours for netctl --- */

/* Percent-encodes everything that would break a space-separated key=value token. */
static char *escape(char *out, const uint8_t *in, size_t len) {
        static const char hex[] = "0123456789abcdef";
        size_t i;

        for (i = 0; i < len; i++) {
                uint8_t c = in[i];

                if (c > 0x20 && c < 0x7f && c != '%' && c != '=')
                        *out++ = (char) c;
                else {
                        *out++ = '%';
                        *out++ = hex[c >> 4];
                        *out++ = hex[c & 15];
                }
        }
        *out = '\0';
        return out;
}

static void write_state_neighbour(FILE *f, const LldpNeighbor *n) {
        /* Worst case: 255 bytes escaped to three characters each, plus a little. */
        char buf[3 * 255 + 8];
        const LldpFrame *fr = &n->f;

        fprintf(f, "N expires=%llu", (unsigned long long) (n->expiry / USEC_PER_SEC_L));
        fprintf(f,
                " src=%02x:%02x:%02x:%02x:%02x:%02x",
                fr->src[0],
                fr->src[1],
                fr->src[2],
                fr->src[3],
                fr->src[4],
                fr->src[5]);
        fprintf(f, " scope=%s", lldp_scope_to_string(fr->scope));
        escape(buf, n->frame + fr->chassis.off, fr->chassis.len);
        fprintf(f, " chassis=%u:%s", fr->chassis_subtype, buf);
        escape(buf, n->frame + fr->port.off, fr->port.len);
        fprintf(f, " port=%u:%s", fr->port_subtype, buf);
        if (fr->port_description.len) {
                escape(buf, n->frame + fr->port_description.off, fr->port_description.len);
                fprintf(f, " descr=%s", buf);
        }
        if (fr->system_name.len) {
                escape(buf, n->frame + fr->system_name.off, fr->system_name.len);
                fprintf(f, " name=%s", buf);
        }
        if (fr->system_description.len) {
                escape(buf, n->frame + fr->system_description.off, fr->system_description.len);
                fprintf(f, " sysdescr=%s", buf);
        }
        if (fr->has_capabilities)
                fprintf(f, " caps=%04x enabled=%04x", fr->capabilities, fr->enabled_capabilities);
        if (fr->has_management_ipv4)
                fprintf(f,
                        " mgmt=%u.%u.%u.%u",
                        fr->management_ipv4[0],
                        fr->management_ipv4[1],
                        fr->management_ipv4[2],
                        fr->management_ipv4[3]);
        if (fr->has_port_vlan_id)
                fprintf(f, " vlan=%u", fr->port_vlan_id);
        if (fr->mud_url.len) {
                escape(buf, n->frame + fr->mud_url.off, fr->mud_url.len);
                fprintf(f, " mud=%s", buf);
        }
        fputc('\n', f);
}

static void write_state(LldpLink *l) {
        char name[32], tmp[PATH_MAX], *path = NULL;
        FILE *f;
        unsigned i;
        int len;

        len = snprintf(name, sizeof(name), "%d", l->ifindex);
        if (len < 0 || (size_t) len >= sizeof(name))
                return;
        if (netd_runtime_path(l->netd, "lldp", name, true, &path) < 0)
                return;

        if (l->table.n == 0) {
                (void) unlink(path);
                free(path);
                return;
        }

        len = snprintf(tmp, sizeof(tmp), "%s.netd-tmp", path);
        if (len < 0 || (size_t) len >= sizeof(tmp)) {
                free(path);
                return;
        }

        f = fopen(tmp, "we");
        if (!f) {
                free(path);
                return;
        }
        fprintf(f, "IFNAME=%s\n", l->ifname);
        for (i = 0; i < l->table.n; i++)
                write_state_neighbour(f, l->table.entries[i]);

        if (fflush(f) != 0 || ferror(f)) {
                (void) fclose(f);
                (void) unlink(tmp);
        } else if (fclose(f) != 0)
                (void) unlink(tmp);
        else if (rename(tmp, path) < 0)
                (void) unlink(tmp);
        free(path);
}

/* --- expiry --- */

static void expire_cb(void *userdata, usec_t now);

static void expire_rearm(LldpLink *l) {
        uint64_t next = lldp_table_next_expiry(&l->table);

        if (next == l->expire_deadline && (l->expire_timer || next == 0))
                return;
        if (l->expire_timer)
                (void) pico_timer_cancel(l->netd->timer, l->expire_timer);
        l->expire_deadline = next;
        if (next != 0 && pico_timer_add(l->netd->timer, next, expire_cb, l, &l->expire_timer) < 0)
                l->expire_deadline = 0;
}

static void expire_cb(void *userdata, usec_t now) {
        LldpLink *l = userdata;
        unsigned removed;

        l->expire_deadline = 0;
        removed = lldp_table_expire(&l->table, now);
        if (removed) {
                pico_log(PICO_LOG_INFO, "netd: %s: LLDP: %u neighbour(s) timed out", l->ifname, removed);
                write_state(l);
        }
        expire_rearm(l);
}

/* --- building and sending our own frame --- */

/* PRETTY_NAME from os-release, quotes removed. Empty when there is none. */
static void read_pretty_name(char out[256]) {
        char line[300];
        FILE *f = fopen("/etc/os-release", "re");

        out[0] = '\0';
        if (!f)
                return;
        while (fgets(line, sizeof(line), f)) {
                char *v;
                size_t n;

                if (strncmp(line, "PRETTY_NAME=", 12) != 0)
                        continue;
                v = line + 12;
                n = strcspn(v, "\n");
                v[n] = '\0';
                if (n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n - 1] == v[0]) {
                        v[n - 1] = '\0';
                        v++;
                }
                snprintf(out, 256, "%.255s", v);
                break;
        }
        fclose(f);
}

static bool ipv4_forwarding(void) {
        char c = '0';
        FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "re");

        if (!f)
                return false;
        if (fread(&c, 1, 1, f) != 1)
                c = '0';
        fclose(f);
        return c == '1';
}

/* The chassis ID: a hash of the machine ID, so the raw ID never leaves the host (systemd does the same). */
static void chassis_from_machine_id(const uint8_t mid[16], char out[33]) {
        static const char hex[] = "0123456789abcdef";
        uint8_t key[16];
        uint64_t h[2];
        unsigned i, j;

        memcpy(key, mid, sizeof(key));
        h[0] = siphash24("lldp-chassis-0", 14, key);
        h[1] = siphash24("lldp-chassis-1", 14, key);
        for (i = 0; i < 2; i++)
                for (j = 0; j < 8; j++) {
                        uint8_t b = (uint8_t) (h[i] >> (8 * j));

                        out[(i * 8 + j) * 2] = hex[b >> 4];
                        out[(i * 8 + j) * 2 + 1] = hex[b & 15];
                }
        out[32] = '\0';
}

static int send_ours(LldpLink *l, unsigned ttl) {
        uint8_t buf[LLDP_FRAME_MAX];
        char chassis_hex[33], hostname[256], descr[256];
        LldpBuild b = { .scope = l->cfg.tx_scope, .ttl = (uint16_t) ttl };
        size_t len = 0;
        ssize_t r;

        memcpy(b.src, l->hw, 6);
        if (l->have_machine_id) {
                chassis_from_machine_id(l->machine_id, chassis_hex);
                b.chassis_subtype = LLDP_CHASSIS_SUBTYPE_LOCAL;
                b.chassis = (const uint8_t *) chassis_hex;
                b.chassis_len = 32;
        } else {
                b.chassis_subtype = LLDP_CHASSIS_SUBTYPE_MAC;
                b.chassis = l->hw;
                b.chassis_len = 6;
        }
        b.port_subtype = LLDP_PORT_SUBTYPE_INTERFACE_NAME;
        b.port = (const uint8_t *) l->ifname;
        b.port_len = strnlen(l->ifname, IFNAMSIZ);

        /* A shutdown frame carries only the three mandatory TLVs. */
        if (ttl != 0) {
                if (gethostname(hostname, sizeof(hostname)) == 0 && hostname[0] &&
                    strcmp(hostname, "(none)") != 0) {
                        hostname[sizeof(hostname) - 1] = '\0';
                        b.system_name = hostname;
                }
                read_pretty_name(descr);
                b.system_description = descr;
                b.has_capabilities = true;
                b.capabilities = LLDP_CAP_STATION | LLDP_CAP_ROUTER;
                b.enabled_capabilities = LLDP_CAP_STATION | (ipv4_forwarding() ? LLDP_CAP_ROUTER : 0);
                if (l->have_address) {
                        b.has_management_ipv4 = true;
                        memcpy(b.management_ipv4, &l->address, 4);
                        b.management_ifindex = l->ifindex;
                }
        }

        r = lldp_frame_build(buf, sizeof(buf), &b, &len);
        if (r < 0)
                return (int) r;

        r = send(l->fd, buf, len, MSG_DONTWAIT);
        return r < 0 ? -errno : 0;
}

static void tx_cb(void *userdata, usec_t now);

static void tx_arm(LldpLink *l, uint64_t delay_usec) {
        if (l->tx_timer) {
                (void) pico_timer_cancel(l->netd->timer, l->tx_timer);
                l->tx_timer = NULL;
        }
        (void) pico_timer_add(l->netd->timer, now_monotonic() + delay_usec, tx_cb, l, &l->tx_timer);
}

static void tx_cb(void *userdata, usec_t now) {
        LldpLink *l = userdata;
        int r;

        (void) now;
        if (!l->active || !l->cfg.tx || !l->carrier)
                return;

        r = send_ours(l, LLDP_TX_INTERVAL_SEC * LLDP_TX_HOLD);
        if (r < 0 && r != -ENETDOWN && r != -ENXIO && r != -ENOBUFS && r != -EAGAIN)
                pico_log(PICO_LOG_DEBUG, "netd: %s: LLDP transmit: %s", l->ifname, strerror(-r));

        if (l->fast_left > 0) {
                l->fast_left--;
                tx_arm(l, TX_FAST_INTERVAL_USEC);
        } else
                tx_arm(l, LLDP_TX_INTERVAL_SEC * USEC_PER_SEC_L + random_below(TX_JITTER_USEC));
}

static void tx_start_fast(LldpLink *l) {
        if (!l->active || !l->cfg.tx || !l->carrier)
                return;
        l->fast_left = LLDP_TX_FAST_COUNT - 1;
        tx_arm(l, random_below(TX_JITTER_USEC) + 1);
}

/* --- receive --- */

static void handle_frame(LldpLink *l, const uint8_t *buf, size_t len, const struct sockaddr_ll *from) {
        LldpFrame f;
        LldpEvent ev;
        const char *why = NULL;
        uint16_t mask = l->cfg.routers_only ? LLDP_CAPS_ALL_ROUTERS : UINT16_MAX;
        usec_t now = now_monotonic();
        char label[48];
        const LldpNeighbor *nb;

        if (from->sll_pkttype == PACKET_OUTGOING)
                return; /* our own transmission, seen by our own socket */
        if (lldp_frame_parse(buf, len, &f, &why) < 0) {
                pico_log(PICO_LOG_DEBUG, "netd: %s: LLDP: dropped a frame: %s", l->ifname, why ? why : "invalid");
                return;
        }
        if (l->have_hw && memcmp(f.src, l->hw, 6) == 0)
                return;

        ev = lldp_table_offer(&l->table, buf, len, &f, mask, now);
        switch (ev) {
        case LLDP_EVENT_ADDED:
        case LLDP_EVENT_UPDATED:
                nb = l->table.entries[l->table.n - 1];
                if (ev == LLDP_EVENT_UPDATED) {
                        unsigned i;

                        for (i = 0; i < l->table.n; i++)
                                if (lldp_frame_same_msap(
                                                    l->table.entries[i]->frame, &l->table.entries[i]->f, buf, &f))
                                        nb = l->table.entries[i];
                }
                neighbour_label(nb, label, sizeof(label));
                pico_log(PICO_LOG_INFO,
                         "netd: %s: LLDP neighbour %s: %s",
                         l->ifname,
                         ev == LLDP_EVENT_ADDED ? "added" : "changed",
                         label);
                write_state(l);
                if (ev == LLDP_EVENT_ADDED && l->fast_left == 0)
                        tx_start_fast(l);
                break;
        case LLDP_EVENT_REMOVED:
                pico_log(PICO_LOG_INFO, "netd: %s: LLDP neighbour removed", l->ifname);
                write_state(l);
                break;
        case LLDP_EVENT_FULL:
                pico_log(PICO_LOG_DEBUG, "netd: %s: LLDP: neighbour table full, frame dropped", l->ifname);
                break;
        case LLDP_EVENT_NOMEM:
                pico_log(PICO_LOG_WARNING, "netd: %s: LLDP: out of memory", l->ifname);
                break;
        case LLDP_EVENT_REFRESHED:
        case LLDP_EVENT_IGNORED:
        default:
                break;
        }
        expire_rearm(l);
}

static int io_cb(Netd *n, struct netd_epoll_tag *tag, uint32_t revents) {
        LldpLink *l = tag->userdata;
        unsigned i;

        (void) n;
        (void) revents;
        for (i = 0; i < LLDP_RX_BATCH && l->active; i++) {
                uint8_t buf[LLDP_FRAME_MAX];
                struct sockaddr_ll from;
                socklen_t fromlen = sizeof(from);
                ssize_t len = recvfrom(
                                l->fd,
                                buf,
                                sizeof(buf),
                                MSG_DONTWAIT | MSG_TRUNC,
                                (struct sockaddr *) &from,
                                &fromlen);

                if (len < 0) {
                        if (errno == EINTR)
                                continue;
                        if (errno != EAGAIN && errno != ENETDOWN)
                                pico_log(PICO_LOG_DEBUG,
                                         "netd: %s: LLDP receive: %s",
                                         l->ifname,
                                         strerror(errno));
                        break;
                }
                if ((size_t) len > sizeof(buf))
                        continue; /* longer than anything accepted; MSG_TRUNC reported the real size */
                handle_frame(l, buf, (size_t) len, &from);
        }
        return 0;
}

/* --- socket and lifecycle --- */

static int open_socket(LldpLink *l) {
        struct sockaddr_ll sa = { .sll_family = AF_PACKET,
                                  .sll_protocol = htons(LLDP_ETHERTYPE),
                                  .sll_ifindex = l->ifindex };
        int fd, bufsize = RX_SOCKET_BUFFER, i, r;

        fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(LLDP_ETHERTYPE));
        if (fd < 0)
                return -errno;
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

        if (!l->cfg.rx) {
                /* Transmit only: accept nothing, so nothing is ever queued here. */
                struct sock_filter drop = BPF_STMT(BPF_RET | BPF_K, 0);
                struct sock_fprog prog = { .len = 1, .filter = &drop };

                if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
                        pico_log(PICO_LOG_DEBUG,
                                 "netd: %s: LLDP: cannot attach the drop filter: %s",
                                 l->ifname,
                                 strerror(errno));
        }

        if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        if (l->cfg.rx)
                for (i = 0; i < _LLDP_SCOPE_MAX; i++) {
                        struct packet_mreq mr = { .mr_ifindex = l->ifindex,
                                                  .mr_type = PACKET_MR_MULTICAST,
                                                  .mr_alen = 6 };

                        memcpy(mr.mr_address, lldp_scope_address((LldpScope) i), 6);
                        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
                                r = -errno;
                                close(fd);
                                return r;
                        }
                }
        return fd;
}

bool lldp_link_is_active(const LldpLink *l) {
        return l && l->active;
}

bool lldp_link_config_equal(const LldpLink *l, const LldpLinkConfig *cfg) {
        return l->cfg.rx == cfg->rx && l->cfg.routers_only == cfg->routers_only && l->cfg.tx == cfg->tx &&
                        (!cfg->tx || l->cfg.tx_scope == cfg->tx_scope);
}

int lldp_link_new(Netd *n, int ifindex, const char *ifname, LldpLink **ret) {
        LldpLink *l;

        if (!n || !ifname || !ret)
                return -EINVAL;
        l = calloc(1, sizeof(*l));
        if (!l)
                return -ENOMEM;
        l->netd = n;
        l->ifindex = ifindex;
        l->fd = -1;
        snprintf(l->ifname, sizeof(l->ifname), "%s", ifname);
        *ret = l;
        return 0;
}

void lldp_link_stop(LldpLink *l) {
        if (!l)
                return;

        if (l->active && l->cfg.tx && l->carrier)
                (void) send_ours(l, 0); /* tell neighbours at once instead of letting the TTL run out */

        if (l->tx_timer)
                (void) pico_timer_cancel(l->netd->timer, l->tx_timer);
        if (l->expire_timer)
                (void) pico_timer_cancel(l->netd->timer, l->expire_timer);
        l->tx_timer = l->expire_timer = NULL;
        l->expire_deadline = 0;

        (void) netd_loop_remove_io(l->netd, &l->io_tag);
        if (l->fd >= 0)
                close(l->fd);
        l->fd = -1;
        l->active = false;
        l->fast_left = 0;

        if (l->table.n) {
                lldp_table_clear(&l->table);
                write_state(l);
        }
        memset(&l->cfg, 0, sizeof(l->cfg));
}

int lldp_link_configure(LldpLink *l, const LldpLinkConfig *cfg, const uint8_t hw[6], const uint8_t *machine_id) {
        int fd, r;

        if (!l || !cfg || !hw)
                return -EINVAL;

        memcpy(l->hw, hw, 6);
        l->have_hw = true;
        l->have_machine_id = machine_id != NULL;
        if (machine_id)
                memcpy(l->machine_id, machine_id, 16);

        if (l->active && lldp_link_config_equal(l, cfg))
                return 0;

        lldp_link_stop(l);
        if (!cfg->rx && !cfg->tx)
                return 0;

        l->cfg = *cfg;
        fd = open_socket(l);
        if (fd < 0) {
                memset(&l->cfg, 0, sizeof(l->cfg));
                return fd;
        }
        l->fd = fd;

        if (cfg->rx) {
                r = netd_loop_add_io(l->netd, &l->io_tag, fd, EPOLLIN, NETD_EPOLL_LLDP, io_cb, l);
                if (r < 0) {
                        close(fd);
                        l->fd = -1;
                        memset(&l->cfg, 0, sizeof(l->cfg));
                        return r;
                }
        }
        l->active = true;
        write_state(l); /* drops a file left by a previous netd */
        pico_log(PICO_LOG_INFO,
                 "netd: %s: LLDP %s%s%s",
                 l->ifname,
                 cfg->rx ? "receive" : "",
                 cfg->rx && cfg->tx ? " and " : "",
                 cfg->tx ? lldp_scope_to_string(cfg->tx_scope) : "");
        tx_start_fast(l);
        return 0;
}

void lldp_link_set_address(LldpLink *l, bool have, struct in_addr address) {
        l->have_address = have;
        if (have)
                l->address = address;
}

void lldp_link_set_carrier(LldpLink *l, bool up) {
        if (l->carrier == up)
                return;
        l->carrier = up;
        if (!l->active)
                return;

        if (up) {
                tx_start_fast(l);
                return;
        }

        /* Whoever we heard is not reachable any more, and nothing can be sent. */
        if (l->tx_timer) {
                (void) pico_timer_cancel(l->netd->timer, l->tx_timer);
                l->tx_timer = NULL;
        }
        l->fast_left = 0;
        if (l->table.n) {
                lldp_table_clear(&l->table);
                write_state(l);
        }
        expire_rearm(l);
}

void lldp_link_free(LldpLink *l) {
        if (!l)
                return;
        lldp_link_stop(l);
        free(l);
}

void lldp_link_free_void(void *l) {
        lldp_link_free(l);
}
