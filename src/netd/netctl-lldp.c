/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* See netctl-lldp.h. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netctl-lldp.h"

static int hexval(char c) {
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

size_t netctl_lldp_unescape(uint8_t *out, size_t size, const char *in, size_t len) {
        size_t i = 0, n = 0;

        while (i < len) {
                uint8_t c;

                if (n >= size)
                        return (size_t) -1;
                if (in[i] == '%') {
                        int hi, lo;

                        if (len - i < 3)
                                return (size_t) -1;
                        hi = hexval(in[i + 1]);
                        lo = hexval(in[i + 2]);
                        if (hi < 0 || lo < 0)
                                return (size_t) -1;
                        c = (uint8_t) (hi << 4 | lo);
                        i += 3;
                } else
                        c = (uint8_t) in[i++];
                out[n++] = c;
        }
        return n;
}

/* Printable ASCII only; anything else is shown as '?'. */
static void sanitize(char *out, size_t size, const uint8_t *in, size_t len) {
        size_t i, n = len < size - 1 ? len : size - 1;

        for (i = 0; i < n; i++)
                out[i] = in[i] >= 0x20 && in[i] < 0x7f ? (char) in[i] : '?';
        out[n] = '\0';
}

void netctl_lldp_format_id(char *out, size_t size, int kind, unsigned subtype, const uint8_t *id, size_t len) {
        bool is_mac = kind == 0 ? subtype == 4 : subtype == 3;
        bool is_addr = kind == 0 ? subtype == 5 : subtype == 4;
        size_t i;
        bool printable = len > 0;

        if (is_mac && len == 6) {
                snprintf(out, size, "%02x:%02x:%02x:%02x:%02x:%02x", id[0], id[1], id[2], id[3], id[4], id[5]);
                return;
        }
        if (is_addr && len == 5 && id[0] == 1) {
                snprintf(out, size, "%u.%u.%u.%u", id[1], id[2], id[3], id[4]);
                return;
        }
        for (i = 0; i < len; i++)
                if (id[i] < 0x20 || id[i] >= 0x7f)
                        printable = false;
        if (printable) {
                sanitize(out, size, id, len);
                return;
        }
        /* Hex, as much as fits. */
        for (i = 0; i < len && 2 * i + 2 < size; i++)
                snprintf(out + 2 * i, size - 2 * i, "%02x", id[i]);
        if (len == 0)
                out[0] = '\0';
}

void netctl_lldp_format_caps(char out[NETCTL_LLDP_CAPS_LEN], uint16_t caps) {
        /* o other, p repeater, b bridge, w wlan-ap, r router, t telephone, d docsis, a station, c cvlan, s svlan, m tpmr */
        static const char table[11] = { 'o', 'p', 'b', 'w', 'r', 't', 'd', 'a', 'c', 's', 'm' };
        unsigned i;

        for (i = 0; i < 11; i++)
                out[i] = caps & (1u << i) ? table[i] : '.';
        out[11] = '\0';
}

/* The value of token "key=" in a space separated line, as a pointer and length; false when absent. */
static bool token(const char *line, const char *key, const char **value, size_t *len) {
        size_t klen = strlen(key);
        const char *p = line;

        while (*p) {
                const char *end = strchr(p, ' ');
                size_t tlen = end ? (size_t) (end - p) : strlen(p);

                if (tlen > klen && strncmp(p, key, klen) == 0 && p[klen] == '=') {
                        *value = p + klen + 1;
                        *len = tlen - klen - 1;
                        return true;
                }
                if (!end)
                        break;
                p = end + 1;
        }
        return false;
}

/* "<subtype>:<escaped>" into a display string. */
static bool id_token(const char *line, const char *key, int kind, char *out, size_t size) {
        const char *v;
        size_t len, decoded;
        uint8_t raw[300];
        char *end;
        unsigned long subtype;

        if (!token(line, key, &v, &len) || len == 0)
                return false;
        subtype = strtoul(v, &end, 10);
        if (end == v || (size_t) (end - v) >= len || *end != ':' || subtype > 255)
                return false;
        decoded = netctl_lldp_unescape(raw, sizeof(raw), end + 1, len - (size_t) (end + 1 - v));
        if (decoded == (size_t) -1)
                return false;
        netctl_lldp_format_id(out, size, kind, (unsigned) subtype, raw, decoded);
        return true;
}

static void text_token(const char *line, const char *key, char *out, size_t size) {
        const char *v;
        size_t len;
        uint8_t raw[300];
        size_t decoded;

        out[0] = '\0';
        if (!token(line, key, &v, &len))
                return;
        decoded = netctl_lldp_unescape(raw, sizeof(raw), v, len);
        if (decoded != (size_t) -1)
                sanitize(out, size, raw, decoded);
}

bool netctl_lldp_parse_row(const char *line, const char *ifname, NetctlLldpRow *row) {
        const char *v;
        size_t len;

        if (strncmp(line, "N ", 2) != 0)
                return false;
        line += 2;

        memset(row, 0, sizeof(*row));
        snprintf(row->link, sizeof(row->link), "%s", ifname);

        if (!id_token(line, "chassis", 0, row->chassis, sizeof(row->chassis)) ||
            !id_token(line, "port", 1, row->port, sizeof(row->port)))
                return false;

        if (token(line, "expires", &v, &len))
                row->expires = strtoull(v, NULL, 10);
        text_token(line, "name", row->name, sizeof(row->name));
        text_token(line, "descr", row->descr, sizeof(row->descr));

        if (token(line, "enabled", &v, &len))
                netctl_lldp_format_caps(row->caps, (uint16_t) strtoul(v, NULL, 16));
        else
                netctl_lldp_format_caps(row->caps, 0);
        return true;
}
