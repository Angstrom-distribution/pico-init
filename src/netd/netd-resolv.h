/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * /etc/resolv.conf.
 *
 * netd writes the real file directly, unlike networkd, which refuses to and
 * needs a helper to do it.
 *
 * Rules:
 *
 *   - atomic tmp + rename, never a truncate-and-rewrite, so no resolver ever
 *     reads a half-written file;
 *   - never replace a working file with an empty one. A link losing its lease
 *     while another still has DNS servers must not blank the file, and even
 *     the last link going away leaves the previous contents in place rather
 *     than writing a resolv.conf with no nameservers in it;
 *   - honour UseDNS=no per link, so a static DNS= on one interface is not
 *     quietly overwritten by DHCP on another.
 */

#pragma once

typedef struct Netd Netd;

#define NETD_RESOLV_CONF "/etc/resolv.conf"

/* glibc reads at most three, and writing more is misleading rather than
 * generous. */
#define NETD_RESOLV_MAX_NAMESERVERS 3

/* Older glibc reads at most six search domains (MAXDNSRCH). */
#define NETD_RESOLV_MAX_DOMAINS 6

/*
 * Rebuild the file from every configured link's static DNS= plus, where
 * [DHCPv4] UseDNS= allows, its lease's option 6, and, where [IPv6AcceptRA]
 * UseDNS= allows, its routers' RDNSS -- in link order, deduplicated, capped
 * at NETD_RESOLV_MAX_NAMESERVERS. IPv4 and IPv6 servers share the cap, and a
 * link-local IPv6 server is written with its interface, `fe80::1%eth0`. The
 * first lease's domain name (option 15), then the routers' DNSSL where
 * UseDomains= allows, make the `search` line, at most
 * NETD_RESOLV_MAX_DOMAINS long.
 *
 * Called after any change to any link's DNS state, not incrementally: the
 * file is small, and a full rebuild cannot drift out of sync with the link
 * table the way an incremental edit can.
 *
 * 0 on success, 1 when there was nothing to write and the existing file was
 * therefore left untouched, or -errno.
 */
int netd_resolv_write(Netd *n);
