/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * /etc/resolv.conf (plan §2.7).
 *
 * netd writes the real file directly. That is the whole reason this project's
 * `pico-resolv` recipe is retired rather than adapted: it exists only because
 * networkd refuses to write /etc/resolv.conf itself, and with it goes the
 * only Path unit in the image -- a unit type pico-init never has to grow.
 *
 * The rules encoded here are the ones the retired script already got right,
 * and each of them is a bug someone hit:
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

/*
 * Rebuild the file from every configured link's static DNS= plus, where
 * UseDNS= allows, its lease's option 6 -- in link order, deduplicated, capped
 * at NETD_RESOLV_MAX_NAMESERVERS. The lease's domain name (option 15) becomes
 * a `search` line.
 *
 * Called after any change to any link's DNS state, not incrementally: the
 * file is small, and a full rebuild cannot drift out of sync with the link
 * table the way an incremental edit can.
 *
 * 0 on success, 1 when there was nothing to write and the existing file was
 * therefore left untouched, or -errno.
 */
int netd_resolv_write(Netd *n);
