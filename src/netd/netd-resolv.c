/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * /etc/resolv.conf. See netd-resolv.h for the rules, all of which exist
 * because someone hit the bug they prevent.
 *
 * N0 scaffold: -ENOSYS until N2, when there is a lease to write from.
 */

#include "netd-resolv.h"

#include <errno.h>

#include "netd.h"

int netd_resolv_write(Netd *n) {
        if (!n)
                return -EINVAL;

        return -ENOSYS;
}
