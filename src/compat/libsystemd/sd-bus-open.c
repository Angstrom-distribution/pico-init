/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Every way to obtain an sd_bus*; all fail, since there is no wire protocol
 * and so no sd_bus can exist (sd-bus-stubs.c relies on that).
 *
 * -ENOENT is what real libsystemd returns on a machine where
 * /run/dbus/system_bus_socket was never created. -ECONNREFUSED is avoided
 * because it suggests a transient condition. -ENOMEDIUM is upstream's
 * errno for "no $XDG_RUNTIME_DIR" (sd-bus.c:1387). -EOPNOTSUPP marks a
 * transport or feature with no code at all (remote/container transports,
 * the sd_bus/sd_bus_creds constructors), as distinct from "no local bus".
 *
 * An image that ships a real dbus-daemon must link real libsystemd
 * instead of this shim.
 */

#include "sd-bus.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int user_bus_open_errno(void) {
        return getenv("XDG_RUNTIME_DIR") ? -ENOENT : -ENOMEDIUM;
}

int sd_bus_open_system(sd_bus **ret) {
        if (!ret)
                return -EINVAL;
        return -ENOENT;
}

int sd_bus_open_system_with_description(sd_bus **ret, const char *description) {
        (void) description;
        if (!ret)
                return -EINVAL;
        return -ENOENT;
}

int sd_bus_open_user(sd_bus **ret) {
        if (!ret)
                return -EINVAL;
        return user_bus_open_errno();
}

int sd_bus_open_user_with_description(sd_bus **ret, const char *description) {
        (void) description;
        if (!ret)
                return -EINVAL;
        return user_bus_open_errno();
}

int sd_bus_open(sd_bus **ret) {
        const char *type;

        if (!ret)
                return -EINVAL;

        type = getenv("DBUS_STARTER_BUS_TYPE");
        if (type && strcmp(type, "user") == 0)
                return user_bus_open_errno();

        return -ENOENT;
}

int sd_bus_open_with_description(sd_bus **ret, const char *description) {
        (void) description;
        return sd_bus_open(ret);
}

int sd_bus_default(sd_bus **ret) {
        if (!ret)
                return -EINVAL;
        return -ENOENT;
}

int sd_bus_default_system(sd_bus **ret) {
        if (!ret)
                return -EINVAL;
        return -ENOENT;
}

int sd_bus_default_user(sd_bus **ret) {
        if (!ret)
                return -EINVAL;
        return user_bus_open_errno();
}

int sd_bus_open_system_remote(sd_bus **ret, const char *host) {
        if (!ret || !host)
                return -EINVAL;
        return -EOPNOTSUPP;
}

int sd_bus_open_system_machine(sd_bus **ret, const char *machine) {
        if (!ret || !machine)
                return -EINVAL;
        return -EOPNOTSUPP;
}

int sd_bus_open_user_machine(sd_bus **ret, const char *machine) {
        if (!ret || !machine)
                return -EINVAL;
        return -EOPNOTSUPP;
}

int sd_bus_new(sd_bus **ret) {
        if (!ret)
                return -EINVAL;
        return -EOPNOTSUPP;
}

int sd_bus_creds_new_from_pid(sd_bus_creds **ret, pid_t pid, uint64_t creds_mask) {
        (void) creds_mask;
        if (!ret || pid < 0)
                return -EINVAL;
        return -EOPNOTSUPP;
}

int sd_bus_creds_new_from_pidfd(sd_bus_creds **ret, int pidfd, uint64_t creds_mask) {
        (void) creds_mask;
        if (!ret)
                return -EINVAL;
        if (pidfd < 0)
                return -EBADF;
        return -EOPNOTSUPP;
}
