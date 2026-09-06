/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Every way to obtain an sd_bus*, all of them honest_failure: this shim
 * has no wire protocol, so no sd_bus can ever exist (sd-bus-stubs.c's
 * entire giant -EINVAL family depends on that invariant holding).
 *
 * -ENOENT is what real libsystemd itself returns connecting to a
 * never-created /run/dbus/system_bus_socket -- byte-identical to a real
 * dbus-less machine, deliberately never -ECONNREFUSED (socket present,
 * daemon not listening: a transient condition this shim must never
 * suggest, since nothing here ever becomes non-transient). -ENOMEDIUM is
 * upstream's own synthetic errno for "no $XDG_RUNTIME_DIR" (sd-bus.c:1387).
 * -EOPNOTSUPP marks a transport/feature this library build has no code
 * for at all (remote/container transports, the sd_bus/sd_bus_creds
 * constructors), distinct from "no local bus".
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
