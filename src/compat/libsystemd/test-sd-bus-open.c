/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Every way to obtain an sd_bus*: all fail, with the specific errno
 * depending only on ret==NULL and the real process environment
 * ($XDG_RUNTIME_DIR, $DBUS_STARTER_BUS_TYPE) -- never on any real bus
 * socket, since none of this shim's callers can create one.
 */

#include "sd-bus.h"

#include <errno.h>
#include <stdlib.h>

#include "../../test-util.h"

static sd_bus *sentinel_bus(void) {
        return (sd_bus *) 0x1;
}

int main(void) {
        sd_bus *bus;

        /* ret==NULL -> -EINVAL, uniformly. */
        ASSERT_EQ_INT(sd_bus_open_system(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_open_user(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_open(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_default(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_default_system(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_default_user(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_new(NULL), -EINVAL);

        /* System bus: always -ENOENT, *ret untouched. */
        bus = sentinel_bus();
        ASSERT_EQ_INT(sd_bus_open_system(&bus), -ENOENT);
        ASSERT_TRUE(bus == sentinel_bus());
        ASSERT_EQ_INT(sd_bus_open_system_with_description(&bus, "test"), -ENOENT);
        ASSERT_EQ_INT(sd_bus_default(&bus), -ENOENT);
        ASSERT_EQ_INT(sd_bus_default_system(&bus), -ENOENT);
        ASSERT_EQ_INT(sd_bus_new(&bus), -EOPNOTSUPP);
        ASSERT_TRUE(bus == sentinel_bus());

        /* User bus: -ENOMEDIUM with no $XDG_RUNTIME_DIR, else -ENOENT. */
        unsetenv("XDG_RUNTIME_DIR");
        ASSERT_EQ_INT(sd_bus_open_user(&bus), -ENOMEDIUM);
        ASSERT_EQ_INT(sd_bus_default_user(&bus), -ENOMEDIUM);

        setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);
        ASSERT_EQ_INT(sd_bus_open_user(&bus), -ENOENT);
        ASSERT_EQ_INT(sd_bus_default_user(&bus), -ENOENT);
        unsetenv("XDG_RUNTIME_DIR");

        /* sd_bus_open() dispatches on $DBUS_STARTER_BUS_TYPE. */
        unsetenv("DBUS_STARTER_BUS_TYPE");
        ASSERT_EQ_INT(sd_bus_open(&bus), -ENOENT); /* unset -> system */

        setenv("DBUS_STARTER_BUS_TYPE", "system", 1);
        ASSERT_EQ_INT(sd_bus_open(&bus), -ENOENT);

        setenv("DBUS_STARTER_BUS_TYPE", "user", 1);
        unsetenv("XDG_RUNTIME_DIR");
        ASSERT_EQ_INT(sd_bus_open(&bus), -ENOMEDIUM);
        setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);
        ASSERT_EQ_INT(sd_bus_open(&bus), -ENOENT);
        unsetenv("XDG_RUNTIME_DIR");
        unsetenv("DBUS_STARTER_BUS_TYPE");

        /* Remote/machine transports: -EINVAL on NULL args, else -EOPNOTSUPP. */
        ASSERT_EQ_INT(sd_bus_open_system_remote(NULL, "host"), -EINVAL);
        ASSERT_EQ_INT(sd_bus_open_system_remote(&bus, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_bus_open_system_remote(&bus, "host"), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_bus_open_system_machine(&bus, "mach"), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_bus_open_user_machine(&bus, "mach"), -EOPNOTSUPP);

        /* Creds constructors. */
        {
                sd_bus_creds *creds = (sd_bus_creds *) 0x1;

                ASSERT_EQ_INT(sd_bus_creds_new_from_pid(NULL, 1, 0), -EINVAL);
                ASSERT_EQ_INT(sd_bus_creds_new_from_pid(&creds, -1, 0), -EINVAL);
                ASSERT_EQ_INT(sd_bus_creds_new_from_pid(&creds, 1, 0), -EOPNOTSUPP);
                ASSERT_TRUE(creds == (sd_bus_creds *) 0x1);

                ASSERT_EQ_INT(sd_bus_creds_new_from_pidfd(NULL, 3, 0), -EINVAL);
                ASSERT_EQ_INT(sd_bus_creds_new_from_pidfd(&creds, -1, 0), -EBADF);
                ASSERT_EQ_INT(sd_bus_creds_new_from_pidfd(&creds, 3, 0), -EOPNOTSUPP);
        }

        printf("test-sd-bus-open: all checks passed\n");
        return 0;
}
