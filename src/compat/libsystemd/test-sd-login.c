/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Everything in sd-login.h except the cgroup/unit/slice family (which has
 * its own real-cgroup test, test-sd-login-cgroup.c): the uid/session/
 * seat/machine/get_all/login_monitor functions: the answers that hold
 * without logind (sd_uid_get_state()'s "offline", sd_get_seats() and friends
 * reporting zero, sd_machine_get_class()'s ".host") and the errors given
 * everywhere else.
 */

#include "sd-login.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../../test-util.h"

/* sd_seat_can_multi_session() is a deprecated stub in libsystemd too, and
 * still part of the ABI. */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static void test_uid_functions(void) {
        char *state = NULL;
        char **sessions = (char **) 0x1;
        char **seats = (char **) 0x1;

        ASSERT_EQ_INT(sd_uid_get_state((uid_t) -1, &state), -EINVAL);
        ASSERT_EQ_INT(sd_uid_get_state(0, &state), 0);
        ASSERT_STREQ(state, "offline");
        free(state);

        /* NULL argument (existence-only query): must not crash. */
        ASSERT_EQ_INT(sd_uid_get_state(0, NULL), 0);

        ASSERT_EQ_INT(sd_uid_get_sessions(0, 0, &sessions), 0);
        ASSERT_TRUE(sessions == NULL);
        ASSERT_EQ_INT(sd_uid_get_seats(0, 0, &seats), 0);
        ASSERT_TRUE(seats == NULL);

        ASSERT_EQ_INT(sd_uid_is_on_seat((uid_t) -1, 0, "seat0"), -EINVAL);
        ASSERT_EQ_INT(sd_uid_is_on_seat(0, 0, NULL), -ENODATA);
        ASSERT_EQ_INT(sd_uid_is_on_seat(0, 0, "seat0"), 0); /* not on that seat */

        ASSERT_EQ_INT(sd_uid_get_display(0, &state), -ENODATA);
        ASSERT_EQ_INT(sd_uid_get_login_time(0, NULL), -ENXIO);
}

static void test_session_functions(void) {
        ASSERT_EQ_INT(sd_session_is_active(NULL), -ENODATA);
        ASSERT_EQ_INT(sd_session_is_active("no/slashes/allowed"), -EINVAL);
        ASSERT_EQ_INT(sd_session_is_active("."), -EINVAL);
        ASSERT_EQ_INT(sd_session_is_active(".."), -EINVAL);
        ASSERT_EQ_INT(sd_session_is_active(""), -EINVAL);
        ASSERT_EQ_INT(sd_session_is_active("1"), -ENXIO); /* well-formed, permanently unregistered */
        ASSERT_EQ_INT(sd_session_get_state("1", NULL), -ENXIO);
        ASSERT_EQ_INT(sd_session_get_uid("1", NULL), -ENXIO);
        ASSERT_EQ_INT(sd_session_get_vt("1", NULL), -ENXIO);
        ASSERT_EQ_INT(sd_session_get_extra_device_access("1", NULL), -ENXIO);
        ASSERT_EQ_INT(sd_session_get_extra_device_access(NULL, NULL), -ENODATA);
}

static void test_seat_functions(void) {
        ASSERT_EQ_INT(sd_seat_get_active(NULL, NULL, NULL), -ENODATA);
        ASSERT_EQ_INT(sd_seat_get_active("bad/seat", NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_seat_get_active("seat0", NULL, NULL), -ENXIO);
        ASSERT_EQ_INT(sd_seat_can_tty("seat0"), -ENXIO);
        ASSERT_EQ_INT(sd_seat_can_graphical("seat0"), -ENXIO);
        ASSERT_EQ_INT(sd_seat_can_multi_session(NULL), 1); /* upstream's unconditional stub */
        ASSERT_EQ_INT(sd_seat_can_multi_session("seat0"), 1);
}

static void test_machine_functions(void) {
        char *clazz = NULL;
        int *ifindices = (int *) 0x1;

        ASSERT_EQ_INT(sd_machine_get_class(NULL, &clazz), -EINVAL);
        ASSERT_EQ_INT(sd_machine_get_class(".host", &clazz), 0);
        ASSERT_STREQ(clazz, "host");
        free(clazz);

        /* NULL argument (existence-only query): must not crash. */
        ASSERT_EQ_INT(sd_machine_get_class(".host", NULL), 0);

        ASSERT_EQ_INT(sd_machine_get_class("not-a-real-machine", &clazz), -ENXIO);
        ASSERT_EQ_INT(sd_machine_get_class("bad/name", &clazz), -EINVAL);

        /* ".host" is a machined-internal sentinel, not a real hostname --
         * unlike get_class(), get_ifindices() has no special case for it. */
        ASSERT_EQ_INT(sd_machine_get_ifindices(".host", &ifindices), -EINVAL);
        ASSERT_EQ_INT(sd_machine_get_ifindices("some-vm", &ifindices), -ENXIO);
        ASSERT_TRUE(ifindices == (int *) 0x1); /* untouched */
}

static void test_get_all_functions(void) {
        char **seats = (char **) 0x1;
        char **sessions = (char **) 0x1;
        uid_t *uids = (uid_t *) 0x1;
        char **machines = (char **) 0x1;

        ASSERT_EQ_INT(sd_get_seats(&seats), 0);
        ASSERT_TRUE(seats == NULL);
        ASSERT_EQ_INT(sd_get_sessions(&sessions), 0);
        ASSERT_TRUE(sessions == NULL);
        ASSERT_EQ_INT(sd_get_uids(&uids), 0);
        ASSERT_TRUE(uids == NULL);
        ASSERT_EQ_INT(sd_get_machine_names(&machines), 0);
        ASSERT_TRUE(machines == NULL);

        /* NULL argument (count-only query): must not crash. */
        ASSERT_EQ_INT(sd_get_seats(NULL), 0);
}

static void test_login_monitor(void) {
        sd_login_monitor *m = (sd_login_monitor *) 0x1;

        ASSERT_EQ_INT(sd_login_monitor_new(NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_login_monitor_new("bogus-category", &m), -EINVAL);
        ASSERT_EQ_INT(sd_login_monitor_new(NULL, &m), -ENOENT);
        ASSERT_EQ_INT(sd_login_monitor_new("seat", &m), -ENOENT);
        ASSERT_EQ_INT(sd_login_monitor_new("session", &m), -ENOENT);
        ASSERT_EQ_INT(sd_login_monitor_new("uid", &m), -ENOENT);
        ASSERT_EQ_INT(sd_login_monitor_new("machine", &m), -ENOENT);

        ASSERT_TRUE(sd_login_monitor_unref(NULL) == NULL);
        ASSERT_EQ_INT(sd_login_monitor_flush(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_login_monitor_get_fd(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_login_monitor_get_events(NULL), -EINVAL);
        ASSERT_EQ_INT(sd_login_monitor_get_timeout(NULL, NULL), -EINVAL);
}

int main(void) {
        test_uid_functions();
        test_session_functions();
        test_seat_functions();
        test_machine_functions();
        test_get_all_functions();
        test_login_monitor();

        printf("test-sd-login: all checks passed\n");
        return 0;
}
