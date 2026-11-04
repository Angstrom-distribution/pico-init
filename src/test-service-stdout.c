/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The service that reads logd's stdout socket must not get that socket as its
 * own stdout and stderr: a full queue would block it on its own output. The
 * socket unit bound at /run/logd/stdout decides which service that is, not
 * the service's name or its StandardOutput= line. Every other service still
 * gets the socket.
 *
 * PID 1 connects to the fixed path /run/logd/stdout, so the test mounts a
 * private tmpfs over /run inside a user and mount namespace and skips (77)
 * when the host refuses that. Each command checks its own descriptors through
 * /proc: `$$$$` reaches the shell as `$$`, its own pid.
 */

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#include "manager.h"
#include "service.h"
#include "socket.h"
#include "test-util.h"
#include "timer.h"
#include "unit.h"
#include "util.h"

#define IS_NULL \
        "test \"$(readlink /proc/$$$$/fd/1)\" = /dev/null && test \"$(readlink /proc/$$$$/fd/2)\" = /dev/null"
#define IS_SOCKET "test -S /proc/$$$$/fd/1 && test -S /proc/$$$$/fd/2"

static Manager *g_drive_m;
static Service *g_drive_s;
static int g_drive_ticks;

static void drive_tick(void *userdata, usec_t now) {
        (void) userdata;
        (void) now;

        g_drive_ticks++;

        if (g_drive_s->state == SERVICE_DEAD || g_drive_s->state == SERVICE_FAILED || g_drive_ticks >= 2000)
                g_drive_m->objective = MANAGER_EXIT;
        else
                ASSERT_EQ_INT(pico_timer_add(g_drive_m->timer,
                                             now_monotonic() + 5 * USEC_PER_MSEC,
                                             drive_tick,
                                             NULL,
                                             NULL),
                              0);
}

static Manager *manager_for(const char *dir) {
        const char * const path[] = { dir, NULL };
        Manager *m = NULL;

        ASSERT_EQ_INT(manager_new(&m), 0);
        ASSERT_EQ_INT(manager_set_unit_path(m, path), 0);

        return m;
}

/* Runs the oneshot service to completion; its result is the verdict of its own checks. */
static void run_service(Manager *m, const char *name, ServiceResult want) {
        Service *s = SERVICE(manager_get_unit(m, name));

        ASSERT_TRUE(s != NULL);
        ASSERT_EQ_INT(unit_start(UNIT(s)), 0);

        g_drive_m = m;
        g_drive_s = s;
        g_drive_ticks = 0;
        m->objective = MANAGER_RUNNING;
        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 5 * USEC_PER_MSEC, drive_tick, NULL, NULL),
                      0);
        manager_loop(m);

        if (s->result != want)
                fprintf(stderr, "%s: result %d, want %d\n", name, (int) s->result, (int) want);
        ASSERT_EQ_INT(s->result, want);
}

static void start_socket(Manager *m, const char *name) {
        Unit *u = manager_get_unit(m, name);

        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(unit_start(u), 0);
        ASSERT_EQ_INT(SOCKET(u)->state, SOCKET_LISTENING);
}

/* logd.service pairs with logd.socket by name; a plain service gets the socket. */
static void test_paired_by_name(void) {
        Manager *m;
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "logd.socket", "[Socket]\nListenDatagram=/run/logd/stdout\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "logd.service",
                                      "[Service]\nType=oneshot\n"
                                      "ExecStartPre=/bin/sh -c '" IS_NULL "'\n"
                                      "ExecStart=/bin/sh -c '" IS_NULL "'\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "plain.service",
                                      "[Service]\nType=oneshot\n"
                                      "ExecStartPre=/bin/sh -c '" IS_SOCKET "'\n"
                                      "ExecStart=/bin/sh -c '" IS_SOCKET "'\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "plain-journal.service",
                                      "[Service]\nType=oneshot\nStandardOutput=journal\n"
                                      "ExecStart=/bin/sh -c '" IS_SOCKET "'\n"),
                      0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);
        start_socket(m, "logd.socket");

        run_service(m, "plain.service", SERVICE_SUCCESS);
        run_service(m, "plain-journal.service", SERVICE_SUCCESS);
        run_service(m, "logd.service", SERVICE_SUCCESS);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A differently named service named by Service=, even one asking for the journal, is the reader too. */
static void test_paired_by_service_line(void) {
        Manager *m;
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "stdout.socket",
                                      "[Socket]\nListenDatagram=/run/logd/stdout\nService=reader.service\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "reader.service",
                                      "[Service]\nType=oneshot\nStandardOutput=journal\nStandardError=journal\n"
                                      "ExecStart=/bin/sh -c '" IS_NULL "'\n"),
                      0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);
        start_socket(m, "stdout.socket");

        run_service(m, "reader.service", SERVICE_SUCCESS);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

/* A socket at another path does not make its service a reader of logd's. */
static void test_other_socket_unaffected(void) {
        Manager *m;
        char *dir = test_tmpdir_new();

        ASSERT_TRUE(dir != NULL);
        ASSERT_EQ_INT(test_write_file(dir, "logd.socket", "[Socket]\nListenDatagram=/run/logd/stdout\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir, "other.socket", "[Socket]\nListenDatagram=/run/other\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir,
                                      "other.service",
                                      "[Service]\nType=oneshot\n"
                                      "ExecStart=/bin/sh -c '" IS_SOCKET "'\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(dir, "logd.service", "[Service]\nType=oneshot\nExecStart=/bin/true\n"),
                      0);

        m = manager_for(dir);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);
        start_socket(m, "logd.socket");
        start_socket(m, "other.socket");

        run_service(m, "other.service", SERVICE_SUCCESS);

        manager_free(m);
        test_rm_rf(dir);
        free(dir);
}

int main(void) {
        if (!test_enter_mount_namespace()) {
                fprintf(stderr, "test-service-stdout: no user and mount namespace, skipping\n");
                return 77;
        }
        if (mount("tmpfs", "/run", "tmpfs", 0, "mode=755") < 0) {
                fprintf(stderr,
                        "test-service-stdout: cannot mount a tmpfs on /run: %s, skipping\n",
                        strerror(errno));
                return 77;
        }

        test_paired_by_name();
        test_paired_by_service_line();
        test_other_socket_unaffected();

        printf("test-service-stdout: all checks passed\n");
        return 0;
}
