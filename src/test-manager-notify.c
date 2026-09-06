/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The sd_notify() listener (manager-notify.c): end-to-end wire protocol,
 * attribution and its CALLBACK CONTRACT drop-then-keep-listening property,
 * per-datagram malformed-input rejection, the child-environment injection
 * and scrub, teardown, and the not-fatal-to-boot setup-failure policy.
 *
 * No manager_startup()/default.target boilerplate here (unlike
 * test-manager-ctrl.c): every case either drives service_start() directly
 * (test-service.c's own pattern) or sets Service.main_pid as a plain field
 * write, so nothing needs a booted transaction and nothing needs root.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "manager-notify.h"
#include "manager-state.h"
#include "manager.h"
#include "sd-daemon.h"
#include "service.h"
#include "test-util.h"
#include "timer.h"
#include "unit.h"
#include "util.h"

/* --- manager_loop() driver, duplicated from test-manager-ctrl.c's own --- */

static Manager *g_drive_m;
static bool (*g_drive_done)(void *userdata);
static void *g_drive_ctx;
static int g_drive_ticks;
static int g_drive_max_ticks;

static void drive_tick(void *userdata, usec_t now) {
        (void) userdata;
        (void) now;

        g_drive_ticks++;

        if (g_drive_done(g_drive_ctx) || g_drive_ticks >= g_drive_max_ticks)
                g_drive_m->objective = MANAGER_EXIT;
        else
                ASSERT_EQ_INT(pico_timer_add(g_drive_m->timer,
                                             now_monotonic() + 5 * USEC_PER_MSEC,
                                             drive_tick,
                                             NULL,
                                             NULL),
                              0);
}

static bool drive_until(Manager *m, bool (*done)(void *), void *ctx, int max_ticks) {
        g_drive_m = m;
        g_drive_done = done;
        g_drive_ctx = ctx;
        g_drive_ticks = 0;
        g_drive_max_ticks = max_ticks;

        m->objective = MANAGER_RUNNING;

        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 5 * USEC_PER_MSEC, drive_tick, NULL, NULL), 0);
        manager_loop(m);

        return done(ctx);
}

static bool always_true(void *userdata) {
        (void) userdata;
        return true;
}

static bool notify_ready_done(void *userdata) {
        return ((Service *) userdata)->notify_ready;
}

static bool notify_n_unattributed_ge1(void *userdata) {
        return manager_notify_debug_n_unattributed((Manager *) userdata) >= 1;
}

/* --- fixture: no manager_startup(), no default.target -- see this file's header --- */

struct notify_fixture {
        char *unitdir;
        char *rtdir;
        Manager *m;
};

static void notify_fixture_setup(struct notify_fixture *f) {
        f->unitdir = test_tmpdir_new();
        f->rtdir = test_tmpdir_new();
        ASSERT_TRUE(f->unitdir != NULL && f->rtdir != NULL);

        ASSERT_EQ_INT(manager_new(&f->m), 0);
        {
                const char * const up[] = { f->unitdir, NULL };

                ASSERT_EQ_INT(manager_set_unit_path(f->m, up), 0);
        }
        ASSERT_EQ_INT(manager_set_runtime_dir(f->m, f->rtdir), 0);
        ASSERT_EQ_INT(manager_state_setup(f->m), 0); /* only test_notify_end_to_end_attributed reads it back */
        ASSERT_EQ_INT(manager_notify_setup(f->m), 0);
}

static void notify_fixture_teardown(struct notify_fixture *f) {
        manager_free(f->m); /* frees ctrl/state/notify too */
        test_rm_rf(f->unitdir);
        test_rm_rf(f->rtdir);
        free(f->unitdir);
        free(f->rtdir);
}

static Service *load_service(Manager *m, const char *dir, const char *name, const char *contents) {
        Unit *u;

        ASSERT_EQ_INT(test_write_file(dir, name, contents), 0);
        ASSERT_EQ_INT(manager_load_units(m, NULL), 0);

        u = manager_get_unit(m, name);
        ASSERT_TRUE(u != NULL);
        ASSERT_EQ_INT(u->type, UNIT_SERVICE);
        ASSERT_EQ_INT(u->load_state, UNIT_LOADED);

        return SERVICE(u);
}

/* --- a raw notify-socket client: one ephemeral socket per send --- */

static void notify_send(const char *rt, const void *data, size_t len) {
        struct sockaddr_un addr;
        char path[PATH_MAX];
        int fd, n;

        n = snprintf(path, sizeof(path), "%s/notify", rt);
        ASSERT_TRUE(n > 0 && (size_t) n < sizeof(path));

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        ASSERT_TRUE(strlen(path) < sizeof(addr.sun_path));
        memcpy(addr.sun_path, path, strlen(path) + 1);

        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT((int) sendto(fd, data, len, 0, (struct sockaddr *) &addr, sizeof(addr)), (int) len);
        close(fd);
}

static void notify_send_str(const char *rt, const char *s) {
        notify_send(rt, s, strlen(s));
}

/* --- tests --- */

/* Sends two real datagrams through the shim's own sd_notify() from a real
 * fork()ed child, attributed via kernel-filled SO_PASSCRED credentials for
 * a genuinely different pid. The second datagram pins the drain property
 * (manager-loop.c's zero-timeout re-poll): the done-predicate only becomes
 * true once BOTH have been processed, so a regression that stops draining
 * after the first would hang out to the tick budget instead of passing. */
static bool notify_second_status_done(void *userdata) {
        Service *s = userdata;

        return s->status_text != NULL && strcmp(s->status_text, "still running") == 0;
}

static void test_notify_end_to_end_attributed(void) {
        struct notify_fixture f;
        Service *s;
        pid_t child;
        char path[PATH_MAX];
        FILE *fp;
        char line[256];
        bool found_ready = false;

        notify_fixture_setup(&f);
        s = load_service(f.m, f.unitdir, "demo.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/true\n");

        child = fork();
        ASSERT_TRUE(child >= 0);
        if (child == 0) {
                setenv("NOTIFY_SOCKET", manager_notify_socket_path(f.m), 1);
                sd_notify(0, "READY=1\nSTATUS=up and running");
                sd_notify(0, "STATUS=still running");
                _exit(0);
        }

        /* Plain field write: no service_spawn() involved, so no root or real
         * ExecStart= is needed to test attribution itself. */
        s->main_pid = child;

        ASSERT_TRUE(drive_until(f.m, notify_second_status_done, s, 400));
        ASSERT_EQ_INT(s->notify_ready, true);
        ASSERT_STREQ(s->status_text, "still running");

        snprintf(path, sizeof(path), "%s/units/demo.service", f.rtdir);
        fp = fopen(path, "r");
        ASSERT_TRUE(fp != NULL);
        while (fgets(line, sizeof(line), fp))
                if (strcmp(line, "NotifyReady=yes\n") == 0)
                        found_ready = true;
        fclose(fp);
        ASSERT_TRUE(found_ready);

        waitpid(child, NULL, 0);
        notify_fixture_teardown(&f);
}

/* A sender no unit claims: dropped, counted, and -- the CALLBACK CONTRACT
 * proof -- the source keeps working afterward for a datagram that IS
 * attributed. */
static void test_notify_unattributed_harmless(void) {
        struct notify_fixture f;
        Service *s;

        notify_fixture_setup(&f);
        s = load_service(f.m, f.unitdir, "demo.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/true\n");

        notify_send_str(f.rtdir, "READY=1"); /* nobody's pid, sent as our own */

        ASSERT_TRUE(drive_until(f.m, notify_n_unattributed_ge1, f.m, 200));
        ASSERT_EQ_INT(manager_notify_debug_n_unattributed(f.m), 1);
        ASSERT_EQ_INT(s->notify_ready, false);

        s->main_pid = getpid();
        notify_send_str(f.rtdir, "READY=1");

        ASSERT_TRUE(drive_until(f.m, notify_ready_done, s, 200));
        ASSERT_EQ_INT(s->notify_ready, true);
        ASSERT_EQ_INT(manager_notify_debug_n_unattributed(f.m), 1); /* unchanged: this one attributed fine */

        notify_fixture_teardown(&f);
}

/* An unknown prefix ahead of a real key changes nothing but the real key. */
static void test_notify_unknown_key_harmless(void) {
        struct notify_fixture f;
        Service *s;

        notify_fixture_setup(&f);
        s = load_service(f.m, f.unitdir, "demo.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/true\n");
        s->main_pid = getpid();

        notify_send_str(f.rtdir, "FROBNICATE=1\nREADY=1");

        ASSERT_TRUE(drive_until(f.m, notify_ready_done, s, 200));
        ASSERT_EQ_INT(s->notify_ready, true);
        ASSERT_TRUE(s->status_text == NULL);
        ASSERT_EQ_INT(s->status_errno, 0);

        notify_fixture_teardown(&f);
}

/* An embedded-NUL datagram and an empty one are both dropped without
 * attribution or a crash, and a well-formed datagram sent right after is
 * still processed -- the drops are per-datagram, never sticky. */
static void test_notify_malformed_dropped(void) {
        struct notify_fixture f;
        Service *s;
        char embedded_nul[7] = { 'R', 'E', 'A', '\0', 'Y', '=', '1' };

        notify_fixture_setup(&f);
        s = load_service(f.m, f.unitdir, "demo.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/true\n");
        s->main_pid = getpid();

        notify_send(f.rtdir, embedded_nul, sizeof(embedded_nul));
        notify_send(f.rtdir, "", 0);
        notify_send_str(f.rtdir, "READY=1");

        ASSERT_TRUE(drive_until(f.m, notify_ready_done, s, 200));
        ASSERT_EQ_INT(s->notify_ready, true);

        notify_fixture_teardown(&f);
}

/* A real service_start(), a real fork/exec of a shell that echoes back
 * $NOTIFY_SOCKET -- proving injection happens, an inherited bogus value is
 * scrubbed rather than merely shadowed (getenv-first-match would hide
 * that), and the envp survives execve() intact. */
static bool notify_file_exists_done(void *userdata) {
        return access((const char *) userdata, F_OK) == 0;
}

static void test_notify_env_injection_and_scrub(void) {
        struct notify_fixture f;
        Service *s;
        char *outdir;
        char outpath[PATH_MAX];
        char contents[PATH_MAX + 128];
        char want[PATH_MAX];
        char got[PATH_MAX];
        FILE *fp;

        setenv("NOTIFY_SOCKET", "/bogus", 1); /* pollute the manager's own environ first */

        notify_fixture_setup(&f);

        outdir = test_tmpdir_new();
        ASSERT_TRUE(outdir != NULL);
        snprintf(outpath, sizeof(outpath), "%s/out", outdir);

        snprintf(contents,
                 sizeof(contents),
                 "[Unit]\n[Service]\nType=oneshot\nExecStart=/bin/sh -c \"printf %%s $NOTIFY_SOCKET > %s\"\n",
                 outpath);
        s = load_service(f.m, f.unitdir, "demo.service", contents);

        ASSERT_EQ_INT(service_start(s), 0);
        ASSERT_TRUE(drive_until(f.m, notify_file_exists_done, outpath, 400));

        fp = fopen(outpath, "r");
        ASSERT_TRUE(fp != NULL);
        ASSERT_TRUE(fgets(got, sizeof(got), fp) != NULL);
        fclose(fp);

        snprintf(want, sizeof(want), "%s/notify", f.rtdir);
        ASSERT_STREQ(got, want);

        unsetenv("NOTIFY_SOCKET");
        test_rm_rf(outdir);
        free(outdir);
        notify_fixture_teardown(&f);
}

/* Teardown really unlinks the socket, is idempotent, leaves nothing a
 * sender can still reach, and manager_free() completes cleanly after. */
static void test_notify_teardown_clean(void) {
        struct notify_fixture f;
        char path[PATH_MAX];
        struct stat st;
        struct sockaddr_un addr;
        int fd;

        notify_fixture_setup(&f);
        snprintf(path, sizeof(path), "%s/notify", f.rtdir);

        manager_notify_done(f.m);
        ASSERT_TRUE(stat(path, &st) < 0 && errno == ENOENT);
        ASSERT_TRUE(manager_notify_socket_path(f.m) == NULL);

        manager_notify_done(f.m); /* idempotent */

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        memcpy(addr.sun_path, path, strlen(path) + 1);
        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        ASSERT_TRUE(fd >= 0);
        ASSERT_TRUE(sendto(fd, "x", 1, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0);
        ASSERT_TRUE(errno == ENOENT || errno == ECONNREFUSED);
        close(fd);

        manager_free(f.m); /* nothing left behind to crash on */
        test_rm_rf(f.unitdir);
        test_rm_rf(f.rtdir);
        free(f.unitdir);
        free(f.rtdir);
}

/* runtime_dir pointing inside a nonexistent parent: setup fails, the socket
 * path stays NULL, and the manager still boots and spawns regardless --
 * the not-fatal-to-boot policy is real behavior, not just a comment.
 * Mirrors test-manager-state.c's own bogus-runtime fixture. */
static void test_notify_setup_failure_not_fatal(void) {
        Manager *m = NULL;
        char *unitdir, *blockdir;
        char bogus_runtime[PATH_MAX];
        Service *s;

        unitdir = test_tmpdir_new();
        blockdir = test_tmpdir_new();
        ASSERT_TRUE(unitdir != NULL && blockdir != NULL);

        ASSERT_EQ_INT(test_write_file(blockdir, "not-a-directory", ""), 0);
        snprintf(bogus_runtime, sizeof(bogus_runtime), "%s/not-a-directory", blockdir);

        ASSERT_EQ_INT(manager_new(&m), 0);
        {
                const char * const up[] = { unitdir, NULL };

                ASSERT_EQ_INT(manager_set_unit_path(m, up), 0);
        }
        ASSERT_EQ_INT(manager_set_runtime_dir(m, bogus_runtime), 0);

        ASSERT_TRUE(manager_notify_setup(m) < 0);
        ASSERT_TRUE(manager_notify_socket_path(m) == NULL);

        s = load_service(m, unitdir, "demo.service", "[Unit]\n[Service]\nType=simple\nExecStart=/bin/true\n");
        ASSERT_EQ_INT(service_start(s), 0);
        ASSERT_TRUE(s->main_pid > 0); /* Type=simple: started the moment it forked */

        ASSERT_TRUE(drive_until(m, always_true, NULL, 5)); /* the loop itself still runs fine */

        manager_free(m);
        test_rm_rf(unitdir);
        test_rm_rf(blockdir);
        free(unitdir);
        free(blockdir);
}

int main(void) {
        test_notify_end_to_end_attributed();
        test_notify_unattributed_harmless();
        test_notify_unknown_key_harmless();
        test_notify_malformed_dropped();
        test_notify_env_injection_and_scrub();
        test_notify_teardown_clean();
        test_notify_setup_failure_not_fatal();

        printf("test-manager-notify: all checks passed\n");
        return 0;
}
