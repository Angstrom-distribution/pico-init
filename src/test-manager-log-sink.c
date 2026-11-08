/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The manager's side of PID 1's log sink (manager_recheck_journal()): records
 * go to logd.socket's /dev/log only while logd.socket is RUNNING and
 * logd.service is active, and to /dev/kmsg otherwise. A fixture unit tree
 * stands in for the real logd units, a regular file for /dev/kmsg, and the
 * test reads the socket's queue through PID 1's own copy of the descriptor.
 *
 * What it guards against: PID 1 holds logd.socket, so a send succeeds while
 * logd is not running -- before it starts (self-activation), while it stops
 * (the re-armed socket drains and drops what arrives) and after it failed
 * (the queue is never read).
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cgroups-v2.h"
#include "manager.h"
#include "sd-event.h"
#include "service.h"
#include "socket.h"
#include "test-util.h"
#include "timer.h"
#include "unit.h"
#include "util.h"

typedef struct Fixture {
        Manager *m;
        char *dir;
        char kmsg_path[PATH_MAX];
        char cgroup_root[PATH_MAX];
        long kmsg_seen;
        Unit *sock;
        Unit *svc;
        char sock_seen[8192]; /* what the stand-in logd read from the socket */
} Fixture;

/*
 * A pid-tagged private cgroup root, as in test-manager-notify.c: the unit
 * names are fixed by manager_recheck_journal(), so without it a root run would
 * use the real system.slice/logd.service and concurrent runs would collide.
 */
static void use_private_cgroup_root(Manager *m, char *out, size_t out_size) {
        int n = snprintf(out, out_size, "/sys/fs/cgroup/pico-log-sink-test-%lld", (long long) getpid());

        ASSERT_TRUE(n > 0 && (size_t) n < out_size);
        if (mkdir(out, 0755) < 0)
                ASSERT_TRUE(errno == EEXIST);
        ASSERT_EQ_INT(manager_set_cgroup_root(m, out), 0);
}

/* Polls: a killed stand-in logd leaves its cgroup a moment after. */
static void free_private_cgroup_root(const char *root) {
        for (int i = 0; i < 100 && cgroup_v2_remove_tree(root) != 0; i++)
                usleep(50 * 1000);
}

/* `args` follows /bin/sh in ExecStart=; NULL runs the fixture's logd.sh. */
static Fixture fixture_new(const char *args, const char *restart) {
        const char *path[2];
        char text[2 * PATH_MAX], log_path[PATH_MAX];
        Fixture f = { 0 };

        f.dir = test_tmpdir_new();
        ASSERT_TRUE(f.dir != NULL);
        snprintf(log_path, sizeof(log_path), "%s/log", f.dir);
        snprintf(f.kmsg_path, sizeof(f.kmsg_path), "%s/kmsg", f.dir);
        ASSERT_EQ_INT(test_write_file(f.dir, "kmsg", ""), 0);

        snprintf(text, sizeof(text), "[Socket]\nListenDatagram=%s\n", log_path);
        ASSERT_EQ_INT(test_write_file(f.dir, "logd.socket", text), 0);
        if (args)
                snprintf(text,
                         sizeof(text),
                         "[Service]\nType=simple\nRestart=%s\nExecStart=/bin/sh %s\n",
                         restart,
                         args);
        else
                snprintf(text,
                         sizeof(text),
                         "[Service]\nType=simple\nRestart=%s\nExecStart=/bin/sh %s/logd.sh\n",
                         restart,
                         f.dir);
        ASSERT_EQ_INT(test_write_file(f.dir, "logd.service", text), 0);
        ASSERT_EQ_INT(test_write_file(f.dir,
                                      "logd.sh",
                                      "trap 'sleep 0.5; exit 0' TERM\nwhile :; do sleep 0.1; done\n"),
                      0);

        path[0] = f.dir;
        path[1] = NULL;
        ASSERT_EQ_INT(manager_new(&f.m), 0);
        use_private_cgroup_root(f.m, f.cgroup_root, sizeof(f.cgroup_root));
        ASSERT_EQ_INT(manager_set_unit_path(f.m, path), 0);
        ASSERT_EQ_INT(manager_load_units(f.m, NULL), 0);
        f.sock = manager_get_unit(f.m, "logd.socket");
        f.svc = manager_get_unit(f.m, "logd.service");
        ASSERT_TRUE(f.sock != NULL && f.svc != NULL);

        pico_log_to_journal_or_kmsg_at(log_path, f.kmsg_path);
        return f;
}

/*
 * A logd left running would keep its cgroup populated and un-removable. The
 * main pid goes first: right after unit_start() it may not have joined the
 * cgroup yet, and would escape the cgroup kill.
 */
static void fixture_kill_logd(Fixture *f) {
        if (SERVICE(f->svc)->main_pid > 0)
                (void) kill(SERVICE(f->svc)->main_pid, SIGKILL);
        if (SERVICE(f->svc)->cgroup)
                (void) cgroup_v2_kill(SERVICE(f->svc)->cgroup);
}

static void fixture_free(Fixture *f) {
        fixture_kill_logd(f);
        manager_free(f->m);
        free_private_cgroup_root(f->cgroup_root);
        pico_log_to_journal_or_kmsg_at(NULL, NULL);
        test_rm_rf(f->dir);
        free(f->dir);
}

/* What reached the stand-in for /dev/kmsg since the last call. */
static const char *kmsg_take(Fixture *f) {
        static char buf[8192];
        FILE *fp = fopen(f->kmsg_path, "re");
        size_t n;

        ASSERT_TRUE(fp != NULL);
        ASSERT_TRUE(fseek(fp, f->kmsg_seen, SEEK_SET) == 0);
        n = fread(buf, 1, sizeof(buf) - 1, fp);
        buf[n] = '\0';
        f->kmsg_seen += (long) n;
        fclose(fp);
        return buf;
}

/* All datagrams queued on logd.socket's /dev/log, newline-terminated. */
static const char *queue_take(Fixture *f) {
        static char buf[8192];
        size_t used = 0;
        int fd = SOCKET(f->sock)->ports->fd;

        buf[0] = '\0';
        if (fd < 0) /* a FAILED socket has closed its descriptors */
                return buf;
        for (;;) {
                ssize_t n = recv(fd, buf + used, sizeof(buf) - used - 2, MSG_DONTWAIT);

                if (n < 0) {
                        ASSERT_TRUE(errno == EAGAIN);
                        break;
                }
                used += (size_t) n;
                buf[used++] = '\n';
                buf[used] = '\0';
        }
        return buf;
}

typedef struct Wait {
        Manager *m;
        Unit *u;
        Fixture *reader;   /* drains the socket like a running logd, or NULL */
        bool until_active; /* wait for ACTIVE instead of down */
        pid_t old_pid;     /* with until_active: the main pid must differ */
} Wait;

/* Down is down: a TERM that beats the shell's trap ends it FAILED. */
static bool is_down(Unit *u) {
        UnitActiveState s = unit_active_state(u);

        return s == UNIT_INACTIVE || s == UNIT_FAILED;
}

/* The SIGKILL is reaped asynchronously: until then the old pid is still ACTIVE. */
static bool is_active_again(Wait *w) {
        return unit_active_state(w->u) == UNIT_ACTIVE && SERVICE(w->u)->main_pid > 0 &&
                        SERVICE(w->u)->main_pid != w->old_pid;
}

static void wait_tick(void *userdata, usec_t now) {
        Wait *w = userdata;

        if (w->reader) {
                size_t used = strlen(w->reader->sock_seen);

                snprintf(w->reader->sock_seen + used,
                         sizeof(w->reader->sock_seen) - used,
                         "%s",
                         queue_take(w->reader));
        }
        if (w->until_active ? is_active_again(w) : is_down(w->u))
                w->m->objective = MANAGER_EXIT;
        else
                ASSERT_EQ_INT(pico_timer_add(w->m->timer, now + 20 * 1000, wait_tick, w, NULL), 0);
}

static void give_up(void *userdata, usec_t now) {
        Manager *m = userdata;

        (void) now;
        m->objective = MANAGER_EXIT;
}

/* Run the loop until `u` is down; the 5s timer ends a run where it never is. */
static void run_until_down_reading(Manager *m, Unit *u, Fixture *reader) {
        Wait w = { .m = m, .u = u, .reader = reader };

        m->objective = MANAGER_RUNNING;
        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 5 * USEC_PER_SEC, give_up, m, NULL), 0);
        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 20 * 1000, wait_tick, &w, NULL), 0);
        ASSERT_EQ_INT(manager_loop(m), MANAGER_EXIT);
        ASSERT_TRUE(is_down(u));
}

/* Run the loop until `u` is ACTIVE under a new main pid, as after an automatic restart. */
static void run_until_active(Manager *m, Unit *u, pid_t old_pid) {
        Wait w = { .m = m, .u = u, .until_active = true, .old_pid = old_pid };

        m->objective = MANAGER_RUNNING;
        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 5 * USEC_PER_SEC, give_up, m, NULL), 0);
        ASSERT_EQ_INT(pico_timer_add(m->timer, now_monotonic() + 20 * 1000, wait_tick, &w, NULL), 0);
        ASSERT_EQ_INT(manager_loop(m), MANAGER_EXIT);
        ASSERT_EQ_INT(unit_active_state(u), UNIT_ACTIVE);
}

static void run_until_down(Manager *m, Unit *u) {
        run_until_down_reading(m, u, NULL);
}

/* Before logd starts, with logd.socket already bound: no datagram queues. */
static void test_kmsg_before_logd_runs(void) {
        Fixture f = fixture_new(NULL, "no");

        ASSERT_EQ_INT(unit_start(f.sock), 0);
        ASSERT_EQ_INT(SOCKET(f.sock)->state, SOCKET_LISTENING);
        (void) kmsg_take(&f);

        pico_log(PICO_LOG_INFO, "probe-before");
        ASSERT_TRUE(strstr(kmsg_take(&f), "<6>pico-init[info]: probe-before\n") != NULL);
        ASSERT_STREQ(queue_take(&f), "");

        fixture_free(&f);
}

/* While logd.socket is RUNNING and logd.service active, records go to the socket. */
static void test_socket_while_logd_runs(void) {
        Fixture f = fixture_new(NULL, "no");

        ASSERT_EQ_INT(unit_start(f.sock), 0);
        ASSERT_EQ_INT(unit_start(f.svc), 0);
        ASSERT_EQ_INT(SOCKET(f.sock)->state, SOCKET_RUNNING);
        ASSERT_EQ_INT(unit_active_state(f.svc), UNIT_ACTIVE);
        (void) kmsg_take(&f);
        (void) queue_take(&f);

        pico_log(PICO_LOG_WARNING, "probe-running");
        ASSERT_STREQ(queue_take(&f), "<4>pico-init[warning]: probe-running\n");
        ASSERT_STREQ(kmsg_take(&f), "");

        ASSERT_EQ_INT(unit_stop(f.svc), 0);
        run_until_down(f.m, f.svc);
        fixture_free(&f);
}

/* daemon-reload re-parses logd's units through scratch copies; the gate stays open. */
static void test_socket_after_reload(void) {
        Fixture f = fixture_new(NULL, "no");

        ASSERT_EQ_INT(unit_start(f.sock), 0);
        ASSERT_EQ_INT(unit_start(f.svc), 0);
        ASSERT_EQ_INT(SOCKET(f.sock)->state, SOCKET_RUNNING);

        ASSERT_TRUE(manager_reload(f.m) >= 0);
        ASSERT_EQ_INT(SOCKET(f.sock)->state, SOCKET_RUNNING);
        ASSERT_EQ_INT(unit_active_state(f.svc), UNIT_ACTIVE);
        (void) kmsg_take(&f);
        (void) queue_take(&f);

        pico_log(PICO_LOG_INFO, "probe-after-reload");
        ASSERT_STREQ(queue_take(&f), "<6>pico-init[info]: probe-after-reload\n");
        ASSERT_STREQ(kmsg_take(&f), "");

        ASSERT_EQ_INT(unit_stop(f.svc), 0);
        run_until_down(f.m, f.svc);
        fixture_free(&f);
}

/*
 * Stop of logd: from the moment logd.service leaves ACTIVE, and after the
 * socket is re-armed to LISTENING, PID 1's records must reach /dev/kmsg, the
 * only reader left. The transition record itself already takes that route.
 */
static void test_kmsg_while_logd_stops(void) {
        Fixture f = fixture_new(NULL, "no");

        ASSERT_EQ_INT(unit_start(f.sock), 0);
        ASSERT_EQ_INT(unit_start(f.svc), 0);
        usleep(200 * 1000); /* the shell installs its TERM trap */
        (void) kmsg_take(&f);
        (void) queue_take(&f);

        ASSERT_EQ_INT(unit_stop(f.svc), 0);
        ASSERT_EQ_INT(unit_active_state(f.svc), UNIT_DEACTIVATING);
        ASSERT_EQ_INT(SOCKET(f.sock)->state, SOCKET_RUNNING);
        ASSERT_TRUE(strstr(kmsg_take(&f), "logd.service: active -> deactivating") != NULL);
        pico_log(PICO_LOG_INFO, "probe-stopping");
        ASSERT_TRUE(strstr(kmsg_take(&f), "probe-stopping") != NULL);
        ASSERT_STREQ(queue_take(&f), "");

        run_until_down(f.m, f.svc);
        ASSERT_EQ_INT(SOCKET(f.sock)->state, SOCKET_LISTENING);
        (void) kmsg_take(&f);
        pico_log(PICO_LOG_INFO, "probe-rearmed");
        ASSERT_TRUE(strstr(kmsg_take(&f), "probe-rearmed") != NULL);
        ASSERT_STREQ(queue_take(&f), "");

        fixture_free(&f);
}

/*
 * A logd that fails: the record of its exit and PID 1's later records go to
 * the ring, none to the socket, and the socket is not re-activated.
 */
static void test_kmsg_when_logd_failed(void) {
        Fixture f = fixture_new("-c \"sleep 0.1; exit 3\"", "no");
        const char *got, *first;

        ASSERT_EQ_INT(unit_start(f.sock), 0);
        (void) kmsg_take(&f);
        ASSERT_EQ_INT(unit_start(f.svc), 0);
        run_until_down_reading(f.m, f.svc, &f);

        got = kmsg_take(&f);
        first = strstr(got, "-> activating");
        ASSERT_TRUE(first != NULL);
        ASSERT_TRUE(strstr(first + 1, "-> activating") == NULL);
        ASSERT_TRUE(strstr(f.sock_seen, "main process exited") == NULL);
        ASSERT_TRUE(strstr(got, "logd.service: main process exited, code=exited, status=3") != NULL);
        ASSERT_STREQ(queue_take(&f), "");
        ASSERT_EQ_INT(SOCKET(f.sock)->state, SOCKET_LISTENING);

        pico_log(PICO_LOG_ERR, "probe-failed");
        ASSERT_TRUE(strstr(kmsg_take(&f), "<3>pico-init[err]: probe-failed\n") != NULL);
        ASSERT_STREQ(queue_take(&f), "");

        fixture_free(&f);
}

/* A logd stopped and started again gets a fresh connection and the gate reopens. */
static void test_reopen_after_restart(void) {
        Fixture f = fixture_new(NULL, "no");

        ASSERT_EQ_INT(unit_start(f.sock), 0);
        ASSERT_EQ_INT(unit_start(f.svc), 0);
        usleep(200 * 1000); /* the shell installs its TERM trap */
        pico_log(PICO_LOG_INFO, "probe-first");
        (void) queue_take(&f); /* an unread queue would re-activate logd once the socket is re-armed */
        ASSERT_EQ_INT(unit_stop(f.svc), 0);
        run_until_down(f.m, f.svc);
        ASSERT_EQ_INT(SOCKET(f.sock)->state, SOCKET_LISTENING);
        (void) kmsg_take(&f);
        (void) queue_take(&f);

        ASSERT_EQ_INT(unit_start(f.svc), 0);
        ASSERT_EQ_INT(SOCKET(f.sock)->state, SOCKET_RUNNING);
        ASSERT_EQ_INT(unit_active_state(f.svc), UNIT_ACTIVE);
        (void) kmsg_take(&f);
        (void) queue_take(&f);

        pico_log(PICO_LOG_INFO, "probe-restarted");
        ASSERT_STREQ(queue_take(&f), "<6>pico-init[info]: probe-restarted\n");
        ASSERT_STREQ(kmsg_take(&f), "");

        ASSERT_EQ_INT(unit_stop(f.svc), 0);
        run_until_down(f.m, f.svc);
        fixture_free(&f);
}

/* A logd that crashes and is restarted by Restart=always: kmsg in between, logd after. */
static void test_reopen_after_crash(void) {
        Fixture f = fixture_new(NULL, "always");
        pid_t old_pid;

        ASSERT_EQ_INT(unit_start(f.sock), 0);
        ASSERT_EQ_INT(unit_start(f.svc), 0);
        old_pid = SERVICE(f.svc)->main_pid;
        ASSERT_TRUE(old_pid > 0);
        pico_log(PICO_LOG_INFO, "probe-before-crash");
        (void) kmsg_take(&f);
        (void) queue_take(&f);

        ASSERT_EQ_INT(kill(old_pid, SIGKILL), 0);
        run_until_active(f.m, f.svc, old_pid);
        ASSERT_TRUE(SERVICE(f.svc)->main_pid > 0 && SERVICE(f.svc)->main_pid != old_pid);
        ASSERT_EQ_INT(SOCKET(f.sock)->state, SOCKET_RUNNING);
        ASSERT_TRUE(strstr(kmsg_take(&f), "logd.service: main process exited") != NULL);
        (void) queue_take(&f);

        pico_log(PICO_LOG_INFO, "probe-after-crash");
        ASSERT_STREQ(queue_take(&f), "<6>pico-init[info]: probe-after-crash\n");
        ASSERT_STREQ(kmsg_take(&f), "");

        ASSERT_EQ_INT(unit_stop(f.svc), 0);
        run_until_down(f.m, f.svc);
        fixture_free(&f);
}

/* Freeing logd's units closes the gate while they still look running. */
static void test_gate_closes_with_the_manager(void) {
        Fixture f = fixture_new(NULL, "no");

        ASSERT_EQ_INT(unit_start(f.sock), 0);
        ASSERT_EQ_INT(unit_start(f.svc), 0);
        ASSERT_EQ_INT(SOCKET(f.sock)->state, SOCKET_RUNNING);

        fixture_kill_logd(&f);
        f.m = manager_free(f.m);
        free_private_cgroup_root(f.cgroup_root);
        (void) kmsg_take(&f);
        pico_log(PICO_LOG_INFO, "probe-gone");
        ASSERT_TRUE(strstr(kmsg_take(&f), "probe-gone") != NULL);

        pico_log_to_journal_or_kmsg_at(NULL, NULL);
        test_rm_rf(f.dir);
        free(f.dir);
}

int main(void) {
        test_kmsg_before_logd_runs();
        test_socket_while_logd_runs();
        test_socket_after_reload();
        test_kmsg_while_logd_stops();
        test_kmsg_when_logd_failed();
        test_reopen_after_restart();
        test_reopen_after_crash();
        test_gate_closes_with_the_manager();

        printf("test-manager-log-sink: all cases passed\n");
        return 0;
}
