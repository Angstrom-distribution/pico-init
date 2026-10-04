/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The picoctl control socket (plan §1.7, milestone C2). See manager-ctrl.h
 * for the contract; this is the real body.
 *
 * Wire protocol, deliberately tiny: one request per connection, a single
 * text line "PICO1 <verb> <unit>[ --no-block]" parsed out of a fixed
 * PICO_CTRL_LINE_MAX-byte on-stack buffer with strict single-space
 * tokenization -- no allocation is ever derived from client bytes. Verbs:
 * start/stop/restart map 1:1 onto manager_add_job()'s JobTypes; reset-failed
 * is a direct action, no job involved. Replies are one line each: "ok ..."
 * or "err <reason>". start/stop/restart replies are DEFERRED until the job
 * finishes (job_finish_full() calls manager_ctrl_notify_job_finished()) so
 * picoctl's exit code reports the real result, not mere enqueueing --
 * --no-block skips the wait and replies "ok queued" immediately instead.
 *
 * The deferred-reply record is keyed by job id, never by Job*: every Job is
 * one malloc size class, so a stale pointer could be handed a *different*
 * job's result once the original is freed and the slot reused -- worse than
 * a hang. job_install()'s displacement path (a second request racing an
 * in-flight job on the same unit) already finishes the old job as
 * JOB_CANCELED through the same job_finish_full() choke point, so it needs
 * no special-casing here: it resolves the first client's pending record with
 * "err canceled" the same way any other finish does.
 *
 * PID 1 must never block on a client: the listening fd and every accepted
 * connection are SOCK_NONBLOCK, every reply write is MSG_DONTWAIT, and a
 * client that never reads its reply just never gets one -- it does not wedge
 * the loop. Connections and pending records are both intrusive lists rather
 * than anything that allocates on lookup; the accepted-connection count is
 * capped at PICO_CTRL_MAX_CONNS, beyond which a new connection is accepted
 * (draining the listen backlog) and immediately rejected with
 * "err too-many-connections" rather than tracked. Once a shutdown is pending,
 * start/restart are refused with "err shutting-down".
 *
 * daemon-reload is the one verb with no <unit> token at all ("PICO1
 * daemon-reload"): a direct, synchronous call into manager_reload() (unit-
 * reload.c), answered immediately. Real `systemctl daemon-reload` is
 * synchronous too (it returns once the manager has re-read unit files), and
 * there is no job engine step to ever defer this one onto.
 */

/* accept4()/SOCK_SEQPACKET/struct ucred/MSG_TRUNC-on-a-UNIX-socket are
 * glibc/Linux extensions guarded by __USE_GNU; -std=gnu17 alone does not
 * imply _GNU_SOURCE (socket.c's own note, same reasoning here), so this has
 * to be explicit and first, before any header pulls in <sys/socket.h> under
 * a narrower feature-test setting. */
#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "job.h"
#include "manager-ctrl.h"
#include "manager.h"
#include "sd-event.h"
#include "service.h"
#include "socket.h"
#include "unit.h"
#include "util.h"

/* The whole request, on the wire, in one fixed on-stack buffer -- see this
 * file's header for why nothing here ever allocates from client bytes. */
#define PICO_CTRL_LINE_MAX 512

/*
 * How many accepted-but-not-yet-freed connections this ctrl instance tracks
 * at once. picoctl invocations are short-lived one-shot CLI runs, so this
 * many concurrent in-flight requests is generous for an on-device admin
 * tool and cheap to hold -- each tracked connection is a handful of words.
 * Beyond it, ctrl_accept() still accept()s (so the listen backlog keeps
 * draining) but replies "err too-many-connections" and closes immediately,
 * never adding to the tracked set.
 */
#define PICO_CTRL_MAX_CONNS 16

struct ctrl_pending {
        uint32_t job_id;
        struct ctrl_conn *conn; /* borrowed; NULL exactly when nothing owns this record any more */
        struct ctrl_pending *next;
};

struct ctrl_conn {
        sd_event_source *source; /* io on fd, EVENT_PRIORITY_CTRL, io_fd_own: DEL+close ride its teardown */
        int fd;

        struct pico_manager_ctrl *ctrl; /* owning ctrl, borrowed */
        struct ctrl_conn *next, *prev;  /* intrusive list, ctrl->conns */

        /*
         * Set once a start/stop/restart request has been parsed and its
         * reply deferred; NULL while still awaiting the one request, and
         * NULL again once the pending record has been resolved one way or
         * another -- see ctrl_conn_free() and manager_ctrl_notify_job_
         * finished() for the two paths that clear it.
         */
        struct ctrl_pending *pending;
};

struct pico_manager_ctrl {
        Manager *manager;

        sd_event_source *listen_source; /* io on the listening fd, EVENT_PRIORITY_CTRL, io_fd_own */
        char *socket_path;              /* owned, unlinked at teardown */

        struct ctrl_conn *conns;
        size_t n_conns;

        struct ctrl_pending *pending;
};

/* --- teardown plumbing --- */

/* Unlink `p` from ctrl->pending and free it. Never touches p->conn -- the
 * two callers each already know what they need to do with it. */
static void ctrl_pending_unlink(struct pico_manager_ctrl *ctrl, struct ctrl_pending *p) {
        struct ctrl_pending **pp = &ctrl->pending;

        while (*pp) {
                if (*pp == p) {
                        *pp = p->next;
                        break;
                }
                pp = &(*pp)->next;
        }

        free(p);
}

/*
 * Unregister, close, unlink from ctrl->conns, and free -- the one exit path
 * every connection goes through, whichever of the several reasons got it
 * here, safe even from inside this very connection's own dispatch. A still-
 * pending deferred reply loses its home right here: the job itself is
 * unaffected (nothing in job.c is tied to this connection), but nobody is
 * listening for the result any more, which is exactly "a client disconnect
 * just drops the pending record" (plan §1.7).
 *
 * No dead-list, no deferred free: the shim's own source refcounting is the
 * deferral now. disable_unref() drops this connection's own ref; if the
 * shim is mid-dispatch on conn->source right now (this function reached from
 * inside that very source's own callback), sd_event_dispatch()'s own extra
 * ref around the callback keeps the sd_event_source struct alive until the
 * callback returns -- but conn->source's `enabled` is already OFF by then,
 * so it can never be dispatched again, and event_source_free() never reads
 * userdata (conn) at all. So conn itself can be freed immediately: nothing
 * still alive ever dereferences it again. io_fd_own means EPOLL_CTL_DEL and
 * close() ride the source's own teardown, always in that order (5dcadb4c83).
 *
 * If instead this runs from a DIFFERENT source's callback (e.g.
 * manager_ctrl_notify_job_finished() reached via a SIGCHLD dispatch, while
 * conn's own EPOLLHUP sits pending later in the same batch), conn->source
 * holds no other ref and is unlinked from e->sources right here -- so that
 * later dispatch of the same batch, which walks the live list fresh, simply
 * never finds it. Nothing dispatches into freed memory either way.
 */
static void ctrl_conn_free(struct ctrl_conn *conn) {
        struct pico_manager_ctrl *ctrl;

        if (!conn)
                return;

        ctrl = conn->ctrl;

        if (conn->pending) {
                ctrl_pending_unlink(ctrl, conn->pending);
                conn->pending = NULL;
        }

        if (conn->prev)
                conn->prev->next = conn->next;
        else
                ctrl->conns = conn->next;
        if (conn->next)
                conn->next->prev = conn->prev;

        ctrl->n_conns--;

        conn->source = sd_event_source_disable_unref(conn->source);
        free(conn);
}

/* Best-effort, never blocking: MSG_DONTWAIT so a full send buffer (a client
 * that never reads) drops the reply rather than wedging PID 1, MSG_NOSIGNAL
 * so a peer that already closed cannot deliver SIGPIPE to PID 1 itself. */
static void ctrl_send_line(int fd, const char *text) {
        send(fd, text, strlen(text), MSG_DONTWAIT | MSG_NOSIGNAL);
}

static void ctrl_send_err(int fd, const char *reason) {
        char line[80];

        snprintf(line, sizeof(line), "err %s\n", reason);
        ctrl_send_line(fd, line);
}

/* --- request parsing: strict single-space tokenization, no allocation --- */

struct ctrl_word {
        const char *p;
        size_t len;
};

/* An empty token (a run of more than one space) is rejected the same way as
 * running out of buffer -- both mean "the grammar does not parse", and no
 * caller needs to tell the two apart any more finely than that. */
static bool ctrl_next_word(const char **p, const char *end, struct ctrl_word *w) {
        const char *sp;

        if (*p >= end)
                return false;

        sp = memchr(*p, ' ', (size_t) (end - *p));
        w->p = *p;
        w->len = sp ? (size_t) (sp - *p) : (size_t) (end - *p);
        *p = sp ? sp + 1 : end;

        return w->len > 0;
}

static bool ctrl_word_is(const struct ctrl_word *w, const char *s) {
        size_t slen = strlen(s);

        return w->len == slen && memcmp(w->p, s, slen) == 0;
}

typedef enum {
        CTRL_VERB_START,
        CTRL_VERB_STOP,
        CTRL_VERB_RESTART,
        CTRL_VERB_RESET_FAILED,
        CTRL_VERB_DAEMON_RELOAD,
        _CTRL_VERB_INVALID,
} CtrlVerb;

static CtrlVerb ctrl_verb_parse(const struct ctrl_word *w) {
        if (ctrl_word_is(w, "start"))
                return CTRL_VERB_START;
        if (ctrl_word_is(w, "stop"))
                return CTRL_VERB_STOP;
        if (ctrl_word_is(w, "restart"))
                return CTRL_VERB_RESTART;
        if (ctrl_word_is(w, "reset-failed"))
                return CTRL_VERB_RESET_FAILED;
        if (ctrl_word_is(w, "daemon-reload"))
                return CTRL_VERB_DAEMON_RELOAD;

        return _CTRL_VERB_INVALID;
}

static JobType ctrl_verb_job_type(CtrlVerb v) {
        switch (v) {
        case CTRL_VERB_START:
                return JOB_START;
        case CTRL_VERB_STOP:
                return JOB_STOP;
        case CTRL_VERB_RESTART:
                return JOB_RESTART;
        default:
                return _JOB_TYPE_INVALID;
        }
}

struct ctrl_request {
        CtrlVerb verb;
        char unit[UNIT_NAME_MAX + 1];
        bool no_block;
};

/*
 * Parse exactly "PICO1 <verb> <unit>" or "...<unit> --no-block" out of
 * buf[0..len) -- or, for daemon-reload alone, "PICO1 daemon-reload" with no
 * third token at all, since there is no unit to name. NULL on success (with
 * *out filled); a short static reason string on any grammar violation.
 * Never allocates: `buf` is the caller's fixed on-stack buffer, out->unit is
 * a fixed on-stack field sized off UNIT_NAME_MAX, and unit_name_is_valid()
 * is the same validator every other unit-name-carrying path in this project
 * already uses.
 */
static const char *ctrl_parse_request(const char *buf, size_t len, struct ctrl_request *out) {
        const char *p = buf, *end = buf + len;
        struct ctrl_word w;

        if (!ctrl_next_word(&p, end, &w) || !ctrl_word_is(&w, "PICO1"))
                return "bad-magic";

        if (!ctrl_next_word(&p, end, &w))
                return "missing-verb";
        out->verb = ctrl_verb_parse(&w);
        if (out->verb == _CTRL_VERB_INVALID)
                return "unknown-verb";

        out->unit[0] = '\0';
        out->no_block = false;
        if (out->verb == CTRL_VERB_DAEMON_RELOAD)
                return p < end ? "malformed" : NULL; /* no unit, no --no-block */

        if (!ctrl_next_word(&p, end, &w))
                return "missing-unit";
        if (w.len > UNIT_NAME_MAX)
                return "unit-name-too-long";
        memcpy(out->unit, w.p, w.len);
        out->unit[w.len] = '\0';
        if (!unit_name_is_valid(out->unit))
                return "bad-unit";

        out->no_block = false;
        if (p < end) {
                /* --no-block has nowhere to apply on an already-immediate
                 * verb; a fourth token here is simply malformed. */
                if (out->verb == CTRL_VERB_RESET_FAILED)
                        return "malformed";
                if (!ctrl_next_word(&p, end, &w) || !ctrl_word_is(&w, "--no-block"))
                        return "malformed";
                out->no_block = true;
                if (p < end)
                        return "malformed"; /* trailing garbage past --no-block */
        }

        return NULL;
}

/* --- reset-failed: a direct action, no job engine involved --- */

/*
 * There is no exported "clear FAILED" entry point in service.c/socket.c
 * (both frozen for this milestone, and neither has one -- service_set_
 * state()/socket_set_state() are file-static). This mirrors exactly what
 * each would have done: recompute the active-state transition and call the
 * same unit_notify() they would have called, directly. Both FAILED-entry
 * paths already cancel any pending timer/close any fds before setting
 * FAILED (service_enter_dead()/service_do_start()'s start-limit branch;
 * socket_enter_failed()), so there is nothing left running to reconcile --
 * this only ever touches the two fields each state machine itself derives
 * ActiveState from. A unit that is not FAILED is a harmless no-op success,
 * matching real systemctl reset-failed.
 */
static const char *ctrl_reset_failed(Unit *u) {
        if (unit_active_state(u) != UNIT_FAILED)
                return NULL;

        switch (u->type) {
        case UNIT_SERVICE: {
                Service *s = SERVICE(u);

                s->result = SERVICE_SUCCESS;
                s->start_limit_begin = 0;
                s->start_limit_num = 0;
                s->state = SERVICE_DEAD;
                unit_notify(u, UNIT_FAILED, UNIT_INACTIVE);
                return NULL;
        }

        case UNIT_SOCKET: {
                Socket *sk = SOCKET(u);

                sk->trigger_ratelimit_begin = 0;
                sk->trigger_ratelimit_num = 0;
                sk->state = SOCKET_DEAD;
                unit_notify(u, UNIT_FAILED, UNIT_INACTIVE);
                return NULL;
        }

        default:
                /* Targets never reach UNIT_FAILED (target.c has no failure
                 * path), so this is unreachable in practice; refuse rather
                 * than guess at a reset no unit of this type was ever
                 * designed to need. */
                return "cannot-reset";
        }
}

/* --- start/stop/restart: enqueue, then defer or reply immediately --- */

/* No edge from u, and no edge to u from any unit in the table. */
static bool ctrl_unit_is_unreferenced(Manager *m, Unit *u) {
        size_t i;
        int d;

        for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++)
                if (u->n_dependencies[d] > 0)
                        return false;

        for (i = 0; i < m->n_units; i++)
                for (d = 0; d < _UNIT_DEPENDENCY_MAX; d++)
                        if (unit_has_dependency(m->units[i], d, u))
                                return false;

        return true;
}

static void ctrl_handle_request(struct ctrl_conn *conn, const char *buf, size_t len) {
        struct pico_manager_ctrl *ctrl = conn->ctrl;
        struct ctrl_request req;
        const char *err;
        Unit *u;

        err = ctrl_parse_request(buf, len, &req);
        if (err) {
                ctrl_send_err(conn->fd, err);
                ctrl_conn_free(conn);
                return;
        }

        /* No unit, no job, nothing to defer: answered on the spot, exactly
         * like reset-failed, just with manager_reload() as the action. */
        if (req.verb == CTRL_VERB_DAEMON_RELOAD) {
                int r = manager_reload(ctrl->manager);

                if (r < 0) {
                        char line[96];

                        snprintf(line, sizeof(line), "err reload-failed: %s\n", strerror(-r));
                        ctrl_send_line(conn->fd, line);
                } else
                        ctrl_send_line(conn->fd, "ok\n");
                ctrl_conn_free(conn);
                return;
        }

        /* manager_shutdown() cancelled every start; do not queue new ones. */
        if (ctrl->manager->pending_objective != MANAGER_RUNNING &&
            (req.verb == CTRL_VERB_START || req.verb == CTRL_VERB_RESTART)) {
                ctrl_send_err(conn->fd, "shutting-down");
                ctrl_conn_free(conn);
                return;
        }

        u = manager_get_unit(ctrl->manager, req.unit);

        /*
         * The instancing entry point: "picoctl start serial-getty@ttyUSB0.
         * service" against a tty no unit file was ever shipped for. stop/
         * reset-failed deliberately do not fall back -- loading a unit in
         * order to stop or reset one that was never running is nonsense,
         * and would otherwise let an unauthenticated-by-name typo silently
         * create a table entry on every miss.
         *
         * A template id never reaches here: ctrl_parse_request() already
         * validated req.unit through unit_name_is_valid(), and manager_
         * load_unit() itself refuses a template with -EINVAL, so
         * "picoctl start foo@.service" falls straight into the no-such-unit
         * reply below with the real reason logged at WARNING.
         */
        if (!u && (req.verb == CTRL_VERB_START || req.verb == CTRL_VERB_RESTART)) {
                if (manager_load_unit(ctrl->manager, req.unit, &u) < 0)
                        u = NULL;
                else if (u && u->load_state != UNIT_LOADED) {
                        /*
                         * manager_load_unit() returns 0 with *ret set even
                         * when no fragment was found -- the node lands in
                         * UNIT_ERROR. Left in the table, "start
                         * nonexistent.service" would reply "ok" today and
                         * leave a permanent UNIT_ERROR node for every future
                         * manager_apply_presets()/manager_dispatch_run_
                         * queue()/manager_free() pass to walk -- a
                         * client-driven table leak the parse path never had,
                         * since the ctrl socket lets anyone with a shell
                         * spell a unit name that was never going to exist.
                         *
                         * Removed only while nothing has an edge to it, the
                         * one condition manager_remove_unit() allows (see its
                         * header). With no fragment at all that always holds.
                         * A fragment that parsed but then failed validation
                         * had its After=/Before= applied during the parse,
                         * inverse edges in its peers included, so that node
                         * stays in the table as UNIT_ERROR.
                         */
                        if (ctrl_unit_is_unreferenced(ctrl->manager, u))
                                manager_remove_unit(ctrl->manager, u);
                        u = NULL;
                }
        }

        if (!u) {
                ctrl_send_err(conn->fd, "no-such-unit");
                ctrl_conn_free(conn);
                return;
        }

        if (req.verb == CTRL_VERB_RESET_FAILED) {
                const char *reset_err = ctrl_reset_failed(u);

                if (reset_err)
                        ctrl_send_err(conn->fd, reset_err);
                else
                        ctrl_send_line(conn->fd, "ok\n");
                ctrl_conn_free(conn);
                return;
        }

        {
                JobType type = ctrl_verb_job_type(req.verb);
                Job *job = NULL;
                struct ctrl_pending *pending;
                int r = manager_add_job(ctrl->manager, type, u, &job);

                if (r < 0) {
                        char line[96];

                        snprintf(line, sizeof(line), "err enqueue-failed: %s\n", strerror(-r));
                        ctrl_send_line(conn->fd, line);
                        ctrl_conn_free(conn);
                        return;
                }

                if (req.no_block) {
                        ctrl_send_line(conn->fd, "ok queued\n");
                        ctrl_conn_free(conn);
                        return;
                }

                /*
                 * Defer: manager_add_job() only installs the job onto the
                 * run queue (job_run() happens later, out of manager_
                 * dispatch_run_queue()), so `job` is guaranteed alive and
                 * still JOB_WAITING here -- reading job->id is never a
                 * use-after-free. The reply is written only once job_
                 * finish_full() reports the real result (manager_ctrl_
                 * notify_job_finished(), below), which is what makes the
                 * exit code the real job result rather than mere
                 * enqueueing (systemctl's own default wait behaviour).
                 */
                pending = calloc(1, sizeof(*pending));
                if (!pending) {
                        /* The job is already enqueued and will run
                         * regardless -- tell the truth about what can no
                         * longer be promised rather than silently drop the
                         * connection while it is still live. */
                        ctrl_send_err(conn->fd, "out-of-memory");
                        ctrl_conn_free(conn);
                        return;
                }

                /*
                 * manager_add_job() can reach job_finish_full() (a displaced
                 * job) and so into ctrl_conn_free() for SOME connection --
                 * but never THIS one: it owns no pending record yet, so
                 * manager_ctrl_notify_job_finished()'s job_id lookup cannot
                 * find it to free. conn is guaranteed still alive here.
                 */
                pending->job_id = job->id;
                pending->conn = conn;
                pending->next = ctrl->pending;
                ctrl->pending = pending;
                conn->pending = pending;
        }
}

/* --- accept / per-connection dispatch --- */

static int ctrl_conn_io_cb(sd_event_source *es, int fd, uint32_t revents, void *userdata);

/*
 * The listen_source io callback (EVENT_PRIORITY_CTRL). Never returns < 0: a
 * transient accept4() error must not permanently stop listening.
 */
static int ctrl_accept(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        struct pico_manager_ctrl *ctrl = userdata;

        (void) es;
        (void) revents;

        for (;;) {
                int cfd, r;
                struct ucred cred;
                socklen_t credlen = sizeof(cred);
                struct ctrl_conn *conn;

                cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (cfd < 0) {
                        if (errno == EAGAIN)
                                return 0;
                        if (errno == ECONNABORTED || errno == EINTR)
                                continue;
                        pico_log(PICO_LOG_WARNING, "picoctl accept: %s", strerror(errno));
                        return 0;
                }

                /*
                 * The peercred gate: compared against the manager's own
                 * euid, NOT a hardcoded 0. Identical in production, where
                 * PID 1 is uid 0 -- the difference is what makes this
                 * milestone testable at all, since `meson test` runs as an
                 * ordinary user and a hardcoded 0 would reject the test
                 * suite's own client (plan §1.7's corrected text).
                 */
                if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &credlen) < 0 || cred.uid != geteuid()) {
                        ctrl_send_err(cfd, "permission-denied");
                        close(cfd);
                        continue;
                }

                if (ctrl->n_conns >= PICO_CTRL_MAX_CONNS) {
                        ctrl_send_err(cfd, "too-many-connections");
                        close(cfd);
                        continue;
                }

                conn = calloc(1, sizeof(*conn));
                if (!conn) {
                        close(cfd);
                        continue; /* transient OOM: drop this one connection, not the manager */
                }

                conn->ctrl = ctrl;
                conn->fd = cfd;

                r = sd_event_add_io(ctrl->manager->event, &conn->source, cfd, EPOLLIN, ctrl_conn_io_cb, conn);
                if (r < 0) {
                        close(cfd);
                        free(conn);
                        continue;
                }
                sd_event_source_set_priority(conn->source, EVENT_PRIORITY_CTRL);
                sd_event_source_set_io_fd_own(conn->source, 1); /* DEL+close ride this source's teardown */

                conn->next = ctrl->conns;
                if (ctrl->conns)
                        ctrl->conns->prev = conn;
                ctrl->conns = conn;
                ctrl->n_conns++;
        }
}

/*
 * One accepted connection's io callback (EVENT_PRIORITY_CTRL). Never
 * returns < 0: see ctrl_accept()'s own note.
 */
static int ctrl_conn_io_cb(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        struct ctrl_conn *conn = userdata;
        char buf[PICO_CTRL_LINE_MAX + 1];
        ssize_t n;

        (void) es;
        (void) revents;

        if (conn->pending) {
                /*
                 * Any activity on a connection already waiting for its
                 * deferred reply means the client went away (or violated
                 * the one-message-per-connection protocol) -- either way,
                 * stop tracking it. The job itself is unaffected: it keeps
                 * running to completion, and job_finish_full() will simply
                 * find nothing left to notify.
                 */
                ctrl_conn_free(conn);
                return 0;
        }

        /*
         * MSG_TRUNC on a UNIX socket (Linux >= 3.4) reports the datagram's
         * real length even when it exceeds the buffer, so an oversized
         * request is detected -- and rejected -- without ever copying more
         * than PICO_CTRL_LINE_MAX bytes into buf, let alone allocating.
         */
        n = recv(fd, buf, PICO_CTRL_LINE_MAX, MSG_DONTWAIT | MSG_TRUNC);
        if (n < 0) {
                if (errno == EAGAIN)
                        return 0;
                ctrl_conn_free(conn);
                return 0;
        }

        if (n == 0) {
                /* Peer closed (or sent an empty message -- recv() cannot
                 * tell the two apart on a message-oriented socket, and both
                 * mean the same thing here: nothing usable arrived). */
                ctrl_conn_free(conn);
                return 0;
        }

        if ((size_t) n > PICO_CTRL_LINE_MAX) {
                ctrl_send_err(conn->fd, "too-long");
                ctrl_conn_free(conn);
                return 0;
        }

        if (memchr(buf, '\0', (size_t) n)) {
                ctrl_send_err(conn->fd, "embedded-nul");
                ctrl_conn_free(conn);
                return 0;
        }

        ctrl_handle_request(conn, buf, (size_t) n);
        return 0;
}

/* --- public API --- */

int manager_ctrl_setup(Manager *m) {
        struct pico_manager_ctrl *ctrl;
        struct sockaddr_un addr;
        char path[PATH_MAX];
        struct stat st;
        mode_t old_mask;
        int fd, n, r;

        if (!m || !m->runtime_dir)
                return -EINVAL;

        if (mkdir(m->runtime_dir, 0755) < 0 && errno != EEXIST)
                return -errno;

        n = snprintf(path, sizeof(path), "%s/control", m->runtime_dir);
        if (n < 0 || (size_t) n >= sizeof(path))
                return -ENAMETOOLONG;

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        if (strlen(path) >= sizeof(addr.sun_path))
                return -ENAMETOOLONG;
        memcpy(addr.sun_path, path, strlen(path) + 1);

        fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        /* Stale-socket hygiene, matching socket.c's own bind-time unlink:
         * the only legitimate way a path is already there is a previous
         * PID 1 that exited without cleanup (a crash, a hard reboot).
         * S_ISSOCK guards against ever unlinking an unrelated file that
         * happens to already sit at this path. */
        if (stat(path, &st) == 0 && S_ISSOCK(st.st_mode))
                unlink(path);

        /*
         * The umask sandwich around bind(), not a chmod() after -- a chmod
         * leaves a real window in which the socket is live at its final
         * path under the process's ambient umask (plan §1.7's own
         * correction, the same reasoning as socket.c's SocketMode= fix).
         * 0600: root-only; the SO_PEERCRED check in ctrl_accept() is the
         * second, defence-in-depth gate.
         */
        old_mask = umask(0177);
        r = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
        umask(old_mask);
        if (r < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        if (listen(fd, PICO_CTRL_MAX_CONNS) < 0) {
                r = -errno;
                close(fd);
                unlink(path);
                return r;
        }

        ctrl = calloc(1, sizeof(*ctrl));
        if (!ctrl) {
                close(fd);
                unlink(path);
                return -ENOMEM;
        }

        ctrl->socket_path = pico_strdup(path);
        if (!ctrl->socket_path) {
                free(ctrl);
                close(fd);
                unlink(path);
                return -ENOMEM;
        }

        ctrl->manager = m;

        r = sd_event_add_io(m->event, &ctrl->listen_source, fd, EPOLLIN, ctrl_accept, ctrl);
        if (r < 0) {
                pico_mfree(ctrl->socket_path);
                free(ctrl);
                close(fd);
                unlink(path);
                return r;
        }
        sd_event_source_set_priority(ctrl->listen_source, EVENT_PRIORITY_CTRL);
        sd_event_source_set_io_fd_own(ctrl->listen_source, 1); /* DEL+close ride this source's teardown */

        m->ctrl = ctrl;
        return 0;
}

void manager_ctrl_done(Manager *m) {
        struct pico_manager_ctrl *ctrl;

        if (!m || !m->ctrl)
                return;

        ctrl = m->ctrl;

        while (ctrl->conns)
                ctrl_conn_free(ctrl->conns); /* drops any pending record too */

        ctrl->listen_source = sd_event_source_disable_unref(ctrl->listen_source);

        if (ctrl->socket_path)
                unlink(ctrl->socket_path);

        pico_mfree(ctrl->socket_path);
        free(ctrl);
        m->ctrl = NULL;
}

void manager_ctrl_notify_job_finished(Job *j, JobResult result) {
        struct pico_manager_ctrl *ctrl;
        struct ctrl_pending *p, *prev = NULL;
        struct ctrl_conn *conn;
        const char *line;

        if (!j || !j->manager || !j->manager->ctrl)
                return;

        ctrl = j->manager->ctrl;

        for (p = ctrl->pending; p; prev = p, p = p->next)
                if (p->job_id == j->id)
                        break;

        if (!p)
                return; /* nobody is listening for this job's result any more */

        if (prev)
                prev->next = p->next;
        else
                ctrl->pending = p->next;

        conn = p->conn;
        free(p);
        conn->pending = NULL; /* ctrl_conn_free() below must not try to unlink this again */

        switch (result) {
        case JOB_DONE:
                line = "ok done\n";
                break;
        case JOB_FAILED:
                line = "err failed\n";
                break;
        case JOB_CANCELED:
                line = "err canceled\n";
                break;
        case JOB_TIMEOUT:
                line = "err timeout\n";
                break;
        case JOB_DEPENDENCY:
                line = "err dependency\n";
                break;
        default:
                line = "err unknown\n";
                break;
        }

        ctrl_send_line(conn->fd, line);
        ctrl_conn_free(conn);
}

size_t manager_ctrl_debug_n_conns(Manager *m) {
        if (!m || !m->ctrl)
                return 0;

        return m->ctrl->n_conns;
}

size_t manager_ctrl_debug_n_pending(Manager *m) {
        struct ctrl_pending *p;
        size_t n = 0;

        if (!m || !m->ctrl)
                return 0;

        for (p = m->ctrl->pending; p; p = p->next)
                n++;

        return n;
}
