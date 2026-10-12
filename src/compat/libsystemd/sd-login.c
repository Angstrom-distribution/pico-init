/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Everything in sd-login.h except the cgroup/unit/slice family
 * (sd-login-cgroup.c): sessions, seats, users, machines and the login
 * monitor, none of which pico-init registers because it is not logind. The
 * errno contract is upstream's (sd-login.c, HEAD ded83144): -ENXIO for a
 * named object that does not exist, -ENODATA for missing metadata on an
 * existing object, or for a NULL session/seat (upstream resolves that via
 * the caller's own session, which cannot exist here).
 *
 * Some answers are true without logind: sd_uid_get_state() is "offline"
 * (upstream's answer when /run/systemd/users/<uid> is absent);
 * sd_uid_get_sessions()/get_seats()/sd_get_seats() and friends report zero;
 * sd_uid_is_on_seat() is 0; sd_machine_get_class() is ".host", as upstream;
 * sd_seat_can_multi_session() is upstream's unconditional "true" stub.
 */

#include "sd-login.h"

#include "sd-login-resolve.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* Shared by every sd_pid_get_*(), sd_pidfd_get_*() and sd_peer_get_*()
 * function below that has no data: confirm the process/pidfd/peer resolves
 * to a live pid (as sd-login-cgroup.c's getters do), then report -ENODATA. */
static int pid_confirmed_but_no_data(pid_t pid) {
        pid_t rpid;
        char *content;
        int r = login_resolve_pid(pid, &rpid, &content);

        if (r < 0)
                return r;
        free(content);
        return -ENODATA;
}

static int pidfd_confirmed_but_no_data(int pidfd) {
        pid_t rpid;
        char *content;
        int r = login_resolve_pidfd(pidfd, &rpid, &content);

        if (r < 0)
                return r;
        free(content);
        return -ENODATA;
}

static int peer_confirmed_but_no_data(int fd) {
        pid_t rpid;
        char *content;
        int r = login_resolve_peer(fd, &rpid, &content);

        if (r < 0)
                return r;
        free(content);
        return -ENODATA;
}

int sd_pid_get_session(pid_t pid, char **ret_session) {
        (void) ret_session;
        return pid_confirmed_but_no_data(pid);
}
int sd_pid_get_owner_uid(pid_t pid, uid_t *ret_uid) {
        (void) ret_uid;
        return pid_confirmed_but_no_data(pid);
}
int sd_pid_get_user_unit(pid_t pid, char **ret_unit) {
        (void) ret_unit;
        return pid_confirmed_but_no_data(pid);
}
int sd_pid_get_user_slice(pid_t pid, char **ret_slice) {
        (void) ret_slice;
        return pid_confirmed_but_no_data(pid);
}
int sd_pid_get_machine_name(pid_t pid, char **ret_machine) {
        (void) ret_machine;
        return pid_confirmed_but_no_data(pid);
}

int sd_pidfd_get_session(int pidfd, char **ret_session) {
        (void) ret_session;
        return pidfd_confirmed_but_no_data(pidfd);
}
int sd_pidfd_get_owner_uid(int pidfd, uid_t *ret_uid) {
        (void) ret_uid;
        return pidfd_confirmed_but_no_data(pidfd);
}
int sd_pidfd_get_user_unit(int pidfd, char **ret_unit) {
        (void) ret_unit;
        return pidfd_confirmed_but_no_data(pidfd);
}
int sd_pidfd_get_user_slice(int pidfd, char **ret_slice) {
        (void) ret_slice;
        return pidfd_confirmed_but_no_data(pidfd);
}
int sd_pidfd_get_machine_name(int pidfd, char **ret_machine) {
        (void) ret_machine;
        return pidfd_confirmed_but_no_data(pidfd);
}

int sd_peer_get_session(int fd, char **ret_session) {
        (void) ret_session;
        return peer_confirmed_but_no_data(fd);
}
int sd_peer_get_owner_uid(int fd, uid_t *ret_uid) {
        (void) ret_uid;
        return peer_confirmed_but_no_data(fd);
}
int sd_peer_get_user_unit(int fd, char **ret_unit) {
        (void) ret_unit;
        return peer_confirmed_but_no_data(fd);
}
int sd_peer_get_user_slice(int fd, char **ret_slice) {
        (void) ret_slice;
        return peer_confirmed_but_no_data(fd);
}
int sd_peer_get_machine_name(int fd, char **ret_machine) {
        (void) ret_machine;
        return peer_confirmed_but_no_data(fd);
}

/* -------------------------------------------------------------------- */

static int is_invalid_uid(uid_t uid) {
        return uid == (uid_t) -1;
}

int sd_uid_get_state(uid_t uid, char **ret_state) {
        char *s;

        if (is_invalid_uid(uid))
                return -EINVAL;

        s = strdup("offline");
        if (!s)
                return -ENOMEM;

        /* ret_state is optional, as in upstream. */
        if (ret_state)
                *ret_state = s;
        else
                free(s);
        return 0;
}

int sd_uid_get_sessions(uid_t uid, int require_active, char ***ret_sessions) {
        (void) require_active;

        if (is_invalid_uid(uid))
                return -EINVAL;

        if (ret_sessions)
                *ret_sessions = NULL;
        return 0;
}

int sd_uid_get_seats(uid_t uid, int require_active, char ***ret_seats) {
        (void) require_active;

        if (is_invalid_uid(uid))
                return -EINVAL;

        if (ret_seats)
                *ret_seats = NULL;
        return 0;
}

int sd_uid_is_on_seat(uid_t uid, int require_active, const char *seat) {
        (void) require_active;

        if (is_invalid_uid(uid))
                return -EINVAL;
        if (!seat)
                return -ENODATA;

        return 0;
}

int sd_uid_get_display(uid_t uid, char **ret_display) {
        (void) ret_display;

        if (is_invalid_uid(uid))
                return -EINVAL;
        return -ENODATA;
}

int sd_uid_get_login_time(uid_t uid, uint64_t *ret_usec) {
        (void) ret_usec;

        if (is_invalid_uid(uid))
                return -EINVAL;
        return -ENXIO;
}

/* -------------------------------------------------------------------- */

/* Shared by every sd_session_get_*()/is_*() and sd_seat_get_*()/can_*()
 * function: NULL means "my own session/seat", which upstream resolves via
 * sd_pid_get_session(0); that cannot succeed here, so its -ENODATA
 * propagates (sd-login.c:45's -ENXIO/-ENOMEDIUM -> -ENODATA mapping). A
 * name containing '/' (or "." / "..") cannot be a
 * /run/systemd/{sessions,seats}/<name> filename: -EINVAL. Any other name is
 * valid but never registered: -ENXIO. */
static int session_or_seat_errno(const char *name) {
        if (!name)
                return -ENODATA;
        if (name[0] == '\0' || strchr(name, '/') || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
                return -EINVAL;
        return -ENXIO;
}

int sd_session_is_active(const char *session) {
        return session_or_seat_errno(session);
}
int sd_session_is_remote(const char *session) {
        return session_or_seat_errno(session);
}
int sd_session_get_state(const char *session, char **ret_state) {
        (void) ret_state;
        return session_or_seat_errno(session);
}
int sd_session_get_uid(const char *session, uid_t *ret_uid) {
        (void) ret_uid;
        return session_or_seat_errno(session);
}
int sd_session_get_username(const char *session, char **ret_username) {
        (void) ret_username;
        return session_or_seat_errno(session);
}
int sd_session_get_seat(const char *session, char **ret_seat) {
        (void) ret_seat;
        return session_or_seat_errno(session);
}
int sd_session_get_start_time(const char *session, uint64_t *ret_usec) {
        (void) ret_usec;
        return session_or_seat_errno(session);
}
int sd_session_get_service(const char *session, char **ret_service) {
        (void) ret_service;
        return session_or_seat_errno(session);
}
int sd_session_get_type(const char *session, char **ret_type) {
        (void) ret_type;
        return session_or_seat_errno(session);
}
int sd_session_get_class(const char *session, char **ret_clazz) {
        (void) ret_clazz;
        return session_or_seat_errno(session);
}
int sd_session_get_desktop(const char *session, char **ret_desktop) {
        (void) ret_desktop;
        return session_or_seat_errno(session);
}
int sd_session_get_display(const char *session, char **ret_display) {
        (void) ret_display;
        return session_or_seat_errno(session);
}
int sd_session_get_extra_device_access(const char *session, char ***ret_ids) {
        (void) ret_ids;
        return session_or_seat_errno(session);
}
int sd_session_get_leader(const char *session, pid_t *ret_leader) {
        (void) ret_leader;
        return session_or_seat_errno(session);
}
int sd_session_get_remote_host(const char *session, char **ret_remote_host) {
        (void) ret_remote_host;
        return session_or_seat_errno(session);
}
int sd_session_get_remote_user(const char *session, char **ret_remote_user) {
        (void) ret_remote_user;
        return session_or_seat_errno(session);
}
int sd_session_get_tty(const char *session, char **ret_tty) {
        (void) ret_tty;
        return session_or_seat_errno(session);
}
int sd_session_get_vt(const char *session, unsigned *ret_vtnr) {
        (void) ret_vtnr;
        return session_or_seat_errno(session);
}

int sd_seat_get_active(const char *seat, char **ret_session, uid_t *ret_uid) {
        (void) ret_session;
        (void) ret_uid;
        return session_or_seat_errno(seat);
}
int sd_seat_get_sessions(const char *seat, char ***ret_sessions, uid_t **ret_uids, unsigned *ret_n_uids) {
        (void) ret_sessions;
        (void) ret_uids;
        (void) ret_n_uids;
        return session_or_seat_errno(seat);
}
int sd_seat_can_tty(const char *seat) {
        return session_or_seat_errno(seat);
}
int sd_seat_can_graphical(const char *seat) {
        return session_or_seat_errno(seat);
}

int sd_seat_can_multi_session(const char *seat) {
        (void) seat;
        return 1;
}

/* -------------------------------------------------------------------- */

/* A hostname never starts or ends with '.' or '-' and has no two dots in a
 * row. ".host" is a machined sentinel, not a hostname: sd_machine_get_class()
 * checks for it before calling this, as upstream does, while
 * sd_machine_get_ifindices() does not, so ".host" gets -EINVAL there. */
static int is_valid_hostname_ish(const char *name) {
        size_t len, i;

        if (!name)
                return 0;
        len = strlen(name);
        if (len == 0 || len > 64) /* HOST_NAME_MAX-ish upper bound */
                return 0;
        if (name[0] == '.' || name[0] == '-' || name[len - 1] == '.' || name[len - 1] == '-')
                return 0;
        for (i = 0; i < len; i++) {
                char c = name[i];
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                                c == '-' || c == '_' || c == '.';
                if (!ok)
                        return 0;
                if (c == '.' && i + 1 < len && name[i + 1] == '.')
                        return 0;
        }
        return 1;
}

int sd_machine_get_class(const char *machine, char **ret_clazz) {
        char *s;

        if (!machine)
                return -EINVAL;

        if (strcmp(machine, ".host") == 0) {
                s = strdup("host");
                if (!s)
                        return -ENOMEM;
                /* ret_clazz is optional, as in upstream. */
                if (ret_clazz)
                        *ret_clazz = s;
                else
                        free(s);
                return 0;
        }

        if (!is_valid_hostname_ish(machine))
                return -EINVAL;

        return -ENXIO;
}

int sd_machine_get_ifindices(const char *machine, int **ret_ifindices) {
        (void) ret_ifindices;

        /* ".host" fails hostname validation as in upstream's
         * assert_return(hostname_is_valid(machine, 0)). */
        if (!machine || !is_valid_hostname_ish(machine))
                return -EINVAL;

        return -ENXIO;
}

int sd_get_seats(char ***ret_seats) {
        if (ret_seats)
                *ret_seats = NULL;
        return 0;
}
int sd_get_sessions(char ***ret_sessions) {
        if (ret_sessions)
                *ret_sessions = NULL;
        return 0;
}
int sd_get_uids(uid_t **ret_users) {
        if (ret_users)
                *ret_users = NULL;
        return 0;
}
int sd_get_machine_names(char ***ret_machines) {
        if (ret_machines)
                *ret_machines = NULL;
        return 0;
}

/* -------------------------------------------------------------------- */

int sd_login_monitor_new(const char *category, sd_login_monitor **ret) {
        if (!ret)
                return -EINVAL;
        if (category && strcmp(category, "seat") != 0 && strcmp(category, "session") != 0 &&
            strcmp(category, "uid") != 0 && strcmp(category, "machine") != 0)
                return -EINVAL;

        /* Upstream's errno without logind: inotify_add_watch() on the missing
         * /run/systemd/<category> directory fails ENOENT (sd-login.c:1183-1218).
         * A monitor that never fires would hang callers instead of letting
         * them use their no-logind fallback. */
        return -ENOENT;
}

sd_login_monitor *sd_login_monitor_unref(sd_login_monitor *m) {
        (void) m;
        return NULL;
}

int sd_login_monitor_flush(sd_login_monitor *m) {
        (void) m;
        return -EINVAL;
}
int sd_login_monitor_get_fd(sd_login_monitor *m) {
        (void) m;
        return -EINVAL;
}
int sd_login_monitor_get_events(sd_login_monitor *m) {
        (void) m;
        return -EINVAL;
}
int sd_login_monitor_get_timeout(sd_login_monitor *m, uint64_t *ret_timeout_usec) {
        (void) m;
        (void) ret_timeout_usec;
        return -EINVAL;
}
