/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-init's own implementation of the sd-login.h ABI surface. Function
 * names, signatures and documented error conventions match systemd's
 * src/systemd/sd-login.h (HEAD ded83144). The implementations are in
 * sd-login-resolve.c, sd-login-cgroup.c and sd-login.c.
 */

#pragma once

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Every string this family returns is malloc'd and freed with plain
 * free(); a string array is NULL-terminated and both the array and its
 * elements need freeing. Errors are negative errno; 0 or positive is
 * success. An empty array/count may come back as NULL/0 rather than an
 * allocated empty array.
 */

int sd_pid_get_session(pid_t pid, char **ret_session);
int sd_pid_get_owner_uid(pid_t pid, uid_t *ret_uid);
int sd_pid_get_unit(pid_t pid, char **ret_unit);
int sd_pid_get_user_unit(pid_t pid, char **ret_unit);
int sd_pid_get_slice(pid_t pid, char **ret_slice);
int sd_pid_get_user_slice(pid_t pid, char **ret_slice);
int sd_pid_get_machine_name(pid_t pid, char **ret_machine);
int sd_pid_get_cgroup(pid_t pid, char **ret_cgroup);

/* Same as the sd_pid_get_* functions above, but resolve via a pidfd
 * instead of a raw pid, closing the pid-recycle race a raw pid can't. */
int sd_pidfd_get_session(int pidfd, char **ret_session);
int sd_pidfd_get_owner_uid(int pidfd, uid_t *ret_uid);
int sd_pidfd_get_unit(int pidfd, char **ret_unit);
int sd_pidfd_get_user_unit(int pidfd, char **ret_unit);
int sd_pidfd_get_slice(int pidfd, char **ret_slice);
int sd_pidfd_get_user_slice(int pidfd, char **ret_slice);
int sd_pidfd_get_machine_name(int pidfd, char **ret_machine);
int sd_pidfd_get_cgroup(int pidfd, char **ret_cgroup);

/* Same again, resolving via the peer of a connected AF_UNIX socket. */
int sd_peer_get_session(int fd, char **ret_session);
int sd_peer_get_owner_uid(int fd, uid_t *ret_uid);
int sd_peer_get_unit(int fd, char **ret_unit);
int sd_peer_get_user_unit(int fd, char **ret_unit);
int sd_peer_get_slice(int fd, char **ret_slice);
int sd_peer_get_user_slice(int fd, char **ret_slice);
int sd_peer_get_machine_name(int fd, char **ret_machine);
int sd_peer_get_cgroup(int fd, char **ret_cgroup);

/* Possible states: offline, lingering, online, active, closing. */
int sd_uid_get_state(uid_t uid, char **ret_state);

/* Primary session of a user, if any. */
int sd_uid_get_display(uid_t uid, char **ret_display);

/* Login time of a user. */
int sd_uid_get_login_time(uid_t uid, uint64_t *ret_usec);

/* 1 if the uid has a session on the given seat (active-only if
 * require_active). */
int sd_uid_is_on_seat(uid_t uid, int require_active, const char *seat);

/* Sessions of a user (active-only if require_active); count if
 * ret_sessions is NULL. */
int sd_uid_get_sessions(uid_t uid, int require_active, char ***ret_sessions);

/* Seats a user is on (active-only if require_active); count if
 * ret_seats is NULL. */
int sd_uid_get_seats(uid_t uid, int require_active, char ***ret_seats);

int sd_session_is_active(const char *session);
int sd_session_is_remote(const char *session);
/* Possible states: online, active, closing. */
int sd_session_get_state(const char *session, char **ret_state);
int sd_session_get_uid(const char *session, uid_t *ret_uid);
int sd_session_get_username(const char *session, char **ret_username);
int sd_session_get_seat(const char *session, char **ret_seat);
int sd_session_get_start_time(const char *session, uint64_t *ret_usec);
int sd_session_get_service(const char *session, char **ret_service);
/* One of "tty", "x11", "wayland", "mir", "web", "unspecified". */
int sd_session_get_type(const char *session, char **ret_type);
/* One of "user", "greeter", "lock-screen". */
int sd_session_get_class(const char *session, char **ret_clazz);
int sd_session_get_desktop(const char *session, char **ret_desktop);
int sd_session_get_display(const char *session, char **ret_display);
/* Extra devices the session may access: every device udev tags "xaccess-$ID" for each returned $ID. */
int sd_session_get_extra_device_access(const char *session, char ***ret_ids);
int sd_session_get_leader(const char *session, pid_t *ret_leader);
int sd_session_get_remote_host(const char *session, char **ret_remote_host);
int sd_session_get_remote_user(const char *session, char **ret_remote_user);
int sd_session_get_tty(const char *session, char **ret_tty);
int sd_session_get_vt(const char *session, unsigned *ret_vtnr);

int sd_seat_get_active(const char *seat, char **ret_session, uid_t *ret_uid);
int sd_seat_get_sessions(const char *seat, char ***ret_sessions, uid_t **ret_uids, unsigned *ret_n_uids);

#if __GNUC__ >= 6
#        define _PICO_SD_LOGIN_DEPRECATED_ __attribute__((__deprecated__))
#else
#        define _PICO_SD_LOGIN_DEPRECATED_
#endif

int sd_seat_can_multi_session(const char *seat) _PICO_SD_LOGIN_DEPRECATED_;
int sd_seat_can_tty(const char *seat);
int sd_seat_can_graphical(const char *seat);

int sd_machine_get_class(const char *machine, char **ret_clazz);
int sd_machine_get_ifindices(const char *machine, int **ret_ifindices);

/* Every sd_get_*() below returns the count (0 if none); its own output
 * (ret_seats etc.) is left untouched when that pointer itself is NULL
 * (a count-only query). */
int sd_get_seats(char ***ret_seats);
int sd_get_sessions(char ***ret_sessions);
int sd_get_uids(uid_t **ret_users);
int sd_get_machine_names(char ***ret_machines);

typedef struct sd_login_monitor sd_login_monitor;

/* category: NULL, "seat", "session", "uid", or "machine". */
int sd_login_monitor_new(const char *category, sd_login_monitor **ret);
sd_login_monitor *sd_login_monitor_unref(sd_login_monitor *m);
int sd_login_monitor_flush(sd_login_monitor *m);
int sd_login_monitor_get_fd(sd_login_monitor *m);
int sd_login_monitor_get_events(sd_login_monitor *m);
int sd_login_monitor_get_timeout(sd_login_monitor *m, uint64_t *ret_timeout_usec);

static inline void sd_login_monitor_unrefp(sd_login_monitor **p) {
        if (*p)
                sd_login_monitor_unref(*p);
}

#ifdef __cplusplus
}
#endif
