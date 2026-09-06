/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-init's own sd-daemon.h: a from-scratch header matching the real
 * public API contract (function signatures, macro values, documented
 * semantics) that github.com/systemd/systemd ships at src/systemd/sd-daemon.h
 * (read there for reference only -- nothing here is copied from that LGPL
 * text; the declarations below are pico's own words for an uncopyrightable
 * ABI). See sd-daemon.c for what each function actually does under
 * pico-init and where it deviates from a real systemd-managed system.
 *
 * Absent-vs-transient convention, held everywhere in this shim: "genuinely
 * not running under an init that provides this" is always a plain 0, no
 * errno; a real, transient failure is always a negative errno. 0 means "run
 * standalone"; <0 means "something is actually wrong" -- callers can treat
 * the two identically to how they'd treat real libsystemd.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __GNUC__
#        define _PICO_SD_PRINTF_(a, b) __attribute__((format(printf, a, b)))
#else
#        define _PICO_SD_PRINTF_(a, b)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Log-level prefixes for stderr, e.g. fprintf(stderr, SD_NOTICE "hi\n").
 * Header-only: no function here parses or emits these. Whether pico-init's
 * own logd honors them on a captured stdout/stderr stream is logd's own
 * business, not this shim's.
 */
#define SD_EMERG "<0>"
#define SD_ALERT "<1>"
#define SD_CRIT "<2>"
#define SD_ERR "<3>"
#define SD_WARNING "<4>"
#define SD_NOTICE "<5>"
#define SD_INFO "<6>"
#define SD_DEBUG "<7>"

/* The first socket-activation fd a consumer may assume it was handed. */
#define SD_LISTEN_FDS_START 3

int sd_listen_fds(int unset_environment);
int sd_listen_fds_with_names(int unset_environment, char ***ret_names);

int sd_is_fifo(int fd, const char *path);
int sd_is_special(int fd, const char *path);
int sd_is_socket(int fd, int family, int type, int listening);
int sd_is_socket_inet(int fd, int family, int type, int listening, uint16_t port);
int sd_is_socket_sockaddr(int fd, int type, const struct sockaddr *addr, unsigned addr_len, int listening);
int sd_is_socket_unix(int fd, int type, int listening, const char *path, size_t length);
int sd_is_mq(int fd, const char *path);

int sd_notify(int unset_environment, const char *state);
int sd_notifyf(int unset_environment, const char *format, ...) _PICO_SD_PRINTF_(2, 3);
int sd_pid_notify(pid_t pid, int unset_environment, const char *state);
int sd_pid_notifyf(pid_t pid, int unset_environment, const char *format, ...) _PICO_SD_PRINTF_(3, 4);

/*
 * The fd-array pair. n_fds == 0 is real (routes to the same path as
 * sd_notify()/sd_pid_notify()); n_fds > 0 is -EOPNOTSUPP -- pico-init has no
 * fd store (no FDSTORE=1 mechanism exists), so returning success while
 * silently dropping the caller's fds would be a real, disguised bug. See
 * sd-daemon.c for the full reasoning.
 *
 * Note the asymmetry versus sd_pid_notifyf_with_fds() below: n_fds is
 * unsigned here, size_t there. Copied verbatim from the real header --
 * it's a real inconsistency upstream carries, not a typo in this one.
 */
int sd_pid_notify_with_fds(pid_t pid, int unset_environment, const char *state, const int *fds, unsigned n_fds);
int sd_pid_notifyf_with_fds(
                pid_t pid, int unset_environment, const int *fds, size_t n_fds, const char *format, ...)
                _PICO_SD_PRINTF_(5, 6);

int sd_notify_barrier(int unset_environment, uint64_t timeout);
int sd_pid_notify_barrier(pid_t pid, int unset_environment, uint64_t timeout);

int sd_pidfd_get_inode_id(int pidfd, uint64_t *ret);

/*
 * Returns 1 on a pico-init system, 0 otherwise. Never protect a call above
 * with this -- every one of them already handles a non-pico-init boot
 * correctly on its own (see the absent-vs-transient convention above).
 */
int sd_booted(void);

int sd_watchdog_enabled(int unset_environment, uint64_t *usec);

#ifdef __cplusplus
}
#endif
