/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The one "who is this process" resolution shared by every sd_pid_get_*(),
 * sd_pidfd_get_*() and sd_peer_get_*() function in sd-login.h -- a raw pid, a
 * pidfd, or a connected AF_UNIX socket's peer, all reduced to a live pid
 * plus the /proc/<pid>/cgroup content that resolving it already had to
 * read, so the real getters (sd-login-cgroup.c) don't re-open the file
 * and the honest_failure getters (sd-login.c) get the same existence
 * check without needing the content at all.
 */

#pragma once

#include <sys/types.h>

/*
 * pid==0 means "the calling process" (getpid()); pid<0 -> -EINVAL.
 * pidfd<0 -> -EBADF; an unresolvable, reaped (-1) or foreign-namespace (0)
 * pidfd's own Pid: field maps to -EBADF/-ESRCH/-EREMOTE respectively,
 * matching the real pidfd_get_pid() contract.
 * fd (peer): a getsockopt(SOL_SOCKET, SO_PEERCRED) failure passes its
 * errno through (-EBADF/-ENOTSOCK typically); a zeroed ucred.pid is
 * -ENODATA.
 *
 * All three then confirm the resolved pid is alive by opening
 * /proc/<pid>/cgroup (ENOENT -> -ESRCH, "process does not exist" --
 * sd-login.c's own errno contract, HEAD ded83144 :30-36); the pidfd form
 * additionally re-reads its Pid: field afterwards and demands it still
 * matches, closing the TOCTOU window pidfd-based lookups exist to avoid.
 *
 * On success, *ret_pid is the live pid and *ret_cgroup_content is the
 * malloc'd whole content of /proc/<pid>/cgroup (never NULL). Every other
 * return leaves both outputs untouched.
 */
int login_resolve_pid(pid_t pid, pid_t *ret_pid, char **ret_cgroup_content);
int login_resolve_pidfd(int pidfd, pid_t *ret_pid, char **ret_cgroup_content);
int login_resolve_peer(int fd, pid_t *ret_pid, char **ret_cgroup_content);
