/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Datagram receive, fragment handling, /dev/log parsing and ucred+cgroup
 * attribution.
 *
 * The fragment tail of a partial stdout line is keyed by stream identity --
 * the sender's bound source address on the stdout socket -- not by PID: a
 * service that dies mid-line could hand its fragment to a later service that
 * got the recycled PID, and an ExecStart=/bin/sh -c '...' spans several PIDs
 * on one stream. PID 1's service-exec.c binds each invocation's outbound
 * socket to an abstract-namespace name before fork(). The child cannot
 * rebind an already-bound AF_UNIX socket (a second bind() returns EINVAL),
 * so the name is unforgeable, unique per invocation and never aliases across
 * a restart. logd only compares the raw address bytes for equality.
 *
 * The same PID recycled within one stream is caught by re-validating
 * /proc/<pid>'s start time on every datagram that reports an unchanged PID;
 * a mismatch force-flushes the tail like a real PID change does, both tagged
 * _LINE_BREAK=pid-change (upstream's field/value, journald-stream.c).
 *
 * Exceeding LOGD_LINE_MAX (logd.h) without finding a break splits: the
 * accumulated bytes are emitted as their own record tagged
 * _LINE_BREAK=line-max and scanning continues, so a record never exceeds the
 * bound.
 *
 * Attribution (_COMM, _SYSTEMD_UNIT) is captured at the first datagram of a
 * stream and cached on it: /proc/<pid> can vanish as soon as a short-lived
 * process exits, while the stream can outlive it. Without attribution the
 * record is still written, without _SYSTEMD_UNIT/_COMM. The unit is the
 * first non-slice cgroup path component (see logd-recv.c).
 *
 * /dev/log shares this receive loop but never the fragment path: each
 * syslog(3) call is one complete datagram (journald-syslog.c is the parse
 * reference for the <N> priority prefix and identifier[pid]: tag), and
 * logd_recv_process_syslog() never touches the stream table.
 */

#pragma once

#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "logd-write.h"

typedef struct LogdRecv LogdRecv;

/* `writer` is not owned -- the caller (logd.c, or a test) keeps it alive
 * for LogdRecv's whole lifetime and frees it separately. */
int logd_recv_new(LogdWriter *writer, LogdRecv **ret);

/* Flushes every stream's pending tail (tagged _LINE_BREAK=eof) before
 * freeing, so a last unterminated line is not lost on shutdown. */
LogdRecv *logd_recv_free(LogdRecv *r);

/*
 * Set SO_PASSCRED on `fd`, whatever its origin (self-bound below, or
 * inherited via LISTEN_FDS). A datagram queued before SO_PASSCRED is set
 * arrives with the SCM_CREDENTIALS cmsg present but pid == 0, which would
 * misattribute the backlog that survives a logd restart. 0 or -errno.
 */
int logd_recv_ensure_passcred(int fd);

/*
 * Create, bind and chmod a real AF_UNIX SOCK_DGRAM at `path`, with
 * SO_PASSCRED set between socket() and bind() (order matters -- see
 * logd_recv_ensure_passcred()'s doc). For standalone operation (no
 * LISTEN_FDS) and for tests. A stale socket already at `path` is unlinked
 * first. 0 or -errno.
 */
int logd_recv_bind_socket(const char *path, mode_t mode, int *ret_fd);

/*
 * Process one already-received stdout-socket datagram. `peer`/`peer_len`
 * is the sender's bound source address (recvfrom()'s reported msg_name) --
 * the stream identity key; a NULL/zero-length peer (an unbound/anonymous
 * sender; PID 1 always binds) gets no fragment carry-over. `cred` is the kernel-verified
 * SCM_CREDENTIALS for this datagram; NULL means none was present at all
 * (pid == 0 is treated as "none" too). 0 or -errno.
 */
int logd_recv_process_stdout(
                LogdRecv *r,
                const void *payload,
                size_t payload_len,
                const struct sockaddr_un *peer,
                socklen_t peer_len,
                const struct ucred *cred);

/*
 * Process one already-received /dev/log datagram: always exactly one
 * record, never the fragment path. `cred` may be NULL (SO_PASSCRED absent
 * or a credential-less sender); attribution is then whatever the message
 * text itself claims. 0 or -errno.
 */
int logd_recv_process_syslog(LogdRecv *r, const void *payload, size_t payload_len, const struct ucred *cred);

/*
 * Drain every datagram currently pending on `fd` (non-blocking, stops at
 * EAGAIN): the real recvmsg()/SCM_CREDENTIALS/peer-address extraction,
 * dispatched to logd_recv_process_stdout() or logd_recv_process_syslog().
 * A truncated datagram (MSG_TRUNC) is logged and still processed with
 * the bytes captured. Returns the number of datagrams processed, or
 * -errno.
 */
int logd_recv_drain_stdout(LogdRecv *r, int fd);
int logd_recv_drain_syslog(LogdRecv *r, int fd);
