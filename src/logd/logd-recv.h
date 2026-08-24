/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Datagram receive, fragment handling, /dev/log parsing and ucred+cgroup
 * attribution (plan §3.2/§3.3, milestone J1).
 *
 * DESIGN CORRECTION, 2026-08-24 (superseding §3.2's original wording of "a
 * small bounded per-PID fragment tail"). A dedicated review found that
 * wrong in both directions: a service that dies mid-line can hand its
 * fragment to an unrelated later service that gets the recycled PID, and
 * an ordinary ExecStart=/bin/sh -c '...' already spans several PIDs (the
 * shell and its children) on ONE stream. The fragment tail is keyed
 * instead by **stream identity** -- the sender's bound source address on
 * the stdout socket. PID 1's service-exec.c (plan §3.6) binds each
 * service invocation's outbound socket to an abstract-namespace name it
 * chooses, in the parent, before fork(): the child cannot rebind an
 * already-bound AF_UNIX socket (a second bind() returns EINVAL), so that
 * name is unforgeable, unique per invocation, and never aliases across a
 * restart. logd reads it from recvfrom()'s reported peer address and never
 * needs to know its internal format -- the raw bytes are compared for
 * equality, nothing more.
 *
 * The residual case the address key alone does not cover -- the same
 * numeric PID recycled *within* one already-known stream, which can only
 * happen if that stream outlives a still-running earlier fork() child's
 * whole lifetime -- is covered by re-validating /proc/<pid>'s start time on
 * every datagram that reports an unchanged PID; a mismatch force-flushes
 * the tail exactly as a real PID *change* on the stream does, both tagged
 * _LINE_BREAK=pid-change (upstream's own field/value, journald-stream.c).
 *
 * Overflow is a SPLIT, not "flush as-is": on exceeding LOGD_LINE_MAX
 * (logd.h) without finding a break, the accumulated bytes are emitted as
 * their own record tagged _LINE_BREAK=line-max and scanning continues --
 * "as-is" would leave a single record's size bounded only by writer
 * behaviour, which a fixed-size ring must never allow.
 *
 * Attribution (_COMM, _SYSTEMD_UNIT) is captured once, at the first
 * datagram of a stream, and cached on it: /proc/<pid> can disappear the
 * moment a short-lived process exits, while its stream's tail (and further
 * datagrams sharing its stream identity, from siblings/children still
 * running) can outlive it. Where attribution is unavailable the record is
 * still written, without _SYSTEMD_UNIT/_COMM, rather than guessed at or
 * dropped -- see logd-recv.c's cgroup-path walk for the §3.3 correction
 * (first non-slice component, not last) this also carries.
 *
 * /dev/log shares this receive loop but never the fragment path: each
 * syslog(3) call is its own complete datagram (journald-syslog.c is the
 * parse reference for the <N> priority prefix and identifier[pid]: tag),
 * and logd_recv_process_syslog() never touches the stream table.
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

/* Flushes every stream's still-pending tail (tagged _LINE_BREAK=eof) before
 * freeing -- a process's last, unterminated line must not be silently lost
 * on shutdown. */
LogdRecv *logd_recv_free(LogdRecv *r);

/*
 * Set SO_PASSCRED on `fd`, whatever its origin (self-bound below, or
 * inherited via LISTEN_FDS). A datagram queued before SO_PASSCRED is set
 * arrives with the SCM_CREDENTIALS cmsg present but pid == 0 -- silently
 * misattributing exactly the crash-survival backlog the whole design
 * exists to preserve -- so this is not cosmetic even where the fd was
 * already correct in production (PID 1's own bound fd has it set before
 * logd ever sees it). 0 or -errno.
 */
int logd_recv_ensure_passcred(int fd);

/*
 * Create, bind and chmod a real AF_UNIX SOCK_DGRAM at `path`, with
 * SO_PASSCRED set between socket() and bind() (order matters -- see
 * logd_recv_ensure_passcred()'s doc). For standalone operation (no
 * LISTEN_FDS yet -- pre-J4/S3) and for tests, which need a real bound
 * socket to send real bytes through rather than a synthetic
 * payload/peer/cred triple. A stale socket already at `path` is unlinked
 * first. 0 or -errno.
 */
int logd_recv_bind_socket(const char *path, mode_t mode, int *ret_fd);

/*
 * Process one already-received stdout-socket datagram. `peer`/`peer_len`
 * is the sender's bound source address (recvfrom()'s reported msg_name) --
 * the stream identity key; a NULL/zero-length peer (an unbound/anonymous
 * sender, which production traffic never produces -- see logd-recv.c) gets
 * no fragment carry-over at all, on the theory that guessing a stream
 * identity is worse than never having one. `cred` is the kernel-verified
 * SCM_CREDENTIALS for this datagram; NULL means none was present at all
 * (as opposed to pid == 0, which this file treats as "none" too -- see the
 * design note above). 0 or -errno.
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
 * text itself claims, same as classic syslogd. 0 or -errno.
 */
int logd_recv_process_syslog(LogdRecv *r, const void *payload, size_t payload_len, const struct ucred *cred);

/*
 * Drain every datagram currently pending on `fd` (non-blocking, stops at
 * EAGAIN): the real recvmsg()/SCM_CREDENTIALS/peer-address extraction,
 * dispatched to logd_recv_process_stdout() or logd_recv_process_syslog().
 * A truncated datagram (MSG_TRUNC) is logged and still processed with
 * whatever bytes were captured, rather than silently accepted as a short
 * read or dropped outright. Returns the number of datagrams processed, or
 * -errno.
 */
int logd_recv_drain_stdout(LogdRecv *r, int fd);
int logd_recv_drain_syslog(LogdRecv *r, int fd);
