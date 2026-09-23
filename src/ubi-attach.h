/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * UBI attach: putting MTD flash under UBI from userspace, as ubiattach(8)
 * does, so that fstab's ubifs lines have a volume to mount.
 *
 * The kernel attaches MTD devices itself when its command line says ubi.mtd=,
 * but only when UBI is built in: a module parameter on the kernel command line
 * is consumed by the kernel's own parser for built-in code alone, and for a
 * module it is modprobe's job to pass it on -- and nothing loads modules before
 * PID 1's fstab pass. So PID 1 reads the same parameter, in the same syntax,
 * and does what the kernel would have done, through /dev/ubi_ctrl's UBI_IOCATT:
 *
 *   ubi.mtd=<name|num|path>[,<vid_hdr_offs>[,<max_beb_per1024>[,<ubi_num>
 *           [,<enable_fm>[,<need_resv_pool>]]]]]
 *
 * one per MTD device, attached in command line order, which is also the order
 * automatic UBI device numbers are handed out in. The same command line then
 * works whether UBI is built in or a module: built in, the kernel has attached
 * everything before PID 1 runs, and every request here finds its MTD device
 * attached already and stops there. Fastmap follows the kernel parameter's
 * default, off unless enable_fm says otherwise, not the ioctl's (on).
 *
 * Each request is a small state machine, run to an end before the next one
 * starts, so automatic numbers come out in the order the kernel would give:
 *
 *   WAIT_MTD   the MTD device -- by number, then name, then character device
 *              node, the kernel's own lookup order -- is listed in sysfs. If
 *              UBI already has it: DONE, or FAILED when it sits under another
 *              number than the one asked for. A number asked for that another
 *              MTD device already holds is FAILED too.
 *   WAIT_CTRL  /dev/ubi_ctrl exists: UBI is built in or its module is loaded.
 *   ATTACH     UBI_IOCATT. DONE with the number the kernel gave, or FAILED with
 *              its errno -- except EEXIST, which is checked against sysfs again
 *              in case something else attached the device meanwhile.
 *
 * One deadline covers every request; a request still waiting when it passes
 * ends as TIMEOUT, and the rest each still get one look. Nothing here loads a
 * module: on a kernel with MTD or UBI as modules, whatever loads them (an
 * initramfs, say) must have done so before PID 1 starts.
 *
 * Every entry point takes its sysfs and /dev roots and the ioctl as
 * parameters, so the whole machine runs against a fixture tree and a fake
 * kernel in test-ubi-attach.c.
 */

#pragma once

#include <mtd/ubi-user.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "util.h"

/* The kernel's limits: UBI_MAX_DEVICES, MTD_PARAM_LEN_MAX (the NUL
 * included) and MAX_MTD_UBI_BEB_LIMIT. */
#define UBI_ATTACH_MAX 32
#define UBI_MTD_PARAM_LEN_MAX 64
#define UBI_BEB_LIMIT_MAX 768

typedef struct UbiMtdParam {
        char mtd[UBI_MTD_PARAM_LEN_MAX]; /* a number, a name, or a node path */
        int vid_hdr_offs;                /* 0: UBI's default */
        int max_beb_per1024;             /* 0: the kernel's default */
        int ubi_num;                     /* UBI_DEV_NUM_AUTO: the lowest free */
        bool enable_fm;
        bool need_resv_pool;
} UbiMtdParam;

/*
 * One ubi.mtd= value, parsed as the kernel's ubi_mtd_param_parse() parses it:
 * comma-separated, at most six fields, vid_hdr_offs a byte count in any base
 * with an optional K/M/G suffix, the rest decimal. Also refused here, where the
 * kernel would only refuse the attach: a max_beb_per1024 outside 0-768 and a
 * ubi_num outside -1-31. 1 with *ret filled, 0 for an empty value (which the
 * kernel ignores too), -EINVAL otherwise.
 */
int ubi_mtd_param_parse(const char *val, UbiMtdParam *ret);

/*
 * Every ubi.mtd= on a kernel command line, in order, quoting as the kernel's
 * own parser handles it and stopping at "--", past which the rest is init's.
 * Malformed values are logged and dropped. Returns how many landed in `ret`,
 * at most `max`.
 */
size_t ubi_cmdline_params(const char *cmdline, UbiMtdParam *ret, size_t max);

/* The same, read from `path` (/proc/cmdline). Count, or -errno. */
int ubi_cmdline_load(const char *path, UbiMtdParam *ret, size_t max);

typedef enum UbiAttachState {
        UBI_ATTACH_WAIT_MTD,
        UBI_ATTACH_WAIT_CTRL,
        UBI_ATTACH_ATTACH,
        UBI_ATTACH_DONE,
        UBI_ATTACH_FAILED,
        UBI_ATTACH_TIMEOUT,
        _UBI_ATTACH_STATE_MAX,
} UbiAttachState;

const char *ubi_attach_state_to_string(UbiAttachState s);

typedef struct UbiAttach {
        UbiMtdParam param;
        UbiAttachState state;
        int mtd_num;  /* -1 until the MTD device is found */
        int ubi_num;  /* -1 until DONE */
        bool already; /* DONE, but attached before PID 1 asked */
        char reason[192];
} UbiAttach;

/* UBI_IOCATT on `ctrl`: 0 with req->ubi_num set to the device number, or
 * -errno. */
typedef int (*ubi_attach_ioctl_t)(const char *ctrl, struct ubi_attach_req *req, void *userdata);

typedef struct UbiEnv {
        const char *sys_root;      /* NULL: "/sys" */
        const char *dev_root;      /* NULL: "/dev" */
        ubi_attach_ioctl_t attach; /* NULL: the real ioctl */
        void *attach_userdata;

        /* Called before every re-look while waiting; tests. */
        void (*poll_hook)(void *userdata, unsigned attempt);
        void *poll_userdata;
} UbiEnv;

#define UBI_ATTACH_POLL (100 * USEC_PER_MSEC)

void ubi_attach_init(UbiAttach *a, const UbiMtdParam *p);

/* Advance `a` as far as it can go without waiting. True once it has reached
 * DONE, FAILED or TIMEOUT. */
bool ubi_attach_step(UbiAttach *a, const UbiEnv *env);

/* Run `n` requests in order under one `timeout`, logging each ending.
 * Returns how many ended DONE. */
size_t ubi_attach_run(UbiAttach *v, size_t n, const UbiEnv *env, usec_t timeout);

/* The MTD device `spec` names, looked up the kernel's way: a number (any
 * base), then an MTD name, then a character device node. Its number, -ENOENT
 * when it is not there (yet), -EINVAL for a node that is not an MTD one. */
int ubi_mtd_find(const char *sys_root, const char *spec);

/* The MTD number behind an MTD character device's number (mtdN is minor 2N,
 * mtdNro 2N+1), or -EINVAL for any other device. */
int ubi_mtd_num_from_devnum(dev_t d);

/* The UBI device `mtd_num` is attached as, or -ENOENT. */
int ubi_attached_as(const char *sys_root, int mtd_num);

/* The MTD device UBI device `ubi_num` is, or -ENOENT. */
int ubi_device_mtd(const char *sys_root, int ubi_num);

/* A ubifs mount source, in the forms the kernel's ubifs open_ubi() takes. */
typedef struct UbiSource {
        int ubi_num;
        int vol_id; /* -1: by name */
        char name[UBI_MAX_VOLUME_NAME + 1];
        bool path; /* a volume character device node, which must exist too */
} UbiSource;

/*
 * "ubiX_Y", "ubiY" (device 0), "ubiX:NAME", "ubi:NAME" (device 0), '!' for
 * ':' in either, and a node path ending in "/ubiX_Y". False for anything
 * else, including a device number past UBI's limit and a name too long for a
 * volume.
 */
bool ubi_source_parse(const char *what, UbiSource *ret);

/* Whether the volume `s` names exists: 1, 0 when its UBI device is attached
 * without it, -ENODEV when the device is not attached. */
int ubi_volume_present(const char *sys_root, const UbiSource *s);

/* "ubi0 volume 1" or "ubi0 volume \"rootfs\"", for log lines and reasons. */
void ubi_source_describe(const UbiSource *s, char *buf, size_t size);
