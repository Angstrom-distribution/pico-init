/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-init's own implementation of the sd-device public API surface (plan:
 * libsystemd-compat, sd-device/sd-network family).
 *
 * This header is written from scratch against the real, current sd-device.h
 * (systemd.git, src/systemd/sd-device.h) for its function signatures and
 * documented error conventions only -- no text from that LGPL-2.1-or-later
 * header is reproduced here. sd-device did not exist yet at the GPL-2.0-era
 * v30 tag this project quarries algorithm shape from (it postdates the
 * libudev/sd-device split by several years), so there is no GPL shape to
 * carry forward either: every function below is a pico-original
 * reimplementation of the documented ABI, backed by real /sys and real
 * netlink, not by a udev database that does not exist on this image.
 *
 * The struct layout behind `sd_device` is private (device-internal.h);
 * callers only ever see the opaque pointer, exactly as real libsystemd users
 * do.
 *
 * Coverage is intentionally partial and every gap is a comment at its call
 * site, not a silent omission: pico runs devtmpfs + devd with no udev
 * database, no udev-added ID_* properties, and no tag mechanism, so
 * getters for data that plainly doesn't exist here return the honest
 * "not present" answer (usually -ENOENT or an empty iterator) rather than a
 * fabricated one. See device-monitor.c for the one family that is
 * genuinely deferred to a future sd-event shim.
 */

#pragma once

#include <stdint.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

/*
 * sd_id128_t (sd_device_get_trigger_uuid()/sd_device_trigger_with_uuid())
 * and sd_event/sd_event_source (sd_device_monitor_attach_event() and
 * friends, part of the real API surface even though device-monitor.c
 * defers their implementation) both now have their own real family in
 * this shim -- include them rather than the stand-in typedefs an earlier
 * version of this header carried while sd-id128/sd-event did not exist
 * yet, exactly as real systemd's own sd-device.h does.
 */
#include "sd-event.h"
#include "sd-id128.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sd_device sd_device;
typedef struct sd_device_enumerator sd_device_enumerator;
typedef struct sd_device_monitor sd_device_monitor;

typedef enum sd_device_action_t {
        SD_DEVICE_ADD,
        SD_DEVICE_REMOVE,
        SD_DEVICE_CHANGE,
        SD_DEVICE_MOVE,
        SD_DEVICE_ONLINE,
        SD_DEVICE_OFFLINE,
        SD_DEVICE_BIND,
        SD_DEVICE_UNBIND,
        _SD_DEVICE_ACTION_MAX,
        _SD_DEVICE_ACTION_INVALID = -1,
} sd_device_action_t;

typedef int (*sd_device_monitor_handler_t)(sd_device_monitor *m, sd_device *device, void *userdata);

/* --- device: refcounting and construction --- */

sd_device *sd_device_ref(sd_device *device);
sd_device *sd_device_unref(sd_device *device);

/* For `__attribute__((cleanup))` callers, matching real libsystemd's macro-generated helper. */
static inline void sd_device_unrefp(sd_device **p) {
        if (*p)
                sd_device_unref(*p);
}

int sd_device_new_from_syspath(sd_device **ret, const char *syspath);
int sd_device_new_from_devnum(sd_device **ret, char type, dev_t devnum);
int sd_device_new_from_subsystem_sysname(sd_device **ret, const char *subsystem, const char *sysname);
int sd_device_new_from_device_id(sd_device **ret, const char *id);
int sd_device_new_from_stat_rdev(sd_device **ret, const struct stat *st);
int sd_device_new_from_devname(sd_device **ret, const char *devname);
int sd_device_new_from_path(sd_device **ret, const char *path);
int sd_device_new_from_ifname(sd_device **ret, const char *ifname);
int sd_device_new_from_ifindex(sd_device **ret, int ifindex);

int sd_device_new_child(sd_device **ret, sd_device *device, const char *suffix);

int sd_device_get_parent(sd_device *device, sd_device **ret);
int sd_device_get_parent_with_subsystem_devtype(
                sd_device *device, const char *subsystem, const char *devtype, sd_device **ret);

/* --- device: scalar getters --- */

int sd_device_get_syspath(sd_device *device, const char **ret);
int sd_device_get_subsystem(sd_device *device, const char **ret);
int sd_device_get_driver_subsystem(sd_device *device, const char **ret);
int sd_device_get_devtype(sd_device *device, const char **ret);
int sd_device_get_devnum(sd_device *device, dev_t *ret);
int sd_device_get_ifindex(sd_device *device, int *ret);
int sd_device_get_driver(sd_device *device, const char **ret);
int sd_device_get_devpath(sd_device *device, const char **ret);
int sd_device_get_devname(sd_device *device, const char **ret);
int sd_device_get_sysname(sd_device *device, const char **ret);
int sd_device_get_sysnum(sd_device *device, const char **ret);
int sd_device_get_action(sd_device *device, sd_device_action_t *ret);
int sd_device_get_seqnum(sd_device *device, uint64_t *ret);
int sd_device_get_diskseq(sd_device *device, uint64_t *ret);
int sd_device_get_device_id(sd_device *device, const char **ret);

int sd_device_get_is_initialized(sd_device *device);
int sd_device_get_usec_initialized(sd_device *device, uint64_t *ret);
int sd_device_get_usec_since_initialized(sd_device *device, uint64_t *ret);

/* --- device: iterators --- */

const char *sd_device_get_tag_first(sd_device *device);
const char *sd_device_get_tag_next(sd_device *device);
const char *sd_device_get_current_tag_first(sd_device *device);
const char *sd_device_get_current_tag_next(sd_device *device);
const char *sd_device_get_devlink_first(sd_device *device);
const char *sd_device_get_devlink_next(sd_device *device);
const char *sd_device_get_property_first(sd_device *device, const char **value);
const char *sd_device_get_property_next(sd_device *device, const char **value);
const char *sd_device_get_sysattr_first(sd_device *device);
const char *sd_device_get_sysattr_next(sd_device *device);
sd_device *sd_device_get_child_first(sd_device *device, const char **ret_suffix);
sd_device *sd_device_get_child_next(sd_device *device, const char **ret_suffix);

int sd_device_has_tag(sd_device *device, const char *tag);
int sd_device_has_current_tag(sd_device *device, const char *tag);
int sd_device_get_property_value(sd_device *device, const char *key, const char **ret);
int sd_device_get_trigger_uuid(sd_device *device, sd_id128_t *ret);
int sd_device_get_sysattr_value_with_size(
                sd_device *device, const char *sysattr, const char **ret_value, size_t *ret_size);
int sd_device_get_sysattr_value(sd_device *device, const char *sysattr, const char **ret);

/* --- device: mutation --- */

int sd_device_set_sysattr_value(sd_device *device, const char *sysattr, const char *value);
int sd_device_set_sysattr_valuef(sd_device *device, const char *sysattr, const char *format, ...)
                __attribute__((__format__(printf, 3, 4)));
int sd_device_trigger(sd_device *device, sd_device_action_t action);
int sd_device_trigger_with_uuid(sd_device *device, sd_device_action_t action, sd_id128_t *ret_uuid);
int sd_device_open(sd_device *device, int flags);

/* --- device enumerator --- */

int sd_device_enumerator_new(sd_device_enumerator **ret);
sd_device_enumerator *sd_device_enumerator_ref(sd_device_enumerator *enumerator);
sd_device_enumerator *sd_device_enumerator_unref(sd_device_enumerator *enumerator);

static inline void sd_device_enumerator_unrefp(sd_device_enumerator **p) {
        if (*p)
                sd_device_enumerator_unref(*p);
}

sd_device *sd_device_enumerator_get_device_first(sd_device_enumerator *enumerator);
sd_device *sd_device_enumerator_get_device_next(sd_device_enumerator *enumerator);
sd_device *sd_device_enumerator_get_subsystem_first(sd_device_enumerator *enumerator);
sd_device *sd_device_enumerator_get_subsystem_next(sd_device_enumerator *enumerator);

int sd_device_enumerator_add_match_subsystem(sd_device_enumerator *enumerator, const char *subsystem, int match);
int sd_device_enumerator_add_match_sysattr(
                sd_device_enumerator *enumerator, const char *sysattr, const char *value, int match);
int sd_device_enumerator_add_match_property(
                sd_device_enumerator *enumerator, const char *property, const char *value);
int sd_device_enumerator_add_match_property_required(
                sd_device_enumerator *enumerator, const char *property, const char *value);
int sd_device_enumerator_add_match_sysname(sd_device_enumerator *enumerator, const char *sysname);
int sd_device_enumerator_add_nomatch_sysname(sd_device_enumerator *enumerator, const char *sysname);
int sd_device_enumerator_add_match_tag(sd_device_enumerator *enumerator, const char *tag);
int sd_device_enumerator_add_match_parent(sd_device_enumerator *enumerator, sd_device *parent);
int sd_device_enumerator_allow_uninitialized(sd_device_enumerator *enumerator);
int sd_device_enumerator_add_all_parents(sd_device_enumerator *enumerator);

/* --- device monitor --- */

int sd_device_monitor_new(sd_device_monitor **ret);
sd_device_monitor *sd_device_monitor_ref(sd_device_monitor *m);
sd_device_monitor *sd_device_monitor_unref(sd_device_monitor *m);

static inline void sd_device_monitor_unrefp(sd_device_monitor **p) {
        if (*p)
                sd_device_monitor_unref(*p);
}

int sd_device_monitor_get_fd(sd_device_monitor *m);
int sd_device_monitor_get_events(sd_device_monitor *m);
int sd_device_monitor_get_timeout(sd_device_monitor *m, uint64_t *ret);
int sd_device_monitor_set_receive_buffer_size(sd_device_monitor *m, size_t size);
int sd_device_monitor_attach_event(sd_device_monitor *m, sd_event *event);
int sd_device_monitor_detach_event(sd_device_monitor *m);
sd_event *sd_device_monitor_get_event(sd_device_monitor *m);
sd_event_source *sd_device_monitor_get_event_source(sd_device_monitor *m);
int sd_device_monitor_set_description(sd_device_monitor *m, const char *description);
int sd_device_monitor_get_description(sd_device_monitor *m, const char **ret);
int sd_device_monitor_is_running(sd_device_monitor *m);
int sd_device_monitor_start(sd_device_monitor *m, sd_device_monitor_handler_t callback, void *userdata);
int sd_device_monitor_stop(sd_device_monitor *m);
int sd_device_monitor_receive(sd_device_monitor *m, sd_device **ret);

int sd_device_monitor_filter_add_match_subsystem_devtype(
                sd_device_monitor *m, const char *subsystem, const char *devtype);
int sd_device_monitor_filter_add_match_tag(sd_device_monitor *m, const char *tag);
int sd_device_monitor_filter_add_match_sysattr(
                sd_device_monitor *m, const char *sysattr, const char *value, int match);
int sd_device_monitor_filter_add_match_parent(sd_device_monitor *m, sd_device *device, int match);
int sd_device_monitor_filter_update(sd_device_monitor *m);
int sd_device_monitor_filter_remove(sd_device_monitor *m);

#ifdef __cplusplus
}
#endif
