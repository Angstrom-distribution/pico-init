/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The private struct sd_device layout and the helpers shared across
 * device-*.c. Nothing here is part of the public ABI (sd-device.h) -- every
 * external caller only ever holds the opaque pointer.
 *
 * A device is a snapshot: everything below is either read once and cached,
 * or scanned once and iterated, and nothing here re-reads /sys behind a
 * caller's back after construction. That is real sd-device's own contract
 * too (a device handle does not track live changes; you get a fresh one from
 * a new constructor call or a monitor event for that).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sd-device.h"

/* One KEY=VALUE property. Properties never embed a NUL (they come from
 * text-line uevent parsing), unlike sysattr values below. */
typedef struct DeviceProperty {
        char *key;
        char *value;
} DeviceProperty;

/* A cached sysattr read. `value == NULL` means a cached negative result
 * (the attribute does not exist, or a transient error was NOT cached --
 * see device-sysattr.c for which errors are excluded). */
typedef struct DeviceSysattr {
        char *name;
        char *value;
        size_t size;      /* valid only when value != NULL */
        int cached_errno; /* valid only when value == NULL */
} DeviceSysattr;

typedef struct DeviceChild {
        char *suffix;      /* relative path component under the parent's syspath */
        sd_device *device; /* owned */
} DeviceChild;

/* One add_match_sysattr() entry -- shared shape between the enumerator and
 * the monitor's filter, since both are "(sysattr, value-or-any, require-or-
 * exclude)". */
typedef struct DeviceSysattrMatch {
        char *sysattr;
        char *value; /* NULL means "any value" */
        bool match;  /* true: require; false: exclude */
} DeviceSysattrMatch;

/* One add_match_property()/add_match_property_required() entry. */
typedef struct DeviceEnumeratorProperty {
        char *key;
        char *value; /* NULL means "any value" */
} DeviceEnumeratorProperty;

struct sd_device {
        unsigned n_ref;

        char *syspath;       /* canonical, "<sys_root>/devices/..." */
        const char *devpath; /* = syspath + strlen(sys_root); borrowed */

        /*
         * True for a device built from a monitor message or from
         * sd_device_enumerator_get_subsystem_first()/_next() (a "subsystem"
         * pseudo-device, which has no uevent file to read at all -- see
         * device_new_from_syspath_internal()'s `relaxed` argument).
         */
        bool from_monitor;
        bool no_uevent_file;

        /* Lazy property table: uevent file (or monitor env) plus synthesized
         * DEVPATH/SUBSYSTEM/DRIVER/ACTION/SEQNUM/SYNTH_UUID. Built once, on
         * first access, by device_ensure_properties(). */
        bool properties_built;
        int properties_errno; /* the result of the one build attempt */
        DeviceProperty *properties;
        size_t n_properties;
        size_t property_iter;

        /* Cached scalar getters that are not part of the property table
         * (readlink- or syspath-grammar-based, not uevent-based). Each has
         * its own resolved flag because "resolved to a real -ENOENT" and
         * "never looked up" are different states. */
        char *subsystem;
        bool subsystem_resolved;
        int subsystem_errno;

        char *driver;
        bool driver_resolved;
        int driver_errno;

        char *driver_subsystem;
        bool driver_subsystem_resolved;
        int driver_subsystem_errno;

        char *sysname;
        char *sysnum; /* NULL when sysname has no trailing digits */
        bool sysname_resolved;

        char *device_id;
        bool device_id_resolved;
        int device_id_errno;

        char *devname; /* "/dev/..."-prefixed, cached from the DEVNAME property */
        bool devname_resolved;

        /* The udev database overlay (device-db.c), read at most once, from
         * inside device_ensure_properties() -- never for a monitor device. */
        bool db_loaded;
        uint64_t usec_initialized; /* the I: record; 0 when there was none */
        unsigned database_version; /* the V: record; 0 when there was none */

        sd_device *parent;
        bool parent_resolved;
        int parent_errno;

        /* Set directly by the monitor/trigger paths; never derived from a
         * plain sysfs uevent file, which carries neither field. */
        sd_device_action_t action;
        bool has_seqnum;
        uint64_t seqnum;
        bool has_synth_uuid;
        sd_id128_t synth_uuid;

        /* devlinks (device-devlink.c) */
        bool devlinks_scanned;
        char **devlinks;
        size_t n_devlinks;
        size_t devlink_iter;

        /* sysattr name iteration (device-sysattr.c) */
        bool sysattr_names_scanned;
        char **sysattr_names;
        size_t n_sysattr_names;
        size_t sysattr_iter;

        /* sysattr value cache (device-sysattr.c) */
        DeviceSysattr *sysattr_cache;
        size_t n_sysattr_cache;

        /* children (device-child.c) */
        bool children_scanned;
        DeviceChild *children;
        size_t n_children;
        size_t child_iter;
};

struct sd_device_enumerator {
        unsigned n_ref;

        /* --- matches --- */
        char **match_subsystem;
        size_t n_match_subsystem;
        char **nomatch_subsystem;
        size_t n_nomatch_subsystem;

        DeviceSysattrMatch *sysattr_matches;
        size_t n_sysattr_matches;

        DeviceEnumeratorProperty *property_matches;
        size_t n_property_matches;

        DeviceEnumeratorProperty *property_required;
        size_t n_property_required;

        char **match_sysname;
        size_t n_match_sysname;
        char **nomatch_sysname;
        size_t n_nomatch_sysname;

        char **match_tag;
        size_t n_match_tag;

        char **match_parent; /* syspaths */
        size_t n_match_parent;

        bool allow_uninitialized; /* stored, changes nothing */
        bool all_parents;

        /* --- scan result --- */
        bool scanned;
        sd_device **devices; /* owned refs */
        size_t n_devices;
        size_t iter;
};

typedef struct DeviceMonitorSubsystemDevtype {
        char *subsystem;
        char *devtype; /* NULL means any devtype */
} DeviceMonitorSubsystemDevtype;

typedef struct DeviceMonitorParentMatch {
        char *syspath;
        bool match; /* true: require under this parent; false: exclude */
} DeviceMonitorParentMatch;

struct sd_device_monitor {
        unsigned n_ref;

        int sock; /* AF_NETLINK/NETLINK_KOBJECT_UEVENT, or -1 before open */
        char *description;

        /* Every filter is evaluated in userspace inside
         * sd_device_monitor_receive(). */
        DeviceMonitorSubsystemDevtype *subsystem_devtype;
        size_t n_subsystem_devtype;

        char **tags;
        size_t n_tags;

        DeviceSysattrMatch *sysattr_matches;
        size_t n_sysattr_matches;

        DeviceMonitorParentMatch *parent_matches;
        size_t n_parent_matches;
};

/* --- device-new.c --- */

/*
 * Shared /sys root, "/sys" in production. Every constructor and the
 * enumerator's bus/class walk goes through this rather than a literal
 * "/sys", so tests can point it at a fixture tree without root and without
 * touching the host's real /sys. Test-only.
 */
const char *device_sys_root(void);
void device_set_sys_root_for_tests(const char *root);

/* The real constructor everything else funnels through. `relaxed` skips the
 * uevent-file-exists requirement, for the enumerator's subsystem pseudo-
 * devices (sd-device.h's sd_device_enumerator_get_subsystem_first()), which
 * name a real sysfs directory that is a device only by convention. */
int device_new_from_syspath_internal(sd_device **ret, const char *syspath, bool relaxed);

sd_device *device_new_bare(void); /* zeroed, n_ref = 1, everything else unset; NULL on OOM */

/*
 * A monitor-received device (device-monitor.c), built with no filesystem
 * access: a "remove" event's device is usually already gone from /sys when
 * the message is read, so requiring it to exist, as
 * device_new_from_syspath_internal() does, would make remove events
 * undeliverable. `devpath` is the kernel-relative path from the message
 * header ("/devices/..."); the syspath is sys_root + devpath. Getters that
 * touch disk (get_driver(), a sysattr read) return -ENOENT for a device
 * that is gone.
 */
int device_new_from_devpath_bare(sd_device **ret, const char *devpath);

/*
 * The device-id grammar -- b<maj>:<min>, c<maj>:<min>, n<ifindex>,
 * +<subsystem>:<sysname> -- from whatever the property table holds right now.
 * sd_device_get_device_id() is this plus caching; device-db.c needs it from
 * INSIDE device_ensure_properties(), where sd_device_get_devnum() would
 * re-enter the build it is part of, so this reads MAJOR/MINOR/IFINDEX with
 * device_get_property_raw() only and never builds the table itself. 0,
 * -ENOENT, or -ENAMETOOLONG.
 */
int device_format_id(sd_device *d, char *buf, size_t size);

/* --- device-uevent.c --- */

/* Build d->properties if not already built: base (uevent file, or the
 * caller-supplied monitor env) plus synthesized keys. 0 or -errno; the
 * result is cached in d->properties_errno so a failing build is not retried
 * on every call. */
int device_ensure_properties(sd_device *d);

/* Add one KEY=VALUE pair, copying both. Later duplicates of the same key are
 * dropped (first write wins), which is what lets synthesized keys be
 * appended unconditionally after the base table without overwriting a real
 * value the base table already had. 0 or -ENOMEM. */
int device_add_property(sd_device *d, const char *key, const char *value);

/* Replace-or-append: the one setter with replace semantics, for the udev
 * database overlay, whose E: records override the uevent's value of the same
 * key the way upstream's do. An existing key keeps its position; a NULL or
 * empty `value` removes the key. 0 or -ENOMEM. */
int device_set_property(sd_device *d, const char *key, const char *value);

/* Overlay a monitor message's properties as the device's base table
 * (device-monitor.c), before device_ensure_properties() adds the
 * synthesized keys. 0 or -ENOMEM. */
int device_set_monitor_properties(sd_device *d, const char * const *keys, const char * const *values, size_t n);

/* Raw lookup in the built table; NULL if absent. Does not itself call
 * device_ensure_properties(). */
const char *device_get_property_raw(sd_device *d, const char *key);

const char *device_action_to_string(sd_device_action_t a);
sd_device_action_t device_action_from_string(const char *s);

/* sd_id128_t <-> RFC 4122 36-char string. */
void device_id128_to_uuid_string(sd_id128_t id, char s[37]);
int device_id128_from_uuid_string(const char *s, sd_id128_t *ret); /* 0 or -EINVAL */

/* --- device-db.c --- */

/* "/run/udev/data" in production; settable for tests, the same shape as
 * device_set_sys_root_for_tests(). NULL restores the default. */
const char *device_udev_db_root(void);
void device_set_udev_db_root_for_tests(const char *root);

/*
 * Overlay the device's /run/udev/data/<device-id> entry, if any, onto its
 * property table: E: records replace or remove, I: sets usec_initialized and
 * USEC_INITIALIZED, V: sets database_version. Once per device, and never for
 * a monitor device or a subsystem pseudo-device. A missing or unreadable
 * entry is no entry. 0, or -ENOMEM.
 */
int device_read_db(sd_device *d);

/* --- device-devlink.c --- */

const char *device_dev_root(void);
void device_set_dev_root_for_tests(const char *root);

/* --- device-monitor.c --- */

/* True when `dev` passes every filter installed on `m`. Exposed so tests
 * can exercise the matching logic against a fixture device without a socket. */
bool device_monitor_filter_matches(sd_device_monitor *m, sd_device *dev);

/* --- shared path-safety helper (device-new.c) --- */

/* True when `p` is a plain relative path with no ".." component and no
 * leading '/' -- the same shape sd_device_new_child()'s suffix, a sysattr
 * name, and a SYMLINK+= target all have to satisfy before touching a real
 * path built by string concatenation. */
bool device_path_component_is_safe(const char *p);
