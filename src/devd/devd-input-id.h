/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Input device classification -- the ID_INPUT* properties upstream's
 * input_id builtin computes for every input device, which input consumers
 * above the kernel key on.
 *
 * Xorg's config/udev backend enumerates the input subsystem filtered on
 * ID_INPUT=1 and decides a device's driver class from ID_INPUT_KEYBOARD/
 * _MOUSE/_TOUCHSCREEN/... With none set, Xorg adds zero input devices even
 * though the event nodes exist.
 *
 * The algorithm is upstream's src/udev/udev-builtin-input_id.c (GPL-2.0-or-
 * later, so ported directly rather than reimplemented) at systemd 041e70d7:
 * test_pointers(), test_key() and the wheel/switch tail of builtin_input_id(),
 * in that order, with the same first-match chains and the same joystick
 * un-detection heuristic. Two properties of that file are kept on purpose
 * because they are easy to "fix" by accident:
 *
 *  - The capability bitmaps are read off the device's input-subsystem
 *    ancestor, not the event node. eventN has no capabilities/ directory; its
 *    parent inputN does. /sys/class/input/mice has neither, and gets no
 *    ID_INPUT at all, exactly as upstream.
 *  - test_key() scans KEY_* bits [0, BTN_MISC) and then two high blocks, and
 *    BTN_TOUCH is in neither. A plain resistive touchscreen is therefore
 *    ID_INPUT_TOUCHSCREEN and NOT ID_INPUT_KEY, which is the classification
 *    that keeps Xorg from opening it a second time as a keyboard.
 *
 * Two divergences: ID_INPUT_WIDTH_MM/HEIGHT_MM are not produced
 * (upstream gets them from EVIOCGABS on the event node, and devd stays
 * sysfs-only), and no rule is needed to trigger any of this -- devd-rules.c
 * skips IMPORT{builtin} whole, so classification runs unconditionally, before
 * the rules, the way upstream's 60-input-id.rules runs before every consumer
 * rule after it.
 *
 * The result reaches consumers by two paths: the device's own property table
 * (so a rule can match ENV{ID_INPUT_TOUCHSCREEN}=="1" and a RUN+= child sees
 * it), and a /run/udev/data entry (devd-udev-db.h) that the compat
 * libsystemd's sd_device overlays onto the uevent properties.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <linux/input.h>

typedef struct Devd Devd;
typedef struct DevdRuleDevice DevdRuleDevice;

/* Same bound, and the same reason, as devd-match.c's DEVD_MATCH_WALK_MAX. */
#define DEVD_INPUT_ID_WALK_MAX 12

/* One capabilities/ line; upstream get_cap_mask()'s own text[4096]. */
#define DEVD_INPUT_ID_TEXT_MAX 4096

/*
 * Upstream's NBITS(), exactly. The kernel prints every capabilities/ file in the
 * reading task's own unsigned long width (input_bits_to_string() splits into
 * 32-bit words for a compat reader), so the array has to be in this process's
 * width too -- a fixed uint32_t layout would mis-index every word on a 64-bit
 * board.
 */
#define DEVD_INPUT_BITS_PER_LONG (sizeof(unsigned long) * 8)
#define DEVD_INPUT_NLONGS(max) ((((max) - 1) / DEVD_INPUT_BITS_PER_LONG) + 1)

/* One bit per property, in upstream's own emission order -- which is also
 * devd_input_id_names()'s order, and so the order of the database's E: lines. */
typedef enum DevdInputIdFlag {
        DEVD_INPUT_ID_INPUT = 1u << 0,         /* ID_INPUT */
        DEVD_INPUT_ID_ACCELEROMETER = 1u << 1, /* ID_INPUT_ACCELEROMETER */
        DEVD_INPUT_ID_POINTINGSTICK = 1u << 2, /* ID_INPUT_POINTINGSTICK */
        DEVD_INPUT_ID_MOUSE = 1u << 3,         /* ID_INPUT_MOUSE */
        DEVD_INPUT_ID_TOUCHPAD = 1u << 4,      /* ID_INPUT_TOUCHPAD */
        DEVD_INPUT_ID_TOUCHSCREEN = 1u << 5,   /* ID_INPUT_TOUCHSCREEN */
        DEVD_INPUT_ID_JOYSTICK = 1u << 6,      /* ID_INPUT_JOYSTICK */
        DEVD_INPUT_ID_TABLET = 1u << 7,        /* ID_INPUT_TABLET */
        DEVD_INPUT_ID_TABLET_PAD = 1u << 8,    /* ID_INPUT_TABLET_PAD */
        DEVD_INPUT_ID_KEY = 1u << 9,           /* ID_INPUT_KEY */
        DEVD_INPUT_ID_KEYBOARD = 1u << 10,     /* ID_INPUT_KEYBOARD */
        DEVD_INPUT_ID_SWITCH = 1u << 11,       /* ID_INPUT_SWITCH */
} DevdInputIdFlag;

#define DEVD_INPUT_ID_N_FLAGS 12

/* Everything the classifier looks at, as sysfs reports it for one device. */
typedef struct DevdInputCaps {
        unsigned long ev[DEVD_INPUT_NLONGS(EV_MAX)];
        unsigned long abs[DEVD_INPUT_NLONGS(ABS_MAX)];
        unsigned long rel[DEVD_INPUT_NLONGS(REL_MAX)];
        unsigned long key[DEVD_INPUT_NLONGS(KEY_MAX)];
        unsigned long props[DEVD_INPUT_NLONGS(INPUT_PROP_MAX)];
        uint16_t bustype; /* id/bustype, hex; 0 when unreadable */
} DevdInputCaps;

/*
 * Parse one capabilities/ line ("1 0 ffffffff" -- most significant word
 * first) into `bitmask`, least significant word at [0]. Upstream's own
 * right-to-left walk: a token that does not parse still consumes its index,
 * and words beyond `n_longs` are dropped. `bitmask` is zeroed first.
 * 0, -EINVAL on a NULL argument, or -E2BIG (bitmask left all-zero) for a line
 * longer than DEVD_INPUT_ID_TEXT_MAX.
 */
int devd_input_id_parse_bitmap(const char *text, unsigned long *bitmask, size_t n_longs);

/*
 * The directory whose capabilities/ev describes `sysfs_dir`: the device
 * itself when it has one, else the nearest ancestor whose subsystem is
 * "input". 1 with `ret` set, 0 when there is none, or -errno.
 */
int devd_input_id_find_caps_dir(const char *sys_root, const char *sysfs_dir, char *ret, size_t size);

/* Read capabilities/{ev,abs,rel,key}, properties and id/bustype under
 * `caps_dir`. An absent or unreadable file is an all-zero mask, as upstream
 * treats it. 0 or -errno. */
int devd_input_id_read_caps(const char *caps_dir, DevdInputCaps *ret);

/* The DevdInputIdFlag set for `caps`. DEVD_INPUT_ID_INPUT is always in it:
 * upstream sets ID_INPUT the moment a capabilities ancestor exists. */
unsigned devd_input_id_classify(const DevdInputCaps *caps);

/* find, read, classify. 1 with *ret_flags set, 0 when the device has no
 * capabilities ancestor (not an input device in input_id's sense), or -errno. */
int devd_input_id_probe(const char *sys_root, const char *sysfs_dir, unsigned *ret_flags);

/* The property names for `flags`, in emission order, at most `max` of them.
 * Returns how many were written. */
size_t devd_input_id_names(unsigned flags, const char **ret, size_t max);

/*
 * The reaction, for both the live and the coldplug path: for an "input"
 * subsystem device, classify, add the properties to `dev`'s own table, and
 * write (or, on remove or no classification, delete) its database entry.
 * Called before devd_rules_react() so the rules see the result. A no-op for
 * every other subsystem.
 */
void devd_input_id_react(Devd *d, DevdRuleDevice *dev);
