/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * input_id, ported. devd-input-id.h has what this is for, which upstream file
 * and revision it follows, and the divergences. Everything below the sysfs
 * reads is upstream's decision tree in upstream's order; where a line looks
 * odd, it is odd upstream too, and the comment says so rather than fixing it.
 */

#include "devd-input-id.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../util.h"
#include "devd-match.h"
#include "devd-udev-db.h"
#include "devd.h"

static inline bool test_bit(unsigned bit, const unsigned long *bitmask) {
        return (bitmask[bit / DEVD_INPUT_BITS_PER_LONG] >> (bit % DEVD_INPUT_BITS_PER_LONG)) & 1UL;
}

/* Any bit set in [from, to). */
static bool any_bit(const unsigned long *bitmask, unsigned from, unsigned to) {
        for (unsigned b = from; b < to; b++)
                if (test_bit(b, bitmask))
                        return true;

        return false;
}

/* How many bits are set in [from, to). */
static size_t count_bits(const unsigned long *bitmask, unsigned from, unsigned to) {
        size_t n = 0;

        for (unsigned b = from; b < to; b++)
                if (test_bit(b, bitmask))
                        n++;

        return n;
}

/* --- reading sysfs --- */

/* One whole hex word, the way upstream's safe_atolu_full() takes it: no sign,
 * no leading space, nothing after it. strtoul() alone would accept " -1". */
static bool parse_hex_word(const char *s, unsigned long *ret) {
        unsigned long v;
        char *end;

        if (!s || !isxdigit((unsigned char) s[0]))
                return false;

        errno = 0;
        v = strtoul(s, &end, 16);
        if (errno != 0 || *end != '\0')
                return false;

        *ret = v;
        return true;
}

int devd_input_id_parse_bitmap(const char *text, unsigned long *bitmask, size_t n_longs) {
        char buf[DEVD_INPUT_ID_TEXT_MAX];
        unsigned long v;
        size_t len, i = 0;
        char *space;

        if (!text || !bitmask)
                return -EINVAL;

        memset(bitmask, 0, n_longs * sizeof(*bitmask));

        len = strlen(text);
        if (len >= sizeof(buf))
                return -E2BIG;

        memcpy(buf, text, len + 1);

        while (len > 0 &&
               (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' ' || buf[len - 1] == '\t'))
                buf[--len] = '\0';

        /*
         * Last token first: the kernel prints the most significant word on the
         * left, so the rightmost one is word 0. A token that fails to parse
         * still advances `i` -- upstream logs it and moves on, and keeping the
         * index is what keeps every word after it in its right place.
         */
        while ((space = strrchr(buf, ' '))) {
                if (parse_hex_word(space + 1, &v) && i < n_longs)
                        bitmask[i] = v;

                *space = '\0';
                i++;
        }

        if (parse_hex_word(buf, &v) && i < n_longs)
                bitmask[i] = v;

        return 0;
}

/* Is <dir>/subsystem a link to a directory called "input"? */
static bool subsystem_is_input(const char *dir) {
        char path[PATH_MAX], target[PATH_MAX];
        const char *base;
        ssize_t k;

        if ((size_t) snprintf(path, sizeof(path), "%s/subsystem", dir) >= sizeof(path))
                return false;

        k = readlink(path, target, sizeof(target) - 1);
        if (k < 0)
                return false;

        target[k] = '\0';
        base = strrchr(target, '/');
        return strcmp(base ? base + 1 : target, "input") == 0;
}

int devd_input_id_find_caps_dir(const char *sys_root, const char *sysfs_dir, char *ret, size_t size) {
        char dir[PATH_MAX];
        size_t root_len;

        if (!sys_root || !sysfs_dir || !ret || size == 0)
                return -EINVAL;

        if ((size_t) snprintf(dir, sizeof(dir), "%s", sysfs_dir) >= sizeof(dir))
                return -ENAMETOOLONG;

        root_len = strlen(sys_root);

        for (unsigned depth = 0; depth < DEVD_INPUT_ID_WALK_MAX; depth++) {
                char probe[PATH_MAX];
                char *slash;

                /*
                 * The device itself on the first pass, whatever its subsystem
                 * -- upstream asks the device for capabilities/ev before it
                 * asks for a parent. After that, only input-subsystem
                 * ancestors count, which is what
                 * sd_device_get_parent_with_subsystem_devtype(dev, "input")
                 * means: a platform or USB device further up is skipped even
                 * if it happened to carry a file of that name.
                 */
                if ((depth == 0 || subsystem_is_input(dir)) &&
                    (size_t) snprintf(probe, sizeof(probe), "%s/capabilities/ev", dir) < sizeof(probe) &&
                    access(probe, F_OK) == 0) {
                        if (strlen(dir) >= size)
                                return -ENAMETOOLONG;

                        strcpy(ret, dir);
                        return 1;
                }

                /* devd-match.c's walk_up(), for the reason it gives: sys_root
                 * is what stops the walk leaving sysfs -- in a test, what stops
                 * it reaching the host's own /sys. */
                slash = strrchr(dir, '/');
                if (!slash)
                        break;

                *slash = '\0';

                if (strlen(dir) <= root_len)
                        break;
        }

        return 0;
}

/* The first line of <dir>/<name>, or "" when it cannot be read. Absent is
 * a real state, not an error: a device with no EV_REL has a capabilities/rel
 * of "0", but upstream treats a missing file as that same empty mask. */
static int read_line(const char *dir, const char *name, char *buf, size_t size) {
        char path[PATH_MAX];
        FILE *f;

        buf[0] = '\0';

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, name) >= sizeof(path))
                return -ENAMETOOLONG;

        f = fopen(path, "re");
        if (!f)
                return 0;

        if (!fgets(buf, (int) size, f))
                buf[0] = '\0';

        (void) fclose(f);
        return 0;
}

static int read_mask(const char *dir, const char *name, unsigned long *bitmask, size_t n_longs) {
        char text[DEVD_INPUT_ID_TEXT_MAX];
        int r;

        r = read_line(dir, name, text, sizeof(text));
        if (r < 0)
                return r;

        /* -E2BIG cannot happen: fgets() already stopped one byte short of the
         * parser's own buffer, which is the same size. */
        return devd_input_id_parse_bitmap(text, bitmask, n_longs);
}

int devd_input_id_read_caps(const char *caps_dir, DevdInputCaps *ret) {
        char text[DEVD_INPUT_ID_TEXT_MAX];
        unsigned long bus;
        char *end;
        int r;

        if (!caps_dir || !ret)
                return -EINVAL;

        memset(ret, 0, sizeof(*ret));

        r = read_mask(caps_dir, "capabilities/ev", ret->ev, DEVD_INPUT_NLONGS(EV_MAX));
        if (r < 0)
                return r;

        r = read_mask(caps_dir, "capabilities/abs", ret->abs, DEVD_INPUT_NLONGS(ABS_MAX));
        if (r < 0)
                return r;

        r = read_mask(caps_dir, "capabilities/rel", ret->rel, DEVD_INPUT_NLONGS(REL_MAX));
        if (r < 0)
                return r;

        r = read_mask(caps_dir, "capabilities/key", ret->key, DEVD_INPUT_NLONGS(KEY_MAX));
        if (r < 0)
                return r;

        r = read_mask(caps_dir, "properties", ret->props, DEVD_INPUT_NLONGS(INPUT_PROP_MAX));
        if (r < 0)
                return r;

        r = read_line(caps_dir, "id/bustype", text, sizeof(text));
        if (r < 0)
                return r;

        text[strcspn(text, "\r\n")] = '\0';

        errno = 0;
        bus = strtoul(text, &end, 16);
        if (text[0] != '\0' && *end == '\0' && errno == 0 && bus <= 0xffff)
                ret->bustype = (uint16_t) bus;

        return 0;
}

/* --- the classification --- */

/* upstream test_pointers(). Sets the pointer-class flags; true for a pointer. */
static bool classify_pointers(const DevdInputCaps *c, unsigned *flags) {
        static const unsigned well_known_keyboard_keys[] = {
                KEY_LEFTCTRL, KEY_CAPSLOCK, KEY_NUMLOCK, KEY_INSERT,    KEY_MUTE,
                KEY_CALC,     KEY_FILE,     KEY_MAIL,    KEY_PLAYPAUSE, KEY_BRIGHTNESSDOWN,
        };
        bool has_keys, has_abs, has_3d, has_mt, has_rel, has_stylus, has_pen, finger_but_no_pen;
        bool has_mouse_button, is_direct, has_touch, has_pad_buttons, has_wheel;
        bool is_tablet = false, is_touchpad = false, is_abs_mouse = false, is_touchscreen = false;
        bool is_joystick = false, is_mouse = false, is_tablet_pad = false, is_pointing_stick;
        size_t jb = 0, ja;

        has_keys = test_bit(EV_KEY, c->ev);
        has_abs = test_bit(ABS_X, c->abs) && test_bit(ABS_Y, c->abs);
        has_3d = has_abs && test_bit(ABS_Z, c->abs);

        /* Three absolute axes and no keys at all is an accelerometer even
         * without the property bit -- upstream's fallback for drivers that
         * predate INPUT_PROP_ACCELEROMETER. And it returns here: nothing below
         * is asked, which is also why the wheel fallback in
         * devd_input_id_classify() never fires for one. */
        if (test_bit(INPUT_PROP_ACCELEROMETER, c->props) || (!has_keys && has_3d)) {
                *flags |= DEVD_INPUT_ID_ACCELEROMETER;
                return true;
        }

        is_pointing_stick = test_bit(INPUT_PROP_POINTING_STICK, c->props);
        has_stylus = test_bit(BTN_STYLUS, c->key);
        has_pen = test_bit(BTN_TOOL_PEN, c->key);
        finger_but_no_pen = test_bit(BTN_TOOL_FINGER, c->key) && !test_bit(BTN_TOOL_PEN, c->key);
        has_mouse_button = any_bit(c->key, BTN_MOUSE, BTN_JOYSTICK);
        has_rel = test_bit(EV_REL, c->ev) && test_bit(REL_X, c->rel) && test_bit(REL_Y, c->rel);
        has_mt = test_bit(ABS_MT_POSITION_X, c->abs) && test_bit(ABS_MT_POSITION_Y, c->abs);

        /* A device that claims every absolute axis up to and including
         * ABS_MT_SLOT is not really multitouch -- upstream's guard against
         * drivers that set the whole range. */
        if (has_mt && test_bit(ABS_MT_SLOT, c->abs) && test_bit(ABS_MT_SLOT - 1, c->abs))
                has_mt = false;

        is_direct = test_bit(INPUT_PROP_DIRECT, c->props);
        has_touch = test_bit(BTN_TOUCH, c->key);
        has_pad_buttons = test_bit(BTN_0, c->key) && test_bit(BTN_1, c->key) && !has_pen;
        has_wheel = test_bit(EV_REL, c->ev) && (test_bit(REL_WHEEL, c->rel) || test_bit(REL_HWHEEL, c->rel));

        /* A mouse with more than sixteen buttons runs into the joystick range,
         * which is why the bit just below it gates the whole count. */
        if (!test_bit(BTN_JOYSTICK - 1, c->key)) {
                jb += count_bits(c->key, BTN_JOYSTICK, BTN_DIGI);
                jb += count_bits(c->key, BTN_TRIGGER_HAPPY1, BTN_TRIGGER_HAPPY40 + 1);
                jb += count_bits(c->key, BTN_DPAD_UP, BTN_DPAD_RIGHT + 1);
        }
        ja = count_bits(c->abs, ABS_RX, ABS_PRESSURE);

        if (has_abs) {
                if (has_stylus || has_pen)
                        is_tablet = true;
                else if (finger_but_no_pen && !is_direct)
                        is_touchpad = true;
                else if (has_mouse_button)
                        /* Upstream's VMware USB mouse: absolute axes, no
                         * touch or pressure button. */
                        is_abs_mouse = true;
                else if (has_touch || is_direct)
                        is_touchscreen = true;
                else if (jb > 0 || ja > 0)
                        is_joystick = true;
        } else if (jb > 0 || ja > 0)
                is_joystick = true;

        if (has_mt) {
                if (has_stylus || has_pen)
                        is_tablet = true;
                else if (finger_but_no_pen && !is_direct)
                        is_touchpad = true;
                else if (has_touch || is_direct)
                        is_touchscreen = true;
        }

        if (is_tablet && has_pad_buttons)
                is_tablet_pad = true;

        if (has_pad_buttons && has_wheel && !has_rel) {
                is_tablet = true;
                is_tablet_pad = true;
        }

        if (!is_tablet && !is_touchpad && !is_joystick && has_mouse_button && (has_rel || !has_abs))
                is_mouse = true;

        /* Upstream: "there is no such thing as an i2c mouse". */
        if (is_mouse && c->bustype == BUS_I2C)
                is_pointing_stick = true;

        /*
         * Joystick un-detection, upstream's (and libinput's) heuristic: a
         * keyboard with stray joystick bits set still has several of these
         * well-known keys, and a "joystick" with fewer than two buttons and
         * axes between them is not one.
         */
        if (is_joystick) {
                size_t well_known = 0;

                if (has_keys)
                        for (size_t i = 0;
                             i < sizeof(well_known_keyboard_keys) / sizeof(well_known_keyboard_keys[0]);
                             i++)
                                if (test_bit(well_known_keyboard_keys[i], c->key))
                                        well_known++;

                if (well_known >= 4 || jb + ja < 2)
                        is_joystick = false;

                if (has_wheel && has_pad_buttons)
                        is_joystick = false;
        }

        if (is_pointing_stick)
                *flags |= DEVD_INPUT_ID_POINTINGSTICK;
        if (is_mouse || is_abs_mouse)
                *flags |= DEVD_INPUT_ID_MOUSE;
        if (is_touchpad)
                *flags |= DEVD_INPUT_ID_TOUCHPAD;
        if (is_touchscreen)
                *flags |= DEVD_INPUT_ID_TOUCHSCREEN;
        if (is_joystick)
                *flags |= DEVD_INPUT_ID_JOYSTICK;
        if (is_tablet)
                *flags |= DEVD_INPUT_ID_TABLET;
        if (is_tablet_pad)
                *flags |= DEVD_INPUT_ID_TABLET_PAD;

        return is_tablet || is_mouse || is_abs_mouse || is_touchpad || is_touchscreen || is_joystick ||
                        is_pointing_stick;
}

/*
 * upstream test_key(). The low scan is per bit rather than upstream's
 * per-word `i < BTN_MISC/BITS_PER_LONG`, which is the same range at either
 * word size without depending on which one this is.
 */
static bool classify_keys(const DevdInputCaps *c, unsigned *flags) {
        bool found, is_key = false;

        if (!test_bit(EV_KEY, c->ev))
                return false;

        /* KEY_* only, not BTN_*; then the two high KEY_* blocks above the
         * button ranges. BTN_TOUCH (0x14a) is in none of these. */
        found = any_bit(c->key, 0, BTN_MISC);
        if (!found)
                found = any_bit(c->key, KEY_OK, BTN_DPAD_UP) ||
                                any_bit(c->key, KEY_ALS_TOGGLE, BTN_TRIGGER_HAPPY);

        if (found) {
                *flags |= DEVD_INPUT_ID_KEY;
                is_key = true;
        }

        /* Bits 1-31, KEY_ESC through KEY_S, all set: a full keyboard.
         * KEY_RESERVED (bit 0) is not required. */
        if ((c->key[0] & 0xFFFFFFFEUL) == 0xFFFFFFFEUL) {
                *flags |= DEVD_INPUT_ID_KEYBOARD;
                is_key = true;
        }

        return is_key;
}

unsigned devd_input_id_classify(const DevdInputCaps *caps) {
        unsigned flags = DEVD_INPUT_ID_INPUT;
        bool is_pointer, is_key;

        if (!caps)
                return 0;

        is_pointer = classify_pointers(caps, &flags);
        is_key = classify_keys(caps, &flags);

        /* A scroll wheel and nothing else is a key device to upstream, so
         * that something opens it. */
        if (!is_pointer && !is_key && test_bit(EV_REL, caps->ev) &&
            (test_bit(REL_WHEEL, caps->rel) || test_bit(REL_HWHEEL, caps->rel)))
                flags |= DEVD_INPUT_ID_KEY;

        if (test_bit(EV_SW, caps->ev))
                flags |= DEVD_INPUT_ID_SWITCH;

        return flags;
}

int devd_input_id_probe(const char *sys_root, const char *sysfs_dir, unsigned *ret_flags) {
        char caps_dir[PATH_MAX];
        DevdInputCaps caps;
        int r;

        if (!ret_flags)
                return -EINVAL;

        r = devd_input_id_find_caps_dir(sys_root, sysfs_dir, caps_dir, sizeof(caps_dir));
        if (r <= 0)
                return r;

        r = devd_input_id_read_caps(caps_dir, &caps);
        if (r < 0)
                return r;

        *ret_flags = devd_input_id_classify(&caps);
        return 1;
}

static const struct {
        DevdInputIdFlag flag;
        const char *name;
} input_id_names[DEVD_INPUT_ID_N_FLAGS] = {
        {         DEVD_INPUT_ID_INPUT,               "ID_INPUT" },
        { DEVD_INPUT_ID_ACCELEROMETER, "ID_INPUT_ACCELEROMETER" },
        { DEVD_INPUT_ID_POINTINGSTICK, "ID_INPUT_POINTINGSTICK" },
        {         DEVD_INPUT_ID_MOUSE,         "ID_INPUT_MOUSE" },
        {      DEVD_INPUT_ID_TOUCHPAD,      "ID_INPUT_TOUCHPAD" },
        {   DEVD_INPUT_ID_TOUCHSCREEN,   "ID_INPUT_TOUCHSCREEN" },
        {      DEVD_INPUT_ID_JOYSTICK,      "ID_INPUT_JOYSTICK" },
        {        DEVD_INPUT_ID_TABLET,        "ID_INPUT_TABLET" },
        {    DEVD_INPUT_ID_TABLET_PAD,    "ID_INPUT_TABLET_PAD" },
        {           DEVD_INPUT_ID_KEY,           "ID_INPUT_KEY" },
        {      DEVD_INPUT_ID_KEYBOARD,      "ID_INPUT_KEYBOARD" },
        {        DEVD_INPUT_ID_SWITCH,        "ID_INPUT_SWITCH" },
};

size_t devd_input_id_names(unsigned flags, const char **ret, size_t max) {
        size_t n = 0;

        if (!ret)
                return 0;

        for (size_t i = 0; i < DEVD_INPUT_ID_N_FLAGS && n < max; i++)
                if (flags & input_id_names[i].flag)
                        ret[n++] = input_id_names[i].name;

        return n;
}

/* --- the reaction --- */

void devd_input_id_react(Devd *d, DevdRuleDevice *dev) {
        const char *names[DEVD_INPUT_ID_N_FLAGS] = { NULL }, *values[DEVD_INPUT_ID_N_FLAGS] = { NULL };
        char id[DEVD_UDEV_DB_ID_MAX], list[DEVD_INPUT_ID_N_FLAGS * 24];
        unsigned flags = 0;
        size_t n, used = 0;
        bool id_ok;
        int r;

        if (!d || !dev || strcmp(dev->subsystem, "input") != 0)
                return;

        id_ok = devd_udev_db_id(dev, id, sizeof(id)) == 0;

        /* sysfs is already gone on a remove, so there is nothing to classify
         * -- only an entry to retire, before a reused devnum inherits it. */
        if (strcmp(dev->action, "remove") == 0) {
                if (id_ok) {
                        r = devd_udev_db_delete(d->udev_db_root, id);
                        if (r < 0)
                                pico_log(PICO_LOG_WARNING,
                                         "devd: cannot remove udev db %s/%s: %s",
                                         d->udev_db_root,
                                         id,
                                         strerror(-r));
                }

                return;
        }

        /*
         * Every other action re-classifies. The capability bitmaps are fixed
         * for the device's lifetime, so a change or bind gets the same answer
         * as the add did, and rewriting is both idempotent and atomic -- which
         * is also what makes a coldplug re-walk after -ENOBUFS harmless. No
         * classification deletes rather than leaves the old entry: that is
         * what keeps a stale-entry sweep unnecessary anywhere.
         */
        r = devd_input_id_probe(dev->sys_root, dev->sysfs, &flags);
        if (r <= 0) {
                if (id_ok)
                        (void) devd_udev_db_delete(d->udev_db_root, id);

                if (r < 0)
                        pico_log(PICO_LOG_DEBUG, "devd: cannot classify %s: %s", dev->kernel, strerror(-r));
                else
                        pico_log(PICO_LOG_DEBUG, "devd: %s has no input capabilities", dev->kernel);
                return;
        }

        n = devd_input_id_names(flags, names, DEVD_INPUT_ID_N_FLAGS);

        list[0] = '\0';
        for (size_t i = 0; i < n; i++) {
                int k;

                values[i] = "1";

                /* Into the device's own table for the rules and any RUN+=
                 * child. A full table only costs the rules their view of it;
                 * the database below is written from `names`, not the table. */
                r = devd_rule_device_set_property(dev, names[i], "1", false);
                if (r < 0)
                        pico_log(PICO_LOG_DEBUG,
                                 "devd: %s: cannot set %s: %s",
                                 dev->kernel,
                                 names[i],
                                 strerror(-r));

                k = snprintf(list + used, sizeof(list) - used, "%s%s", i > 0 ? " " : "", names[i]);
                if (k > 0 && (size_t) k < sizeof(list) - used)
                        used += (size_t) k;
        }

        if (id_ok) {
                r = devd_udev_db_write(d->udev_db_root, id, now_monotonic(), names, values, n);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "devd: cannot write udev db %s/%s: %s",
                                 d->udev_db_root,
                                 id,
                                 strerror(-r));
        }

        pico_log(PICO_LOG_DEBUG, "devd: %s: %s", dev->kernel, list);
}
