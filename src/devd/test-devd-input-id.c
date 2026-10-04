/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * input_id: the bitmap parser, the classification, and the sysfs walk that
 * finds what to classify.
 *
 * The classification cases build DevdInputCaps directly, one per device
 * shape upstream's decision tree distinguishes, and assert the WHOLE flag
 * set rather than one bit of it -- most of what can go wrong in a port of
 * that tree is an extra property (a touchscreen that is also ID_INPUT_KEY, a
 * keyboard that is also a joystick), and a single-bit check cannot see it.
 * The h2200's resistive touchscreen is the first case because it is the one
 * this exists for.
 *
 * The sysfs fixture writes every capabilities/ file the way the kernel does,
 * most significant word first and in this process's own word width -- which
 * is the only layout the parser can be right about, since the kernel chooses
 * the width by who is reading.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../test-util.h"
#include "../util.h"
#include "devd-input-id.h"

static void mkdir_p(const char *path) {
        char buf[PATH_MAX];

        ASSERT_TRUE((size_t) snprintf(buf, sizeof(buf), "%s", path) < sizeof(buf));

        for (char *p = buf + 1; *p; p++) {
                if (*p != '/')
                        continue;

                *p = '\0';
                ASSERT_TRUE(mkdir(buf, 0755) == 0 || errno == EEXIST);
                *p = '/';
        }

        ASSERT_TRUE(mkdir(buf, 0755) == 0 || errno == EEXIST);
}

static void set_bit(unsigned long *bitmask, unsigned bit) {
        bitmask[bit / DEVD_INPUT_BITS_PER_LONG] |= 1UL << (bit % DEVD_INPUT_BITS_PER_LONG);
}

static void set_bits(unsigned long *bitmask, unsigned from, unsigned to) {
        for (unsigned b = from; b <= to; b++)
                set_bit(bitmask, b);
}

/* The kernel's input_print_bitmap(): leading zero words skipped, then every
 * word from the highest non-zero one down, "%lx" each, space-separated. */
static void format_bitmap(const unsigned long *bitmask, size_t n_longs, char *buf, size_t size) {
        size_t top = n_longs, used = 0;

        while (top > 1 && bitmask[top - 1] == 0)
                top--;

        buf[0] = '\0';
        for (size_t i = top; i > 0; i--) {
                int k = snprintf(buf + used, size - used, "%s%lx", i < top ? " " : "", bitmask[i - 1]);

                ASSERT_TRUE(k > 0 && (size_t) k < size - used);
                used += (size_t) k;
        }
}

/* --- the parser --- */

static void test_parse_bitmap(void) {
        unsigned long m[4];
        char huge[DEVD_INPUT_ID_TEXT_MAX + 8];

        ASSERT_EQ_INT(devd_input_id_parse_bitmap("3", m, 4), 0);
        ASSERT_TRUE(m[0] == 0x3 && m[1] == 0 && m[2] == 0 && m[3] == 0);

        /* Most significant first, so the rightmost token is word 0. */
        ASSERT_EQ_INT(devd_input_id_parse_bitmap("1 0 ffffffff", m, 4), 0);
        ASSERT_TRUE(m[0] == 0xffffffffUL && m[1] == 0 && m[2] == 1 && m[3] == 0);

        /* Words past n_longs are dropped, and nothing past n_longs is
         * touched, not even zeroed. */
        m[2] = 0x55;
        ASSERT_EQ_INT(devd_input_id_parse_bitmap("5 4 3 2 1", m, 2), 0);
        ASSERT_TRUE(m[0] == 1 && m[1] == 2 && m[2] == 0x55);

        /* A token that does not parse still takes its index: the "3" stays
         * word 0 and the "1" stays word 2, as upstream keeps them. */
        ASSERT_EQ_INT(devd_input_id_parse_bitmap("1 zz 3", m, 4), 0);
        ASSERT_TRUE(m[0] == 3 && m[1] == 0 && m[2] == 1);

        ASSERT_EQ_INT(devd_input_id_parse_bitmap("1 -2 3", m, 4), 0);
        ASSERT_TRUE(m[0] == 3 && m[1] == 0 && m[2] == 1);

        m[0] = m[1] = 0x77;
        ASSERT_EQ_INT(devd_input_id_parse_bitmap("", m, 4), 0);
        ASSERT_TRUE(m[0] == 0 && m[1] == 0 && m[2] == 0 && m[3] == 0);

        /* The newline a sysfs read hands over. */
        ASSERT_EQ_INT(devd_input_id_parse_bitmap("3\n", m, 4), 0);
        ASSERT_TRUE(m[0] == 3 && m[1] == 0);

        ASSERT_EQ_INT(devd_input_id_parse_bitmap("a 3 \n", m, 4), 0);
        ASSERT_TRUE(m[0] == 3 && m[1] == 0xa);

        ASSERT_EQ_INT(devd_input_id_parse_bitmap(NULL, m, 4), -EINVAL);

        memset(huge, '1', sizeof(huge) - 1);
        huge[sizeof(huge) - 1] = '\0';
        m[0] = 0x77;
        ASSERT_EQ_INT(devd_input_id_parse_bitmap(huge, m, 4), -E2BIG);
        ASSERT_TRUE(m[0] == 0);
}

/* --- the classification --- */

static void test_classify_touchscreen(void) {
        DevdInputCaps c;

        /* h2200-style resistive panel: EV_KEY with just BTN_TOUCH, and X/Y/
         * pressure. Not ID_INPUT_KEY -- BTN_TOUCH is outside every range
         * test_key() looks at. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_SYN);
        set_bit(c.ev, EV_KEY);
        set_bit(c.ev, EV_ABS);
        set_bit(c.key, BTN_TOUCH);
        set_bit(c.abs, ABS_X);
        set_bit(c.abs, ABS_Y);
        set_bit(c.abs, ABS_PRESSURE);
        ASSERT_EQ_INT(devd_input_id_classify(&c), DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_TOUCHSCREEN);

        /* INPUT_PROP_DIRECT alone is enough, no BTN_TOUCH needed. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_ABS);
        set_bit(c.abs, ABS_X);
        set_bit(c.abs, ABS_Y);
        set_bit(c.props, INPUT_PROP_DIRECT);
        ASSERT_EQ_INT(devd_input_id_classify(&c), DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_TOUCHSCREEN);
}

static void test_classify_keys(void) {
        DevdInputCaps c;

        /* gpio-keys: a couple of KEY_* codes, nowhere near a keyboard. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_KEY);
        set_bit(c.key, KEY_POWER);
        set_bit(c.key, KEY_VOLUMEUP);
        ASSERT_EQ_INT(devd_input_id_classify(&c), DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_KEY);

        /* KEY_ESC (1) through KEY_S (31): a full keyboard. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_KEY);
        set_bits(c.key, KEY_ESC, KEY_S);
        ASSERT_EQ_INT(devd_input_id_classify(&c),
                      DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_KEY | DEVD_INPUT_ID_KEYBOARD);

        /* One short of it is not. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_KEY);
        set_bits(c.key, KEY_ESC, KEY_W);
        ASSERT_EQ_INT(devd_input_id_classify(&c), DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_KEY);

        /* A key in only the high block still counts. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_KEY);
        set_bit(c.key, KEY_OK);
        ASSERT_EQ_INT(devd_input_id_classify(&c), DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_KEY);

        /* A lid switch. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_SW);
        ASSERT_EQ_INT(devd_input_id_classify(&c), DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_SWITCH);

        /* A wheel and nothing else is a key device to upstream. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_REL);
        set_bit(c.rel, REL_WHEEL);
        ASSERT_EQ_INT(devd_input_id_classify(&c), DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_KEY);
}

static void test_classify_pointers(void) {
        DevdInputCaps c;

        /* A USB mouse. Its buttons are BTN_*, not KEY_*, so no ID_INPUT_KEY. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_KEY);
        set_bit(c.ev, EV_REL);
        set_bit(c.rel, REL_X);
        set_bit(c.rel, REL_Y);
        set_bit(c.key, BTN_LEFT);
        c.bustype = BUS_USB;
        ASSERT_EQ_INT(devd_input_id_classify(&c), DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_MOUSE);

        /* The same on I2C: "there is no such thing as an i2c mouse". */
        c.bustype = BUS_I2C;
        ASSERT_EQ_INT(devd_input_id_classify(&c),
                      DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_POINTINGSTICK | DEVD_INPUT_ID_MOUSE);

        /* A touchpad: finger tool, no pen, not direct. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_KEY);
        set_bit(c.ev, EV_ABS);
        set_bit(c.abs, ABS_X);
        set_bit(c.abs, ABS_Y);
        set_bit(c.key, BTN_TOOL_FINGER);
        set_bit(c.key, BTN_TOUCH);
        ASSERT_EQ_INT(devd_input_id_classify(&c), DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_TOUCHPAD);

        /* Three absolute axes and no keys: an accelerometer, and nothing
         * else -- the pointer logic is never reached. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_ABS);
        set_bit(c.abs, ABS_X);
        set_bit(c.abs, ABS_Y);
        set_bit(c.abs, ABS_Z);
        ASSERT_EQ_INT(devd_input_id_classify(&c), DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_ACCELEROMETER);

        /* A real joystick: two axes and two joystick buttons. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_KEY);
        set_bit(c.ev, EV_ABS);
        set_bit(c.abs, ABS_X);
        set_bit(c.abs, ABS_Y);
        set_bit(c.key, BTN_TRIGGER);
        set_bit(c.key, BTN_THUMB);
        ASSERT_EQ_INT(devd_input_id_classify(&c), DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_JOYSTICK);

        /* A keyboard with two stray joystick buttons: still a keyboard, and
         * NOT a joystick, because it has five of the well-known keys. */
        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_KEY);
        set_bits(c.key, KEY_ESC, KEY_S);
        set_bit(c.key, KEY_CAPSLOCK);
        set_bit(c.key, KEY_NUMLOCK);
        set_bit(c.key, KEY_INSERT);
        set_bit(c.key, KEY_MUTE);
        set_bit(c.key, BTN_TRIGGER);
        set_bit(c.key, BTN_THUMB);
        ASSERT_EQ_INT(devd_input_id_classify(&c),
                      DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_KEY | DEVD_INPUT_ID_KEYBOARD);
}

static void test_names(void) {
        const char *names[DEVD_INPUT_ID_N_FLAGS];
        size_t n;

        n = devd_input_id_names((1u << DEVD_INPUT_ID_N_FLAGS) - 1, names, DEVD_INPUT_ID_N_FLAGS);
        ASSERT_EQ_INT(n, DEVD_INPUT_ID_N_FLAGS);
        ASSERT_STREQ(names[0], "ID_INPUT");
        ASSERT_STREQ(names[1], "ID_INPUT_ACCELEROMETER");
        ASSERT_STREQ(names[2], "ID_INPUT_POINTINGSTICK");
        ASSERT_STREQ(names[3], "ID_INPUT_MOUSE");
        ASSERT_STREQ(names[4], "ID_INPUT_TOUCHPAD");
        ASSERT_STREQ(names[5], "ID_INPUT_TOUCHSCREEN");
        ASSERT_STREQ(names[6], "ID_INPUT_JOYSTICK");
        ASSERT_STREQ(names[7], "ID_INPUT_TABLET");
        ASSERT_STREQ(names[8], "ID_INPUT_TABLET_PAD");
        ASSERT_STREQ(names[9], "ID_INPUT_KEY");
        ASSERT_STREQ(names[10], "ID_INPUT_KEYBOARD");
        ASSERT_STREQ(names[11], "ID_INPUT_SWITCH");

        n = devd_input_id_names(
                        DEVD_INPUT_ID_SWITCH | DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_TOUCHSCREEN, names, 8);
        ASSERT_EQ_INT(n, 3);
        ASSERT_STREQ(names[0], "ID_INPUT");
        ASSERT_STREQ(names[1], "ID_INPUT_TOUCHSCREEN");
        ASSERT_STREQ(names[2], "ID_INPUT_SWITCH");

        /* `max` is a hard bound. */
        ASSERT_EQ_INT(devd_input_id_names(DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_KEY, names, 1), 1);
        ASSERT_STREQ(names[0], "ID_INPUT");
}

/* --- the sysfs walk --- */

static void write_line(const char *dir, const char *name, const char *value) {
        char path[PATH_MAX];
        FILE *f;

        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/%s", dir, name) < sizeof(path));

        f = fopen(path, "we");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fprintf(f, "%s\n", value) > 0);
        ASSERT_EQ_INT(fclose(f), 0);
}

/*
 * The h2200 touchscreen as the kernel lays it out: inputN under its platform
 * device holding capabilities/, properties and id/, and eventN under it
 * holding only a uevent. Both have a subsystem link to class/input.
 */
static void make_touchscreen(const char *sys, char *input_dir, char *event_dir, size_t size) {
        DevdInputCaps c;
        char path[PATH_MAX], text[512], class_input[PATH_MAX];

        memset(&c, 0, sizeof(c));
        set_bit(c.ev, EV_SYN);
        set_bit(c.ev, EV_KEY);
        set_bit(c.ev, EV_ABS);
        set_bit(c.key, BTN_TOUCH);
        set_bit(c.abs, ABS_X);
        set_bit(c.abs, ABS_Y);
        set_bit(c.abs, ABS_PRESSURE);

        ASSERT_TRUE((size_t) snprintf(input_dir, size, "%s/devices/platform/ts/input/input3", sys) < size);
        ASSERT_TRUE((size_t) snprintf(event_dir, size, "%s/event3", input_dir) < size);
        ASSERT_TRUE((size_t) snprintf(class_input, sizeof(class_input), "%s/class/input", sys) <
                    sizeof(class_input));

        mkdir_p(class_input);
        mkdir_p(event_dir);

        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/capabilities", input_dir) < sizeof(path));
        mkdir_p(path);
        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/id", input_dir) < sizeof(path));
        mkdir_p(path);

        format_bitmap(c.ev, DEVD_INPUT_NLONGS(EV_MAX), text, sizeof(text));
        write_line(input_dir, "capabilities/ev", text);
        format_bitmap(c.key, DEVD_INPUT_NLONGS(KEY_MAX), text, sizeof(text));
        write_line(input_dir, "capabilities/key", text);
        format_bitmap(c.abs, DEVD_INPUT_NLONGS(ABS_MAX), text, sizeof(text));
        write_line(input_dir, "capabilities/abs", text);
        write_line(input_dir, "capabilities/rel", "0");
        write_line(input_dir, "properties", "0");
        write_line(input_dir, "id/bustype", "0019");
        write_line(event_dir, "uevent", "MAJOR=13\nMINOR=67\nDEVNAME=input/event3");

        ASSERT_EQ_INT(test_symlink(input_dir, "subsystem", class_input), 0);
        ASSERT_EQ_INT(test_symlink(event_dir, "subsystem", class_input), 0);
}

static void test_find_caps_dir(void) {
        char *root = test_tmpdir_new(), sys[PATH_MAX], input_dir[PATH_MAX], event_dir[PATH_MAX];
        char found[PATH_MAX], path[PATH_MAX], class_input[PATH_MAX];
        DevdInputCaps c;
        unsigned flags = 0;

        ASSERT_TRUE(root != NULL);
        ASSERT_TRUE((size_t) snprintf(sys, sizeof(sys), "%s/sys", root) < sizeof(sys));
        ASSERT_TRUE((size_t) snprintf(class_input, sizeof(class_input), "%s/class/input", sys) <
                    sizeof(class_input));

        make_touchscreen(sys, input_dir, event_dir, sizeof(input_dir));

        /* eventN answers with its parent inputN; inputN with itself. */
        ASSERT_EQ_INT(devd_input_id_find_caps_dir(sys, event_dir, found, sizeof(found)), 1);
        ASSERT_STREQ(found, input_dir);
        ASSERT_EQ_INT(devd_input_id_find_caps_dir(sys, input_dir, found, sizeof(found)), 1);
        ASSERT_STREQ(found, input_dir);

        /* The fixture round-trips through the kernel's own text format. */
        ASSERT_EQ_INT(devd_input_id_read_caps(input_dir, &c), 0);
        ASSERT_EQ_INT(c.bustype, BUS_HOST);
        ASSERT_EQ_INT(devd_input_id_classify(&c), DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_TOUCHSCREEN);

        ASSERT_EQ_INT(devd_input_id_probe(sys, event_dir, &flags), 1);
        ASSERT_EQ_INT(flags, DEVD_INPUT_ID_INPUT | DEVD_INPUT_ID_TOUCHSCREEN);

        /* A device with no input ancestor at all. */
        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/devices/platform/foo", sys) < sizeof(path));
        mkdir_p(path);
        ASSERT_EQ_INT(devd_input_id_find_caps_dir(sys, path, found, sizeof(found)), 0);
        ASSERT_EQ_INT(devd_input_id_probe(sys, path, &flags), 0);

        /* /sys/class/input/mice's shape: input subsystem, no capabilities,
         * and a parent (devices/virtual/input) that is no device at all. */
        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/devices/virtual/input/mice", sys) < sizeof(path));
        mkdir_p(path);
        ASSERT_EQ_INT(test_symlink(path, "subsystem", class_input), 0);
        ASSERT_EQ_INT(devd_input_id_find_caps_dir(sys, path, found, sizeof(found)), 0);

        /* A non-input ancestor that happens to carry capabilities/ev is
         * skipped: only the device itself, or an input-subsystem ancestor,
         * is asked. */
        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/devices/platform/bogus/capabilities", sys) <
                    sizeof(path));
        mkdir_p(path);
        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/devices/platform/bogus", sys) < sizeof(path));
        write_line(path, "capabilities/ev", "b");
        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/devices/platform/bogus/child", sys) <
                    sizeof(path));
        mkdir_p(path);
        ASSERT_EQ_INT(devd_input_id_find_caps_dir(sys, path, found, sizeof(found)), 0);

        test_rm_rf(root);
        free(root);
}

int main(void) {
        test_parse_bitmap();
        test_classify_touchscreen();
        test_classify_keys();
        test_classify_pointers();
        test_names();
        test_find_caps_dir();

        return 0;
}
