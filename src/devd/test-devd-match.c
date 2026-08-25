/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * What a rule means, against a sysfs tree built out of directories.
 *
 * A mock would be the wrong tool twice over. Half of what is under test is
 * literally file I/O -- ATTR{} is one open(), ATTRS{} is that open() repeated up
 * a chain of parent directories -- and the other half is what those reads add
 * up to for a real device topology. So each case builds the topology: a USB
 * serial adapter as /sys really lays one out, with the descriptor strings on
 * the usb_device four levels above the tty, and the interface number on the
 * interface in between. Getting the answer right means walking that.
 *
 * Two cases here carry the weight:
 *
 *  - The same-ancestor ATTRS{} rule, using usb-modeswitch's own Huawei
 *    catch-all. The fixture is built so that evaluating the rule's two ATTRS
 *    clauses independently would MATCH an Android phone the rule exists to
 *    exclude -- `ATTRS{manufacturer}!="Android"` is trivially true of the root
 *    hub further up the chain. Only requiring one ancestor to satisfy both
 *    gets it right, and that is what the assertion pins.
 *  - The shipped 60-pico-serial.rules file, parsed from its own bytes rather
 *    than from a copy of its rule pasted in here, so the file this project
 *    installs and the engine that reads it are tested together.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../test-util.h"
#include "../util.h"
#include "devd-match.h"
#include "devd-rules.h"

/* The USB tree every case below hangs off, relative to <root>/sys. */
#define USB_DEV "/devices/platform/soc/usb1/1-1"
#define USB_IFACE USB_DEV "/1-1:1.0"
#define TTY_DEV USB_IFACE "/ttyUSB0/tty/ttyUSB0"

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

/* Write one sysfs attribute, with the trailing newline the kernel puts there --
 * which is exactly what the reader has to trim, so the fixture keeps it. */
static void write_attr(const char *dir, const char *name, const char *value) {
        char path[PATH_MAX];
        FILE *f;

        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/%s", dir, name) < sizeof(path));

        f = fopen(path, "we");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fprintf(f, "%s\n", value) > 0);
        ASSERT_EQ_INT(fclose(f), 0);
}

static void join(char *ret, size_t size, const char *a, const char *b) {
        ASSERT_TRUE((size_t) snprintf(ret, size, "%s%s", a, b) < size);
}

/*
 * Lay out one USB serial adapter under <root>/sys. `manufacturer` may be NULL
 * for a device whose descriptors carry no strings -- the named v1 divergence,
 * where upstream's usb_id would fall back to hex IDs and devd deliberately does
 * not.
 */
static void
                make_usb_serial(const char *sys,
                                const char *vendor,
                                const char *manufacturer,
                                const char *product,
                                const char *serial) {
        char dev[PATH_MAX], iface[PATH_MAX], tty[PATH_MAX];

        join(dev, sizeof(dev), sys, USB_DEV);
        join(iface, sizeof(iface), sys, USB_IFACE);
        join(tty, sizeof(tty), sys, TTY_DEV);

        mkdir_p(tty);

        write_attr(dev, "idVendor", vendor);
        write_attr(dev, "idProduct", "6001");

        if (manufacturer)
                write_attr(dev, "manufacturer", manufacturer);
        if (product)
                write_attr(dev, "product", product);
        if (serial)
                write_attr(dev, "serial", serial);

        write_attr(iface, "bInterfaceNumber", "00");
        write_attr(iface, "bInterfaceClass", "08");
}

/* A device context pointing at the tty at the bottom of that tree. */
static DevdRuleDevice *tty_device(const char *sys, const char *dev_root, const char *action) {
        DevdRuleDevice *d = calloc(1, sizeof(*d));

        ASSERT_TRUE(d != NULL);

        d->sys_root = sys;
        d->dev_root = dev_root;

        ASSERT_TRUE((size_t) snprintf(d->devpath, sizeof(d->devpath), "%s", TTY_DEV) < sizeof(d->devpath));
        ASSERT_TRUE((size_t) snprintf(d->sysfs, sizeof(d->sysfs), "%s%s", sys, TTY_DEV) < sizeof(d->sysfs));
        (void) snprintf(d->kernel, sizeof(d->kernel), "ttyUSB0");
        (void) snprintf(d->devname, sizeof(d->devname), "ttyUSB0");
        (void) snprintf(d->subsystem, sizeof(d->subsystem), "tty");
        (void) snprintf(d->action, sizeof(d->action), "%s", action);
        d->number = 0;
        d->have_number = true;

        return d;
}

/* --- the shipped serial rules file --- */

static void test_pico_serial_rules(void) {
        char *root = test_tmpdir_new(), sys[PATH_MAX];
        DevdRuleDevice *d;
        DevdRuleResult res;
        DevdRuleSet *rs = NULL;

        ASSERT_TRUE(root != NULL);
        join(sys, sizeof(sys), root, "/sys");

        make_usb_serial(sys, "0403", "FTDI", "FT232R USB UART", "A50285BI");

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);

        /* The file meson installs, read as bytes -- not a copy of its rule. */
        ASSERT_EQ_INT(devd_ruleset_load_file(rs, PICO_SOURCE_DIR "/src/devd/60-pico-serial.rules"), 3);
        ASSERT_EQ_INT(rs->n_skipped, 0);

        d = tty_device(sys, "/dev", "add");
        ASSERT_EQ_INT(devd_rules_apply(rs, d, &res), 0);

        /* Both the guard and the naming rule matched; the guard's GOTO did not
         * fire because its ACTION=="remove" did not. */
        ASSERT_EQ_INT(res.n_matched, 1);
        ASSERT_EQ_INT(res.n_symlinks, 1);

        /*
         * Four $attr{} lookups, resolved at three different depths of the
         * parent chain, with the whitespace in "FT232R USB UART" collapsed by
         * the same sanitiser upstream's usb_id applies.
         */
        ASSERT_STREQ(res.symlinks[0], "serial/by-id/usb-FTDI_FT232R_USB_UART_A50285BI-if00");

        /* A remove takes the guard's GOTO to the label and creates nothing. */
        free(d);
        d = tty_device(sys, "/dev", "remove");
        ASSERT_EQ_INT(devd_rules_apply(rs, d, &res), 0);
        ASSERT_EQ_INT(res.n_matched, 1);
        ASSERT_EQ_INT(res.n_symlinks, 0);

        free(d);
        devd_ruleset_free(rs);
        test_rm_rf(root);
        free(root);
}

static void test_pico_serial_rules_without_descriptors(void) {
        char *root = test_tmpdir_new(), sys[PATH_MAX];
        DevdRuleDevice *d;
        DevdRuleResult res;
        DevdRuleSet *rs = NULL;

        ASSERT_TRUE(root != NULL);
        join(sys, sizeof(sys), root, "/sys");

        /* No manufacturer, product or serial: the recorded divergence. The
         * link is still made, with the empty components it really has, rather
         * than falling back to hex IDs the way upstream's usb_id would. */
        make_usb_serial(sys, "0403", NULL, NULL, NULL);

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);
        ASSERT_EQ_INT(devd_ruleset_load_file(rs, PICO_SOURCE_DIR "/src/devd/60-pico-serial.rules"), 3);

        d = tty_device(sys, "/dev", "add");
        ASSERT_EQ_INT(devd_rules_apply(rs, d, &res), 0);
        ASSERT_EQ_INT(res.n_symlinks, 1);
        ASSERT_STREQ(res.symlinks[0], "serial/by-id/usb-__-if00");

        free(d);
        devd_ruleset_free(rs);
        test_rm_rf(root);
        free(root);
}

/* --- the same-ancestor ATTRS{} rule --- */

/* usb-modeswitch's Huawei catch-all, verbatim. */
static const char huawei_rule[] =
                "ATTRS{idVendor}==\"12d1\", ATTRS{manufacturer}!=\"Android\", "
                "ATTR{bInterfaceNumber}==\"00\", ATTR{bInterfaceClass}==\"08\", "
                "RUN+=\"usb_modeswitch '%b/%k'\"\n";

/* A context on the USB interface, which is where those ATTR{} clauses live. */
static DevdRuleDevice *iface_device(const char *sys, const char *action) {
        DevdRuleDevice *d = calloc(1, sizeof(*d));

        ASSERT_TRUE(d != NULL);

        d->sys_root = sys;
        d->dev_root = "/dev";

        ASSERT_TRUE((size_t) snprintf(d->devpath, sizeof(d->devpath), "%s", USB_IFACE) < sizeof(d->devpath));
        ASSERT_TRUE((size_t) snprintf(d->sysfs, sizeof(d->sysfs), "%s%s", sys, USB_IFACE) < sizeof(d->sysfs));
        (void) snprintf(d->kernel, sizeof(d->kernel), "1-1:1.0");
        (void) snprintf(d->subsystem, sizeof(d->subsystem), "usb");
        (void) snprintf(d->action, sizeof(d->action), "%s", action);

        return d;
}

static void test_attrs_must_match_one_ancestor(void) {
        char *root = test_tmpdir_new(), sys[PATH_MAX], hub[PATH_MAX];
        DevdRuleDevice *d;
        DevdRuleResult res;
        DevdRuleSet *rs = NULL;

        ASSERT_TRUE(root != NULL);
        join(sys, sizeof(sys), root, "/sys");

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);
        ASSERT_EQ_INT(devd_ruleset_load_string(rs, huawei_rule, "huawei.rules"), 1);

        /* A real Huawei stick: the rule fires, and %b names the usb_device the
         * ATTRS group matched -- not the interface the event is about. */
        make_usb_serial(sys, "12d1", "HUAWEI", "HUAWEI Mobile", "0123456789ABCDEF");

        d = iface_device(sys, "add");
        ASSERT_EQ_INT(devd_rules_apply(rs, d, &res), 0);
        ASSERT_EQ_INT(res.n_matched, 1);
        ASSERT_EQ_INT(res.n_runs, 1);
        ASSERT_STREQ(res.runs[0], "usb_modeswitch '1-1/1-1:1.0'");
        ASSERT_STREQ(d->parent, "1-1");
        free(d);

        test_rm_rf(root);

        /*
         * The same device claiming to be an Android phone. The root hub above
         * it has no `manufacturer` attribute at all, so `ATTRS{manufacturer}
         * !="Android"` is satisfied THERE -- which is exactly the trap: an
         * engine that let each ATTRS clause find its own ancestor would fire
         * this rule on the one device it was written to exclude.
         */
        mkdir_p(sys);
        join(hub, sizeof(hub), sys, "/devices/platform/soc/usb1");
        mkdir_p(hub);
        make_usb_serial(sys, "12d1", "Android", "Android Phone", "deadbeef");

        d = iface_device(sys, "add");
        ASSERT_EQ_INT(devd_rules_apply(rs, d, &res), 0);
        ASSERT_EQ_INT(res.n_matched, 0);
        ASSERT_EQ_INT(res.n_runs, 0);
        free(d);

        devd_ruleset_free(rs);
        test_rm_rf(root);
        free(root);
}

/* --- the 415-rule shape, and the guards around it --- */

static void test_vendor_pair_rule_and_guards(void) {
        static const char text[] =
                        "ACTION!=\"add|change\", GOTO=\"end\"\n"
                        "SUBSYSTEM!=\"usb\", ACTION!=\"add\",, GOTO=\"end\"\n"
                        "ATTR{idVendor}==\"12d1\", ATTR{idProduct}==\"1f01\", "
                        "RUN+=\"usb_modeswitch '/%k'\"\n"
                        "LABEL=\"end\"\n";

        char *root = test_tmpdir_new(), sys[PATH_MAX], dev[PATH_MAX];
        DevdRuleDevice *d;
        DevdRuleResult res;
        DevdRuleSet *rs = NULL;

        ASSERT_TRUE(root != NULL);
        join(sys, sizeof(sys), root, "/sys");
        join(dev, sizeof(dev), sys, USB_DEV);

        mkdir_p(dev);
        write_attr(dev, "idVendor", "12d1");
        write_attr(dev, "idProduct", "1f01");

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);
        ASSERT_EQ_INT(devd_ruleset_load_string(rs, text, "pairs.rules"), 4);

        d = calloc(1, sizeof(*d));
        ASSERT_TRUE(d != NULL);
        d->sys_root = sys;
        d->dev_root = "/dev";
        ASSERT_TRUE((size_t) snprintf(d->devpath, sizeof(d->devpath), "%s", USB_DEV) < sizeof(d->devpath));
        ASSERT_TRUE((size_t) snprintf(d->sysfs, sizeof(d->sysfs), "%s%s", sys, USB_DEV) < sizeof(d->sysfs));
        (void) snprintf(d->kernel, sizeof(d->kernel), "1-1");
        (void) snprintf(d->subsystem, sizeof(d->subsystem), "usb");
        (void) snprintf(d->action, sizeof(d->action), "add");

        ASSERT_EQ_INT(devd_rules_apply(rs, d, &res), 0);
        ASSERT_EQ_INT(res.n_runs, 1);
        ASSERT_STREQ(res.runs[0], "usb_modeswitch '/1-1'");

        /* The first guard's GOTO jumps past everything, so a `remove` reaches
         * no RUN at all -- which is what makes the guard a guard. */
        (void) snprintf(d->action, sizeof(d->action), "remove");
        ASSERT_EQ_INT(devd_rules_apply(rs, d, &res), 0);
        ASSERT_EQ_INT(res.n_runs, 0);

        /*
         * The second guard, isolated: `change` gets past the first one, and a
         * non-USB subsystem then hits this one. Its two clauses are ANDed, not
         * ORed -- reading `SUBSYSTEM!="usb", ACTION!="add"` as "skip anything
         * that is not a USB add" is the obvious misreading, and it is not what
         * the line says or what devd does with it.
         */
        (void) snprintf(d->action, sizeof(d->action), "change");
        (void) snprintf(d->subsystem, sizeof(d->subsystem), "block");
        ASSERT_EQ_INT(devd_rules_apply(rs, d, &res), 0);
        ASSERT_EQ_INT(res.n_runs, 0);

        /* Same subsystem, `add`: the second guard's ACTION!="add" is false, so
         * it does not fire and the vendor rule is reached after all. */
        (void) snprintf(d->action, sizeof(d->action), "add");
        ASSERT_EQ_INT(devd_rules_apply(rs, d, &res), 0);
        ASSERT_EQ_INT(res.n_runs, 1);

        free(d);
        devd_ruleset_free(rs);
        test_rm_rf(root);
        free(root);
}

/* --- substitutions --- */

static void test_substitutions(void) {
        char *root = test_tmpdir_new(), sys[PATH_MAX], out[256];
        DevdRuleDevice *d;

        ASSERT_TRUE(root != NULL);
        join(sys, sizeof(sys), root, "/sys");

        make_usb_serial(sys, "0403", "FTDI", "FT232R USB UART", "A50285BI");

        d = tty_device(sys, "/dev", "add");
        ASSERT_EQ_INT(devd_rule_device_set_property(d, "MAJOR", "188", false), 0);
        ASSERT_EQ_INT(devd_rule_device_set_property(d, ".PART_SUFFIX", "-part3", false), 0);

        devd_rules_substitute(d, "%k", out, sizeof(out));
        ASSERT_STREQ(out, "ttyUSB0");

        devd_rules_substitute(d, "$kernel", out, sizeof(out));
        ASSERT_STREQ(out, "ttyUSB0");

        devd_rules_substitute(d, "%p", out, sizeof(out));
        ASSERT_STREQ(out, TTY_DEV);

        devd_rules_substitute(d, "n=%n", out, sizeof(out));
        ASSERT_STREQ(out, "n=0");

        /* %b is empty until an ATTRS group has matched something -- it means
         * "the ancestor this rule matched", not "some ancestor". */
        devd_rules_substitute(d, "[%b]", out, sizeof(out));
        ASSERT_STREQ(out, "[]");

        devd_rules_substitute(d, "$env{MAJOR}/$env{MINOR}", out, sizeof(out));
        ASSERT_STREQ(out, "188/");

        /* Private names are ordinary to $env{}; they are only absent from a
         * child's environment. */
        devd_rules_substitute(d, "x$env{.PART_SUFFIX}", out, sizeof(out));
        ASSERT_STREQ(out, "x-part3");

        devd_rules_substitute(d, "$attr{manufacturer}_$attr{product}", out, sizeof(out));
        ASSERT_STREQ(out, "FTDI_FT232R_USB_UART");

        devd_rules_substitute(d, "%s{serial}", out, sizeof(out));
        ASSERT_STREQ(out, "A50285BI");

        devd_rules_substitute(d, "$attr{nosuchthing}!", out, sizeof(out));
        ASSERT_STREQ(out, "!");

        devd_rules_substitute(d, "100%% $$ done", out, sizeof(out));
        ASSERT_STREQ(out, "100% $ done");

        /* An escape devd does not implement stays visible rather than
         * shortening the result into something that looks deliberate. */
        devd_rules_substitute(d, "%c", out, sizeof(out));
        ASSERT_STREQ(out, "%c");

        free(d);
        test_rm_rf(root);
        free(root);
}

/* --- ENV, MODE/OWNER/GROUP, and the child environment --- */

static void test_env_and_permissions(void) {
        static const char text[] =
                        "SUBSYSTEM==\"tty\", ENV{PICO_TAG}=\"serial\"\n"
                        "ENV{PICO_TAG}==\"serial\", ENV{PICO_TAG}+=\"port\"\n"
                        "ENV{PICO_TAG}==\"serial port\", MODE=\"0660\", OWNER=\"root\", "
                        "GROUP=\"dialout\"\n"
                        "ENV{NOSUCH}!=\"anything\", ENV{.PRIV}=\"hidden\"\n";

        char *root = test_tmpdir_new(), sys[PATH_MAX];
        DevdRuleDevice *d;
        DevdRuleResult res;
        DevdRuleSet *rs = NULL;
        char **env = NULL;
        bool saw_tag = false, saw_priv = false, saw_action = false;

        ASSERT_TRUE(root != NULL);
        join(sys, sizeof(sys), root, "/sys");
        make_usb_serial(sys, "0403", "FTDI", "FT232R USB UART", "A50285BI");

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);
        ASSERT_EQ_INT(devd_ruleset_load_string(rs, text, "env.rules"), 4);

        d = tty_device(sys, "/dev", "add");
        ASSERT_EQ_INT(devd_rules_apply(rs, d, &res), 0);

        /* Each rule saw what the one before it assigned. */
        ASSERT_STREQ(devd_rule_device_property(d, "PICO_TAG"), "serial port");
        ASSERT_TRUE(res.have_mode);
        ASSERT_EQ_INT(res.mode, 0660);
        ASSERT_STREQ(res.owner, "root");
        ASSERT_STREQ(res.group, "dialout");

        /* An unset property is the empty string to a match, which is what makes
         * the fourth rule fire at all. */
        ASSERT_STREQ(devd_rule_device_property(d, ".PRIV"), "hidden");

        ASSERT_EQ_INT(devd_rules_environment(d, &env), 0);

        for (size_t i = 0; env[i]; i++) {
                if (strcmp(env[i], "PICO_TAG=serial port") == 0)
                        saw_tag = true;
                if (strncmp(env[i], ".PRIV=", 6) == 0)
                        saw_priv = true;
                if (strcmp(env[i], "ACTION=add") == 0)
                        saw_action = true;
        }

        ASSERT_TRUE(saw_tag);
        ASSERT_TRUE(saw_action);
        ASSERT_TRUE(!saw_priv); /* private names never reach a child */

        pico_strv_free(env);
        free(d);
        devd_ruleset_free(rs);
        test_rm_rf(root);
        free(root);
}

static void test_lookup_id(void) {
        char *root = test_tmpdir_new(), path[PATH_MAX];
        unsigned id = 0;

        ASSERT_TRUE(root != NULL);
        ASSERT_EQ_INT(test_write_file(root,
                                      "group",
                                      "root:x:0:\n"
                                      "dialout:x:20:koen\n"
                                      "broken\n"),
                      0);

        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/group", root) < sizeof(path));

        ASSERT_EQ_INT(devd_rules_lookup_id(path, "dialout", &id), 1);
        ASSERT_EQ_INT(id, 20);

        ASSERT_EQ_INT(devd_rules_lookup_id(path, "root", &id), 1);
        ASSERT_EQ_INT(id, 0);

        ASSERT_EQ_INT(devd_rules_lookup_id(path, "nosuchgroup", &id), 0);

        /* A numeric name answers itself, which is what makes MODE/OWNER/GROUP
         * work on an image with no /etc/group at all -- today's pico image. */
        ASSERT_EQ_INT(devd_rules_lookup_id("/nonexistent", "44", &id), 1);
        ASSERT_EQ_INT(id, 44);

        test_rm_rf(root);
        free(root);
}

/* --- building the context from the two sources --- */

static void test_device_from_uevent(void) {
        static const char msg[] =
                        "add@/devices/platform/soc/usb1/1-1\0"
                        "ACTION=add\0"
                        "DEVPATH=/devices/platform/soc/usb1/1-1\0"
                        "SUBSYSTEM=usb\0"
                        "DEVNAME=bus/usb/001/004\0"
                        "DEVTYPE=usb_device\0"
                        "PRODUCT=12d1/1f01/102\0"
                        "MAJOR=189\0"
                        "MINOR=3";

        DevdRuleDevice *d = calloc(1, sizeof(*d));
        DevdUevent u;

        ASSERT_TRUE(d != NULL);
        ASSERT_EQ_INT(devd_uevent_parse(msg, sizeof(msg), &u), 0);
        ASSERT_EQ_INT(devd_rule_device_from_uevent(d, "/sys", "/dev", &u), 0);

        ASSERT_STREQ(d->action, "add");
        ASSERT_STREQ(d->subsystem, "usb");
        ASSERT_STREQ(d->kernel, "1-1");
        ASSERT_STREQ(d->devname, "bus/usb/001/004");
        ASSERT_STREQ(d->sysfs, "/sys/devices/platform/soc/usb1/1-1");

        /* The whole property tail is there, not just the six fields H1
         * decoded -- that is what ENV{} matches on and what a RUN+= child is
         * handed. */
        ASSERT_STREQ(devd_rule_device_property(d, "PRODUCT"), "12d1/1f01/102");
        ASSERT_STREQ(devd_rule_device_property(d, "DEVTYPE"), "usb_device");
        ASSERT_TRUE(devd_rule_device_property(d, "NOTHERE") == NULL);

        free(d);
}

static void test_device_from_sysfs(void) {
        char *root = test_tmpdir_new(), sys[PATH_MAX], dev[PATH_MAX], sub[PATH_MAX];
        DevdRuleDevice *d = calloc(1, sizeof(*d));
        char path[PATH_MAX];
        FILE *f;

        ASSERT_TRUE(root != NULL && d != NULL);
        join(sys, sizeof(sys), root, "/sys");
        join(dev, sizeof(dev), sys, USB_DEV);
        join(sub, sizeof(sub), sys, "/class/usb");

        mkdir_p(dev);
        mkdir_p(sub);

        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/uevent", dev) < sizeof(path));

        f = fopen(path, "we");
        ASSERT_TRUE(f != NULL);
        ASSERT_TRUE(fputs("DEVTYPE=usb_device\nDEVNAME=bus/usb/001/004\nPRODUCT=12d1/1f01/102\n", f) >= 0);
        ASSERT_EQ_INT(fclose(f), 0);

        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/subsystem", dev) < sizeof(path));
        ASSERT_EQ_INT(symlink("../../../../class/usb", path), 0);

        /* The coldplug path: same properties as a broadcast message, with the
         * ACTION and DEVPATH only a real event carries supplied here. */
        ASSERT_EQ_INT(devd_rule_device_from_sysfs(d, sys, "/dev", dev, "add"), 0);
        ASSERT_STREQ(d->action, "add");
        ASSERT_STREQ(d->subsystem, "usb");
        ASSERT_STREQ(d->kernel, "1-1");
        ASSERT_STREQ(d->devpath, USB_DEV);
        ASSERT_STREQ(d->devname, "bus/usb/001/004");
        ASSERT_STREQ(devd_rule_device_property(d, "PRODUCT"), "12d1/1f01/102");

        free(d);
        test_rm_rf(root);
        free(root);
}

int main(void) {
        test_pico_serial_rules();
        test_pico_serial_rules_without_descriptors();
        test_attrs_must_match_one_ancestor();
        test_vendor_pair_rule_and_guards();
        test_substitutions();
        test_env_and_permissions();
        test_lookup_id();
        test_device_from_uevent();
        test_device_from_sysfs();

        return 0;
}
