/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The udev database writer, against a real directory.
 *
 * What matters about this file is byte-exactness, because its reader is a
 * different program: the compat libsystemd's device-db.c finds the entry by
 * the device-id grammar and parses it by the record grammar, and a writer
 * that is merely "close" -- an id spelled differently, an E: line out of
 * place, a missing V: -- produces a file that is there and is never read.
 * So the content assertion compares the whole file, not a substring of it.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../test-util.h"
#include "../util.h"
#include "devd-match.h"
#include "devd-udev-db.h"

static DevdRuleDevice *device_new(const char *subsystem, const char *kernel) {
        DevdRuleDevice *d = calloc(1, sizeof(*d));

        ASSERT_TRUE(d != NULL);
        (void) snprintf(d->subsystem, sizeof(d->subsystem), "%s", subsystem);
        (void) snprintf(d->kernel, sizeof(d->kernel), "%s", kernel);
        return d;
}

static void read_file(const char *path, char *buf, size_t size) {
        FILE *f = fopen(path, "re");
        size_t n;

        ASSERT_TRUE(f != NULL);
        n = fread(buf, 1, size - 1, f);
        buf[n] = '\0';
        ASSERT_EQ_INT(fclose(f), 0);
}

/* Nothing but `name` in `dir` -- in particular no ".#<id>.devd" left over. */
static void assert_only_entry(const char *dir, const char *name) {
        struct dirent *e;
        unsigned seen = 0;
        DIR *dd = opendir(dir);

        ASSERT_TRUE(dd != NULL);

        while ((e = readdir(dd))) {
                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                        continue;

                ASSERT_STREQ(e->d_name, name);
                seen++;
        }

        ASSERT_EQ_INT(closedir(dd), 0);
        ASSERT_EQ_INT(seen, 1);
}

static void test_id(void) {
        char id[DEVD_UDEV_DB_ID_MAX];
        DevdRuleDevice *d;

        /* An event node: the devnum form, 'c' for anything not block. */
        d = device_new("input", "event3");
        ASSERT_EQ_INT(devd_rule_device_set_property(d, "MAJOR", "13", false), 0);
        ASSERT_EQ_INT(devd_rule_device_set_property(d, "MINOR", "67", false), 0);
        ASSERT_EQ_INT(devd_udev_db_id(d, id, sizeof(id)), 0);
        ASSERT_STREQ(id, "c13:67");
        free(d);

        /* inputN has no node: subsystem and sysname. */
        d = device_new("input", "input3");
        ASSERT_EQ_INT(devd_udev_db_id(d, id, sizeof(id)), 0);
        ASSERT_STREQ(id, "+input:input3");
        free(d);

        d = device_new("block", "sda");
        ASSERT_EQ_INT(devd_rule_device_set_property(d, "MAJOR", "8", false), 0);
        ASSERT_EQ_INT(devd_rule_device_set_property(d, "MINOR", "0", false), 0);
        ASSERT_EQ_INT(devd_udev_db_id(d, id, sizeof(id)), 0);
        ASSERT_STREQ(id, "b8:0");
        free(d);

        d = device_new("net", "eth0");
        ASSERT_EQ_INT(devd_rule_device_set_property(d, "IFINDEX", "2", false), 0);
        ASSERT_EQ_INT(devd_udev_db_id(d, id, sizeof(id)), 0);
        ASSERT_STREQ(id, "n2");
        free(d);

        /* A MAJOR that is not a number is not a devnum; the sysname form
         * takes over rather than a "c0:..." nobody would look up. */
        d = device_new("input", "input4");
        ASSERT_EQ_INT(devd_rule_device_set_property(d, "MAJOR", "13x", false), 0);
        ASSERT_EQ_INT(devd_rule_device_set_property(d, "MINOR", "1", false), 0);
        ASSERT_EQ_INT(devd_udev_db_id(d, id, sizeof(id)), 0);
        ASSERT_STREQ(id, "+input:input4");
        free(d);

        d = device_new("", "");
        ASSERT_EQ_INT(devd_udev_db_id(d, id, sizeof(id)), -ENOENT);
        free(d);

        d = device_new("input", "input3");
        ASSERT_EQ_INT(devd_udev_db_id(d, id, 4), -ENAMETOOLONG);
        free(d);
}

static void test_write_and_delete(void) {
        static const char * const keys[] = { "ID_INPUT", "ID_INPUT_TOUCHSCREEN" };
        static const char * const values[] = { "1", "1" };
        char *root = test_tmpdir_new(), db[PATH_MAX], path[PATH_MAX], buf[256];
        struct stat st;

        ASSERT_TRUE(root != NULL);

        /* Two levels that do not exist yet, the way /run/udev/data does not on
         * a pico image until devd makes it. */
        ASSERT_TRUE((size_t) snprintf(db, sizeof(db), "%s/run/udev/data", root) < sizeof(db));
        ASSERT_TRUE((size_t) snprintf(path, sizeof(path), "%s/c13:67", db) < sizeof(path));

        ASSERT_EQ_INT(devd_udev_db_write(db, "c13:67", 12345, keys, values, 2), 0);

        read_file(path, buf, sizeof(buf));
        ASSERT_STREQ(buf, "I:12345\nE:ID_INPUT=1\nE:ID_INPUT_TOUCHSCREEN=1\nV:1\n");

        ASSERT_EQ_INT(stat(path, &st), 0);
        ASSERT_EQ_INT(st.st_mode & 07777, 0644);
        assert_only_entry(db, "c13:67");

        /* A rewrite replaces, it does not append. And no I: line without a
         * timestamp. */
        ASSERT_EQ_INT(devd_udev_db_write(db, "c13:67", 0, keys, values, 1), 0);
        read_file(path, buf, sizeof(buf));
        ASSERT_STREQ(buf, "E:ID_INPUT=1\nV:1\n");

        ASSERT_EQ_INT(devd_udev_db_write(db, "c13:67", USEC_INFINITY, keys, values, 1), 0);
        read_file(path, buf, sizeof(buf));
        ASSERT_STREQ(buf, "E:ID_INPUT=1\nV:1\n");
        assert_only_entry(db, "c13:67");

        /* Nothing to say is a delete, not an empty file. */
        ASSERT_EQ_INT(devd_udev_db_write(db, "c13:67", 12345, keys, values, 0), 0);
        ASSERT_TRUE(access(path, F_OK) < 0 && errno == ENOENT);

        ASSERT_EQ_INT(devd_udev_db_write(db, "c13:67", 12345, keys, values, 2), 0);
        ASSERT_EQ_INT(devd_udev_db_delete(db, "c13:67"), 0);
        ASSERT_TRUE(access(path, F_OK) < 0 && errno == ENOENT);

        /* Already gone is success: a remove for a device devd never wrote an
         * entry for is the ordinary case, not an error. */
        ASSERT_EQ_INT(devd_udev_db_delete(db, "c13:67"), 0);

        test_rm_rf(root);
        free(root);
}

static void test_rejects(void) {
        static const char * const good_keys[] = { "ID_INPUT" };
        static const char * const good_values[] = { "1" };
        static const char * const eq_keys[] = { "ID=INPUT" };
        static const char * const nl_keys[] = { "ID\nINPUT" };
        static const char * const empty_keys[] = { "" };
        static const char * const nl_values[] = { "1\nE:ID_INPUT_KEYBOARD=1" };
        char *root = test_tmpdir_new();

        ASSERT_TRUE(root != NULL);

        ASSERT_EQ_INT(devd_udev_db_write(root, "../c13:67", 1, good_keys, good_values, 1), -EINVAL);
        ASSERT_EQ_INT(devd_udev_db_write(root, "a/b", 1, good_keys, good_values, 1), -EINVAL);
        ASSERT_EQ_INT(devd_udev_db_write(root, ".#c13:67.devd", 1, good_keys, good_values, 1), -EINVAL);
        ASSERT_EQ_INT(devd_udev_db_write(root, "", 1, good_keys, good_values, 1), -EINVAL);
        ASSERT_EQ_INT(devd_udev_db_write(root, "c13:67", 1, eq_keys, good_values, 1), -EINVAL);
        ASSERT_EQ_INT(devd_udev_db_write(root, "c13:67", 1, nl_keys, good_values, 1), -EINVAL);
        ASSERT_EQ_INT(devd_udev_db_write(root, "c13:67", 1, empty_keys, good_values, 1), -EINVAL);

        /* The one that matters most: a value that would smuggle in a second
         * record the writer never meant. */
        ASSERT_EQ_INT(devd_udev_db_write(root, "c13:67", 1, good_keys, nl_values, 1), -EINVAL);

        ASSERT_EQ_INT(devd_udev_db_delete(root, "a/b"), -EINVAL);
        ASSERT_EQ_INT(devd_udev_db_delete(root, ".."), -EINVAL);

        /* None of those left anything behind. */
        {
                DIR *dd = opendir(root);
                struct dirent *e;

                ASSERT_TRUE(dd != NULL);
                while ((e = readdir(dd)))
                        ASSERT_TRUE(strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0);
                ASSERT_EQ_INT(closedir(dd), 0);
        }

        test_rm_rf(root);
        free(root);
}

int main(void) {
        test_id();
        test_write_and_delete();
        test_rejects();

        return 0;
}
