/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The identity readers against real mkfs output, compared with what blkid
 * itself says about the same image.
 *
 * The per-format tests build their images byte by byte, which pins every
 * offset and rule but can only ever agree with the reading of the format they
 * were written from. This is the independent check: each formatting tool this
 * host has makes an image with a known label (and UUID where the tool takes
 * one), and the reader's TYPE, UUID and LABEL must equal `blkid -p`'s,
 * byte for byte, because that equality is exactly what makes an fstab line
 * copied from blkid resolve.
 *
 * Every tool is optional. A missing mkfs skips its images; no blkid, or no
 * image made at all, SKIPs the test (77). A build host typically has mke2fs
 * and mkswap; dosfstools, exfatprogs, xfsprogs, btrfs-progs and ntfs-3g
 * complete the set.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fsid.h"
#include "test-util.h"

static const char * const bindirs[] = { "/usr/sbin", "/sbin", "/usr/bin", "/bin" };

static bool find_tool(const char *name, char *ret, size_t size) {
        for (size_t i = 0; i < sizeof(bindirs) / sizeof(bindirs[0]); i++) {
                snprintf(ret, size, "%s/%s", bindirs[i], name);
                if (access(ret, X_OK) == 0)
                        return true;
        }
        return false;
}

/* Run argv[0] (a full path) with argv, stdout into `out` when given. The
 * exit status, or -1 when it did not exit normally. */
static int run(char * const argv[], char *out, size_t size) {
        int pipefd[2] = { -1, -1 }, status;
        size_t n = 0;
        pid_t pid;

        if (out)
                ASSERT_EQ_INT(pipe2(pipefd, O_CLOEXEC), 0);

        pid = fork();
        ASSERT_TRUE(pid >= 0);
        if (pid == 0) {
                int null = open("/dev/null", O_RDWR | O_CLOEXEC);

                (void) dup2(null, STDIN_FILENO);
                (void) dup2(out ? pipefd[1] : null, STDOUT_FILENO);
                (void) dup2(null, STDERR_FILENO);
                (void) setenv("LC_ALL", "C.UTF-8", 1);
                execv(argv[0], argv);
                _exit(127);
        }

        if (out) {
                ssize_t k;

                close(pipefd[1]);
                while (n + 1 < size && (k = read(pipefd[0], out + n, size - 1 - n)) > 0)
                        n += (size_t) k;
                out[n] = '\0';
                close(pipefd[0]);

                while (n > 0 && out[n - 1] == '\n')
                        out[--n] = '\0';
        }

        ASSERT_TRUE(waitpid(pid, &status, 0) == pid);
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static char blkid[PATH_MAX];

static void blkid_value(const char *image, const char *tag, char *ret, size_t size) {
        char *argv[] = { blkid,         (char *) "-p",    (char *) "-s",  (char *) tag,
                         (char *) "-o", (char *) "value", (char *) image, NULL };

        (void) run(argv, ret, size);
}

typedef struct Case {
        const char *name;
        const char *tool;
        unsigned size_mib;
        const char *args[10]; /* before the image path */
} Case;

static const Case cases[] = {
        {
         .name = "swap",
         .tool = "mkswap",
         .size_mib = 1,
         .args = { "-U", "6f0e4c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6", "-L", "picoswap" },
         },
        {
         .name = "swap-nolabel",
         .tool = "mkswap",
         .size_mib = 1,
         .args = { "-U", "22222222-2222-3333-4444-555555555555" },
         },
        {
         .name = "ext4",
         .tool = "mke2fs",
         .size_mib = 8,
         .args = { "-q", "-F", "-t", "ext4", "-U", "12345678-90ab-cdef-1234-567890abcdef", "-L", "PICO EXT4" },
         },
        {
         .name = "ext2",
         .tool = "mke2fs",
         .size_mib = 8,
         .args = { "-q", "-F", "-t", "ext2", "-L", "old" },
         },
        {
         .name = "fat12",
         .tool = "mkfs.vfat",
         .size_mib = 2,
         .args = { "-F", "12", "-i", "1A2B3C4D", "-n", "PICO F12" },
         },
        {
         .name = "fat16",
         .tool = "mkfs.vfat",
         .size_mib = 32,
         .args = { "-F", "16", "-i", "DEADBEEF", "-n", "PICO F16" },
         },
        {
         .name = "fat32",
         .tool = "mkfs.vfat",
         .size_mib = 40,
         .args = { "-F", "32", "-i", "0000ABCD", "-n", "PICO F32" },
         },
        {
         .name = "fat-nolabel",
         .tool = "mkfs.vfat",
         .size_mib = 8,
         .args = { "-i", "CAFEF00D" },
         },
        {
         .name = "exfat",
         .tool = "mkfs.exfat",
         .size_mib = 16,
         .args = { "-L", "PicoExFAT" },
         },
        {
         .name = "exfat-utf8",
         .tool = "mkfs.exfat",
         .size_mib = 16,
         .args = { "-L", "\xc3\x9cn\xc3\xaf" },
         },
        {
         .name = "xfs",
         .tool = "mkfs.xfs",
         .size_mib = 320,
         .args = { "-q", "-m", "uuid=abcdef01-2345-6789-abcd-ef0123456789", "-L", "xfslbl" },
         },
        {
         .name = "btrfs",
         .tool = "mkfs.btrfs",
         .size_mib = 128,
         .args = { "-q", "-U", "01234567-89ab-cdef-0123-456789abcdef", "-L", "pico btrfs" },
         },
        {
         .name = "ntfs",
         .tool = "mkntfs",
         .size_mib = 16,
         .args = { "-q", "-F", "-Q", "-L", "PICO NTFS" },
         },
        {
         .name = "ntfs-utf8",
         .tool = "mkntfs",
         .size_mib = 16,
         .args = { "-q", "-F", "-Q", "-L", "T\xc3\xabst" },
         },
};

/* 1 checked and matched, 0 skipped (no tool, or it would not make one). */
static int check(const char *dir, const Case *c) {
        char tool[PATH_MAX], image[PATH_MAX], want_type[64], want_uuid[128], want_label[1024];
        char *argv[16];
        size_t n = 0;
        PicoFsId id;
        int fd;

        if (!find_tool(c->tool, tool, sizeof(tool))) {
                printf("  %-12s skipped: no %s\n", c->name, c->tool);
                return 0;
        }

        snprintf(image, sizeof(image), "%s/%s.img", dir, c->name);
        fd = open(image, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        ASSERT_TRUE(fd >= 0);
        ASSERT_EQ_INT(ftruncate(fd, (off_t) c->size_mib << 20), 0);
        close(fd);

        argv[n++] = tool;
        for (size_t i = 0; c->args[i]; i++)
                argv[n++] = (char *) c->args[i];
        argv[n++] = image;
        argv[n] = NULL;

        if (run(argv, NULL, 0) != 0) {
                printf("  %-12s skipped: %s failed\n", c->name, c->tool);
                (void) unlink(image);
                return 0;
        }

        blkid_value(image, "TYPE", want_type, sizeof(want_type));
        blkid_value(image, "UUID", want_uuid, sizeof(want_uuid));
        blkid_value(image, "LABEL", want_label, sizeof(want_label));

        /* One reader serves every ext revision and names it after ext4. */
        if (strcmp(want_type, "ext2") == 0 || strcmp(want_type, "ext3") == 0)
                snprintf(want_type, sizeof(want_type), "ext4");

        ASSERT_EQ_INT(pico_fs_probe(image, PICO_FS_NONE, &id), 1);
        printf("  %-12s TYPE=%s UUID=%s LABEL=%s\n", c->name, pico_fs_kind_to_string(id.kind), id.uuid, id.label);
        ASSERT_STREQ(pico_fs_kind_to_string(id.kind), want_type);
        ASSERT_STREQ(id.uuid, want_uuid);
        ASSERT_STREQ(id.label, want_label);

        /* And by the fstab type blkid reports, as a UUID=/LABEL= line with
         * that type would ask. */
        ASSERT_EQ_INT(pico_fs_probe(image, pico_fs_kind_from_type(want_type), &id), 1);

        (void) unlink(image);
        return 1;
}

int main(void) {
        unsigned checked = 0;
        char *dir;

        if (!find_tool("blkid", blkid, sizeof(blkid))) {
                printf("test-fsid-real: no blkid here, skipping\n");
                return 77;
        }

        dir = test_tmpdir_new();
        ASSERT_TRUE(dir != NULL);

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
                checked += (unsigned) check(dir, &cases[i]);

        test_rm_rf(dir);
        free(dir);

        if (checked == 0) {
                printf("test-fsid-real: no formatting tool here, skipping\n");
                return 77;
        }

        printf("test-fsid-real: %u real images identical to blkid\n", checked);
        return 0;
}
