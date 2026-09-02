/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The GPT reader and PID 1's Discoverable-Partitions swap activation.
 * gpt-scan.h has the why, the seam between the two halves, and the API.
 *
 * On the shape of the code: every field is pulled out of a read buffer with an
 * explicit little-endian accessor rather than by overlaying a packed struct.
 * That is not fussiness. A packed struct would have to be right about the
 * host's own byte order (this project targets ARMv5TE today and says nothing
 * about tomorrow) and about unaligned access on a machine that traps it, and
 * it would hide the one property that actually matters here: that no read ever
 * reaches past the bytes that were really read from the device. Offsets against
 * a size-checked buffer make that property visible on every line.
 *
 * The input deserves that care. A partition table is data from a disk someone
 * may have handed the machine, parsed by PID 1 as root before anything else
 * runs, and every length in it -- entry size, entry count, where the array
 * lives -- is a number the table itself supplies. Each one is range-checked
 * before it is used, and the two CRC-32s the format carries are verified rather
 * than skipped, which is what makes "this table is corrupt" a conclusion rather
 * than a crash. This is the same discipline conf-scan.c applies to unbounded
 * text input, in the shape a binary format needs.
 */

#include "gpt-scan.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/swap.h>
#include <unistd.h>

#include "util.h"

/* 0657fd6d-a4ab-43c4-84e5-0933c84b4f4f, in on-disk mixed-endian byte order:
 * the first three fields little-endian, the last two big-endian. */
const GptGuid gpt_type_linux_swap = {
        { 0x6d, 0xfd, 0x57, 0x06, 0xab, 0xa4, 0xc4, 0x43, 0x84, 0xe5, 0x09, 0x33, 0xc8, 0x4b, 0x4f, 0x4f }
};

#define GPT_SIGNATURE "EFI PART"
#define GPT_SIGNATURE_LEN 8

/* Byte offsets inside the header, which the spec fixes and this never
 * discovers. 92 is the header's own defined size; a real one says 92. */
enum {
        GPT_H_HEADER_SIZE = 12,
        GPT_H_HEADER_CRC32 = 16,
        GPT_H_MY_LBA = 24,
        GPT_H_ENTRY_LBA = 72,
        GPT_H_ENTRY_COUNT = 80,
        GPT_H_ENTRY_SIZE = 84,
        GPT_H_ARRAY_CRC32 = 88,
        GPT_H_MIN_SIZE = 92,
};

/* And inside one partition entry. The UTF-16LE name occupies the remaining 72
 * bytes of a 128-byte entry -- 36 code units, decoded by gpt_name_to_utf8()
 * below for devd's by-partlabel links and its /media/<partlabel> mount points. */
enum {
        GPT_E_TYPE = 0,
        GPT_E_UUID = 16,
        GPT_E_FIRST_LBA = 32,
        GPT_E_LAST_LBA = 40,
        GPT_E_ATTRIBUTES = 48,
        GPT_E_NAME = 56,
        GPT_E_NAME_UNITS = 36,
        GPT_E_MIN_SIZE = 128,
};

/*
 * Caps on what the header is allowed to ask for. A real table is 128 entries of
 * 128 bytes, 16 KiB; these allow four times that and refuse the rest. The point
 * is not the exact number -- it is that the allocation below is bounded by this
 * file rather than by a uint32_t someone else wrote onto a disk, on a machine
 * whose entire RAM budget is 64 MiB.
 */
#define GPT_ENTRY_SIZE_MAX 512u
#define GPT_ENTRY_COUNT_MAX 512u

/*
 * Where the primary entry array is allowed to live. Two reasons for a ceiling
 * rather than none: it keeps the byte offset inside off_t on a 32-bit build
 * without large-file support, and the primary array sits immediately after the
 * header on every table anyone has ever written -- the copy far out at the end
 * of the disk is the backup, which this deliberately does not read.
 */
#define GPT_ARRAY_OFFSET_MAX UINT64_C(0x40000000) /* 1 GiB */

/*
 * Logical block sizes to look for the header at, in order. LBA 1 means byte 512
 * on a 512-byte-sector disk and byte 4096 on a 4Kn one, and the header carries
 * no field saying which -- finding the magic is what decides it.
 */
static const uint32_t gpt_block_sizes[] = { 512, 4096 };

#define GPT_BLOCK_SIZE_MAX 4096u

static uint32_t gpt_le32(const uint8_t *p) {
        return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static uint64_t gpt_le64(const uint8_t *p) {
        return (uint64_t) gpt_le32(p) | ((uint64_t) gpt_le32(p + 4) << 32);
}

/*
 * Bitwise CRC-32, no lookup table. The whole boot pays for this exactly twice,
 * over a 512-byte header and a 16 KiB array; a 1 KiB table to make that faster
 * would cost more image than the cycles are worth on this machine.
 */
uint32_t gpt_crc32(const void *data, size_t n) {
        const uint8_t *p = data;
        uint32_t crc = 0xffffffffU;
        size_t i;
        unsigned k;

        for (i = 0; i < n; i++) {
                crc ^= p[i];

                for (k = 0; k < 8; k++)
                        crc = (crc >> 1) ^ (0xedb88320U * (crc & 1));
        }

        return crc ^ 0xffffffffU;
}

char *gpt_guid_to_string(const GptGuid *guid, char buf[static GPT_GUID_STRING_MAX]) {
        const uint8_t *b = guid->bytes;

        /* The mixed endianness is the whole content of this function: the
         * first three groups come out reversed, the last two in order. */
        snprintf(buf,
                 GPT_GUID_STRING_MAX,
                 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 b[3],
                 b[2],
                 b[1],
                 b[0],
                 b[5],
                 b[4],
                 b[7],
                 b[6],
                 b[8],
                 b[9],
                 b[10],
                 b[11],
                 b[12],
                 b[13],
                 b[14],
                 b[15]);

        return buf;
}

/*
 * Decode an entry's UTF-16LE name field into `ret` as UTF-8, stopping at the
 * first NUL code unit or at the end of the 36-unit field.
 *
 * A name is data off a disk like every other field here, and a decoder is the
 * usual place that goes wrong: a low surrogate with no high half in front of
 * it, a high surrogate as the very last unit of the field, a pair that does not
 * pair. Every one of those is dropped rather than emitted, so what comes out is
 * always valid UTF-8 and always terminated -- and a name none of it survives
 * comes back as "", which every caller already has to handle for the unnamed
 * partitions that are the common case anyway.
 */
static void gpt_name_to_utf8(const uint8_t *field, char ret[static GPT_PARTITION_NAME_MAX]) {
        size_t out = 0, i;

        for (i = 0; i < GPT_E_NAME_UNITS; i++) {
                uint32_t c = (uint32_t) field[i * 2] | ((uint32_t) field[i * 2 + 1] << 8);
                size_t len;

                if (c == 0)
                        break;

                if (c >= 0xdc00 && c <= 0xdfff)
                        continue;

                if (c >= 0xd800 && c <= 0xdbff) {
                        uint32_t lo;

                        if (i + 1 >= GPT_E_NAME_UNITS)
                                break;

                        lo = (uint32_t) field[(i + 1) * 2] | ((uint32_t) field[(i + 1) * 2 + 1] << 8);
                        if (lo < 0xdc00 || lo > 0xdfff)
                                continue;

                        c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
                        i++;
                }

                len = c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;

                /* Cannot trigger for a 36-unit field (108 bytes at worst, one
                 * under the buffer), and checked anyway: the bound is what
                 * makes that arithmetic a fact rather than a belief. */
                if (out + len >= GPT_PARTITION_NAME_MAX)
                        break;

                switch (len) {
                case 1:
                        ret[out++] = (char) c;
                        break;
                case 2:
                        ret[out++] = (char) (0xc0 | (c >> 6));
                        ret[out++] = (char) (0x80 | (c & 0x3f));
                        break;
                case 3:
                        ret[out++] = (char) (0xe0 | (c >> 12));
                        ret[out++] = (char) (0x80 | ((c >> 6) & 0x3f));
                        ret[out++] = (char) (0x80 | (c & 0x3f));
                        break;
                default:
                        ret[out++] = (char) (0xf0 | (c >> 18));
                        ret[out++] = (char) (0x80 | ((c >> 12) & 0x3f));
                        ret[out++] = (char) (0x80 | ((c >> 6) & 0x3f));
                        ret[out++] = (char) (0x80 | (c & 0x3f));
                        break;
                }
        }

        ret[out] = '\0';
}

/*
 * pread() the whole of `n` bytes or say why not. -ENODATA specifically means
 * the device ended first, which for a partition table is "malformed", not "I/O
 * error" -- the two get different treatment above.
 */
static int gpt_read_at(int fd, void *buf, size_t n, uint64_t offset) {
        uint8_t *p = buf;
        size_t done = 0;

        while (done < n) {
                ssize_t k = pread(fd, p + done, n - done, (off_t) (offset + done));

                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        return -errno;
                }

                if (k == 0)
                        return -ENODATA;

                done += (size_t) k;
        }

        return 0;
}

typedef struct GptHeader {
        uint32_t block_size;
        uint64_t entry_lba;
        uint32_t entry_count;
        uint32_t entry_size;
        uint32_t array_crc32;
} GptHeader;

/*
 * Find and validate the primary header. Returns 1 with *ret filled in, 0 for
 * "there is no usable GPT here" (every rejection below), or -errno.
 *
 * Note the asymmetry between the two exits: a missing magic is a debug line,
 * because a disk without a partition table is an ordinary thing to be handed. A
 * magic that IS there followed by something that does not add up is a warning,
 * because somebody meant that to be a partition table and it is damaged.
 */
static int gpt_read_header(int fd, const char *device, GptHeader *ret) {
        uint8_t buf[GPT_BLOCK_SIZE_MAX];
        size_t i;

        for (i = 0; i < sizeof(gpt_block_sizes) / sizeof(gpt_block_sizes[0]); i++) {
                uint32_t bs = gpt_block_sizes[i];
                uint32_t header_size, stored_crc, entry_size, entry_count;
                uint64_t entry_lba;
                int r;

                r = gpt_read_at(fd, buf, bs, bs); /* LBA 1 */
                if (r == -ENODATA)
                        continue; /* the device is not even two blocks long */
                if (r < 0)
                        return r;

                if (memcmp(buf, GPT_SIGNATURE, GPT_SIGNATURE_LEN) != 0)
                        continue;

                /* From here on the magic matched, so this IS the answer for
                 * this device -- a failure below is not a reason to go on
                 * looking at another block size. */

                header_size = gpt_le32(buf + GPT_H_HEADER_SIZE);
                if (header_size < GPT_H_MIN_SIZE || header_size > bs) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: GPT header claims a size of %u bytes, ignoring the table",
                                 device,
                                 header_size);
                        return 0;
                }

                /* The header's CRC is computed over itself with its own CRC
                 * field zeroed, which is why this clobbers the buffer. */
                stored_crc = gpt_le32(buf + GPT_H_HEADER_CRC32);
                memset(buf + GPT_H_HEADER_CRC32, 0, 4);

                if (gpt_crc32(buf, header_size) != stored_crc) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: GPT header checksum does not match, ignoring the table",
                                 device);
                        return 0;
                }

                /* The primary header says it lives at LBA 1. One that says
                 * anything else is either the backup found by accident or a
                 * table built by something confused; neither is ours. */
                if (gpt_le64(buf + GPT_H_MY_LBA) != 1) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: GPT header at LBA 1 does not claim to be there, ignoring the table",
                                 device);
                        return 0;
                }

                entry_lba = gpt_le64(buf + GPT_H_ENTRY_LBA);
                entry_count = gpt_le32(buf + GPT_H_ENTRY_COUNT);
                entry_size = gpt_le32(buf + GPT_H_ENTRY_SIZE);

                if (entry_size < GPT_E_MIN_SIZE || entry_size > GPT_ENTRY_SIZE_MAX || (entry_size % 8) != 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: GPT entry size %u is out of range, ignoring the table",
                                 device,
                                 entry_size);
                        return 0;
                }

                if (entry_count == 0 || entry_count > GPT_ENTRY_COUNT_MAX) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: GPT entry count %u is out of range, ignoring the table",
                                 device,
                                 entry_count);
                        return 0;
                }

                /* entry_lba is bounded before it is multiplied, so the
                 * multiplication itself cannot wrap. */
                if (entry_lba < 2 || entry_lba > GPT_ARRAY_OFFSET_MAX / bs) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: GPT entry array claims to start at LBA %llu, ignoring the table",
                                 device,
                                 (unsigned long long) entry_lba);
                        return 0;
                }

                ret->block_size = bs;
                ret->entry_lba = entry_lba;
                ret->entry_count = entry_count;
                ret->entry_size = entry_size;
                ret->array_crc32 = gpt_le32(buf + GPT_H_ARRAY_CRC32);

                return 1;
        }

        pico_log(PICO_LOG_DEBUG, "%s: no GPT partition table", device);
        return 0;
}

/*
 * Read the entry array whole and verify its checksum before a single entry is
 * looked at. Doing it in that order is the point: the array CRC is the only
 * thing that says the bytes below are the table the header describes, and
 * checking it afterwards would mean having already trusted them.
 */
static int gpt_read_entries(int fd, const char *device, const GptHeader *h, uint8_t **ret) {
        size_t total = (size_t) h->entry_count * h->entry_size;
        uint8_t *array;
        int r;

        array = malloc(total);
        if (!array)
                return -ENOMEM;

        r = gpt_read_at(fd, array, total, h->entry_lba * h->block_size);
        if (r == -ENODATA) {
                pico_log(PICO_LOG_WARNING,
                         "%s: GPT entry array runs past the end of the device, ignoring the table",
                         device);
                free(array);
                return 0;
        }
        if (r < 0) {
                free(array);
                return r;
        }

        if (gpt_crc32(array, total) != h->array_crc32) {
                pico_log(PICO_LOG_WARNING,
                         "%s: GPT entry array checksum does not match, ignoring the table",
                         device);
                free(array);
                return 0;
        }

        *ret = array;
        return 1;
}

/* An entry whose type GUID is all zeroes is an unused slot, not a partition. */
static bool gpt_guid_is_null(const GptGuid *guid) {
        static const GptGuid null_guid = { { 0 } };

        return memcmp(guid, &null_guid, sizeof(GptGuid)) == 0;
}

/*
 * The one scan, behind both entry points.
 *
 * `type` NULL means "every used entry", which is also when `skip_no_auto` is
 * false: the two knobs move together because they express one distinction --
 * gpt_scan() answers "what should be acted on automatically", gpt_scan_all()
 * answers "what is on this disk". Keeping them as parameters of one function
 * rather than two copies of the header/CRC/entry-array walk is the point; that
 * walk is where every range check lives and it should exist exactly once.
 */
static int gpt_scan_internal(
                const char *device, const GptGuid *type, bool skip_no_auto, GptPartition **ret, size_t *ret_n) {

        GptPartition *found = NULL;
        uint8_t *array = NULL;
        GptHeader h;
        size_t n = 0, pass;
        int fd, r;

        if (!device || !ret || !ret_n)
                return -EINVAL;

        fd = open(device, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = gpt_read_header(fd, device, &h);
        if (r <= 0) {
                close(fd);
                if (r == 0) {
                        *ret = NULL;
                        *ret_n = 0;
                }
                return r;
        }

        r = gpt_read_entries(fd, device, &h, &array);
        close(fd);
        if (r <= 0) {
                if (r == 0) {
                        *ret = NULL;
                        *ret_n = 0;
                }
                return r;
        }

        /*
         * Two passes over the array: count, allocate exactly, fill. The
         * alternative -- realloc per match -- would be the same work with a
         * failure path in the middle of a half-built result.
         */
        for (pass = 0; pass < 2; pass++) {
                size_t i;

                n = 0;

                for (i = 0; i < h.entry_count; i++) {
                        const uint8_t *e = array + i * h.entry_size;
                        uint64_t attributes;
                        GptGuid t;

                        memcpy(&t, e + GPT_E_TYPE, sizeof(GptGuid));

                        if (gpt_guid_is_null(&t))
                                continue;

                        if (type && memcmp(&t, type, sizeof(GptGuid)) != 0)
                                continue;

                        attributes = gpt_le64(e + GPT_E_ATTRIBUTES);

                        if (skip_no_auto && (attributes & GPT_ATTR_NO_AUTO)) {
                                if (pass == 0)
                                        pico_log(PICO_LOG_INFO,
                                                 "%s: partition %zu matches but is marked no-auto, skipping it",
                                                 device,
                                                 i + 1);
                                continue;
                        }

                        if (found) {
                                found[n].nr = (unsigned) (i + 1);
                                found[n].type = t;
                                memcpy(&found[n].uuid, e + GPT_E_UUID, sizeof(GptGuid));
                                found[n].first_lba = gpt_le64(e + GPT_E_FIRST_LBA);
                                found[n].last_lba = gpt_le64(e + GPT_E_LAST_LBA);
                                found[n].attributes = attributes;
                                gpt_name_to_utf8(e + GPT_E_NAME, found[n].name);
                        }

                        n++;
                }

                if (pass == 0) {
                        if (n == 0)
                                break;

                        found = calloc(n, sizeof(GptPartition));
                        if (!found) {
                                free(array);
                                return -ENOMEM;
                        }
                }
        }

        free(array);

        *ret = found;
        *ret_n = n;

        return 1;
}

int gpt_scan(const char *device, const GptGuid *type, GptPartition **ret, size_t *ret_n) {
        if (!type)
                return -EINVAL;

        return gpt_scan_internal(device, type, true, ret, ret_n);
}

int gpt_scan_all(const char *device, GptPartition **ret, size_t *ret_n) {
        return gpt_scan_internal(device, NULL, false, ret, ret_n);
}

/*
 * Split `line` into its first `n` whitespace-separated fields, in place.
 * Returns -EINVAL if there are fewer than that, which for mountinfo means a
 * line this does not understand rather than a file it cannot read.
 */
static int gpt_split_fields(char *line, char **field, size_t n) {
        char *p = line;
        size_t i;

        for (i = 0; i < n; i++) {
                p += strspn(p, " \t");
                if (*p == '\0')
                        return -EINVAL;

                field[i] = p;
                p += strcspn(p, " \t");

                if (*p != '\0')
                        *p++ = '\0';
        }

        return 0;
}

/*
 * Is `name` one of the comma-separated tokens in a mountinfo option list?
 *
 * Whole tokens, never substrings, and that is the entire point of writing this
 * out rather than reaching for strstr(): "errors=remount-ro" ends in the three
 * letters this is usually asked about, "rootflags=ro" contains them, and
 * neither of those mounts is read-only. A read-only root is spelled by an "ro"
 * token standing on its own between commas.
 *
 * An empty list, an empty token from a doubled comma, a trailing comma: none of
 * them match anything and none of them run past the end of the string.
 */
static bool gpt_option_present(const char *options, const char *name) {
        size_t len = strlen(name);
        const char *p = options;

        if (!options || len == 0)
                return false;

        for (;;) {
                size_t n = strcspn(p, ",");

                if (n == len && memcmp(p, name, len) == 0)
                        return true;

                if (p[n] == '\0')
                        return false;

                p += n + 1;
        }
}

/*
 * The device number of whatever is mounted on "/", from a mountinfo file, and
 * whether that mount is read-only right now.
 *
 * Fields, per proc(5): id, parent id, "major:minor", root within the
 * filesystem, mount point, per-mount options, then the optional fields and the
 * " - " separator this never reaches. The last matching line wins, because that
 * is the mount a path lookup of "/" would actually land on if something was
 * mounted over an earlier one.
 *
 * Six fields rather than five because field 6 is the per-mount option list, and
 * that list is where "am I read-only" is answered. Reading it is strictly
 * better than upstream systemd's write probe on the same question: it reports
 * the mount flags the kernel actually holds, and it attempts no write to a
 * filesystem whose integrity is the thing in doubt.
 *
 * A line with fewer than six fields is skipped, as one with fewer than five
 * always was. Real mountinfo lines carry at least ten.
 *
 * Mount points are octal-escaped in this file (a space is \040), which nothing
 * here undoes: the only mount point it compares against is "/", which has
 * nothing to escape.
 */
static int gpt_mountinfo_root(const char *mountinfo, unsigned *ret_maj, unsigned *ret_min, bool *ret_ro) {
        char *line = NULL;
        size_t cap = 0;
        bool found = false, ro = false;
        unsigned maj = 0, min = 0;
        FILE *f;

        f = fopen(mountinfo, "re");
        if (!f)
                return -errno;

        for (;;) {
                char *field[6];
                unsigned a, b;

                if (getline(&line, &cap, f) < 0)
                        break;

                if (gpt_split_fields(line, field, sizeof(field) / sizeof(field[0])) < 0)
                        continue;

                if (strcmp(field[4], "/") != 0)
                        continue;

                if (sscanf(field[2], "%u:%u", &a, &b) != 2)
                        continue;

                maj = a;
                min = b;
                ro = gpt_option_present(field[5], "ro");
                found = true;
        }

        free(line);
        fclose(f);

        if (!found)
                return -ENOENT;

        *ret_maj = maj;
        *ret_min = min;
        *ret_ro = ro;

        return 0;
}

int gpt_boot_root(
                const char *mountinfo,
                char *ret_node,
                size_t node_size,
                char *ret_sysfs,
                size_t sysfs_size,
                char *ret_part_node,
                size_t part_size,
                bool *ret_read_only) {

        char link[PATH_MAX], real[PATH_MAX], probe[PATH_MAX];
        /* Initialized because gcc cannot see across the call below that they
         * are only read after it returned 0, and warns under the target's own
         * optimization level while a -O0 host build stays silent. */
        unsigned maj = 0, min = 0;
        bool ro = false;
        char *slash;
        int r;

        r = gpt_mountinfo_root(mountinfo, &maj, &min, &ro);
        if (r < 0)
                return r;

        /*
         * Published before the guards below, and deliberately: "root is
         * read-only" is an answer the mountinfo line alone settles, and a
         * caller that only wants that must still get it when the guards go on
         * to say there is no block device to name.
         */
        if (ret_read_only)
                *ret_read_only = ro;

        /*
         * Major 0 is the kernel's marker for a filesystem with no block device
         * under it at all -- tmpfs, overlayfs, an initramfs rootfs. There is
         * nothing to scan, and saying -ENOENT here is what lets the caller
         * treat it as an ordinary answer instead of a failure.
         */
        if (maj == 0)
                return -ENOENT;

        if ((size_t) snprintf(link, sizeof(link), "/sys/dev/block/%u:%u", maj, min) >= sizeof(link))
                return -ENAMETOOLONG;

        /*
         * /sys/dev/block/<maj>:<min> is a symlink into the device tree, so
         * resolving it gives a path whose parent directory is the containing
         * disk when the target is a partition: .../block/vda/vda1. That parent
         * relationship is the kernel's own, which is why this asks sysfs rather
         * than trying to strip a trailing "1" or "p1" off a node name.
         */
        if (!realpath(link, real))
                return -errno;

        /*
         * The partition, before the strip below turns `real` into its disk.
         * This is the node the root filesystem actually lives on, which is what
         * a filesystem checker has to be pointed at -- the disk would hand it
         * the partition table instead. When root is on a whole unpartitioned
         * device there is nothing to strip and the two answers are the same
         * node, which is still correct: that device IS what carries the
         * filesystem.
         */
        slash = strrchr(real, '/');
        if (!slash || slash[1] == '\0')
                return -EINVAL;

        if (ret_part_node && (size_t) snprintf(ret_part_node, part_size, "/dev/%s", slash + 1) >= part_size)
                return -ENAMETOOLONG;

        if ((size_t) snprintf(probe, sizeof(probe), "%s/partition", real) >= sizeof(probe))
                return -ENAMETOOLONG;

        if (access(probe, F_OK) == 0) {
                slash = strrchr(real, '/');
                if (!slash || slash == real)
                        return -EINVAL;

                *slash = '\0';
        }

        slash = strrchr(real, '/');
        if (!slash || slash[1] == '\0')
                return -EINVAL;

        /* The sysfs directory name IS the device node name; devtmpfs makes the
         * node from the same string. Nothing else needs to agree. */
        if (ret_node && (size_t) snprintf(ret_node, node_size, "/dev/%s", slash + 1) >= node_size)
                return -ENAMETOOLONG;

        if (ret_sysfs && (size_t) snprintf(ret_sysfs, sysfs_size, "%s", real) >= sysfs_size)
                return -ENAMETOOLONG;

        return 0;
}

int gpt_boot_disk(const char *mountinfo, char *ret_node, size_t node_size, char *ret_sysfs, size_t sysfs_size) {
        return gpt_boot_root(mountinfo, ret_node, node_size, ret_sysfs, sysfs_size, NULL, 0, NULL);
}

/*
 * Turn a partition number back into a device node, by asking the disk's own
 * sysfs directory which of its children carries that number.
 *
 * The alternative -- pasting the number onto the disk name -- gets /dev/vda2
 * right and /dev/mmcblk0p2 wrong, and this project's next hardware target has
 * an SD slot.
 */
static int gpt_partition_node(const char *sysfs_disk, unsigned nr, char *ret, size_t size) {
        struct dirent *e;
        DIR *d;
        int r = -ENOENT;

        d = opendir(sysfs_disk);
        if (!d)
                return -errno;

        while ((e = readdir(d))) {
                char path[PATH_MAX], buf[32];
                unsigned n;
                FILE *f;

                if (e->d_name[0] == '.')
                        continue;

                if ((size_t) snprintf(path, sizeof(path), "%s/%s/partition", sysfs_disk, e->d_name) >=
                    sizeof(path))
                        continue;

                f = fopen(path, "re");
                if (!f)
                        continue; /* not a partition of this disk */

                if (fgets(buf, sizeof(buf), f) && sscanf(buf, "%u", &n) == 1 && n == nr) {
                        if ((size_t) snprintf(ret, size, "/dev/%s", e->d_name) < size)
                                r = 0;
                        else
                                r = -ENAMETOOLONG;
                }

                fclose(f);

                if (r != -ENOENT)
                        break;
        }

        closedir(d);

        return r;
}

int dps_scan(void) {
        char disk[PATH_MAX], sysfs[PATH_MAX];
        GptPartition *parts = NULL;
        size_t n = 0, i;
        int activated = 0;
        int r;

        r = gpt_boot_disk("/proc/self/mountinfo", disk, sizeof(disk), sysfs, sizeof(sysfs));
        if (r == -ENOENT) {
                pico_log(PICO_LOG_DEBUG, "the root filesystem is not on a block device, no swap to discover");
                return 0;
        }
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "cannot identify the boot disk: %s", strerror(-r));
                return r;
        }

        r = gpt_scan(disk, &gpt_type_linux_swap, &parts, &n);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "%s: cannot read the partition table: %s", disk, strerror(-r));
                return r;
        }

        for (i = 0; i < n; i++) {
                char node[PATH_MAX], uuid[GPT_GUID_STRING_MAX];

                gpt_guid_to_string(&parts[i].uuid, uuid);

                r = gpt_partition_node(sysfs, parts[i].nr, node, sizeof(node));
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s partition %u (%s) has no device node: %s",
                                 disk,
                                 parts[i].nr,
                                 uuid,
                                 strerror(-r));
                        continue;
                }

                /* Reported, not acted on: swapon() is about to say the same
                 * thing with the kernel's own authority. See gpt-scan.h. */
                if (parts[i].attributes & GPT_ATTR_READ_ONLY)
                        pico_log(PICO_LOG_WARNING, "%s is a read-only partition", node);

                if (swapon(node, 0) < 0) {
                        pico_log(PICO_LOG_WARNING, "swapon %s: %s", node, strerror(errno));
                        continue;
                }

                pico_log(PICO_LOG_INFO, "swap on %s activated (partuuid %s)", node, uuid);
                activated++;
        }

        free(parts);

        return activated;
}
