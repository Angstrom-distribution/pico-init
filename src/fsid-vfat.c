/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * FAT12/16/32: what nearly every SD card, CF card and USB stick ships
 * formatted as.
 *
 * FAT has no one magic number. blkid accepts a boot sector on any of several
 * signatures -- a type string at 0x36 or 0x52, and failing those a bare x86
 * jump byte or the 0x55AA boot signature -- and then decides on the boot
 * parameter block instead: at least one FAT, reserved sectors, a media byte, a
 * power-of-two cluster and sector size, and a cluster count that fits the FAT
 * width the geometry implies. Those rules are kept exactly, because they are
 * what separates a FAT volume from exFAT, NTFS and BitLocker volumes that share
 * the jump byte and the boot signature. A FAT32 volume's FSInfo sector must
 * carry its signatures or be blank.
 *
 * The two strings, as blkid produces them:
 *
 *  - UUID is the 32-bit volume serial number, printed "1A2B-3C4D" in upper
 *    case, most significant half first. FAT12/16 only have one when the
 *    extended boot signature says the field is there.
 *  - LABEL is the volume-label entry in the ROOT DIRECTORY, not the copy in
 *    the boot sector. The two usually agree; when they do not (a label changed
 *    by an OS that only rewrites the directory entry) the directory entry is
 *    the one blkid reports, and so the one a by-label link or `mount -L` goes
 *    by. The FAT32 root directory is a cluster chain, followed for at most 99
 *    clusters as blkid follows it. One deliberate narrowing: the scan stops at
 *    the end-of-directory marker, which blkid only honours within a cluster.
 *    Past that marker the FAT specification says nothing is a live entry, so
 *    the two only differ on a corrupt directory.
 *
 * The label is 11 bytes in whatever DOS code page the formatting tool used,
 * and is reported byte for byte, with FAT's 0x05 escape for a leading 0xE5
 * undone.
 */

#include <errno.h>
#include <string.h>

#include "fsid.h"

#define FAT_BS_SIZE 512

/* Boot parameter block, common to all three widths. */
#define BPB_BYTES_PER_SEC 0x0b
#define BPB_SEC_PER_CLUS 0x0d
#define BPB_RSVD_SEC_CNT 0x0e
#define BPB_NUM_FATS 0x10
#define BPB_ROOT_ENT_CNT 0x11
#define BPB_TOT_SEC16 0x13
#define BPB_MEDIA 0x15
#define BPB_FAT_SZ16 0x16
#define BPB_TOT_SEC32 0x20

/* FAT12/16 extended boot record. */
#define BS16_BOOT_SIG 0x26
#define BS16_VOL_ID 0x27
#define BS16_FS_TYPE 0x36

/* FAT32 extended BPB. */
#define BPB32_FAT_SZ32 0x24
#define BPB32_ROOT_CLUS 0x2c
#define BPB32_FS_INFO 0x30
#define BS32_VOL_ID 0x43
#define BS32_FS_TYPE 0x52

#define FAT12_MAX 0xff4u
#define FAT16_MAX 0xfff4u
#define FAT32_MAX 0x0ffffff6u

#define DIR_ENTRY_SIZE 32
#define DIR_ATTR 11
#define DIR_CLUSTER_HI 20
#define DIR_CLUSTER_LO 26
#define ATTR_VOLUME_ID 0x08
#define ATTR_DIRECTORY 0x10
#define ATTR_LONG_NAME 0x0f
#define ATTR_MASK 0x3f
#define ENTRY_FREE 0xe5

/* How much of a directory is read per pread(). */
#define DIR_WINDOW 4096

/* blkid's loop counter starts at 100 and pre-decrements. */
#define FAT32_ROOT_CLUSTERS_MAX 99

static bool is_power_of_2(uint32_t v) {
        return v != 0 && (v & (v - 1)) == 0;
}

/* The length of the signature blkid would have matched, 0 for none. The
 * short ones (the jump bytes and the boot signature) get the extra scrutiny
 * in valid_bpb(). */
static size_t signature_len(const uint8_t *bs) {
        static const struct {
                size_t off;
                const char *magic;
                size_t len;
        } magics[] = {
                {  0x52,    "MSWIN", 5 },
                {  0x52, "FAT32   ", 8 },
                {  0x36,    "MSDOS", 5 },
                {  0x36, "FAT16   ", 8 },
                {  0x36, "FAT12   ", 8 },
                {  0x36, "FAT     ", 8 },
                {     0,     "\xeb", 1 },
                {     0,     "\xe9", 1 },
                { 0x1fe, "\x55\xaa", 2 },
        };
        size_t i;

        for (i = 0; i < sizeof(magics) / sizeof(magics[0]); i++)
                if (memcmp(bs + magics[i].off, magics[i].magic, magics[i].len) == 0)
                        return magics[i].len;

        return 0;
}

typedef struct FatGeometry {
        uint32_t sector_size;
        uint32_t cluster_sectors;
        uint32_t reserved;
        uint32_t fat_size; /* sectors, all FATs together */
        bool fat32;
} FatGeometry;

static bool valid_bpb(const uint8_t *bs, size_t sig_len, FatGeometry *g) {
        uint32_t dir_entries, sect_count, fat_length, dir_size, cluster_count, max_count;
        uint8_t media = bs[BPB_MEDIA];

        if (sig_len <= 2) {
                if (bs[0x1fe] != 0x55 || bs[0x1ff] != 0xaa)
                        return false;
                /* OS/2 and DFSee leave a FAT-like pseudo boot sector on JFS
                 * and HPFS volumes. */
                if (memcmp(bs + BS16_FS_TYPE, "JFS     ", 8) == 0 ||
                    memcmp(bs + BS16_FS_TYPE, "HPFS    ", 8) == 0)
                        return false;
        }

        if (bs[BPB_NUM_FATS] == 0 || pico_le16(bs + BPB_RSVD_SEC_CNT) == 0)
                return false;
        if (!(media >= 0xf8 || media == 0xf0))
                return false;
        if (!is_power_of_2(bs[BPB_SEC_PER_CLUS]))
                return false;

        g->sector_size = pico_le16(bs + BPB_BYTES_PER_SEC);
        if (!is_power_of_2(g->sector_size) || g->sector_size < 512 || g->sector_size > 4096)
                return false;

        g->cluster_sectors = bs[BPB_SEC_PER_CLUS];
        g->reserved = pico_le16(bs + BPB_RSVD_SEC_CNT);
        dir_entries = pico_le16(bs + BPB_ROOT_ENT_CNT);

        sect_count = pico_le16(bs + BPB_TOT_SEC16);
        if (sect_count == 0)
                sect_count = pico_le32(bs + BPB_TOT_SEC32);

        fat_length = pico_le16(bs + BPB_FAT_SZ16);
        if (fat_length == 0)
                fat_length = pico_le32(bs + BPB32_FAT_SZ32);

        /* 32-bit arithmetic, wrapping where blkid's wraps: a geometry that
         * does not add up comes out as an impossible cluster count. */
        g->fat_size = fat_length * bs[BPB_NUM_FATS];
        dir_size = (dir_entries * DIR_ENTRY_SIZE + (g->sector_size - 1)) / g->sector_size;
        cluster_count = (sect_count - (g->reserved + g->fat_size + dir_size)) / g->cluster_sectors;

        g->fat32 = pico_le16(bs + BPB_FAT_SZ16) == 0 && pico_le32(bs + BPB32_FAT_SZ32) != 0;
        if (g->fat32)
                max_count = FAT32_MAX;
        else
                max_count = cluster_count > FAT12_MAX ? FAT16_MAX : FAT12_MAX;

        if (cluster_count > max_count)
                return false;

        /* BitLocker keeps a FAT-shaped boot sector behind its own signature. */
        if (memcmp(bs + 3, "-FVE-FS-", 8) == 0)
                return false;

        return true;
}

typedef enum DirScan {
        DIR_SCAN_MORE,  /* read every entry asked for, found nothing */
        DIR_SCAN_END,   /* hit the end-of-directory marker */
        DIR_SCAN_FOUND, /* label copied out */
} DirScan;

/* Look through `entries` directory entries at `off` for the volume label. */
static int scan_dir(int fd, uint64_t off, uint32_t entries, uint8_t label[11]) {
        uint8_t buf[DIR_WINDOW];
        uint32_t done = 0;
        int r;

        while (done < entries) {
                uint32_t n = entries - done;

                if (n > DIR_WINDOW / DIR_ENTRY_SIZE)
                        n = DIR_WINDOW / DIR_ENTRY_SIZE;

                r = pico_fs_read(fd, off + (uint64_t) done * DIR_ENTRY_SIZE, buf, (size_t) n * DIR_ENTRY_SIZE);
                if (r == -ENODATA)
                        return DIR_SCAN_END;
                if (r < 0)
                        return r;

                for (uint32_t i = 0; i < n; i++) {
                        const uint8_t *e = buf + i * DIR_ENTRY_SIZE;
                        uint8_t attr = e[DIR_ATTR];

                        if (e[0] == 0x00)
                                return DIR_SCAN_END;

                        if (e[0] == ENTRY_FREE || pico_le16(e + DIR_CLUSTER_HI) != 0 ||
                            pico_le16(e + DIR_CLUSTER_LO) != 0 || (attr & ATTR_MASK) == ATTR_LONG_NAME)
                                continue;

                        if ((attr & (ATTR_VOLUME_ID | ATTR_DIRECTORY)) == ATTR_VOLUME_ID) {
                                memcpy(label, e, 11);
                                if (label[0] == 0x05)
                                        label[0] = ENTRY_FREE;
                                return DIR_SCAN_FOUND;
                        }
                }

                done += n;
        }

        return DIR_SCAN_MORE;
}

static int fat32_root_label(int fd, const uint8_t *bs, const FatGeometry *g, uint8_t label[11]) {
        uint64_t cluster_bytes = (uint64_t) g->cluster_sectors * g->sector_size;
        uint64_t data_start = (uint64_t) g->reserved + g->fat_size;
        uint64_t fat_entries = (uint64_t) pico_le32(bs + BPB32_FAT_SZ32) * g->sector_size / 4;
        uint32_t next = pico_le32(bs + BPB32_ROOT_CLUS);
        unsigned loops;
        int r;

        for (loops = 0; loops < FAT32_ROOT_CLUSTERS_MAX && next >= 2 && next < fat_entries; loops++) {
                uint64_t off = (data_start + (uint64_t) (next - 2) * g->cluster_sectors) * g->sector_size;
                uint8_t entry[4];

                r = scan_dir(fd, off, (uint32_t) (cluster_bytes / DIR_ENTRY_SIZE), label);
                if (r != DIR_SCAN_MORE)
                        return r;

                r = pico_fs_read(fd, (uint64_t) g->reserved * g->sector_size + (uint64_t) next * 4, entry, 4);
                if (r == -ENODATA)
                        return DIR_SCAN_END;
                if (r < 0)
                        return r;

                next = pico_le32(entry) & 0x0fffffff;
        }

        return DIR_SCAN_END;
}

/* An FSInfo sector names itself at both ends, or was never written at all. */
static int fat32_fsinfo_ok(int fd, const uint8_t *bs, const FatGeometry *g) {
        uint16_t sector = pico_le16(bs + BPB32_FS_INFO);
        uint8_t sig1[4], sig2[4];
        int r;

        if (sector == 0)
                return 1;

        r = pico_fs_read(fd, (uint64_t) sector * g->sector_size, sig1, 4);
        if (r >= 0)
                r = pico_fs_read(fd, (uint64_t) sector * g->sector_size + 484, sig2, 4);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        if (memcmp(sig1, "RRaA", 4) != 0 && memcmp(sig1, "RRdA", 4) != 0 && !pico_fs_bytes_zero(sig1, 4))
                return 0;
        if (memcmp(sig2, "rrAa", 4) != 0 && !pico_fs_bytes_zero(sig2, 4))
                return 0;

        return 1;
}

int pico_fs_probe_vfat(int fd, PicoFsId *ret) {
        uint8_t bs[FAT_BS_SIZE], label[11];
        const uint8_t *serial = NULL;
        bool have_label = false;
        FatGeometry g;
        size_t sig;
        int r;

        r = pico_fs_read(fd, 0, bs, sizeof(bs));
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        sig = signature_len(bs);
        if (sig == 0 || !valid_bpb(bs, sig, &g))
                return 0;

        if (pico_le16(bs + BPB_FAT_SZ16) != 0) {
                /* FAT12/16: a fixed root directory right after the FATs. */
                uint64_t root = ((uint64_t) g.reserved + g.fat_size) * g.sector_size;

                r = scan_dir(fd, root, pico_le16(bs + BPB_ROOT_ENT_CNT), label);
                if (r < 0)
                        return r;
                have_label = r == DIR_SCAN_FOUND;

                if (bs[BS16_BOOT_SIG] == 0x28 || bs[BS16_BOOT_SIG] == 0x29)
                        serial = bs + BS16_VOL_ID;
        } else if (g.fat32) {
                r = fat32_root_label(fd, bs, &g, label);
                if (r < 0)
                        return r;
                have_label = r == DIR_SCAN_FOUND;

                serial = bs + BS32_VOL_ID;

                r = fat32_fsinfo_ok(fd, bs, &g);
                if (r <= 0)
                        return r;
        }

        memset(ret, 0, sizeof(*ret));
        ret->kind = PICO_FS_VFAT;
        if (have_label)
                pico_fs_label_set(ret->label, sizeof(ret->label), label, sizeof(label));
        if (serial)
                pico_fs_serial32_format(serial, ret->uuid);

        return 1;
}
