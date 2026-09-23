/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * NTFS: the boot sector, then the $Volume record in the Master File Table.
 *
 * "NTFS    " at byte 3 names it, and blkid then insists on an NTFS-shaped
 * boot parameter block before believing that: a power-of-two sector size of
 * 256-4096 bytes, a cluster size (possibly given as a negative power of two)
 * of at most 2 MiB, the FAT-only fields zero, a plausible MFT record size,
 * and the MFT and its mirror inside the volume. The MFT's first record and
 * record 3 ($Volume) must both start with "FILE". All of that is kept.
 *
 * UUID is the 64-bit volume serial number as sixteen upper-case hex digits,
 * which is how blkid prints it and so how an fstab line names it. LABEL is
 * the value of $Volume's $VOLUME_NAME attribute (type 0x60), UTF-16 converted
 * to UTF-8. Like blkid, this reads the record without applying the update
 * sequence fixups: $VOLUME_NAME sits well inside the first sector of the
 * record, before the first fixup position.
 *
 * One narrowing: an MFT record larger than 64 KiB is refused. The format
 * allows the arithmetic to reach far larger sizes than any NTFS
 * implementation creates (1 KiB and 4 KiB are what exist), and PID 1 reading
 * megabytes on a stranger's say-so is the thing to avoid.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "fsid.h"

#define NTFS_SECTOR_SIZE 11
#define NTFS_SEC_PER_CLUS 13
#define NTFS_RESERVED 14
#define NTFS_FATS 16
#define NTFS_ROOT_ENTRIES 17
#define NTFS_SECTORS16 19
#define NTFS_SEC_PER_FAT 22
#define NTFS_LARGE_SECTORS 32
#define NTFS_NUM_SECTORS 40
#define NTFS_MFT_LCN 48
#define NTFS_MFTMIRR_LCN 56
#define NTFS_CLUS_PER_MFT 64
#define NTFS_SERIAL 72

#define NTFS_MAX_CLUSTER (2 * 1024 * 1024)
#define NTFS_MFT_RECORD_MAX (64 * 1024)
#define NTFS_MFT_VOLUME 3

#define MFT_ATTRS_OFFSET 20
#define MFT_BYTES_ALLOCATED 28

#define ATTR_TYPE 0
#define ATTR_LEN 4
#define ATTR_VALUE_LEN 16
#define ATTR_VALUE_OFFSET 20
#define ATTR_HEADER_SIZE 22
#define ATTR_VOLUME_NAME 0x60
#define ATTR_END 0xffffffffu

static bool is_power_of_2(uint32_t v) {
        return v != 0 && (v & (v - 1)) == 0;
}

/* The MFT record size and where the MFT starts, or false for a boot sector
 * blkid would not accept. */
static bool parse_boot(const uint8_t *bs, uint32_t *ret_record, uint64_t *ret_mft) {
        uint32_t sector_size = pico_le16(bs + NTFS_SECTOR_SIZE);
        uint8_t spc = bs[NTFS_SEC_PER_CLUS];
        int8_t cpm = (int8_t) bs[NTFS_CLUS_PER_MFT];
        uint64_t sectors, clusters, mft, mirr, cluster_size;
        uint32_t spc_real;

        if (sector_size < 256 || sector_size > 4096 || !is_power_of_2(sector_size))
                return false;

        if (spc != 0 && spc <= 128 && is_power_of_2(spc))
                spc_real = spc;
        else if (spc >= 240 && spc <= 249)
                spc_real = 1u << (256 - spc);
        else
                return false;

        cluster_size = (uint64_t) sector_size * spc_real;
        if (cluster_size > NTFS_MAX_CLUSTER)
                return false;

        if (pico_le16(bs + NTFS_RESERVED) != 0 || pico_le16(bs + NTFS_ROOT_ENTRIES) != 0 ||
            pico_le16(bs + NTFS_SECTORS16) != 0 || pico_le16(bs + NTFS_SEC_PER_FAT) != 0 ||
            pico_le32(bs + NTFS_LARGE_SECTORS) != 0 || bs[NTFS_FATS] != 0)
                return false;

        /* Positive: clusters per record, a power of two up to 64. Negative
         * (0xe1-0xf7 as a byte): the record is 2^-n bytes. */
        if ((uint8_t) cpm < 0xe1 || (uint8_t) cpm > 0xf7) {
                if (cpm <= 0 || cpm > 64 || !is_power_of_2((uint32_t) cpm))
                        return false;
        }

        if (cpm > 0) {
                uint64_t record = (uint64_t) cpm * cluster_size;

                if (record > NTFS_MFT_RECORD_MAX)
                        return false;
                *ret_record = (uint32_t) record;
        } else {
                unsigned shift = (unsigned) -cpm;

                if (shift >= 31 || (UINT64_C(1) << shift) > NTFS_MFT_RECORD_MAX)
                        return false;
                *ret_record = 1u << shift;
        }

        if (*ret_record < 4)
                return false;

        sectors = pico_le64(bs + NTFS_NUM_SECTORS);
        clusters = sectors / spc_real;
        mft = pico_le64(bs + NTFS_MFT_LCN);
        mirr = pico_le64(bs + NTFS_MFTMIRR_LCN);
        if (mft > clusters || mirr > clusters)
                return false;

        /* Refused well before the multiplication or the record offsets
         * added to it could wrap: no device is 2^62 bytes long. */
        if (mft > (UINT64_C(1) << 62) / cluster_size)
                return false;
        *ret_mft = mft * cluster_size;
        return true;
}

static void volume_name(const uint8_t *rec, uint32_t size, char *label, size_t label_size) {
        uint32_t off = pico_le16(rec + MFT_ATTRS_OFFSET);
        uint32_t allocated = pico_le32(rec + MFT_BYTES_ALLOCATED);

        while ((uint64_t) off + ATTR_HEADER_SIZE <= size && off <= allocated) {
                const uint8_t *a = rec + off;
                uint32_t type = pico_le32(a + ATTR_TYPE);
                uint32_t len = pico_le32(a + ATTR_LEN);

                if (len == 0 || type == ATTR_END)
                        return;

                if (type == ATTR_VOLUME_NAME) {
                        uint32_t voff = pico_le16(a + ATTR_VALUE_OFFSET);
                        uint32_t vlen = pico_le32(a + ATTR_VALUE_LEN);

                        if (voff <= size - off && vlen <= size - off - voff)
                                pico_fs_label_set_utf16le(label, label_size, a + voff, vlen);
                        return;
                }

                if (len > size - off)
                        return;
                off += len;
        }
}

int pico_fs_probe_ntfs(int fd, PicoFsId *ret) {
        char label[PICO_FS_LABEL_MAX] = "";
        uint8_t bs[512], magic[4], *rec;
        uint32_t record;
        uint64_t mft, serial;
        int r;

        r = pico_fs_read(fd, 0, bs, sizeof(bs));
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        if (memcmp(bs + 3, "NTFS    ", 8) != 0 || !parse_boot(bs, &record, &mft))
                return 0;

        r = pico_fs_read(fd, mft, magic, sizeof(magic));
        if (r < 0)
                return r == -ENODATA || r == -EOVERFLOW ? 0 : r;
        if (memcmp(magic, "FILE", 4) != 0)
                return 0;

        rec = malloc(record);
        if (!rec)
                return -ENOMEM;

        r = pico_fs_read(fd, mft + (uint64_t) NTFS_MFT_VOLUME * record, rec, record);
        if (r < 0) {
                free(rec);
                return r == -ENODATA || r == -EOVERFLOW ? 0 : r;
        }
        if (memcmp(rec, "FILE", 4) != 0) {
                free(rec);
                return 0;
        }

        volume_name(rec, record, label, sizeof(label));
        free(rec);

        memset(ret, 0, sizeof(*ret));
        ret->kind = PICO_FS_NTFS;
        memcpy(ret->label, label, sizeof(ret->label));

        serial = pico_le64(bs + NTFS_SERIAL);
        if (serial != 0) {
                static const char hex[] = "0123456789ABCDEF";

                for (int i = 0; i < 16; i++)
                        ret->uuid[i] = hex[(serial >> (60 - 4 * i)) & 0xf];
                ret->uuid[16] = '\0';
        }

        return 1;
}
