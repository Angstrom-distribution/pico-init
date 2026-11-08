/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The MBR disk signature. devd-mbr.h has why only the signature is read and
 * which checks the sector has to pass first.
 */

#include "devd-mbr.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "../fsid.h"

int devd_mbr_decode(const uint8_t *sector, size_t n, uint32_t *ret) {
        if (!sector || !ret || n < DEVD_MBR_SECTOR_SIZE)
                return -EINVAL;

        if (sector[DEVD_MBR_MAGIC_OFF] != 0x55 || sector[DEVD_MBR_MAGIC_OFF + 1] != 0xaa)
                return 0;

        for (size_t i = 0; i < DEVD_MBR_ENTRIES; i++) {
                const uint8_t *e = sector + DEVD_MBR_TABLE_OFF + i * DEVD_MBR_ENTRY_SIZE;

                /* Byte 0 is the boot indicator, byte 4 the partition type. */
                if (e[0] != 0x00 && e[0] != 0x80)
                        return 0;
                if (e[4] == DEVD_MBR_TYPE_GPT_PROTECTIVE)
                        return 0;
        }

        *ret = pico_le32(sector + DEVD_MBR_SIGNATURE_OFF);
        return 1;
}

int devd_mbr_read(const char *device, uint32_t *ret) {
        uint8_t sector[DEVD_MBR_SECTOR_SIZE];
        int fd, r;

        if (!device || !ret)
                return -EINVAL;

        fd = open(device, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (fd < 0)
                return -errno;

        r = pico_fs_read(fd, 0, sector, sizeof(sector));
        (void) close(fd);

        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        return devd_mbr_decode(sector, sizeof(sector), ret);
}

int devd_mbr_partuuid(uint32_t signature, unsigned nr, char *ret, size_t size) {
        int k;

        if (!ret || size == 0)
                return -EINVAL;

        k = snprintf(ret, size, "%08x-%02x", (unsigned) signature, nr);
        if (k < 0 || (size_t) k >= size)
                return -ENAMETOOLONG;

        return 0;
}
