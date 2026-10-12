/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Calls both sd_path_lookup*() functions for every type: a NULL output is
 * -EINVAL, everything else -EOPNOTSUPP, and no output is touched.
 */

#include "sd-path.h"

#include <errno.h>

#include "../../test-util.h"

int main(void) {
        char *s = (char *) 0x1;
        char **l = (char **) 0x1;

        ASSERT_EQ_INT(sd_path_lookup(SD_PATH_TEMPORARY, NULL, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_path_lookup_strv(SD_PATH_SEARCH_BINARIES, NULL, NULL), -EINVAL);

        for (uint64_t t = 0; t < _SD_PATH_MAX; t++) {
                ASSERT_EQ_INT(sd_path_lookup(t, NULL, &s), -EOPNOTSUPP);
                ASSERT_EQ_INT(sd_path_lookup(t, "suffix", &s), -EOPNOTSUPP);
                ASSERT_EQ_INT(sd_path_lookup_strv(t, NULL, &l), -EOPNOTSUPP);
                ASSERT_EQ_INT(sd_path_lookup_strv(t, "suffix", &l), -EOPNOTSUPP);
        }

        ASSERT_EQ_INT(sd_path_lookup(_SD_PATH_MAX, NULL, &s), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_path_lookup(_SD_PATH_INVALID, NULL, &s), -EOPNOTSUPP);
        ASSERT_EQ_INT(sd_path_lookup_strv(_SD_PATH_INVALID, NULL, &l), -EOPNOTSUPP);

        ASSERT_TRUE(s == (char *) 0x1);
        ASSERT_TRUE(l == (char **) 0x1);
        return 0;
}
