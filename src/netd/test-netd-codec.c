/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Golden-byte tests for the carried DHCP wire codec.
 *
 * Split out from test-netd-dhcp deliberately (see meson.build): this program
 * asserts the wire format against fixed byte strings, while test-netd-dhcp
 * runs the real client against the real server over a veth pair. Keeping them
 * apart is what stops a mirrored encoder/decoder bug from passing -- a
 * netd-encodes/netd-decodes round trip agrees with itself no matter how wrong
 * both halves are, so the bytes have to be pinned against material that did
 * not come from netd.
 *
 * Placeholder body until N2 lands the codec.
 */

#include <stdio.h>

int main(void) {
        printf("test-netd-codec: placeholder, codec lands in N2\n");
        return 0;
}
