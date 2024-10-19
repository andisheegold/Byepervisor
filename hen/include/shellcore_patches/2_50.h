#ifndef SHELLCORE_PATCHES_2_50
#define SHELLCORE_PATCHES_2_50

#include "common.h"

struct patch g_shellcore_patches_250[] = {
    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x25CBC3,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x25CC0C,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0x25CC80,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xACE363,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xACE3AC,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xACE420,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xB5FC12,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xDA8953,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xDA899C,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * xor eax, eax; nop; nop; nop
         */
        0xDA8A10,
        "\x31\xC0\x90\x90\x90",
        5
    },

    {
        /*
         * longjmp
         */
        0x4F50F1,
        "\x90\xE9",
        2
    },

    {
        /*
         * strfree
         */
        0x15054CC,
        "\x66\x72\x65\x65",
        4
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x3D7244,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x3D727F,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; nop
         */
        0x3D760E,
        "\x31\xC0\xFF\xC0\x90",
        5
    },

    {
        /*
         * xor eax, eax; inc eax; ret
         */
        0x4EAC40,
        "\x31\xC0\xFF\xC0\xC3",
        5
    }
};

#endif // SHELLCORE_PATCHES_2_50