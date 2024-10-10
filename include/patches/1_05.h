#ifndef PATCHES_1_05_H
#define PATCHES_1_05_H

#include "patch_common.h"

struct patch g_kernel_patches_105[] = {
    {
        /*
            mov qword ptr [rdi + 0x408], 0xc0ffee;
            xor eax, eax;
            ret
        */
        "sys_getgid()", 
        0x02F17D0, 
        "\x48\xC7\x87\x08\x04\x00\x00\xEE\xFF\xC0\x00\x31\xC0\xC3",
        14 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrHasMmapSelfCapability()", 
        0x05A9C20, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrIsAllowedToMmapSelf()", 
        0x05A9C30, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6
    }, 
    {
        // xor eax, eax; 3x nop;
        "vm_mmap sceSblAuthMgrIsLoadable() call", 
        0x0981909, 
        "\x31\xC0\x90\x90\x90", 
        5
    }, 
};

#endif // PATCHES_1_05_H