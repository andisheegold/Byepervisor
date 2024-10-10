#ifndef PATCHES_2_50_H
#define PATCHES_2_50_H

#include "patch_common.h"

struct patch g_kernel_patches_250[] = {
    {
        /*
            mov qword ptr [rdi + 0x408], 0xc0ffee;
            xor eax, eax;
            ret
        */
        "sys_getgid()", 
        0x02A67D0, 
        "\x48\xC7\x87\x08\x04\x00\x00\xEE\xFF\xC0\x00\x31\xC0\xC3",
        14 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrHasMmapSelfCapability()", 
        0x0580EB0, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6 
    }, 
    {
        // mov eax, 1; ret
        "sceSblACMgrIsAllowedToMmapSelf()", 
        0x0580EC0, 
        "\xB8\x01\x00\x00\x00\xC3", 
        6
    }, 
    {
        // xor eax, eax; 3x nop;
        "vm_mmap sceSblAuthMgrIsLoadable() call", 
        0x09A6A59, 
        "\x31\xC0\x90\x90\x90", 
        5
    }, 
};

#endif // PATCHES_2_50_H