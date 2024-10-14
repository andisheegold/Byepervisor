#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

extern "C"
{
#include <ps5/kernel.h>
}

#include "debug_log.h"
#include "kdlsym.h"
#include "patching.h"

#include "patches/1_05.h"
#include "patches/2_50.h"

int apply_kernel_patches()
{
    uint64_t fw_ver;
    uint64_t kernel_base; 
    uint64_t patch_addr;
    struct patch *patches;
    struct patch *cur_patch;
    int num_patches;

    fw_ver = kernel_get_fw_version() & 0xFFFF0000;
    kernel_base = ktext(0);

    SOCK_LOG("apply_kernel_patches: fw_ver=0x%lx\n", fw_ver);

    switch (fw_ver) {
    case 0x1050000:
        patches = (struct patch *) &g_kernel_patches_105;
        num_patches = sizeof(g_kernel_patches_105) / sizeof(struct patch);
        break;
    case 0x2500000:
        patches = (struct patch *) &g_kernel_patches_250;
        num_patches = sizeof(g_kernel_patches_250) / sizeof(struct patch);
        break;
    default:
        return -ENOENT;
    }

    SOCK_LOG("[+] Applying kernel patches...\n");
    for (int i = 0; i < num_patches; i++) {
        cur_patch  = &patches[i];
        patch_addr = kernel_base + cur_patch->offset;
        SOCK_LOG("  [+] %s (offset=0x%lx, size=0x%x)\n", cur_patch->purpose, cur_patch->offset, cur_patch->size);

        kernel_copyin(cur_patch->data, patch_addr, cur_patch->size);
    }

    return 0;
}
