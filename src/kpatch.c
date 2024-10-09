#include <sys/types.h>
#include <ps5/kernel.h>

#include "debug_log.h"
#include "kdlsym.h"

void kpatch(kpatch_t patch, uint8_t *data, uint64_t len)
{
    uint64_t addr;

    addr = kdlpatch(patch);
    if (addr != 0) {
        kernel_copyin(data, addr, len);
    }
}

void patch_get_gid()
{
    uint8_t patch_data[0x100];
    int patch_cur;

    // Patch sys_getgid()
    patch_cur = 0;
    patch_data[patch_cur++] = 0x48;
    patch_data[patch_cur++] = 0xC7;
    patch_data[patch_cur++] = 0x87;
    patch_data[patch_cur++] = 0x08;
    patch_data[patch_cur++] = 0x04;
    patch_data[patch_cur++] = 0x00;
    patch_data[patch_cur++] = 0x00;
    patch_data[patch_cur++] = 0xEE;
    patch_data[patch_cur++] = 0xFF;
    patch_data[patch_cur++] = 0xC0;
    patch_data[patch_cur++] = 0x00;
    patch_data[patch_cur++] = 0x31;
    patch_data[patch_cur++] = 0xC0;
    patch_data[patch_cur++] = 0xC3;

    kpatch(KERNEL_PATCH_SYS_GETGID, (uint8_t *) &patch_data, patch_cur);
}

void patch_enable_mmap_self()
{
    uint8_t patch_data[0x100];
    int patch_cur;

    // Patch sceSblACMgrHasMmapSelfCapability() + sceSblACMgrIsAllowedToMmapSelf()
    patch_cur = 0;
    patch_data[patch_cur++] = 0xB8; // mov eax, 1;
    patch_data[patch_cur++] = 0x01;
    patch_data[patch_cur++] = 0x00;
    patch_data[patch_cur++] = 0x00;
    patch_data[patch_cur++] = 0x00; 
    patch_data[patch_cur++] = 0xC3; // ret;

    kpatch(KERNEL_PATCH_HAS_MMAP_SELF_CAPABILITY, (uint8_t *) &patch_data, patch_cur);
    kpatch(KERNEL_PATCH_IS_ALLOWED_TO_MMAP_SELF, (uint8_t *) &patch_data, patch_cur);
    patch_cur = 0;

    // Patch mmap self call to sceSblAuthMgrIsLoadable()
    patch_data[patch_cur++] = 0x31; // xor eax, eax
    patch_data[patch_cur++] = 0xC0;
    patch_data[patch_cur++] = 0x90;
    patch_data[patch_cur++] = 0x90;
    patch_data[patch_cur++] = 0x90;

    kpatch(KERNEL_PATCH_MMAP_SELF_CALL_IS_LOADABLE, (uint8_t *) &patch_data, patch_cur);
}
