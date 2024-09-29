#include <sys/types.h>
#include <ps5/kernel.h>

#include "debug_log.h"
#include "kdlsym.h"

uint64_t g_fw_version;
uint64_t g_kernel_base = 0;

uint64_t g_sym_map_2xx[] = {
    0x4CB3B50, // KERNEL_SYM_DMPML4I,
    0x4CB3B54, // KERNEL_SYM_DMPDPI,
    0x4CB38AC, // KERNEL_SYM_PML4PML4I,
    0x248E7EC, // KERNEL_SYM_DATA_CAVE_1,
    0x2FF0000, // KERNEL_SYM_DATA_CAVE_2,
    0x7F6139F, // KERNEL_SYM_CFI_DISABLE,
    0x1CE6D10, // KERNEL_SYM_PROSPERO_SYSENT,
    0x1CDE4F0, // KERNEL_SYM_ORBIS_SYSENT,
    0x026DE98, // KERNEL_SYM_J_SYS_GETPID,
    0x4CB38C8, // KERNEL_SYM_PMAP_STORE,
};

void init_kdlsym()
{
    // Set firmware version
    g_fw_version    = kernel_get_fw_version() & 0xFFFF0000;

    // Resolve symbols
    switch (g_fw_version) {
    case 0x2000000:
        g_kernel_base = KERNEL_ADDRESS_DATA_BASE - 0x1B80000;
        break;
    }
}

uint64_t kdlsym(ksym_t sym)
{
    // Init kdlsym if it's not initialized already
    if (g_kernel_base == 0)
        init_kdlsym();

    // Don't overflow sym table
    if (sym >= KERNEL_SYM_MAX)
        return 0;

    switch (g_fw_version) {
    case 0x2000000:
        return g_kernel_base + g_sym_map_2xx[sym];
    // case 0x4000000:
    // case 0x4030000:
    // case 0x4500000:
    // case 0x4510000:
    //     return g_kernel_base + g_sym_map_4xx[sym];
    }

    return 0;
}

uint64_t ktext(uint64_t offset)
{
    // Init kdlsym if it's not initialized already
    if (g_kernel_base == 0)
        init_kdlsym();

    return g_kernel_base + offset;
}
