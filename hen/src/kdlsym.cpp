#include <stdint.h>

#include "kdlsym.h"
#include "offsets/2_50.h"

uint64_t g_fw_version;
uint64_t g_kernel_base = 0;

void init_kdlsym(uint64_t fw_ver, uint64_t kernel_base)
{
    g_fw_version    = fw_ver;
    g_kernel_base   = kernel_base;
}

uint64_t get_fw_version()
{
    return g_fw_version;
}

uint64_t ktext(uint64_t offset)
{
    if (g_kernel_base == 0)
        return 0;

    return g_kernel_base + offset;
}

uint64_t kdlsym(ksym_t sym)
{
    if (g_kernel_base == 0)
        return 0;

    // Don't overflow sym table
    if (sym >= KERNEL_SYM_MAX)
        return 0;

    switch (g_fw_version) {
    case 0x2000000:
    case 0x2200000:
    case 0x2250000:
    case 0x2260000:
    case 0x2300000:
    case 0x2500000:
        return g_kernel_base + g_sym_map_250[sym];
    }

    return 0;
}
