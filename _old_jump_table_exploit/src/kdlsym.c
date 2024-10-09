#include <sys/types.h>
#include <ps5/kernel.h>

#include "debug_log.h"
#include "kdlsym.h"

#include "offsets/2_00.h"
#include "offsets/2_50.h"

uint64_t g_fw_version;
uint64_t g_kernel_base = 0;

void init_kdlsym()
{
    // Set firmware version
    g_fw_version    = kernel_get_fw_version() & 0xFFFF0000;

    // Resolve symbols
    switch (g_fw_version) {
    case 0x2000000:
    case 0x2500000:
        g_kernel_base = KERNEL_ADDRESS_DATA_BASE - 0x1B80000;
        break;
    }
}

uint64_t ktext(uint64_t offset)
{
    // Init kdlsym if it's not initialized already
    if (g_kernel_base == 0)
        init_kdlsym();

    return g_kernel_base + offset;
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
        return g_kernel_base + g_sym_map_200[sym];
    case 0x2500000:
        return g_kernel_base + g_sym_map_250[sym];
    }

    return 0;
}

uint64_t kdlgadget(kgadget_t gadget)
{
    // Init kdlsym if it's not initialized already
    if (g_kernel_base == 0)
        init_kdlsym();

    // Don't overflow gadget table
    if (gadget >= KERNEL_GADGET_MAX)
        return 0;

    switch (g_fw_version) {
    case 0x2000000:
        return g_kernel_base + g_gadget_map_200[gadget];
    case 0x2500000:
        return g_kernel_base + g_gadget_map_250[gadget];
    }

    return 0;
}
