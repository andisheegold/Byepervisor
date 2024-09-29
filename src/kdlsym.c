#include <sys/types.h>
#include <ps5/kernel.h>

#include "debug_log.h"
#include "kdlsym.h"

uint64_t g_fw_version;
uint64_t g_kernel_base = 0;

uint64_t g_sym_map_200[] = {
    0x4CB3B50,          // KERNEL_SYM_DMPML4I
    0x4CB3B54,          // KERNEL_SYM_DMPDPI
    0x4CB38AC,          // KERNEL_SYM_PML4PML4I
    0x248E7AC,          // KERNEL_SYM_DATA_CAVE
    0x4CB38C8,          // KERNEL_SYM_PMAP_STORE
    0x245BAB0,          // KERNEL_SYM_HV_JMP_TABLE
    0x248EB70,          // KERNEL_SYM_HIJACKED_JMP_PTR
};

uint64_t g_gadget_map_200[] = {
    0x167241,           // KERNEL_GADGET_RET
    0x263BD1,           // KERNEL_GADGET_INFLOOP
    0xADF680,           // KERNEL_GADGET_HYPERCALL_SET_CPUID_PS4
    0xADFCEF,           // KERNEL_GADGET_RETURN_ADDR
    0x1A6878,           // KERNEL_GADGET_POP_RDI
    0x167430,           // KERNEL_GADGET_POP_RSI
    0x25C034,           // KERNEL_GADGET_POP_RDX
    0x1C34D0,           // KERNEL_GADGET_POP_RAX
    0x172C9F,           // KERNEL_GADGET_POP_RBX
    0x201F99,           // KERNEL_GADGET_ADD_RAX_RDX
    0x672787,           // KERNEL_GADGET_MOV_R9_QWORD_PTR_RDI_48
    0x62CC31,           // KERNEL_GADGET_POP_R12
    0x3B2A96,           // KERNEL_GADGET_MOV_QWORD_PTR_RDI_RSI
    0x20F3F0,           // KERNEL_GADGET_POP_RSP
    0x16B590,           // KERNEL_GADGET_MOV_RAX_QWORD_PTR_RAX
    0x16B737,           // KERNEL_GADGET_MOV_QWORD_PTR_RAX_0
    0x2488F0,           // KERNEL_GADGET_SETJMP
    0x248920,           // KERNEL_GADGET_LONGJMP
    0xB5C7BC,           // KERNEL_GADGET_JOP1
    0x21A5AB,           // KERNEL_GADGET_JOP2
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
    }

    return 0;
}
