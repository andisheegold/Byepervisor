#pragma once
#ifndef KDLSYM_H
#define KDLSYM_H

typedef enum {
    KERNEL_SYM_DMPML4I,
    KERNEL_SYM_DMPDPI,
    KERNEL_SYM_PML4PML4I,
    KERNEL_SYM_DATA_CAVE_1,
    KERNEL_SYM_DATA_CAVE_2,
    KERNEL_SYM_CFI_DISABLE,
    KERNEL_SYM_PROSPERO_SYSENT,
    KERNEL_SYM_ORBIS_SYSENT,
    KERNEL_SYM_J_SYS_GETPID,
    KERNEL_SYM_PMAP_STORE,
    KERNEL_SYM_MAX,
} ksym_t;

uint64_t kdlsym(ksym_t sym);
uint64_t ktext(uint64_t offset);

#endif // KDLSYM_H