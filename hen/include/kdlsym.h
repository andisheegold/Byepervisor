#pragma once
#ifndef KDLSYM_H
#define KDLSYM_H

#include <stdint.h>

typedef enum {
    KERNEL_SYM_DMPML4I,
    KERNEL_SYM_DMPDPI,
    KERNEL_SYM_PML4PML4I,
    KERNEL_SYM_PMAP_STORE,
    KERNEL_SYM_DATA_CAVE,
    KERNEL_SYM_PRINTF,
    KERNEL_SYM_SCESBLAUTHMGRISLOADABLE2,
    KERNEL_SYM_SCESBLAUTHMGRGETSELFINFO,
    KERNEL_SYM_SCESBLACMGRGETPATHID,
    KERNEL_SYM_MAX,
} ksym_t;

void init_kdlsym(uint64_t fw_ver, uint64_t kernel_base);
uint64_t kdlsym(ksym_t sym);
uint64_t ktext(uint64_t offset);

#endif // KDLSYM_H