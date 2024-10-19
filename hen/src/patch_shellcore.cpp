#include <sys/types.h>
#include <sys/param.h>
#include <sys/uio.h>

#include "kdlsym.h"
#include "util.h"
#include "patch_shellcore.h"
#include "proc.h"

#include "shellcore_patches/2_50.h"

int proc_rw_mem(void *p, off_t procAddr, size_t sz, void *kAddr, size_t *ioSz, int write)
{
    auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    auto debug_rwmem = (int (*)(void *proc, struct uio *uio)) kdlsym(KERNEL_SYM_RW_MEM);

    printf("proc_rw_mem(%p, 0x%lx, %lx, %p, %p, %d)\n", p, procAddr, sz, kAddr, ioSz, write);

    if (!p) {
        printf("no proc\n");
        return -1;
    }

    if (!procAddr || !kAddr) {
        printf("no addrs\n");
        return -1;
    }

    if (!sz) {
        if (ioSz) {
            *ioSz = 0;
        }
        return 0;
    }

    struct iovec _iov{};
    struct uio _uio{};

    _iov.iov_base = kAddr;
    _iov.iov_len = sz;

    _uio.uio_iov = &_iov;
    _uio.uio_iovcnt = 1;
    _uio.uio_offset = procAddr;
    _uio.uio_resid = sz;
    _uio.uio_segflg = UIO_SYSSPACE;
    _uio.uio_rw = (write) ? UIO_WRITE : UIO_READ;
    _uio.uio_td = curthread;

    printf("debug_rwmem: try\n");
    int ret = debug_rwmem(p, &_uio);
    printf("debug_rwmem: ret = 0x%x\n", ret);

    if (ioSz) {
        *ioSz = (sz - _uio.uio_resid);
    }

    return ret;
}

uint64_t shellcore_get_addr(void *shellcore_proc)
{
    void *vm_map;
    void *first_entry;
    void *entry;
    uint64_t entry_start;
    uint8_t entry_prot;
    char *entry_name;
    uint64_t addr;

    auto printf                 = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    auto _vm_map_lock_read      = (void (*)(void *map, const char *file, int line)) kdlsym(KERNEL_SYM_VM_MAP_LOCK_READ);
	auto _vm_map_unlock_read    = (void (*)(void *map, const char *file, int line)) kdlsym(KERNEL_SYM_VM_MAP_UNLOCK_READ);
    auto _vm_map_lookup_entry   = (int (*)(void *map, uint64_t offset, void *entry)) kdlsym(KERNEL_SYM_VM_MAP_LOOKUP_ENTRY);

    vm_map = get_proc_vmmap(shellcore_proc);
    printf("[HEN] [SHELLCORE] vm_map = %p\n", vm_map);

    _vm_map_lock_read(vm_map, "", 0);

    if (_vm_map_lookup_entry(vm_map, 0, &entry) != 0) {
        printf("[HEN] [SHELLCORE] Failed to lookup first entry\n");
        _vm_map_unlock_read(vm_map, "", 0);
        return 0;
    }

    first_entry = entry;
    addr = 0;

    do {
        entry_name  = (char *) ((char *) (entry) + VM_ENTRY_OFFSET_NAME);
        entry_start = *(uint64_t *) ((char *) (entry) + VM_ENTRY_OFFSET_START);
        entry_prot  = *(uint8_t *) ((char *) (entry) + VM_ENTRY_OFFSET_PROT);

        printf("  vm entry (start=0x%lx, prot=0x%x), '%s'\n", entry_start, entry_prot, entry_name);
        entry = (void *) *(uint64_t *) ((char *) (entry) + VM_ENTRY_OFFSET_NEXT);

        if (!strncmp(entry_name, "executable", strlen("executable")) && entry_prot == 4) {
            // for (int i = 0; i < 0x200; i += 0x8) {
            //     printf("  +%02x: 0x%lx\n", i, *(uint64_t *) ((char *) (entry) + i));
            // }
            addr = entry_start;
            break;
        }
    } while (entry != NULL && entry != first_entry);

    _vm_map_unlock_read(vm_map, "", 0);
    return addr;
}

void apply_shellcore_patches()
{
    uint64_t fw_ver;
    struct patch *patches;
    struct patch *cur_patch;
    void *shellcore_proc;
    uint64_t shellcore_base_addr;
    int num_patches;

    auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);

    // Resolve patches for this fw
    fw_ver = get_fw_version();
    printf("apply_shellcore_patches: fw_ver = 0x%lx\n", fw_ver);

    switch (fw_ver) {
    case 0x2500000:
        patches = (struct patch *) &g_shellcore_patches_250;
        num_patches = sizeof(g_shellcore_patches_250) / sizeof(struct patch);
        break;
    default:
        printf("apply_shellcore_patches: don't have offsets for this firmware\n");
        return;
    }

    // Get shellcore proc
    printf("[HEN] [SHELLCORE] Finding shellcore\n");
    shellcore_proc = find_proc_by_name("SceShellCore");
    if (shellcore_proc == NULL) {
        printf("[HEN] [SHELLCORE] Failed to find shellcore\n");
        return;
    }
    printf("[HEN] [SHELLCORE] shellcore proc = %p\n", shellcore_proc);

    // Resolve shellcore base address
    shellcore_base_addr = shellcore_get_addr(shellcore_proc);
    printf("[HEN] [SHELLCORE] Found shellcore base = 0x%lx\n", shellcore_base_addr);

    printf("[HEN] [SHELLCORE] Applying shellcore patches...\n");
    for (int i = 0; i < num_patches; i++) {
        cur_patch = &patches[i];
        printf("  offset=0x%lx, size=0x%x, data=%p\n", cur_patch->offset, cur_patch->size, &cur_patch->data);

        proc_rw_mem(shellcore_proc, (shellcore_base_addr + cur_patch->offset), cur_patch->size, (void *) &cur_patch->data, NULL, 1);
    }
}
