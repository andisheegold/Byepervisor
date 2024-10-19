#include <sys/types.h>
#include <sys/param.h>
#include <sys/uio.h>

#include "kdlsym.h"
#include "util.h"

#include "shellcore_patches/2_50.h"

void *curthread;

int proc_rw_mem(void *p, off_t procAddr, size_t sz, void *kAddr, size_t *ioSz, bool write)
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

    int ret = debug_rwmem(p, &_uio);
    printf("debug_rwmem: ret = 0x%x\n", ret);

    if (ioSz) {
        *ioSz = (sz - _uio.uio_resid);
    }

    return ret;
}

void apply_shellcore_patches(void *td)
{
    uint64_t fw_ver;
    struct patch *patches;
    struct patch *cur_patch;
    int num_patches;

    auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);

    curthread = td;

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

    // Resolve shellcore base address
    // TODO

    printf("[HEN] [SHELLCORE] Applying shellcore patches...\n");
    for (int i = 0; i < num_patches; i++) {
        cur_patch = &patches[i];
        printf("  offset=0x%lx, size=0x%x, data=%p\n", cur_patch->offset, cur_patch->size, &cur_patch->data);

        // TODO: Apply patch
    }
}
