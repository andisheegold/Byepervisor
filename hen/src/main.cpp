#include <stdint.h>

#include "fpkg.h"
#include "fself.h"
#include "hook.h"
#include "kdlsym.h"
#include "patch_shellcore.h"
#include "util.h"

struct args
{
    uint64_t fptr;
    uint64_t fw;
    uint64_t kernel_base;
};

extern "C" {
    int kernel_main(void *td, struct args *args);
}

int kernel_main(void *td, struct args *args)
{
    int ret;

    init_kdlsym(args->fw, args->kernel_base);

    auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);

    printf("[HEN] Applying test hook\n");
    ret = apply_test_hook();
    if (ret != 0) {
        printf("[HEN] Failed to apply test hook\n");
        return -1;
    }

    printf("[HEN] Applying fself hooks\n");
    apply_fself_hooks();

    printf("[HEN] Applying fpkg hooks\n");
    apply_fpkg_hooks();

    printf("[HEN] Applying shellcore patches\n");
    apply_shellcore_patches(td);

    return 0;
}

// extern "C" {
//     __attribute__ ((section(".text.prologue")))
//     int _start(void *td, struct args *args) { return kernel_main(td, args); }
// }
