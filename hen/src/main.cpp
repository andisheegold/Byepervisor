#include <stdint.h>

#include "fself.h"
#include "hook.h"
#include "kdlsym.h"

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
    printf("[HEN] ret = 0x%x\n", ret);

    printf("[HEN] Applying fself hooks\n");
    apply_fself_hooks();

    return 0;
}

// extern "C" {
//     __attribute__ ((section(".text.prologue")))
//     int _start(void *td, struct args *args) { return kernel_main(td, args); }
// }
