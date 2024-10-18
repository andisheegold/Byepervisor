#include <stdint.h>
#include <stddef.h>

#include "kdlsym.h"

uint64_t g_dmap_base = 0;

void init_dmap_resolve()
{
    uint32_t DMPML4I;
    uint32_t DMPDPI;

    DMPML4I = *(uint32_t *) (kdlsym(KERNEL_SYM_DMPML4I));
    DMPDPI  = *(uint32_t *) (kdlsym(KERNEL_SYM_DMPDPI));

    g_dmap_base = ((uint64_t) (DMPDPI) << 30) | ((uint64_t ) (DMPML4I) << 39) | 0xFFFF800000000000;
}

uint64_t get_dmap_addr(uint64_t pa)
{
    // Init dmap resolve if it's not initialized already
    if (g_dmap_base == 0)
        init_dmap_resolve();

    return g_dmap_base + pa;
}

void memcpy(void *dest, const void *src, size_t n)
{
    char *csrc = (char *) src;
    char *cdest = (char *) dest;

    for (size_t i = 0; i < n; i++) {
        cdest[i] = csrc[i];
    }
}

size_t strlen(const char *str)
{
    const char *s;

    for (s = str; *s; s++) ;
    return (s - str);
}

char *strstr(const char *str, const char *substring)
{
    const char *a;
    const char *b;

    b = substring;

    if (*b == 0) {
        return (char *) str;
    }

    for ( ; *str != 0; str += 1) {
        if (*str != *b) {
            continue;
        }

        a = str;
        while (1) {
            if (*b == 0) {
                return (char *) str;
            }
            if (*a++ != *b++) {
                break;
            }
        }
        b = substring;
    }

    return NULL;
}
