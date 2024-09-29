#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

#include "bump_alloc.h"
#include "debug_log.h"

char *g_bump_allocator_base = NULL;
char *g_bump_allocator_cur;
uint64_t g_bump_allocator_len;

int bump_init(uint64_t len)
{
    g_bump_allocator_len  = len;
    g_bump_allocator_base = mmap(NULL, g_bump_allocator_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (g_bump_allocator_base == MAP_FAILED) {
        SOCK_LOG("[!] failed to allocate backing memory for bump allocator\n");
        return -ENOMEM;
    }

    g_bump_allocator_cur = g_bump_allocator_base;
    return 0;
}

void *bump_alloc(uint64_t len)
{
    void *ptr;

    // Initialize bump allocator if its not already
    if (g_bump_allocator_base == NULL) {
        if (bump_init(BUMP_ALLOC_AREA_SIZE) != 0)
            return NULL;
    }

    // Check length doesn't exceed bounds of backing buffer
    if (g_bump_allocator_cur + len >= (g_bump_allocator_base + g_bump_allocator_len)) {
        return NULL;
    }

    // Allocate and increase cursor
    ptr = (void *) g_bump_allocator_cur;
    g_bump_allocator_cur += len;

    // Zero init to avoid stupid bugs
    (void)memset(ptr, 0, len);

    return ptr;
}

void *bump_calloc(uint64_t count, uint64_t len)
{
    uint64_t total_len;

    total_len = count * len;
    return bump_alloc(total_len);
}

void bump_reset()
{
    g_bump_allocator_cur = g_bump_allocator_base;
}
