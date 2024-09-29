#ifndef BUMP_ALLOC_H
#define BUMP_ALLOC_H

#define BUMP_ALLOC_AREA_SIZE    0x100000

void *bump_alloc(uint64_t len);
void *bump_calloc(uint64_t count, uint64_t len);
void bump_reset();

#endif // BUMP_ALLOC_H