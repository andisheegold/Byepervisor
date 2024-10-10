#ifndef PATCH_COMMON_H
#define PATCH_COMMON_H

struct patch
{
    char *purpose;
    uint64_t offset;
    char *data;
    int size;
};

#endif // PATCH_COMMON_H