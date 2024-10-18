#pragma once
#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>

uint64_t get_dmap_addr(uint64_t pa);
void memcpy(void *dest, const void *src, size_t n);
size_t strlen(const char *str);
char *strstr(const char *str, const char *substring);

#endif // UTIL_H