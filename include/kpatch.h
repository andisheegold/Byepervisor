#pragma once
#ifndef KPATCH_H
#define KPATCH_H

void kpatch(kpatch_t patch, uint8_t *data, uint64_t len);
void patch_get_gid();
void patch_enable_mmap_self();

#endif // KPATCH_H