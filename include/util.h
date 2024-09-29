#ifndef UTIL_H
#define UTIL_H

// Core pinning
int pin_to_core(int num);
void pin_to_first_available_core();
int get_cpu_core();

// Dumping
void DumpHex(const void* data, size_t size);

#endif // UTIL_H