#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H

extern int g_debug_sock;

#define SOCK_LOG(format, ...)                                          \
{                                                                            \
    char _macro_printfbuf[512];                                              \
    int _macro_size = sprintf(_macro_printfbuf, format, ##__VA_ARGS__);      \
    write(g_debug_sock, _macro_printfbuf, _macro_size);                             \
} while(0);

void DumpHex(const void* data, size_t size);

#endif // DEBUG_LOG_H
