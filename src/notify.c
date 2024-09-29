#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "notify.h"

typedef struct notify_request {
	char unk_00h[45];
	char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

int flash_notification(const char *fmt, ...)
{
    va_list args;
    notify_request_t req;

    // Zero-init buffer to prevent dumb bugs
    bzero(&req, sizeof(req));

    // Construct message
    va_start(args, fmt);
    vsnprintf((char *) &req.message, sizeof(req.message), fmt, args);
    va_end(args);

	return sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}
