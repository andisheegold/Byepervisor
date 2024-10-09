#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <ps5/kernel.h>

#include "config.h"
#include "debug_log.h"
#include "kdlsym.h"
#include "kpatch.h"
#include "paging.h"
#include "self.h"
#include "util.h"

int g_debug_sock = -1;

int sceKernelSleep(int secs);

// void dump_self_to_client(int client)
// {
//     int ret;
//     uint64_t size;
//     int write_ret;
//     void *libkernel_data;

//     // Try to decrypt libkernel
//     ret = decrypt_self("/system/common/lib/libkernel.sprx", &libkernel_data, &size);
//     SOCK_LOG("[+] decrypt test: 0x%x (%p, size = 0x%lx)\n", ret, libkernel_data, size);

//     write_ret = write(client, libkernel_data, size);
//     if (write_ret < 0)
//         return;
//     SOCK_LOG("[+] wrote 0x%x bytes\n", write_ret);

//     close(client);
//     SOCK_LOG("[+] Done\n");
// }

void dump_kernel_to_client(int client)
{
    int write_ret;
    char data_buf[0x4000];
    uint64_t qword;

    SOCK_LOG("[+] Dumping kernel to client\n");

    // Write firmware version
    qword = kernel_get_fw_version() & 0xFFFF0000;
    if (write(client, &qword, sizeof(qword)) != sizeof(qword)) {
        SOCK_LOG("[!] Failed to send FW version\n");
        close(client);
        return;
    }

    // Write kernel base address
    qword = ktext(0);
    if (write(client, &qword, sizeof(qword)) != sizeof(qword)) {
        SOCK_LOG("[!] Failed to send kernel base\n");
        close(client);
        return;
    }

    // Write kernel .text + data
    for (uint64_t addr = ktext(0); ; addr += sizeof(data_buf)) {
        kernel_copyout(addr, &data_buf, sizeof(data_buf));
        write_ret = write(client, &data_buf, sizeof(data_buf));
        if (write_ret < 0)
            break;
    }

    // We shouldn't reach here, we should crash
    close(client);
    SOCK_LOG("[+] Done\n");
}

// int run_dump_server(int port)
// {
//     int s;
//     int client;
//     struct sockaddr_in sockaddr;

//     s = socket(AF_INET, SOCK_STREAM, 0);
//     bzero(&sockaddr, sizeof(sockaddr));

//     sockaddr.sin_family = AF_INET;
// 	sockaddr.sin_port = htons(port);
// 	sockaddr.sin_addr.s_addr = INADDR_ANY;

//     if (bind(s, (const struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0) {
//         SOCK_LOG("[!] failed to bind server\n");
// 		return -1;
//     }

// 	if (listen(s, 5) < 0) {
//         SOCK_LOG("[!] failed to listen on server\n");
// 		return -1;
//     }

//     SOCK_LOG("[SRV] dump server is now running (port: %d)...\n", port);

//     // Accept clients
// 	for (;;) {
//         client = accept(s, 0, 0);
//         SOCK_LOG("[SRV] accepted a client = %d\n", client);

//         if (client > 0) {
//             //dump_kernel_to_client(client);
//             dump_self_to_client(client);
//         }
//     }

//     return 0;
// }

int main()
{
    int ret;
	int debug_sock = -1;
	struct sockaddr_in addr;
    uint64_t kernel_pmap;
    uint64_t pte_addr;
    uint64_t pde_addr;
    uint64_t pte;
    uint64_t pde;

	// Open a debug socket if enabled
	if (PC_DEBUG_ENABLED) {
		debug_sock = socket(AF_INET, SOCK_STREAM, 0);
		if (debug_sock < 0) {
			return 0xDEAD0001;
		}

		inet_pton(AF_INET, PC_DEBUG_IP, &addr.sin_addr);
		addr.sin_family = AF_INET;
		addr.sin_len    = sizeof(addr);
		addr.sin_port   = htons(PC_DEBUG_PORT);

		ret = connect(debug_sock, (const struct sockaddr *) &addr, sizeof(addr));
		if (ret < 0) {
			return 0xDEAD0002;
		}

		SOCK_LOG("[!] debug socket connected\n");
        g_debug_sock = debug_sock;
	}

    // Jailbreak
    kernel_set_proc_rootdir(getpid(), kernel_get_root_vnode());

    kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
    SOCK_LOG("[+] Kernel pmap = 0x%lx\n", kernel_pmap);

    // Disable xotext + enable write  on kernel .text pages
    SOCK_LOG("[+] Disabling xotext + enabling write\n");
    for (uint64_t addr = ktext(0); addr < KERNEL_ADDRESS_DATA_BASE; addr += 0x1000) {
        pde_addr = find_pde(kernel_pmap, addr, &pde);
        if (pde_addr != 0xFFFFFFFFFFFFFFFFull) {
            CLEAR_PDE_BIT(pde, XOTEXT);
            SET_PDE_BIT(pde, RW);
            kernel_copyin(&pde, pde_addr, sizeof(pde));
        }

        pte_addr = find_pte(kernel_pmap, addr, &pte);
        if (pte_addr != 0xFFFFFFFFFFFFFFFFull) {
            CLEAR_PDE_BIT(pte, XOTEXT);
            SET_PDE_BIT(pte, RW);
            kernel_copyin(&pte, pte_addr, sizeof(pte));
        }
    }

    // Check if this is a resume state or not, if it's not, prompt for restart and exit
    if (kernel_read4(kdlsym(KERNEL_SYM_DATA_CAVE)) != 0x1337) {
        SOCK_LOG("[+] System needs to be suspended and resumed...\n");
        flash_notification("Byepervisor\nEnter rest mode and resume");
        kernel_write4(kdlsym(KERNEL_SYM_DATA_CAVE), 0x1337);
        return 0;
    }

    // Apply patches
    SOCK_LOG("[+] Test pre-patch  sys_getgid: 0x%x\n", getgid());
    patch_get_gid();
    SOCK_LOG("[+] Test post-patch sys_getgid: 0x%x\n", getgid());

    SOCK_LOG("[+] Patching to allow mmap MAP_SELF...\n");
    patch_enable_mmap_self();
    run_self_server(9004);

    // run_dump_server(9003);
    return 0;
}