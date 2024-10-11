#pragma once
#include <sys/stdint.h>

// Structure Credit: Flatz
// Pulled from Mira-vnext for Byepervisor by kiwidog
typedef struct self_auth_info_t 
{
    uint64_t paid;
    uint64_t caps[4];
    uint64_t attrs[4];
    uint8_t unk[0x40];
}self_auth_info_t, SelfAuthInfo;
static_assert(offsetof(struct self_auth_info_t, paid) == 0x00);
static_assert(offsetof(struct self_auth_info_t, caps) == 0x08);
static_assert(offsetof(struct self_auth_info_t, attrs) == 0x28);
static_assert(offsetof(struct self_auth_info_t, unk) == 0x48);
static_assert(sizeof(struct self_auth_info_t) == 0x88);

typedef struct self_context_t 
{
    uint32_t format;
    uint32_t elf_auth_type;
    uint32_t total_header_size;
    uint32_t unk_0C;
    void *segment;
    uint32_t unk_18;
    uint32_t ctx_id;
    uint64_t svc_id;
    uint64_t unk_28;
    uint32_t buf_id;
    uint32_t unk_34;
    struct self_header_t *header;
    uint8_t mtx_struct[0x20];
} self_context_t, SelfContext;
static_assert(offsetof(struct self_context_t, format) == 0x00);
static_assert(offsetof(struct self_context_t, elf_auth_type) == 0x04);
static_assert(offsetof(struct self_context_t, total_header_size) == 0x08);
static_assert(offsetof(struct self_context_t, unk_0C) == 0x0C);
static_assert(offsetof(struct self_context_t, segment) == 0x10);
static_assert(offsetof(struct self_context_t, ctx_id) == 0x1C);
static_assert(offsetof(struct self_context_t, svc_id) == 0x20);
static_assert(offsetof(struct self_context_t, buf_id) == 0x30);
static_assert(offsetof(struct self_context_t, unk_34) == 0x34);
static_assert(offsetof(struct self_context_t, header) == 0x38);
static_assert(offsetof(struct self_context_t, mtx_struct) == 0x40);
static_assert(sizeof(struct self_context_t) == 96, "self_context_t size mismatch.");

typedef struct self_ex_info_t
{
    uint64_t paid;
    uint64_t ptype;
    uint64_t app_version;
    uint64_t firmware_version;
    uint8_t digest[0x20];
} self_ex_info_t, SelfExInfo;
static_assert(offsetof(struct self_ex_info_t, paid) == 0x00);
static_assert(offsetof(struct self_ex_info_t, ptype) == 0x08);
static_assert(offsetof(struct self_ex_info_t, app_version) == 0x10);
static_assert(offsetof(struct self_ex_info_t, firmware_version) == 0x18);
static_assert(offsetof(struct self_ex_info_t, digest) == 0x20);
static_assert(sizeof(struct self_ex_info_t) == 0x40);

typedef enum _SelfFormat
{
    None,
    Elf,
    Self,
    Count
} SelfFormat;

enum
{
    LoadSelfSegment = 2,
    LoadSelfBlock = 6,

    SelfMagic = 0x1D3D154F,
    ElfMagic = 0x464C457F,

    SelfPtypeFake = 1,

    AuthInfoSize = 136,
};

#define false 0
#define true 1

int32_t IsFakeSelf(SelfContext* p_Context);
int OnSceSblAuthMgrIsLoadable2(SelfContext* p_Context, SelfAuthInfo* p_OldAuthInfo, int32_t p_PathId, SelfAuthInfo* p_NewAuthInfo);
int32_t BuildFakeSelfAuthInfo(SelfContext* p_Context, SelfAuthInfo* p_ParentAuthInfo, SelfAuthInfo* p_AuthInfo);

const uint8_t c_ExecAuthInfo[AuthInfoSize];
const uint8_t c_DynlibAuthInfo[AuthInfoSize];
