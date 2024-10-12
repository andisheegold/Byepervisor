#pragma once
#include <sys/stdint.h>
#include <sys/elf.h>
#include <assert.h>
#include <stddef.h>

struct self_auth_info_t;
struct self_context_t;
struct self_ex_info_t;
struct self_header_t;
enum self_format_t;
struct self_fake_auth_info_t;
struct self_entry_t;

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

typedef struct self_entry_t 
{
    uint32_t props;
    uint32_t reserved;
    uint64_t offset;
    uint64_t filesz;
    uint64_t memsz;
} self_entry_t, SelfEntry;
static_assert(offsetof(struct self_entry_t, props) == 0x00);
static_assert(offsetof(struct self_entry_t, offset) == 0x08);
static_assert(offsetof(struct self_entry_t, filesz) == 0x10);
static_assert(offsetof(struct self_entry_t, memsz) == 0x18);
static_assert(sizeof(struct self_entry_t) == 0x20);

typedef struct self_header_t 
{
    uint32_t magic;
    uint8_t version;
    uint8_t mode;
    uint8_t endian;
    uint8_t attr;
    uint32_t key_type;
    uint16_t header_size;
    uint16_t meta_size;
    uint64_t file_size;
    uint16_t num_entries;
    uint16_t flags;
    uint32_t reserved;
    struct self_entry_t entries[0];
} self_header_t, SelfHeader;

typedef struct self_fake_auth_info_t
{
    uint64_t size;
    SelfAuthInfo info;
} self_fake_auth_info_t, SelfFakeAuthInfo;
static_assert(offsetof(struct self_fake_auth_info_t, size) == 0x00);
static_assert(offsetof(struct self_fake_auth_info_t, info) == 0x08);
static_assert(sizeof(struct self_fake_auth_info_t) == sizeof(uint64_t) + sizeof(SelfAuthInfo));

enum self_format_t
{
    SF_None,
    SF_Elf,
    SF_Self,
    SF_Count
};

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

#define ET_SCE_EXEC      0xFE00
#define ET_SCE_EXEC_ASLR 0xFE10
#define ET_SCE_DYNAMIC   0xFE18

int32_t IsFakeSelf(SelfContext* p_Context);
int32_t OnSceSblAuthMgrIsLoadable2(SelfContext* p_Context, SelfAuthInfo* p_OldAuthInfo, int32_t p_PathId, SelfAuthInfo* p_NewAuthInfo);
int32_t BuildFakeSelfAuthInfo(SelfContext* p_Context, SelfAuthInfo* p_ParentAuthInfo, SelfAuthInfo* p_AuthInfo);
int32_t SceSblAuthMgrGetElfHeader(SelfContext* p_Context, Elf64_Ehdr** p_OutElfHeader);
int32_t SceSblAuthMgrGetSelfAuthInfoFake(SelfContext* p_Context, SelfAuthInfo* p_Info);

const uint8_t c_ExecAuthInfo[AuthInfoSize];
const uint8_t c_DynlibAuthInfo[AuthInfoSize];
