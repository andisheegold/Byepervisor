/**
 * Credits:
 *      Inital Structures: flat_z
 *      Structs and asserts: mira-vnext/kiwidog
*/
#ifndef FAKE_H
#define FAKE_H

#include <stdint.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>

#include <sys/stdint.h>
#include <sys/elf.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>

/**
 * @brief This is just here to prevent errors, too lazy to remove logging
 * 
 */
#define WriteLog(x, y, ...)

/**
 * C++ to C fixes
*/
#define false 0
#define true 1

/**
 * Fake Self
*/
#pragma region FAKE SELF
// Forward declarations
struct self_auth_info_t;
struct self_context_t;
struct self_ex_info_t;
struct self_header_t;
enum self_format_t : int;
struct self_fake_auth_info_t;
struct self_entry_t;

/**
 * SELF authentication information
*/
typedef struct self_auth_info_t 
{
    uint64_t paid;
    uint64_t caps[4];
    uint64_t attrs[4];
    uint8_t unk[0x40];
}self_auth_info_t, SelfAuthInfo;

/**
 * SELF kernel context
*/
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

/**
 * SELF extra information
*/
typedef struct self_ex_info_t
{
    uint64_t paid;
    uint64_t ptype;
    uint64_t app_version;
    uint64_t firmware_version;
    uint8_t digest[0x20];
} self_ex_info_t, SelfExInfo;

/**
 * SELF entry
*/
typedef struct self_entry_t 
{
    uint32_t props;
    uint32_t reserved;
    uint64_t offset;
    uint64_t filesz;
    uint64_t memsz;
} self_entry_t, SelfEntry;

/**
 * SELF header
*/
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

/**
 * SELF fake authentication information
*/
typedef struct self_fake_auth_info_t
{
    uint64_t size;
    SelfAuthInfo info;
} self_fake_auth_info_t, SelfFakeAuthInfo;

/**
 * SELF formats
*/
enum self_format_t : int
{
    /**
     * No Specified format
    */
    SF_None,

    /**
     * RAW elf format
    */
    SF_Elf,

    /**
     * SELF format
    */
    SF_Self,

    /**
     * Count of formats
    */
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
#pragma endregion

enum
{
    EKPFS_SIZE = 0x20,
    EEKPFS_SIZE = 0x100,
    PFS_SEED_SIZE = 0x10,
    PFS_FINAL_KEY_SIZE = 0x20,
    SIZEOF_PFS_KEY_BLOB = 0x140,
    CONTENT_KEY_SEED_SIZE = 0x10,
    SELF_KEY_SEED_SIZE = 0x10,
    EEKC_SIZE = 0x20,
    MAX_FAKE_KEYS = 32,
    SIZEOF_RSA_KEY = 0x48,
    PFS_FAKE_OBF_KEY_ID = 0x1337,
    SIZEOF_PFS_HEADER = 0x5A0,

    // RIF
    RIF_DATA_SIZE = 0x90,
    RIF_DIGEST_SIZE = 0x10,
    RIF_KEY_TABLE_SIZE = 0x230,
    RIF_MAX_KEY_SIZE = 0x20,
    SIZEOF_ACTDAT = 0x200,
    SIZEOF_RIF = 0x400,
    RIF_PAYLOAD_SIZE = (RIF_DIGEST_SIZE + RIF_DATA_SIZE),

    SCE_SBL_ERROR_NPDRM_ENOTSUP = 0x800F0A25,
    SIZEOF_SBL_KEY_RBTREE_ENTRY = 0xA8, // sceSblKeymgrSetKey
    SIZEOF_SBL_MAP_LIST_ENTRY = 0x50, // sceSblDriverMapPages
    TYPE_SBL_KEY_RBTREE_ENTRY_DESC_OFFSET = 0x04,
    TYPE_SBL_KEY_RBTREE_ENTRY_LOCKED_OFFSET = 0x80,

    SBL_MSG_SERVICE_MAILBOX_MAX_SIZE = 0x80,
    SBL_MSG_CCP = 0x8,

    #define SWAP_16(x) ((((uint16_t)(x) & 0xff) << 8) | ((uint16_t)(x) >> 8))
    #define BE16(val) SWAP_16(val)
    #define LE32(val) (val)
};

/**
 * Mailbox message structure
*/
typedef struct _MailboxMessage
{
    int16_t funcId; // 2
    char pad02[2];
    int32_t retVal; // Return Value
    uint64_t unk08;
    uint32_t unk16;
    uint32_t unk20;
    uint64_t unk24;
    uint64_t unk32;
    uint64_t unk40;
    uint32_t unk48;
    char unk52[76];
} MailboxMessage;

struct fake_key_desc_t
{
    uint8_t key[0x20];
    char occupied;
};

struct fake_key_d_t
{
    uint32_t index;
    uint8_t seed[PFS_SEED_SIZE];
};

struct ekc_t
{
    uint8_t contentKeySeed[CONTENT_KEY_SEED_SIZE];
    uint8_t selfKeySeed[SELF_KEY_SEED_SIZE];
};

struct rif_key_blob_t
{
    struct ekc_t eekc;
    uint8_t entitlementKey[0x10];
};

typedef union _PfsKeyBlob
{
    struct _In
    {
        uint8_t eekpfs[EEKPFS_SIZE];
        struct ekc_t eekc;
        uint32_t pubkeyVer; /* 0x1/0x80000001/0xC0000001 */
        uint32_t keyVer;    /* 1 (if (rif_ver_major & 0x1) != 0, then pfs_key_ver=1, otherwise pfs_key_ver=0) */
        uint64_t headerGva;
        uint32_t headerSize;
        uint32_t type;
        uint32_t finalized;
        uint32_t isDisc;
    } In;
    struct _Out
    {
        uint8_t escrowedKeys[0x40];
    } Out;

} PfsKeyBlob;

typedef union _KeymgrPayload
{
    struct
    {
        uint32_t cmd;
        uint32_t status;
        uint64_t data;
    };
    uint8_t buf[0x80];
} KeymgrPayload;

struct rsa_key_t
{
    uint8_t _pad00[0x20];
    uint8_t* p;
    uint8_t* q;
    uint8_t* dmp1;
    uint8_t* dmq1;
    uint8_t* iqmp;
};

struct act_dat_t
{
    uint32_t magic;
    uint16_t versionMajor;
    uint16_t versionMinor;
    uint64_t accountId;
    uint64_t startTime;
    uint64_t endTime;
    uint64_t flags;
    uint32_t unk3;
    uint32_t unk4;
    uint8_t _pad30[0x30];
    uint8_t openPsidHash[0x20];
    uint8_t staticPerConsoleData1[0x20];
    uint8_t digest[0x10];
    uint8_t keyTable[0x20];
    uint8_t staticPerConsoleData2[0x10];
    uint8_t staticPerConsoleData3[0x20];
    uint8_t signature[0x100];
};

struct rif_t
{
    uint32_t magic;
    uint16_t versionMajor;
    uint16_t versionMinor;
    uint64_t accountId;
    uint64_t startTime;
    uint64_t endTime;
    char contentId[0x30];
    uint16_t format;
    uint16_t drmType;
    uint16_t contentType;
    uint16_t skuFlag;
    uint64_t contentFlags;
    uint32_t iroTag;
    uint32_t ekcVersion;
    uint8_t _pad6A[2];
    uint16_t unk3;
    uint16_t unk4;
    uint8_t _pad6E[0x1F2];
    uint8_t digest[0x10];
    uint8_t data[RIF_DATA_SIZE];
    uint8_t signature[0x100];
};

typedef struct _RsaBuffer
{
    uint8_t* ptr;
    size_t size;
} RsaBuffer;

typedef struct _PfsHeader
{
    uint8_t _pad00[0x370];
    uint8_t cryptSeed[0x10];
    uint8_t _pad380[0x220];
} PfsHeader;

typedef union _KeymgrResponse
{
    struct
    {
        uint32_t type;
        uint8_t key[RIF_MAX_KEY_SIZE];
        uint8_t data[RIF_DIGEST_SIZE + RIF_DATA_SIZE];
    } DecryptRif;
    struct
    {
        uint8_t raw[SIZEOF_RIF];
    } DecryptEntireRif;
} KeymgrResponse;

typedef union _KeymgrRequest
{
    struct
    {
        uint32_t type;
        uint8_t key[RIF_MAX_KEY_SIZE];
        uint8_t data[RIF_DIGEST_SIZE + RIF_DATA_SIZE];
    } DecryptRif;

    struct
    {
        struct rif_t rif;
        uint8_t keyTable[RIF_KEY_TABLE_SIZE];
        uint64_t timestamp;
        int status;
    } DecryptEntireRif;
} KeymgrRequest;

#endif /* FAKE_H */