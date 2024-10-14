#ifndef SBL_H
#define SBL_H
#include "fake.h"

// CCP
#define CCP_OP(cmd) (cmd >> 24)
#define CCP_MAX_PAYLOAD_SIZE        0x88
#define CCP_OP_AES                  0
#define CCP_OP_XTS                  2
#define CCP_OP_HMAC                 9
#define CCP_USE_KEY_FROM_SLOT       (1 << 18)
#define CCP_GENERATE_KEY_AT_SLOT    (1 << 19)
#define CCP_USE_KEY_HANDLE          (1 << 20)

#define SIZEOF_SBL_KEY_DESC         0x7C // sceSblKeymgrSetKey

struct sbl_msg_header_t;
union sbl_key_desc_t;
struct sbl_key_rbtree_entry_t;
struct sbl_msg_header_t;
struct sbl_msg_t;
union sbl_msg_service_t;
union ccp_op;

union ccp_op
{
    struct
    {
        uint32_t cmd;
        uint32_t status;
    } common;
    struct 
    {
        uint32_t cmd;
        uint32_t status;
        uint64_t data_size;
        uint64_t in_data;
        uint64_t out_data;
        union 
        {
            uint32_t key_index;
            uint8_t key[0x20];
        };
        uint8_t iv[0x10];
    } aes;
    uint8_t buf[CCP_MAX_PAYLOAD_SIZE];
};

typedef union sbl_key_desc_t
{
    struct pfs_t
    {
        uint16_t obfuscated_key_id;
        uint16_t key_size;
        uint8_t escrowed_key[0x20];
    } pfs;
    struct portability_t
    {
        uint16_t command;
        uint16_t pad;
        uint16_t key_id;
    } portability;
    uint8_t raw[SIZEOF_SBL_KEY_DESC];
} sbl_key_desc_t, SblKeyDesc;

typedef struct sbl_key_rbtree_entry_t
{
    uint32_t handle;
    uint32_t occupied;
    SblKeyDesc desc;
    uint8_t pad[0x4];
    //uint32_t locked; // this seems wrong, it says 0x80, but that's in the SblKeyDesc??
    struct sbl_key_rbtree_entry_t* left;
    struct sbl_key_rbtree_entry_t* right;
    struct sbl_key_rbtree_entry_t* parent;
    uint32_t set;
} sbl_key_rbtree_entry_t, SblKeyRbtreeEntry;

typedef struct sbl_msg_header_t
{
    uint32_t cmd;
    uint32_t status;
    uint64_t message_id;
    uint64_t extended_msgs;
} sbl_msg_header_t, _SblMsgHeader, SblMsgHeader;

typedef union sbl_msg_service_t
{
    struct
    {
        union ccp_op op;
    } ccp;
    
} sbl_msg_service_t, SblMsgService;

typedef struct sbl_msg_t
{
    struct sbl_msg_header_t hdr;
    union 
    {
        SblMsgService service;
        uint8_t raw[0x1000];
    };
    
} sbl_msg_t, SblMsg;

#endif /* SBL_H*/