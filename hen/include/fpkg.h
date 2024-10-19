#ifndef FPKG_H
#define FPKG_H

#include "fake.h"
#include "sbl.h"

struct sx;
struct fpu_kern_ctx;

static void GenPfsCryptoKey(uint8_t* p_EncryptionKeyPFS, uint8_t p_Seed[PFS_SEED_SIZE], uint32_t p_Index, uint8_t p_Key[PFS_FINAL_KEY_SIZE]);
static void GenPfsEncKey(uint8_t* p_EncryptionKeyPFS, uint8_t p_Seed[PFS_SEED_SIZE], uint8_t p_Key[PFS_FINAL_KEY_SIZE]);
static void GenPfsSignKey(uint8_t* p_EncryptionKeyPFS, uint8_t p_Seed[PFS_SEED_SIZE], uint8_t p_Key[PFS_FINAL_KEY_SIZE]);
static int32_t DecryptNpdrmDebugRif(uint32_t p_Type, uint8_t* p_Data);
static struct sbl_map_list_entry_t* SceSblDriverFindMappedPageListByGpuVa(vm_offset_t p_GpuVa);
static vm_offset_t SceSblDriverGpuVaToCpuVa(vm_offset_t p_GpuVa, size_t* p_NumPageGroups);

static int32_t SceSblPfsSetKeys(uint32_t* p_Ekh, uint32_t* p_Skh, uint8_t* p_EekPfs, struct ekc_t* p_Eekc, uint32_t p_PubKeyVersion, uint32_t p_KeyVersion, PfsHeader* p_Header, size_t p_HeaderSize, uint32_t p_Type, uint32_t p_Finalized, uint32_t p_IsDisc);
static struct sbl_key_rbtree_entry_t* sceSblKeymgrGetKey(unsigned int p_Handle);

static int32_t OnSceSblPfsSetKeys(uint32_t* p_Ekh, uint32_t* p_Skh, uint8_t* p_EekPfs, struct ekc_t* p_Eekc, uint32_t p_PubKeyVersion, uint32_t p_KeyVersion, PfsHeader* p_Header, size_t p_HeaderSize, uint32_t p_Type, uint32_t p_Finalized, uint32_t p_IsDisc);
static int32_t OnNpdrmDecryptIsolatedRif(KeymgrPayload* p_Payload);
static int32_t OnNpdrmDecryptRifNew(KeymgrPayload* p_Payload);
static int32_t OnSceSblDriverSendMsg(struct sbl_msg_t* p_Message, size_t p_Size) __attribute__ ((optnone));
static int32_t OnSceSblKeymgrInvalidateKeySxXlock(struct sx* p_Sx, int p_Opts, const char* p_File, int p_Line);

#endif /* FPKG_H */