#pragma once
#include "fake.h"

#define ET_SCE_EXEC      0xFE00
#define ET_SCE_EXEC_ASLR 0xFE10
#define ET_SCE_DYNAMIC   0xFE18

int32_t IsFakeSelf(SelfContext* p_Context);
int32_t OnSceSblAuthMgrIsLoadable2(SelfContext* p_Context, SelfAuthInfo* p_OldAuthInfo, int32_t p_PathId, SelfAuthInfo* p_NewAuthInfo);
int32_t BuildFakeSelfAuthInfo(SelfContext* p_Context, SelfAuthInfo* p_ParentAuthInfo, SelfAuthInfo* p_AuthInfo);
int32_t SceSblAuthMgrGetElfHeader(SelfContext* p_Context, Elf64_Ehdr** p_OutElfHeader);
int32_t SceSblAuthMgrGetSelfAuthInfoFake(SelfContext* p_Context, SelfAuthInfo* p_Info);
