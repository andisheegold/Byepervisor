#include "fself.h"
#include "kdlsym.h"
#include <sys/errno.h>
#include <sys/elf.h>

/**
 * @brief This is just here to prevent errors, too lazy to remove logging
 * 
 */
*/
#define WriteLog(x, y, ...)

/**
 * @brief The exec authentication information
 * 
 */
const uint8_t c_ExecAuthInfo[] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x80, 0x03, 0x00, 0x20,
	0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x00, 0x40,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
	0x00, 0x40, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/**
 * @brief The dynlib authentication information
 * 
 */
const uint8_t c_DynlibAuthInfo[] =
{
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x00, 0x30,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
	0x00, 0x40, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/**
 * @brief The hooked function for OnSceSblAuthMgrIsLoadable2
 * 
 * @param p_Context 
 * @param p_OldAuthInfo 
 * @param p_PathId 
 * @param p_NewAuthInfo 
 * @return int 
 */
int OnSceSblAuthMgrIsLoadable2(SelfContext* p_Context, SelfAuthInfo* p_OldAuthInfo, int32_t p_PathId, SelfAuthInfo* p_NewAuthInfo)
{
    // I freaking hate C
    (int(*)(SelfContext*, SelfAuthInfo*, int32_t, SelfAuthInfo*)) sceSblAuthMgrIsLoadable2 = (int(*)(SelfContext* p_Context, SelfAuthInfo* p_OldAuthInfo, int32_t p_PathId, SelfAuthInfo* p_NewAuthInfo))kdlsym(sceSblAuthMgrIsLoadable2);

    if (p_Context == NULL)
    {
        WriteLog(LL_Error, "invalid context");
        return sceSblAuthMgrIsLoadable2(p_Context, p_OldAuthInfo, p_PathId, p_NewAuthInfo);
    }

    if (p_OldAuthInfo == NULL)
    {
        WriteLog(LL_Error, "invalid old auth info.");
        return sceSblAuthMgrIsLoadable2(p_Context, p_OldAuthInfo, p_PathId, p_NewAuthInfo);
    }

    if (p_NewAuthInfo == NULL)
    {
        WriteLog(LL_Error, "invalid new auth info.");
        return sceSblAuthMgrIsLoadable2(p_Context, p_OldAuthInfo, p_PathId, p_NewAuthInfo);
    }
    
    if (p_Context->format == SelfFormat::Elf || IsFakeSelf(p_Context))
    {
        WriteLog(LL_Debug, "building fake self information");
        return BuildFakeSelfAuthInfo(p_Context, p_OldAuthInfo, p_NewAuthInfo);
    }        
    else
        return sceSblAuthMgrIsLoadable2(p_Context, p_OldAuthInfo, p_PathId, p_NewAuthInfo);

}

/**
 * @brief Checks if the current self format is FSelf or Regular
 * 
 * @param p_Context Self Context
 * @return int32_t True if fself, false otherwise
 */
int32_t IsFakeSelf(SelfContext* p_Context)
{
    (int (*)(SelfContext* ctx, void *exInfo)) _sceSblAuthMgrGetSelfInfo = (int (*)(SelfContext* ctx, void *exInfo))kdlsym(_sceSblAuthMgrGetSelfInfo);
    if (p_Context == NULL)
    {
        WriteLog(LL_Error, "invalid context");
        return false;
    }
    
    SelfExInfo* s_Info = NULL;
    if (p_Context->format == SelfFormat::Self)
    {
        if (_sceSblAuthMgrGetSelfInfo(p_Context, &s_Info))
            return false;
        
        return s_Info->ptype == SelfPtypeFake;
    }

    return false;
}

int32_t BuildFakeSelfAuthInfo(SelfContext* p_Context, SelfAuthInfo* p_ParentAuthInfo, SelfAuthInfo* p_AuthInfo)
{
    (int (*)(SelfContext* ctx, void *exInfo)) _sceSblAuthMgrGetSelfInfo = (int (*)(SelfContext* ctx, void *exInfo))kdlsym(_sceSblAuthMgrGetSelfInfo);

    if (p_Context == NULL || p_ParentAuthInfo == NULL || p_AuthInfo == NULL)
    {
        WriteLog(LL_Error, "invalid context (%p) || parentAuthInfo (%p) || authInfo (%p)", p_Context, p_ParentAuthInfo, p_AuthInfo);
        return -EINVAL;
    }
    
    if (!IsFakeSelf(p_Context))
    {
        WriteLog(LL_Error, "not fake self");
        return -EINVAL;
    }

    SelfExInfo* s_ExInfo = nullptr;
    int32_t s_Result = _sceSblAuthMgrGetSelfInfo(p_Context, &s_ExInfo);
    if (s_Result)
    {
        WriteLog(LL_Error, "could not get self info (%d).", s_Result);
        return s_Result;
    }

    Elf64_Ehdr* s_ElfHeader = nullptr;
    s_Result = SceSblAuthMgrGetElfHeader(p_Context, &s_ElfHeader);
    if (s_Result)
    {
        WriteLog(LL_Error, "could not get elf header (%d).", s_Result);
        return s_Result;
    }

    if (s_ElfHeader == nullptr)
    {
        WriteLog(LL_Error, "elf header invalid");
        return -ESRCH;
    }
    
    SelfAuthInfo s_FakeAuthInfo = { 0 };
    s_Result = SceSblAuthMgrGetSelfAuthInfoFake(p_Context, &s_FakeAuthInfo);
    if (s_Result)
    {
        switch (s_ElfHeader->e_type)
        {
        case ET_EXEC:
        case ET_SCE_EXEC:
        case ET_SCE_EXEC_ASLR:
            memcpy(&s_FakeAuthInfo, c_ExecAuthInfo, sizeof(s_FakeAuthInfo));
            s_Result = 0;
            break;
        case ET_SCE_DYNAMIC:
            memcpy(&s_FakeAuthInfo, c_DynlibAuthInfo, sizeof(s_FakeAuthInfo));
            s_Result = 0;
            break;
        default:
            s_Result = ENOTSUP;
            return s_Result;
        }

        s_FakeAuthInfo.paid = s_ExInfo->paid;
    }

    // p_AuthInfo is checked already
    memcpy(p_AuthInfo, &s_FakeAuthInfo, sizeof(*p_AuthInfo));

    return s_Result;
}