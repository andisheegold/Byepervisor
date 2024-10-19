#include "fpkg.h"
#include "hook.h"
#include "kdlsym.h"
#include "util.h"

extern "C" {
    #include <sys/types.h>
    #include <sys/param.h>
}

constexpr uint8_t rif_debug_key[] = {
    0x96, 0xC2, 0x26, 0x8D, 0x69, 0x26, 0x1C, 0x8B, 0x1E, 0x3B, 0x6B, 0xFF, 0x2F, 0xE0, 0x4E, 0x12
};

int npdrm_cmd_5_sceSblServiceMailbox(uint64_t handle, const NpDrmCmd5* input, NpDrmCmd5* output) {
    auto printf                 = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    auto sceSblServiceMailbox   = (int (*)(uint64_t handle, void *in, void *out)) kdlsym(KERNEL_SYM_SCESBLSERVICEMAILBOX);

    printf("npdrm_cmd_5_sceSblServiceMailbox pre call\n");
    //hexdump(input, 0x80, nullptr, 0);
    if(input->rif_pa) {
        //auto va = get_dmap_addr(input->rif_pa);
        //printf("rif_dump_pre\n");
        //hexdump(va, 0x400, nullptr, 0);
    }

    int res = sceSblServiceMailbox(handle, (void *) input, output);
    if(output->res == 0x800F0A01) {
        printf("fixup npdrm cmd 5\n");
        auto layout = reinterpret_cast<RifCmd5MemoryLayout*>(get_dmap_addr(input->rif_pa));
        if(layout->rif.type == 2) {

            layout->output.version = __builtin_bswap16(layout->rif.version);
            layout->output.unk04 = __builtin_bswap16(layout->rif.unk06);
            layout->output.psnid = __builtin_bswap64(layout->rif.psnid);
            layout->output.startTimestamp = __builtin_bswap64(layout->rif.startTimestamp);
            layout->output.endTimestamp = __builtin_bswap64(layout->rif.endTimestamp);
            layout->output.extraFlags = __builtin_bswap64(layout->rif.extraFlags);
            layout->output.type = __builtin_bswap16(layout->rif.type);
            layout->output.contentType = __builtin_bswap16(layout->rif.contentType);
            layout->output.skuFlag = __builtin_bswap16(layout->rif.skuFlag);
            layout->output.unk34 = __builtin_bswap32(layout->rif.unk60);
            layout->output.unk38 = __builtin_bswap32(layout->rif.unk64);
            layout->output.unk3C = 0;
            layout->output.unk40 = 0;
            layout->output.unk44 = 0;
            memcpy(layout->output.contentId, layout->rif.contentId, 0x30);
            memcpy(layout->output.rifIv, layout->rif.rifIv, 0x10);
            layout->output.unk88 = __builtin_bswap32(layout->rif.unk70);
            layout->output.unk8C = __builtin_bswap32(layout->rif.unk74);
            layout->output.unk90 = __builtin_bswap32(layout->rif.unk78);
            layout->output.unk94 = __builtin_bswap32(layout->rif.unk7C);
            memcpy(layout->output.unk98, layout->rif.unk80, 0x10);
            if (layout->output.skuFlag == 2) {
                layout->output.skuFlag = 1;
            }

            output->res = 0;
            res = 0;
        }
    }

    //printf("npdrm_cmd_5_sceSblServiceMailbox post call (%i)\n", res);
    //hexdump(output, 0x80, nullptr, 0);

    if(output->rif_pa) {
        //auto va = get_dmap_addr(output->rif_pa);
        //printf("rif_dump_post\n");
        //hexdump(va, 0x4A8, nullptr, 0);
    }

    return res;
}

int npdrm_cmd_6_sceSblServiceMailbox(uint64_t handle, const NpDrmCmd6* input, NpDrmCmd6* output) {
    auto printf                 = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);
    auto sceSblServiceMailbox   = (int (*)(uint64_t handle, void *in, void *out)) kdlsym(KERNEL_SYM_SCESBLSERVICEMAILBOX);
    auto bnet_crypto_aes_cbc_cfb128_decrypt = (void (*)(void *, void *, size_t, void *, size_t, void *)) kdlsym(KERNEL_SYM_BNET_CRYPTO_AES_CBC_CFB128_DECRYPT);

    printf("npdrm_cmd_6_sceSblServiceMailbox pre call\n");
    //hexdump(input, 0x80, nullptr, 0);
    if(input->rif_pa) {
        //auto va = get_dmap_addr(input->rif_pa);
        //printf("rif_dump_pre\n");
        //hexdump(va, 0x400, nullptr, 0);
    }

    int res = sceSblServiceMailbox(handle, (void *) input, output);
    if(output->res == 0x800F0A01) {
        printf("fixup npdrm cmd\n");
        auto va = reinterpret_cast<Rif*>(get_dmap_addr(input->rif_pa));
        if(va->type == 0x2) {
            bnet_crypto_aes_cbc_cfb128_decrypt(va->rifSecret, va->rifSecret, sizeof(va->rifSecret), (void *) rif_debug_key, 128, va->rifIv);
            memcpy(output->unk10, &va->rifSecret[0x70], 0x10);
            memcpy(output->unk20, &va->rifSecret[0x80], 0x10);
            output->res = 0;
        }

    }

    //printf("npdrm_cmd_6_sceSblServiceMailbox post call (%i)\n", res);
    //hexdump(output, 0x80, nullptr, 0);
    if(output->rif_pa) {
        //auto va = get_dmap_addr(output->rif_pa);
        //printf("rif_dump_post\n");
        //hexdump(va, 0x4A8, nullptr, 0);
    }

    return res;
}

int verifySuperBlock_sceSblServiceMailbox(uint64_t handle, const PfsmgrCmd11* input, const PfsmgrCmd11 *output)
{
    auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);

    printf("sceSblPfsSetKeys verify superblock\n");
}

void apply_fpkg_hooks()
{
    auto printf = (void (*)(const char *fmt, ...)) kdlsym(KERNEL_SYM_PRINTF);

    printf("[HEN] [FPKG] npdrm_ioctl(cmd=5) -> sceSblServiceMailbox()\n");
    install_hook(HOOK_FPKG_NPDRM_IOCTL_CMD_5_CALL_SCE_SBL_SERVICE_MAILBOX, (void *) &npdrm_cmd_5_sceSblServiceMailbox);

    printf("[HEN] [FPKG] npdrm_ioctl(cmd=6) -> sceSblServiceMailbox()\n");
    install_hook(HOOK_FPKG_NPDRM_IOCTL_CMD_6_CALL_SCE_SBL_SERVICE_MAILBOX, (void *) &npdrm_cmd_6_sceSblServiceMailbox);

    // TODO: set keys
}
