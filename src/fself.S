.intel_syntax noprefix
.text

.org 0

.org 0x10
_padding:
	nop
	nop
	nop
	nop

# Extended initialization parameter support
_g_osKernelTextBase: .quad 0
_g_osKernelTextSize: .quad 0
_g_osKernelDataBase: .quad 0
_g_osKernelDataSize: .quad 0
_g_osKernelPrison0: .quad 0
_g_osKernelRootvnode: .quad 0

_mira_elf_start:
.incbin MIRA_ELF_PATH
_mira_elf_end: