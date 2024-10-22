'''
File:      bn_view_ps5_kernel.py
Author(s): @SpecterDev
Purpose:   Implements the ps5 kernel binary view for binary ninja
'''

import binaryninja as bn
import struct

fw_segment_map = {
    "01.05": {
        "text_size":        0x0B40000,
        "hv_data_size":     0x1010000,
        "ro_data_size":     0x08E88A0,
        "prospero_sysvec":  0x275A5C8,
    },
    "02.50": {
        "text_size":        0x0B70000,
        "hv_data_size":     0x1010000,
        "ro_data_size":     0x08E88A0,
        "prospero_sysvec":  0x27C0458
    }
}

# Extracts a substring between two deliminators in a string
def getBetween(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ''
    return ''

class UpdateKernel(bn.BackgroundTaskThread):
    def __init__(self, bv):
        global task

        bn.BackgroundTaskThread.__init__(self, "Updating kernel with symbols...", False)

        # Binaryview is needed for common binja functions
        self.bv = bv

    # Creates syscall stub and function
    def define_syscall_funcs(self, sysent_addr, sysnames_addr, num):
        fptr_addr       = sysent_addr + (num * 0x30) + 0x8
        handler_addr    = struct.unpack("<Q", self.bv.read(fptr_addr, 0x8))[0]

        # Get syscall name
        name_ptr_addr   = sysnames_addr + (num * 0x8)
        name_addr       = struct.unpack("<Q", self.bv.read(name_ptr_addr, 0x8))[0]
        syscall_name    = self.bv.get_string_at(name_addr)

        # Make wrapper function in-case analysis pass missed it
        stub_func = self.bv.get_function_at(handler_addr)
        if stub_func == None:
            self.bv.define_auto_symbol_and_var_or_function(
                bn.Symbol(bn.SymbolType.FunctionSymbol, handler_addr, f'j_sys_{syscall_name}'),
                bn.Type.function(bn.Type.int(8), [
                                 bn.Type.pointer(self.bv.arch, bn.Type.void()),
                                 bn.Type.pointer(self.bv.arch, bn.Type.void())
                ]),
                self.bv.arch.standalone_platform
            )
            self.bv.log("making wrapper function for syscall 0x{:x} ({}) @ 0x{:x}".format(num, syscall_name, handler_addr))
        else:
            stub_func.name = f'j_sys_{syscall_name}'
            self.bv.log("renaming wrapper function for syscall 0x{:x} ({}) @ 0x{:x}".format(num, syscall_name, handler_addr))

        # We need to update analysis when we add functions
        self.bv.update_analysis_and_wait()

        # Parse stub function to get real function and name it
        stub_func = self.bv.get_function_at(handler_addr)
        for inst in stub_func.instructions:
            if inst[0][0].text == "jmp":
                jmp_dest = int(inst[0][2].text, 16)

                handler_func = self.bv.get_function_at(jmp_dest)
                if handler_func == None:
                    self.bv.define_auto_symbol_and_var_or_function(
                        bn.Symbol(bn.SymbolType.FunctionSymbol, jmp_dest, f'sys_{syscall_name}'),
                        bn.Type.function(bn.Type.int(8), [
                                         bn.Type.pointer(self.bv.arch, bn.Type.void()),
                                         bn.Type.pointer(self.bv.arch, bn.Type.void())
                        ]),
                        self.bv.arch.standalone_platform
                    )
                    self.bv.log("making function for syscall 0x{:x} ({}) @ 0x{:x}".format(num, syscall_name, jmp_dest))
                else:
                    handler_func.name = f'sys_{syscall_name}'
                    self.bv.log("renaming function for syscall 0x{:x} ({}) @ 0x{:x}".format(num, syscall_name, jmp_dest))
                break

        # We need to update analysis when we add functions
        self.bv.update_analysis_and_wait()

    def run(self):
        # Define sysentvec
        sysentvec = self.bv.build_sysentvec_type()
        self.bv.define_user_type('sysentvec', bn.Type.structure_type(sysentvec))

        sysentvec_addr = self.bv.load_address + fw_segment_map[self.bv.fw]["prospero_sysvec"]
        self.bv.define_user_data_var(sysentvec_addr, bn.Type.structure_type(sysentvec), 'prospero_sysvec')

        # Define sysents
        sysent = self.bv.build_sysent_type()
        self.bv.define_user_type('sysent', bn.Type.structure_type(sysent))

        # Get num syscalls and syscall ent
        sysent_size_addr    = sysentvec_addr + 0x00
        sysent_ptr_addr     = sysentvec_addr + 0x08
        sysent_names_addr   = sysentvec_addr + 0xB8
        sysent_size         = struct.unpack("<I", self.bv.read(sysent_size_addr, 4))[0]
        sysent_ptr          = struct.unpack("<Q", self.bv.read(sysent_ptr_addr, 8))[0]
        sysent_names        = struct.unpack("<Q", self.bv.read(sysent_names_addr, 8))[0]

        sysent_table = bn.Type.array(sysent, sysent_size)
        self.bv.define_user_data_var(sysent_ptr, sysent_table, 'prospero_sysent')

        # Define syscalls
        for i in range(0, sysent_size):
            self.define_syscall_funcs(sysent_ptr, sysent_names, i)

class PS5KernelView(bn.BinaryView):
    name = "PS5 Kernel"
    long_name = "PS5 Kernel Dump"

    def log(self, msg, error=False):
        msg = f"[PS5 Kernel Dump Loader] {msg}"
        if not error:
            bn.log_info(msg)
        else:
            bn.log_error(msg)

    def __init__(self, data):
        bn.BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data

    # Builds sysvec type
    def build_sysentvec_type(self):
        sysentvec = bn.types.StructureBuilder.create()
        sysentvec.add_member_at_offset('sv_size', bn.Type.int(4), 0x00)
        sysentvec.add_member_at_offset('sv_table', bn.Type.pointer(self.arch, self.parse_type_string("void")[0]), 0x08)
        sysentvec.add_member_at_offset('sv_mask', bn.Type.int(4), 0x10)
        sysentvec.add_member_at_offset('sv_errsize', bn.Type.int(4), 0x14)
        sysentvec.add_member_at_offset('sv_errtbl', bn.Type.pointer(self.arch, self.parse_type_string("void")[0]), 0x18)
        sysentvec.add_member_at_offset('sv_transtrap', bn.Type.pointer(self.arch, self.parse_type_string("void")[0]), 0x20)
        sysentvec.add_member_at_offset('sv_fixup', bn.Type.pointer(self.arch, bn.Type.function()), 0x28)
        sysentvec.add_member_at_offset('sv_sendsig', bn.Type.pointer(self.arch, bn.Type.function()), 0x30)
        sysentvec.add_member_at_offset('sv_sigcode', bn.Type.pointer(self.arch, bn.Type.function()), 0x38)
        sysentvec.add_member_at_offset('sv_szsigcode', bn.Type.int(8), 0x40)
        sysentvec.add_member_at_offset('sv_name', bn.Type.pointer(self.arch, self.parse_type_string("char")[0]), 0x48)
        sysentvec.add_member_at_offset('sv_coredump', bn.Type.pointer(self.arch, self.parse_type_string("void")[0]), 0x50)
        sysentvec.add_member_at_offset('sv_imgact_try', bn.Type.pointer(self.arch, bn.Type.function()), 0x58)
        sysentvec.add_member_at_offset('sv_minsigstksz', bn.Type.int(4), 0x60)
        sysentvec.add_member_at_offset('sv_pagesize', bn.Type.int(4), 0x64)
        sysentvec.add_member_at_offset('sv_minuser', bn.Type.int(8), 0x68)
        sysentvec.add_member_at_offset('sv_maxuser', bn.Type.int(8), 0x70)
        sysentvec.add_member_at_offset('sv_stackprot', bn.Type.int(4), 0x78)
        sysentvec.add_member_at_offset('sv_copyout_strings', bn.Type.pointer(self.arch, bn.Type.function()), 0x80)
        sysentvec.add_member_at_offset('sv_setregs', bn.Type.pointer(self.arch, bn.Type.function()), 0x88)
        sysentvec.add_member_at_offset('sv_fixlimit', bn.Type.pointer(self.arch, bn.Type.function()), 0x90)
        sysentvec.add_member_at_offset('sv_maxssiz', bn.Type.pointer(self.arch, self.parse_type_string("uint64_t")[0]), 0x98)
        sysentvec.add_member_at_offset('sv_flags', bn.Type.int(4), 0xA0)
        sysentvec.add_member_at_offset('sv_set_syscall_retval', bn.Type.pointer(self.arch, bn.Type.function()), 0xA8)
        sysentvec.add_member_at_offset('sv_fetch_syscall_args', bn.Type.pointer(self.arch, bn.Type.function()), 0xB0)
        sysentvec.add_member_at_offset('sv_names', bn.Type.pointer(self.arch, self.parse_type_string("char **")[0]), 0xB8)
        sysentvec.add_member_at_offset('sv_timekeep_base', bn.Type.int(8), 0xC0)
        sysentvec.add_member_at_offset('sv_shared_page_len', bn.Type.int(8), 0xC8)
        sysentvec.add_member_at_offset('sv_sigcode_base', bn.Type.int(8), 0xD0)
        sysentvec.add_member_at_offset('sv_shared_page_obj', bn.Type.pointer(self.arch, self.parse_type_string("void")[0]), 0xD8)
        sysentvec.add_member_at_offset('sv_schedtail', bn.Type.pointer(self.arch, bn.Type.function()), 0xE0)
        sysentvec.add_member_at_offset('sv_thread_detach', bn.Type.pointer(self.arch, bn.Type.function()), 0xE8)
        sysentvec.add_member_at_offset('sv_trap', bn.Type.pointer(self.arch, bn.Type.function()), 0xF0)

        return sysentvec

    # Builds sysent type
    def build_sysent_type(self):
        sysent = bn.types.StructureBuilder.create()
        sysent.add_member_at_offset('sy_narg', bn.Type.int(4), 0x00)
        sysent.add_member_at_offset(
            'sy_call',
            bn.Type.pointer(self.arch, bn.Type.function()),
            0x08
        )
        sysent.add_member_at_offset('sy_auevent', bn.Type.int(2), 0x10)
        sysent.add_member_at_offset('sy_systrace_args_func', bn.Type.int(8), 0x18)
        sysent.add_member_at_offset('sy_entry', bn.Type.int(4), 0x20)
        sysent.add_member_at_offset('sy_return', bn.Type.int(4), 0x24)
        sysent.add_member_at_offset('sy_flags', bn.Type.int(4), 0x28)
        sysent.add_member_at_offset('sy_thrcnt', bn.Type.int(4), 0x2C)

        return sysent

    @classmethod
    def is_valid_for_data(self, data):
        # Hacky, but test if first 0x10000 bytes contains 0xFFF0 breakpoints
        # this should be pretty unique to PS5 kernel dumps.
        test_data = data[:0x10000]
        if test_data.count(0xCC) == 0xFFF0:
            return True
        self.log("doesn't look like a ps5 kernel, count = 0x{:x}".format(test_data.count(0xCC)))

    def on_complete(self):
        backgroundTask = UpdateKernel(self)
        backgroundTask.start()

    def find_fw_ver(self):
        # This sucks, but because analysis hasn't started (and we need to find the FW ver before
        # analysis), we have a bit of a chicken and egg, so we need to manually find the string
        q = b'releases/'
        fw_str = b''
        for i in range(0x1000000, 0x3000000, 0x8):
            test = self.data[i:i+len(q)]
            if test == q:
                fw_str = self.data[i:i+0x20].decode("utf-8")
        return getBetween(fw_str, "releases/", " ")

    def parse_fw_version(self, fw):
        # Correct format for leading zero
        if fw[0] != 0 and fw[1] == '.':
            fw = "0" + fw

        # Check if firmware exists in mapping
        if fw in fw_segment_map:
            return fw
        return ""

    def find_entrypoint(self):
        # Pattern: mov word ptr ds:472h, 1234h
        opcodes = bytes([0x66, 0xC7, 0x04, 0x25, 0x72, 0x04, 0x00, 0x00, 0x34, 0x12])
        entry = self.find_next_data(self.load_address, opcodes)
        self.log("Found entrypoint? 0x{:x}".format(entry))
        return entry

    def init(self):
        # PS5 kernel will always be AMD64
        self.arch = bn.Architecture["x86_64"]
        self.platform = self.arch.standalone_platform
        self.platform.default_calling_convention = self.arch.calling_conventions['sysv']

        for con in self.platform.calling_conventions:
            self.log("calling convention: {}".format(con))

        # Prompt user for load address if we don't have it
        try:
            self.log("metadata = [{}]".format(self.query_metadata("ps5_fw")))
            self.fw = self.query_metadata("ps5_fw")
            self.load_address = self.query_metadata("ps5_loadaddr")
        except:
            fw_field = bn.TextLineField("PS5 firmware version")
            load_addr_field = bn.AddressField("PS5 kernel base address")
            bn.get_form_input([fw_field, load_addr_field], "Configure kernel info")

            self.fw = self.parse_fw_version(fw_field.result)
            self.load_address = load_addr_field.result

            # Set metadata
            self.store_metadata("ps5_fw", self.fw)
            self.store_metadata("ps5_loadaddr", self.load_address)

        self.log("Detected PS5 Kernel Dump")

        # Find the firmware version
        self.log("Firmware version: '{}'".format(self.fw))

        if self.fw == "":
            bn.show_message_box("Error loading PS5 kernel", "Firmware is not supported.", bn.MessageBoxButtonSet.OKButtonSet, bn.MessageBoxIcon.ErrorIcon)
            return

        # Code segment
        code_segment_offset = 0
        code_segment_size   = fw_segment_map[self.fw]["text_size"]

        self.add_auto_segment(
            self.load_address + code_segment_offset,
            code_segment_size,
            code_segment_offset,
            code_segment_size,
            bn.SegmentFlag.SegmentReadable | bn.SegmentFlag.SegmentExecutable
        )

        self.add_user_section(".text", self.load_address + code_segment_offset, code_segment_size,
            bn.SectionSemantics.ReadOnlyCodeSectionSemantics)

        # HV data segment
        hv_data_segment_offset = code_segment_offset + code_segment_size
        hv_data_segment_size   = fw_segment_map[self.fw]["hv_data_size"]

        self.add_auto_segment(
            self.load_address + hv_data_segment_offset,
            hv_data_segment_size,
            hv_data_segment_offset,
            hv_data_segment_size,
            bn.SegmentFlag.SegmentReadable | bn.SegmentFlag.SegmentWritable
        )

        self.add_user_section(".hv_data", self.load_address + hv_data_segment_offset, hv_data_segment_size,
            bn.SectionSemantics.ReadWriteDataSectionSemantics)

        # Read-only data segment
        ro_data_segment_offset = hv_data_segment_offset + hv_data_segment_size
        ro_data_segment_size = fw_segment_map[self.fw]["ro_data_size"]

        self.add_auto_segment(
            self.load_address + ro_data_segment_offset,
            ro_data_segment_size,
            ro_data_segment_offset,
            ro_data_segment_size,
            bn.SegmentFlag.SegmentReadable
        )

        self.add_user_section(".ro_data", self.load_address + ro_data_segment_offset, ro_data_segment_size,
            bn.SectionSemantics.ReadOnlyDataSectionSemantics)

        # Regular data segment
        data_segment_offset = ro_data_segment_offset + ro_data_segment_size
        data_segment_size   = self.end - data_segment_offset

        self.add_auto_segment(
            self.load_address + data_segment_offset,
            data_segment_size,
            data_segment_offset,
            data_segment_size,
            bn.SegmentFlag.SegmentReadable | bn.SegmentFlag.SegmentWritable
        )

        self.add_user_section(".data", self.load_address + data_segment_offset, data_segment_size,
            bn.SectionSemantics.ReadWriteDataSectionSemantics)

        # Add the entrypoint
        entry_point_addr     = self.find_entrypoint()
        self.add_entry_point(entry_point_addr)

        self.define_auto_symbol_and_var_or_function(
            bn.Symbol(bn.SymbolType.FunctionSymbol, entry_point_addr, 'btext'),
            bn.Type.function(bn.Type.void(), []),
            bn.Architecture["x86_64"].standalone_platform
        )

        self.update_analysis()

        # Register a completion event to create structs
        bn.AnalysisCompletionEvent(self, self.on_complete)
        return True

    def perform_get_address_size(self):
        return 8
