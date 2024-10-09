import os
import socket
import struct
import time

# Console info
CONSOLE_IP   = "10.0.0.217"
CONSOLE_PORT = 9004

ctrl_header_fmt = '<IIQ'
ctrl_header_len = struct.calcsize(ctrl_header_fmt)

blacklist = [
    "first_img_writer.elf",
    "safemode.elf",
    "SceSysAvControl.elf"
]

class rpc_packet:
    socket      = None
    cmd         = 0
    size        = 0
    status      = 0
    data        = b''

    def __init__(self, s):
        self.socket = s

    def set_cmd(self, cmd):
        self.cmd    = cmd

    def set_data(self, data):
        self.data = data
        self.size = len(data)

    def send(self):
        packet_header = struct.pack(ctrl_header_fmt, self.cmd, self.size, 0)
        final_packet  = packet_header + self.data
        self.socket.sendall(final_packet)

    def recv(self):
        # Receive control header first
        recv_data = self.socket.recv(ctrl_header_len)
        if not recv_data:
            pass

        cmd, size, status = struct.unpack(ctrl_header_fmt, recv_data)

        # Receive data if needed
        if size > 0:
            received = 0
            self.data = bytes()
            while received < size:
                self.data += self.socket.recv(size - received)
                received = len(self.data)

        # Update object
        self.cmd    = cmd
        self.status = status

    def transact(self):
        try:
            self.send()
            self.recv()
        except Exception as err:
            print(f"Exception {err=}, {type(err)=}")
            raise
        return self.status

def build_packet(s, cmd, data):
    packet = rpc_packet(s)
    packet.set_cmd(cmd)
    packet.set_data(data)
    return packet

def ping(s):
    ping_packet = build_packet(s, 1, b'')
    return ping_packet.transact()

def die(s):
    die_packet = build_packet(s, 2, b'')
    return die_packet.transact()

def get_fw(s):
    get_fw_packet = build_packet(s, 3, b'')
    return get_fw_packet.transact()

def get_dir_selfs(s, path):
    get_dir_selfs_packet = build_packet(s, 4, path)
    get_dir_selfs_packet.transact()
    return get_dir_selfs_packet.data

def decrypt_self(s, path):
    decrypt_self_packet = build_packet(s, 5, path)
    decrypt_self_packet.transact()
    if decrypt_self_packet.status == 0:
        return decrypt_self_packet.data
    return b''

def fw_int_to_str(fw_ver):
    fw_str = ""
    if fw_ver == 0x1000000:
        fw_str = "1.00"
    elif fw_ver == 0x1020000:
        fw_str = "1.02"
    elif fw_ver == 0x1050000:
        fw_str = "1.05"
    elif fw_ver == 0x1100000:
        fw_str = "1.10"
    elif fw_ver == 0x1110000:
        fw_str = "1.11"
    elif fw_ver == 0x1120000:
        fw_str = "1.12"
    elif fw_ver == 0x1130000:
        fw_str = "1.13"
    elif fw_ver == 0x1140000:
        fw_str = "1.14"
    elif fw_ver == 0x2000000:
        fw_str = "2.00"
    elif fw_ver == 0x2200000:
        fw_str = "2.20"
    elif fw_ver == 0x2250000:
        fw_str = "2.25"
    elif fw_ver == 0x2260000:
        fw_str = "2.26"
    elif fw_ver == 0x2300000:
        fw_str = "2.30"
    elif fw_ver == 0x2500000:
        fw_str = "2.50"
    return fw_str

def dump_selfs_in_dir(s, pc_dir, ps5_dir):
    failed_dumps = 0

    # Get listing
    selfs_list = get_dir_selfs(s, bytes(ps5_dir, 'ascii') + b'\x00')

    # Iterate
    files = selfs_list.split(b"\x00")
    for file in files:
        if file == b'':
            break

        file_name = str(file, 'ascii')

        if file_name in blacklist:
            continue

        # PS5 file path
        ps5_file_path = "{}/{}".format(ps5_dir, file_name)

        # Decrypt file
        file_contents = decrypt_self(s, bytes(ps5_file_path, 'ascii') + b'\x00')
        if file_contents == b'':
            print("[!] Failed to dump {}".format(file_name))
            failed_dumps += 1

        # Create output file
        file_name = file_name.replace(".sprx", ".elf")

        dump_dir  = "{}/{}".format(pc_dir, ps5_dir)
        dump_path = "{}/{}".format(dump_dir, file_name)
        os.makedirs(dump_dir, 511, True)

        #print("[+] Dumping {}...".format(dump_path))

        dump_file = open(dump_path, 'wb')
        dump_file.write(file_contents)
        dump_file.close()

    print("[*] Finished dumping directory '{}', failed decryptions: {}".format(ps5_dir, failed_dumps))

def dump_selfs():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((CONSOLE_IP, CONSOLE_PORT))
        s.settimeout(60)

        # die(s)
        # return

        # Get firmware version
        fw = fw_int_to_str(get_fw(s))
        if fw == "":
            print("[!] Failed to read firmware version")
            return

        print("[+] Firmware version: {}".format(fw))

        # PC dump path
        dump_path = "./dump/{}".format(fw)

        # Dump known paths
        dump_selfs_in_dir(s, dump_path, "/")
        dump_selfs_in_dir(s, dump_path, "/system/common/lib")
        dump_selfs_in_dir(s, dump_path, "/system_ex/common_ex/lib")
        dump_selfs_in_dir(s, dump_path, "/system/priv/lib")
        dump_selfs_in_dir(s, dump_path, "/system/sys")
        dump_selfs_in_dir(s, dump_path, "/system/vsh")

        print("[+] Done.")
        s.close()

dump_selfs()