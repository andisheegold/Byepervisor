import socket
import struct
import time

# Console info
CONSOLE_IP   = "10.0.0.217"
CONSOLE_PORT = 9003

def recv_qword(s):
    data = s.recv(8)
    if not data:
        print("[!] Failed to receive qword")
        return 0
    return struct.unpack("<Q", data)[0]

def dump_kernel():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((CONSOLE_IP, CONSOLE_PORT))
        s.settimeout(60)

        # Receive firmware version
        fw_ver = recv_qword(s)
        if fw_ver == 0:
            print("[!] Failed to read firmware version")
            return

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

        print("[+] Firmware version: {}".format(fw_str))

        # Receive kernel base
        ktext_base = recv_qword(s)
        if ktext_base == 0:
            print("[!] Failed to read kernel .text base")
            return

        print("[+] Kernel .text: 0x{:x}".format(ktext_base))

        # Create dump path
        dump_path = "./dump/{}_kernel_{:x}.bin".format(fw_str, ktext_base)

        # Receive kernel data
        dump_data = bytearray()
        first_packet_recv = False
        first_packet_time = time.monotonic()

        while True:
            try:
                data = s.recv(0x1000)
                if not data:
                    break
                if not first_packet_recv:
                    first_packet_recv = True
                    first_packet_time = time.monotonic()

                dump_data.extend(data)
                data_recv = len(dump_data)

                kbps = 0
                if first_packet_time != time.monotonic():
                    kbps = round(data_recv / (time.monotonic() - first_packet_time) / 1024)

                print("Received {} bytes ({} kb/s)...".format(data_recv, kbps))

                # If data received has exceeded 200MB, exit for safety
                if len(dump_data) > 0xC800000:
                    break
            except socket.timeout:
                print("Timeout reached for receiving data (1 min)")
                break

        dump_file = open(dump_path, "wb")
        dump_file.write(dump_data)
        dump_file.close()
        s.close()

dump_kernel()