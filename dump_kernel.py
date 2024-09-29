import socket
import struct
import time

# Console info
CONSOLE_IP   = "10.0.0.217"
CONSOLE_PORT = 9003

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((CONSOLE_IP, CONSOLE_PORT))

    dump_data = bytearray()
    first_packet_recv = False
    first_packet_time = time.monotonic()
    s.settimeout(60)
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

    dump_file = open("./kernel_dump.bin", "wb")
    dump_file.write(dump_data)
    dump_file.close()
    s.close()
