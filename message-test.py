import socket
import struct

data = "0200D0000000000000000000000000000000161234567890123456000000005699"

final_data = b'\x42\x00' + data.encode('utf-8')
ip_address = '172.17.0.2'
port = 8080

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


try:
    sock.connect((ip_address, port))
    sock.sendall(final_data)
    print(len(final_data))
finally:
    sock.close()