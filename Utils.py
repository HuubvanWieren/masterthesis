import struct
import socket

def uint32_to_ip(ipn):
    t = struct.pack('I', ipn)
    return socket.inet_ntoa(t)


def ip_to_uint32(ip):
    t = socket.inet_aton(ip)
    return struct.unpack('I', t)[0]
