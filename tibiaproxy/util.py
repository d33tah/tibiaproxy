import sys
import socket
import struct


def log(_str):
    sys.stderr.write(_str + "\n")
    sys.stderr.flush()


def ip_to_u32(ip):
    return struct.unpack("<I", socket.inet_aton(ip))[0]
