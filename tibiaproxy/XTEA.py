import struct
import ctypes
import numpy

from NetworkMessage import NetworkMessage


u = numpy.uint32


class XTEA:

    @classmethod
    def encrypt(cls, msg, k):
        buf = msg.getRest()
        ret = ""
        for offset in range(len(buf)/8):
            v0 = u(struct.unpack("<I", buf[offset*8:offset*8+4]))
            v1 = u(struct.unpack("<I", buf[offset*8+4:offset*8+8]))
            delta = u(0x61C88647)
            sum = u(0)

            for i in range(32):
                v0 += ((v1 << u(4) ^ v1 >> u(5)) + v1) ^ \
                      (sum + u(k[sum & u(3)]))
                sum -= delta
                v1 += ((v0 << u(4) ^ v0 >> u(5)) + v0) ^ \
                      (sum + u(k[sum >> u(11) & u(3)]))

            ret += struct.pack("<I", v0) + struct.pack("<I", v1)
        return NetworkMessage(ret, True)

    @classmethod
    def decrypt(cls, msg, k):
        buf = msg.getRest()
        ret = ""
        for offset in range(len(buf)/8):
            v0 = u(struct.unpack("<I", buf[offset*8:offset*8+4]))
            v1 = u(struct.unpack("<I", buf[offset*8+4:offset*8+8]))
            delta = u(0x61C88647)
            sum = u(0xC6EF3720)

            for i in range(32):
                v1 -= ((v0 << u(4) ^ v0 >> u(5)) + v0) ^ \
                      (sum + u(k[sum >> u(11) & u(3)]))
                sum += delta
                v0 -= ((v1 << u(4) ^ v1 >> u(5)) + v1) ^ \
                      (sum + u(k[sum & u(3)]))

            ret += struct.pack("<I", v0) + struct.pack("<I", v1)
        return NetworkMessage(ret)
