import struct


class NetworkMessage:

    def __init__(self, buf):
        self.buf = buf
        self.pos = 0

    def getByte(self):
        ret = self.buf[self.pos]
        self.pos += 1
        return ord(ret)

    def getU32(self):
        u32 = struct.unpack("<I", self.buf[self.pos:self.pos+4])[0]
        self.pos += 4
        return u32

    def getU16(self):
        u16 = struct.unpack("<H", self.buf[self.pos:self.pos+2])[0]
        self.pos += 2
        return u16

    def getString(self):
        size = self.getU16()
        ret = self.buf[self.pos:self.pos+size]
        self.pos += size
        return ret
