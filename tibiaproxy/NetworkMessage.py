import struct


class NetworkMessage:

    def __init__(self, buf=None, writable=False):
        self.writable = (buf is None or writable)
        self.buf = buf or ""
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

    def skipBytes(self, _bytes):
        ret = self.buf[self.pos:self.pos+_bytes]
        self.pos += _bytes
        return ret

    def getRest(self):
        return self.buf[self.pos:]

    def getBuffer(self):
        if not self.writable:
            return self.buf
        else:
            return struct.pack("<H", len(self.buf)) + self.buf

    def addByte(self, byte):
        assert(self.writable)
        self.buf += chr(byte)

    def addU32(self, u32):
        assert(self.writable)
        self.buf += struct.pack("<I", u32)

    def addU16(self, u16):
        assert(self.writable)
        self.buf += struct.pack("<H", u16)

    def prependU16(self, u16):
        assert(self.writable)
        self.buf = struct.pack("<H", u16) + self.buf

    def addString(self, _str):
        assert(self.writable)
        self.buf += struct.pack("<H", len(_str))
        self.buf += _str
