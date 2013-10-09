"""
This file is part of tibiaproxy.

tibiaproxy is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Joggertester is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Foobar; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
"""

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
