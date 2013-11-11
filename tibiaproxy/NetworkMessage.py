"""
A utility class used to extract structures out of network messages and build
custom ones.
"""

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
import XTEA


def adlerChecksum(buf):
    """Calculates the Adler checksum for the given buffer.

    Args:
        buf (str): the buffer that will have its Adler checksum calculated

    Returns int
    """
    length = len(buf)
    adler = 65521
    a = 1
    b = 0
    pos = 0
    while length > 0:
        tmp = 5552 if length > 5552 else length
        length -= tmp
        for i in reversed(range(tmp)):
            a += ord(buf[pos])
            b += a
            pos += 1
        a %= adler
        b %= adler
    return (b << 16) | a


class NetworkMessage:
    """A utility class used to extract structures out of network messages and
    build custom ones."""

    def __init__(self, buf=None):
        """Create a NetworkMessage instance.

        If no arguments are given, an empty network message used for writing
        is created.

        Args:
            buf (str): the initial buffer.
        """
        self.buf = buf or ""
        self.pos = 0

    def getByte(self):
        """Returns the next unprocessed unsigned 8-bit integer.

        Returns int
        """
        ret = self.buf[self.pos]
        self.pos += 1
        return ord(ret)

    def getU32(self):
        """Returns the next unprocessed unsigned 32-bit integer.

        Returns int
        """
        u32 = struct.unpack("<I", self.buf[self.pos:self.pos+4])[0]
        self.pos += 4
        return u32

    def getU16(self):
        """Returns the next unprocessed unsigned 16-bit integer.

        Returns int
        """
        u16 = struct.unpack("<H", self.buf[self.pos:self.pos+2])[0]
        self.pos += 2
        return u16

    def getString(self):
        """Returns the next unprocessed string.

        Returns str
        """
        size = self.getU16()
        ret = self.buf[self.pos:self.pos+size]
        self.pos += size
        return ret

    def skipBytes(self, _bytes):
        """Skips a number of bytes from the network message.

        Args:
            _bytes (int): the number of the bytes to be skipped.

        Returns None
        """
        ret = self.buf[self.pos:self.pos+_bytes]
        self.pos += _bytes

    def getRest(self):
        """Returns the unprocessed part of the network message.

        Returns str
        """
        return self.buf[self.pos:]

    def getWithHeader(self):
        """Returns the unencrypted buffer for the network message with the
        required padding and size header, ready for XTEA encryption.

        Returns str
        """
        ret = self.buf
        # Add the padding
        size = len(ret)
        for i in range(8 - (size) % 8):
           ret += "%c" % 0x33

        ret_with_size = struct.pack("<H", size) + ret
        return ret_with_size


    def getEncrypted(self, xtea_key):
        """Returns the network message in a form ready to be sent over the
        wire. Adds all the necessary headers, encryption and checksums.

        Args:
            xtea_key (list): XTEA key; a four-element-long array of integers

        Returns str
        """
        ret_encrypted = XTEA.XTEA_encrypt(self.getWithHeader(), xtea_key)
        checksum = adlerChecksum(ret_encrypted)
        ret_encrypted =  struct.pack("<I", checksum) + ret_encrypted
        return struct.pack("<H", len(ret_encrypted)) + ret_encrypted

    def getRaw(self):
        """Returns the raw buffer without any additional headers.

        Returns str
        """
        return self.buf

    def addByte(self, byte):
        """Adds a unsigned 8-bit integer to the end of the network message.

        Args:
            byte (int): the unsigned 8-bit integer to be appended to the
                network message

        Returns None
        """
        self.buf += chr(byte)

    def addU32(self, u32):
        """Adds an unsigned 32-bit integer to the end of the network message.

        Args:
            u32 (int): the unsigned 32-bit integer to be appended to the
                network message

        Returns None
        """
        self.buf += struct.pack("<I", u32)

    def addU16(self, u16):
        """Adds an unsigned 16-bit integer to the end of the network message.

        Args:
            u16 (int): the unsigned 16-bit integer to be appended to the
                network message

        Returns None
        """
        self.buf += struct.pack("<H", u16)

    def prependU16(self, u16):
        """Adds an unsigned 16-bit integer to the beginning of the network
        message.

        Args:
            u16 (int): the unsigned 16-bit integer to be prepended to the
                network message

        Returns None
        """
        self.buf = struct.pack("<H", u16) + self.buf

    def prependU32(self, u32):
        """Adds an unsigned 32-bit integer to the beginning of the network
        message.

        Args:
            u32 (int): the unsigned 32-bit integer to be prepended to the
                network message

        Returns None
        """
        self.buf = struct.pack("<I", u32) + self.buf

    def addString(self, _str):
        """Adds a string to the end of the network message.

        Args:
            _str (str): the string to be appended to the network message

        Returns None
        """
        self.buf += struct.pack("<H", len(_str))
        self.buf += _str
