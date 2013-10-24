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
import ctypes
import numpy

from NetworkMessage import NetworkMessage


u = numpy.uint32


class XTEA:
    """Handles XTEA messages encryption/decryption."""

    @classmethod
    def encrypt(cls, msg, k):
        """Encrypts a given message using the given key.

        Args:
            msg (NetworkMessage): the network message pointed to encrypted data
            k (list): XTEA key - a list of four OpenTibia U32 integers

        Returns NetworkMessage
        """
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
        """Decrypts a given message using the given key.

        Args:
            msg (NetworkMessage): the network message pointed to decrypted data
            k (list): XTEA key - a list of four OpenTibia U32 integers

        Returns NetworkMessage
        """
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
