"""
XTEA encryption/decryption module.
"""

#This file is part of tibiaproxy.
#
#tibiaproxy is free software; you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation; either version 2 of the License, or
#(at your option) any later version.
#
#Joggertester is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with Foobar; if not, write to the Free Software
#Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

import struct


class U32:
    """Emulates 32-bit unsigned int known from C programming language."""

    def __init__(self, num=0, base=None):
        """Creates the U32 object.

        Args:
            num: the integer/string to use as the initial state
            base: the base of the integer use if the num given was a string
        """
        if base is None:
            self.int_ = int(num) % 2**32
        else:
            self.int_ = int(num, base) % 2**32

    def __coerce__(self, ignored):
        return None

    def __str__(self):
        return "<U32 instance at 0x%x, int=%d>" % (id(self), self.int_)

    def __getattr__(self, attribute_name):
        # you might want to take a look here:
        # http://stackoverflow.com/q/19611001/1091116
        r = getattr(self.int_, attribute_name)
        if callable(r):  # return a wrapper if integer's function was requested
            def f(*args, **kwargs):
                if args and isinstance(args[0], U32):
                    args = (args[0].int_, ) + args[1:]
                ret = r(*args, **kwargs)
                if ret is NotImplemented:
                    return ret
                if attribute_name in ['__str__', '__repr__', '__index__']:
                    return ret
                ret %= 2**32
                return U32(ret)
            return f
        return r


def XTEA_encrypt(buf, k):
    """Encrypts a given message using the given key.

    Args:
        buf (str): the data to be encrypted
        k (list): XTEA key - a list of four OpenTibia U32 integers

    Returns bytearray
    """
    ret = ""
    for offset in range(len(buf)/8):
        v0 = U32(struct.unpack("<I", buf[offset*8:offset*8+4])[0])
        v1 = U32(struct.unpack("<I", buf[offset*8+4:offset*8+8])[0])
        delta = U32(0x61C88647)
        sum_ = U32(0)

        for _ in range(32):
            v0 += ((v1 << U32(4) ^ v1 >> U32(5)) + v1) ^ \
                  (sum_ + U32(k[sum_ & U32(3)]))
            sum_ -= delta
            v1 += ((v0 << U32(4) ^ v0 >> U32(5)) + v0) ^ \
                  (sum_ + U32(k[sum_ >> U32(11) & U32(3)]))

        ret += struct.pack("<I", v0) + struct.pack("<I", v1)
    return bytearray(ret)


def XTEA_decrypt(buf, k):
    """Decrypts a given message using the given key.

    Args:
        buf (str): the data to be decrypted
        k (list): XTEA key - a list of four OpenTibia U32 integers

    Returns bytearray
    """
    ret = ""
    for offset in range(len(buf)/8):
        v0 = U32(struct.unpack("<I", buf[offset*8:offset*8+4])[0])
        v1 = U32(struct.unpack("<I", buf[offset*8+4:offset*8+8])[0])
        delta = U32(0x61C88647)
        sum_ = U32(0xC6EF3720)

        for _ in range(32):
            v1 -= ((v0 << U32(4) ^ v0 >> U32(5)) + v0) ^ \
                  (sum_ + U32(k[sum_ >> U32(11) & U32(3)]))
            sum_ += delta
            v0 -= ((v1 << U32(4) ^ v1 >> U32(5)) + v1) ^ \
                  (sum_ + U32(k[sum_ & U32(3)]))

        ret += struct.pack("<I", v0) + struct.pack("<I", v1)
    return bytearray(ret)
