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


def XTEA_encrypt(buf, k):
    """Encrypts a given message using the given key.

    >>> key = [4060739823, 3225438839, 2808461571, 1241583342]
    >>> encrypted = b\'\\xfc\\xd9\\xd8A\\x0b\\xc4~\\x82\'
    >>> decrypted = b\'I\\x00\\x14"\\x001\\nW\'
    >>> XTEA_encrypt(decrypted, key) == encrypted
    True

    Args:
        buf (str): the data to be encrypted
        k (list): XTEA key - a list of four OpenTibia U32 integers

    Returns bytearray
    """
    ret = bytearray()
    for offset in range(int(len(buf)/8)):
        v0 = struct.unpack("<I", buf[offset*8:offset*8+4])[0]
        v1 = struct.unpack("<I", buf[offset*8+4:offset*8+8])[0]
        delta = 0x61C88647
        sum_ = 0

        for _ in range(32):
            v0 = (
                v0
                +
                (
                    (
                        (v1 << 4) % 2**32 ^ (v1 >> 5) % 2**32
                    ) % 2**32
                    +
                    v1 ^ (sum_ + k[sum_ & 3]) % 2**32
                ) % 2**32
            ) % 2**32

            sum_ = (sum_ - delta) % 2 ** 32

            v1 = (
                v1
                +
                (
                    (
                        (
                            (v0 << 4) % 2**32 ^ (v0 >> 5) % 2**32
                        ) % 2**32 + v0
                    ) % 2**32
                    ^
                    (sum_ + k[(sum_ >> 11) % 2**32 & 3]) % 2**32
                ) % 2**32
            ) % 2**32

        ret += struct.pack("<I", v0) + struct.pack("<I", v1)
    return ret


def XTEA_decrypt(buf, k):
    """Decrypts a given message using the given key.

    >>> key = [4060739823, 3225438839, 2808461571, 1241583342]
    >>> encrypted = b\'\\xfc\\xd9\\xd8A\\x0b\\xc4~\\x82\'
    >>> decrypted = b\'I\\x00\\x14"\\x001\\nW\'
    >>> XTEA_decrypt(encrypted, key) == decrypted
    True

    Args:
        buf (str): the data to be decrypted
        k (list): XTEA key - a list of four OpenTibia U32 integers

    Returns bytearray
    """
    ret = bytearray()
    for offset in range(int(len(buf)/8)):
        v0 = struct.unpack("<I", buf[offset*8:offset*8+4])[0]
        v1 = struct.unpack("<I", buf[offset*8+4:offset*8+8])[0]
        delta = 0x61C88647
        sum_ = 0xC6EF3720

        for _ in range(32):

            v1 = (
                v1
                -
                (
                    (
                        (
                            (v0 << 4) % 2**32 ^ (v0 >> 5) % 2**32
                        ) % 2**32 + v0
                    ) % 2**32
                    ^
                    (sum_ + k[(sum_ >> 11) % 2**32 & 3]) % 2**32
                ) % 2**32
            ) % 2**32

            sum_ = (sum_ + delta) % 2**32

            v0 = (
                v0
                -
                (
                    (
                        (v1 << 4) % 2**32 ^ (v1 >> 5) % 2**32
                    ) % 2**32
                    +
                    v1 ^ (sum_ + k[sum_ & 3]) % 2**32
                ) % 2**32
            ) % 2**32

        ret += struct.pack("<I", v0) + struct.pack("<I", v1)
    return bytearray(ret)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
