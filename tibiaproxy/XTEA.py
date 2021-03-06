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
        v0 = struct.unpack("<I", bytes(buf[offset*8:offset*8+4]))[0]
        v1 = struct.unpack("<I", bytes(buf[offset*8+4:offset*8+8]))[0]
        delta = 0x9E3779B9
        sum_ = 0

        for _ in range(32):

            v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum_ + k[sum_ & 3])
            v0 &= 0xFFFFFFFF

            sum_ = (sum_ + delta) & 0xFFFFFFFF

            v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum_ + k[sum_ >> 11 & 3])
            v1 &= 0xFFFFFFFF

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
        v0 = struct.unpack("<I", bytes(buf[offset*8:offset*8+4]))[0]
        v1 = struct.unpack("<I", bytes(buf[offset*8+4:offset*8+8]))[0]
        delta = 0x9E3779B9
        sum_ = 0xC6EF3720

        for _ in range(32):

            v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum_ + k[sum_ >> 11 & 3])
            v1 &= 0xFFFFFFFF

            sum_ = (sum_ - delta) & 0xFFFFFFFF

            v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum_ + k[sum_ & 3])
            v0 &= 0xFFFFFFFF

        ret += struct.pack("<I", v0) + struct.pack("<I", v1)
    return bytearray(ret)

if __name__ == "__main__":
    import sys
    if len(sys.argv) <= 1:
        import doctest
        doctest.testmod()
        sys.exit()

    # Switch stdout to binary mode so that Python 3 doesn't complain
    import os
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'wb', 0)

    buf = bytearray(open(sys.argv[1], "rb").read())
    offset = int(sys.argv[2])

    # Note to self: to convert hexdump to an XTEA key, do:
    # binary = [chr(int(x,16)) for x in sys.argv[3].replace("  ", " ").split()]
    # [ struct.unpack("<I", ''.join(binary)[i*4:(i+1)*4])[0] for i in range(4)]
    k = [int(i) for i in sys.argv[3:]]

    d = XTEA_decrypt(buf[offset:], k)
    if d[2] == 0x14:
        sys.stdout.write(d)
    else:
        for offset in range(len(buf)):
            d = XTEA_decrypt(buf[offset:], k)
            if d[2] == 0x14:
                sys.exit("Try offset=%d" % offset)
