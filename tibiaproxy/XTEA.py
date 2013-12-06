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


# You might want to take a look here:
# http://stackoverflow.com/q/20430637/1091116
def _build_delegate(name, attr, cls):
    def f(*args, **kwargs):
        args = tuple(a if not isinstance(a, cls) else a.int_ for a in args)
        ret = attr(*args, **kwargs)
        if ret is NotImplemented:
            return ret
        if name in ['__str__', '__repr__', '__index__', '__hash__']:
            return ret
        ret %= 2**32
        return cls(ret)
    return f


def delegated_special_methods(type_):
    def decorator(cls):
        for name, value in vars(type_).items():
            if (name[:2], name[-2:]) != ('__', '__') or not callable(value):
                continue
            if hasattr(cls, name) and not name == '__repr__':
                continue
            setattr(cls, name, _build_delegate(name, value, cls))
        return cls
    return decorator


@delegated_special_methods(int)
class U32(object):
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

if __name__ == "__main__":
    import doctest
    doctest.testmod()
