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

import sys
import socket
import struct


def log(_str):
    """Poor man's log function. Prints the argument to the standard error
    output, with a newline added. Then, it flushes it just-in-case.

    Args:
        _str (str): the message to be printed

    Returns None
    """
    sys.stderr.write(_str + "\n")
    sys.stderr.flush()


def u32_to_ip(ip):
    """Converts an OpenTibia U32 number to an IP address.

    Args:
        ip (int): the OpenTibia U32 number to be translated into an IP address.

    Returns str
    """
    return socket.inet_ntoa(struct.pack("<I", ip))


def ip_to_u32(ip):
    """Converts an IP address to an OpenTibia U32 number.

    Args:
        ip (str): the IP address to be translated into an OpenTibia U32 number.

    Returns int
    """
    return struct.unpack("<I", socket.inet_aton(ip))[0]
