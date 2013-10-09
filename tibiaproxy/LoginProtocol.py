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

from NetworkMessage import NetworkMessage
from RSA import RSA
from XTEA import XTEA
from util import *


class LoginCharacterEntry:
    name = ""
    world = ""
    ip = 0
    port = 0


class LoginReply:
    motd = ""
    characters = []


class LoginProtocol:

    def parseFirstMessage(self, msg):
        msg.skipBytes(16)
        msg = RSA.decrypt(msg)
        self.k = [msg.getU32() for i in range(4)]

    def parseReply(self, msg):
        ret = LoginReply()

        size = msg.getU16()
        msg = XTEA.decrypt(msg, self.k)
        assert(len(msg.getBuffer()) == size)
        decrypted_size = msg.getU16()
        assert(decrypted_size == size - 5)

        packet_type = msg.getByte()
        assert(packet_type == 0x14)
        ret.motd = msg.getString()

        assert(msg.getByte() == 0x64)
        num_chars = msg.getByte()
        for i in range(num_chars):
            char = LoginCharacterEntry()
            char.name = msg.getString()
            char.world = msg.getString()
            char.ip = u32_to_ip(msg.getU32())
            char.port = msg.getU16()
            ret.characters += [char]

        return ret

    def prepareReply(self, login_reply):
        ret = NetworkMessage()
        ret.addByte(0x14)
        ret.addString(login_reply.motd)
        ret.addByte(0x64)
        ret.addByte(len(login_reply.characters))
        for char in login_reply.characters:
            ret.addString(char.name)
            ret.addString(char.world)
            ret.addU32(ip_to_u32(char.ip))
            ret.addU16(char.port)
        # FIXME: This is probably wrong. See what's the right way and keep in
        # mind that getBuffer makes the buffer temporarily larger.
        ret.prependU16(len(ret.getBuffer()))
        ret = XTEA.encrypt(ret, self.k)
        return ret
