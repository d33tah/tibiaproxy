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

    def __init__(self, conn):
        self.conn = conn

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
            char.ip = msg.getU32()
            char.port = msg.getU16()
            ret.characters += [char]

        return ret
