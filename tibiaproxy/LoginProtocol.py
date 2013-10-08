from RSA import RSA
from XTEA import XTEA
from util import *


class LoginProtocol:

    def __init__(self, conn):
        self.conn = conn

    def parseFirstMessage(self, msg):
        msg.skipBytes(16)
        msg = RSA.decrypt(msg)
        self.k = [msg.getU32() for i in range(4)]

    def parseReply(self, msg):
        msg.skipBytes(2)
        decrypted = XTEA.decrypt(msg, self.k)
