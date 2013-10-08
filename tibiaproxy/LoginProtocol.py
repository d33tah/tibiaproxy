from RSA import RSA


class LoginProtocol:

    def __init__(self, conn):
        self.conn = conn

    def parseFirstMessage(self, msg):
        msg.skipBytes(16)
        msg = RSA.decrypt(msg)
        print(msg.buf)
