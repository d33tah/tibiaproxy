from NetworkMessage import NetworkMessage
from LoginProtocol import LoginProtocol
from util import *

import socket
import copy


class Server:

    def __init__(self, destination_host, destination_port,
                 listen_host, listen_port):
        self.destination_host = destination_host
        self.destination_port = int(destination_port)
        self.listen_host = listen_host
        self.listen_port = int(listen_port)

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((self.listen_host, self.listen_port))

    def handleLogin(self, conn, msg):
        proto = LoginProtocol(conn)
        proto.parseFirstMessage(msg)
        dest_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log("Connecting to the destination host...")
        dest_s.connect((self.destination_host, self.destination_port))
        dest_s.send(msg.getBuffer())

        data = dest_s.recv(1024)
        msg = NetworkMessage(data)
        reply = proto.parseReply(msg)
        client_reply = copy.copy(reply)
        for character in client_reply.characters:
            character.ip = self.listen_host
        client_reply_msg = proto.prepareReply(client_reply)
        conn.send(client_reply_msg.getBuffer())

    def run(self):
        log(("Listening on address %s:%s, connections will be forwarded " +
             "to %s:%s") % (self.listen_host, self.listen_port,
                            self.destination_host, self.destination_port))

        self.s.listen(1)
        conn, addr = self.s.accept()
        log("Received a connection from %s:%s" % addr)
        data = conn.recv(1024)
        msg = NetworkMessage(data)

        msg_size = msg.getU16()
        assert(msg_size == len(data) - 2)
        first_byte = msg.getByte()
        if first_byte == 0x01:
            self.handleLogin(conn, msg)
        elif first_byte == 0x0A:
            log("TODO: Will parse a game server packet.")
        else:
            log("ERROR: Unknown packet type %s" % hex(first_byte))
            conn.close()
