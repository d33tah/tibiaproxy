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
from LoginProtocol import LoginProtocol
from XTEA import XTEA
from util import *

import select
import socket
import copy


class Server:
    """Runs the proxy, coordinating the data flow between the user, proxy and
    the server."""

    def __init__(self, destination_host, destination_port,
                 listen_host, listen_port, announce_host, announce_port):
        self.destination_host = destination_host
        self.destination_port = int(destination_port)
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.announce_host = announce_host
        self.announce_port = int(announce_port)

        # Try to request the TCP port from the operating system. Tell it that
        # it is going to be a reusable port, so that a sudden crash of the
        # program is not going to block the port forever for other processes.
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((self.listen_host, self.listen_port))

    def handleLogin(self, conn, msg):
        """Handles the login communication, passing it to the destination host,
        modifying the server IPs and returning the modified character list to
        the user.

        Args:
            conn (socket): the already established connection.
            msg (NetworkMessage): the first message received.

        Returns None
        """
        proto = LoginProtocol()
        xtea_key = proto.parseFirstMessage(msg)

        # Connect to the destination host, send the request and read the reply.
        dest_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log("Connecting to the destination host...")
        dest_s.connect((self.destination_host, self.destination_port))
        dest_s.send(msg.getBuffer())
        data = dest_s.recv(1024)
        msg = NetworkMessage(data)
        reply = proto.parseReply(msg, xtea_key)

        # Replace the IP and port with the address to the proxy.
        # FIXME: the prepareReply is bugged, builds broken login server
        # packets.
        # TODO: save the original IP addresses in a dictionary so that game
        # server IPs different than the login server IP.
        client_reply = copy.copy(reply)
        for character in client_reply.characters:
            character.ip = self.announce_host
            character.port = self.announce_port
        client_reply_msg = proto.prepareReply(client_reply, xtea_key)

        # Send the message and close the connection.
        conn.send(client_reply_msg.getBuffer())
        conn.close()

    def handleGame(self, conn, data):
        """Connect to the game server, relay the packets between the the
        player, the proxy and the game server, reading them and running
        callbacks based on incoming/outgoing data.

        TODO: add anything beyond the eval() proof of concept. This function
        is one giant kludge at the moment.

        Args:
            conn (socket): the already established connection.
            data (str): the raw data sent by the player.

        Returns None
        """

        # Connect to the game server.
        dest_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log("Connecting to the hardcoded game server...")
        dest_s.connect((self.destination_host, self.destination_port))

        # Read the XTEA key from the player, pass on the original packet.
        msg = NetworkMessage(data)
        xtea_key = LoginProtocol().parseFirstMessage(msg, 7)
        dest_s.send(data)

        # You might not know this trick.
        #
        # By default, the read(n) operation on a socket causes a so-called
        # blocking read. This means that the operating system will block the
        # program flow until it reads all the n requested bytes. This means
        # that we will keep waiting for the socket data if it's not there and
        # for example, while we're waiting for the player data, a game server
        # could send something interesting. It could even take seconds. This
        # is not acceptable.
        #
        # This is why we're switching the sockets to the non-blocking mode.
        # In this mode, recv(n) will return immediately with *at most* n bytes,
        # and if there's less than n bytes in the buffer, we'll read them all.
        dest_s.setblocking(0)
        conn.setblocking(0)
        while True:
            # Wait until either the player or the server sent some data.
            has_data, _, _ = select.select([conn, dest_s], [], [])
            if conn in has_data:
                data = conn.recv(1024)
                msg = NetworkMessage(data)
                msg_size = msg.getU16()
                assert(msg_size == len(data) - 2)
                msg = XTEA.decrypt(msg, xtea_key)
                msg.getU16()
                packet_type = msg.getByte()
                if packet_type == 150:
                    # We got a player "say" request. Read what the player
                    # wanted to say, treat it like a Python expression and send
                    # the result back to the user.
                    msg.skipBytes(1)
                    player_said = msg.getString()
                    print("Player said %s!" % player_said)
                    to_send = str(eval(player_said))
                    sendmsg = NetworkMessage()
                    sendmsg.addByte(0xB4)  # send text message
                    sendmsg.addByte(0x1A)  # console, orange text
                    sendmsg.addString(to_send)
                    sendmsg.prependU16(len(sendmsg.getBuffer()) - 2)
                    # Add some padding bytes.
                    for i in range(8 - (len(sendmsg.getBuffer()) % 8)):
                      sendmsg.addByte(0x33)
                    sendmsg = XTEA.encrypt(sendmsg, xtea_key)
                    conn.send(sendmsg.getBuffer())
                else:
                    # Otherwise, just pass the packet to the server.
                    dest_s.send(data)
            if dest_s in has_data:
                # Server sent us some data. Currently, no parsing is done -
                # just pass it to the player.
                data = dest_s.recv(1024)
                conn.send(data)

    def run(self):
        """Enter the proxy main loop.

        Returns None
        """
        log(("Listening on address %s:%s, connections will be forwarded " +
             "to %s:%s") % (self.listen_host, self.listen_port,
                            self.destination_host, self.destination_port))

        self.s.listen(1)
        while True:
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
                self.handleGame(conn, data)
            else:
                log("ERROR: Unknown packet type %s" % hex(first_byte))
                conn.close()
