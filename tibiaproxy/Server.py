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

from NetworkMessage import NetworkMessage, adlerChecksum
from LoginProtocol import LoginProtocol
import XTEA
import RSA
from util import *

import select
import socket
import copy
import time
import threading
import sys
import struct


class Server:
    """Runs the proxy, coordinating the data flow between the user, proxy and
    the server."""

    def __init__(self, destination_login_host, destination_login_port,
                 destination_game_host, destination_game_port,
                 listen_login_host, listen_login_port,
                 listen_game_host, listen_game_port,
                 announce_host, announce_port, real_tibia):
        self.destination_login_host = destination_login_host
        self.destination_login_port = int(destination_login_port)
        self.destination_game_host = destination_game_host
        self.destination_game_port = int(destination_game_port)
        self.listen_login_host = listen_login_host
        self.listen_login_port = int(listen_login_port)
        self.listen_game_host = listen_game_host
        self.listen_game_port = int(listen_game_port)
        self.announce_host = announce_host
        self.announce_port = int(announce_port)
        self.real_tibia = real_tibia

        # Try to request the TCP port from the operating system. Tell it that
        # it is going to be a reusable port, so that a sudden crash of the
        # program is not going to block the port forever for other processes.
        self.l_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.l_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l_s.bind((self.listen_login_host, self.listen_login_port))

        self.g_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.g_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.g_s.bind((self.listen_game_host, self.listen_game_port))

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
        dest_s.connect((self.destination_login_host,
                        self.destination_login_port))
        if not self.real_tibia:
            dest_s.send(msg.getRaw())
        else:
            reencrypted = RSA.RSA_encrypt(RSA.RSA_decrypt(msg.getRaw()[28:]))
            new_buf = ""
            new_buf += msg.getRaw()[:2]
            new_buf += struct.pack("<I", adlerChecksum(reencrypted))
            new_buf += msg.getRaw()[6:28]
            new_buf += reencrypted
            dest_s.send(new_buf)
        data = dest_s.recv(1024)
        if data == '':
            print("Server disconnected.")
            conn.close()
            return
        msg = NetworkMessage(data)
        reply = proto.parseReply(msg, xtea_key)
        if reply is None:
            # The reply doesn't seem to contain character list - just forward
            # it.
            conn.send(data)
            conn.close()
            return

        # Replace the IP and port with the address to the proxy.
        # FIXME: the prepareReply is bugged, builds broken login server
        # packets.
        # TODO: save the original IP addresses in a dictionary so that game
        # server IPs different than the login server IP.
        client_reply = copy.copy(reply)
        for world in client_reply.worlds:
            world.hostname = self.announce_host
            world.port = self.announce_port
        client_reply_msg = proto.prepareReply(client_reply)
        # Send the message and close the connection.
        conn.send(client_reply_msg.getEncrypted(xtea_key))
        conn.close()

    def handleGame(self, conn):
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
        log("Connecting to the hardcoded game server (%s:%s)..." % (
            self.destination_game_host, self.destination_game_port))
        dest_s.connect((self.destination_game_host,
                        self.destination_game_port))
        buf = dest_s.recv(1024)
        conn.send(buf)

        data = conn.recv(2)
        size = struct.unpack("<H", data)[0]
        data += conn.recv(size)

        # Read the XTEA key from the player, pass on the original packet.
        msg = NetworkMessage(data)
        xtea_key = LoginProtocol().parseFirstMessage(msg, 16)
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
                if data == '':
                    log("The client disconnected")
                    break
                msg = NetworkMessage(data)
                msg_size = msg.getU16()
                msg.getU32()
                if msg_size != len(data) - 2:
                    log("Strange packet: %s" % repr(data))
                    continue
                msg_buf = XTEA.XTEA_decrypt(msg.getRest(), xtea_key)
                msg = NetworkMessage(msg_buf)
                msg.getU16()
                packet_type = msg.getByte()
                player_said = ""
                if packet_type == 150:
                    # We got a player "say" request. Read what the player
                    # wanted to say, treat it like a Python expression and send
                    # the result back to the user.
                    msg.skipBytes(1)
                    player_said = msg.getString()
                    print("Player said %s!" % player_said)
                if player_said.startswith(">"):
                    try:
                        to_send = str(eval(player_said[1:].lstrip()))
                    except Exception, e:
                        to_send = str(e)
                    sendmsg = NetworkMessage()
                    sendmsg.addByte(0xAA)
                    sendmsg.addU32(3)  # statement ID
                    sendmsg.addString("1")
                    sendmsg.addU16(1)  # level
                    sendmsg.addByte(1)  # type: SPEAK_SAY
                    sendmsg.addU16(96)  # pos
                    sendmsg.addU16(123)
                    sendmsg.addByte(7)
                    sendmsg.writable = True
                    sendmsg.addString(to_send)
                    conn.send(sendmsg.getEncrypted(xtea_key))
                else:
                    # Otherwise, just pass the packet to the server.
                    dest_s.send(data)
            if dest_s in has_data:
                # Server sent us some data. Currently, no parsing is done -
                # just pass it to the player.
                data = dest_s.recv(1024)
                if data == '':
                    conn.close()
                    log("The server disconnected")
                    break
                conn.send(data)

    def serveLogin(self):
        """Listen for login server connections and handle them.

        Returns None
        """
        while True:
            conn, addr = self.l_s.accept()
            log("Received a login connection from %s:%s" % addr)
            data = conn.recv(1024)
            msg = NetworkMessage(data)
            t = threading.Thread(target=self.handleLogin, args=[conn, msg])
            t.start()

    def serveGame(self):
        """Listen for game server connections and handle them.

        Returns None
        """
        while True:
            conn, addr = self.g_s.accept()
            log("Received a game server connection from %s:%s" % addr)
            t = threading.Thread(target=self.handleGame, args=[conn])
            t.start()

    def run(self):
        """Run serveLogin and serveGame threads and sleep forever.

        Returns None
        """
        log(("Listening on address %s:%s (login), %s:%s (game), connections " +
             "will be forwarded to %s:%s") % (self.listen_login_host,
                                              self.listen_login_port,
                                              self.listen_game_host,
                                              self.listen_game_port,
                                              self.destination_login_host,
                                              self.destination_login_port))

        self.l_s.listen(1)
        self.g_s.listen(1)

        t_l = threading.Thread(target=self.serveLogin)
        g_l = threading.Thread(target=self.serveGame)

        t_l.daemon = True
        g_l.daemon = True

        t_l.start()
        g_l.start()

        # http://stackoverflow.com/q/3788208/1091116
        try:
            while True:
                time.sleep(100)
        except (KeyboardInterrupt, SystemExit):
            sys.exit("Received keyboard interrupt, quitting")
