"""tibiaproxy's main class. Responsible for relaying the data.
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

from tibiaproxy.NetworkMessage import NetworkMessage, adlerChecksum
from tibiaproxy import LoginProtocol
from tibiaproxy import GameProtocol
from tibiaproxy import XTEA
from tibiaproxy import RSA
from tibiaproxy.util import log

import select
import socket
import copy
import time
import threading
import sys
import struct


class Connection:
    def __init__(self, conn, xtea_key):
        self.conn = conn
        self.xtea_key = xtea_key

    def client_send_said(self, player, pos, msg):
        sendmsg = NetworkMessage()
        sendmsg.addByte(0xAA)
        sendmsg.addU32(3)  # statement ID
        sendmsg.addString("1")
        sendmsg.addU16(1)  # level
        sendmsg.addByte(1)  # type: SPEAK_SAY
        assert(len(pos) == 3)
        sendmsg.addU16(pos[0])
        sendmsg.addU16(pos[1])
        sendmsg.addByte(pos[2])
        sendmsg.writable = True  # FIXME
        sendmsg.addString(msg)
        self.conn.send(sendmsg.getEncrypted(self.xtea_key))


class Server:
    """Runs the proxy, coordinating the data flow between the user, proxy and
    the server."""

    def __init__(self, destination_login_host, destination_login_port,
                 listen_login_host, listen_login_port,
                 listen_game_host, listen_game_port,
                 announce_host, announce_port, real_tibia, debug, plugins):
        self.destination_login_host = destination_login_host
        self.destination_login_port = int(destination_login_port)
        self.listen_login_host = listen_login_host
        self.listen_login_port = int(listen_login_port)
        self.listen_game_host = listen_game_host
        self.listen_game_port = int(listen_game_port)
        self.announce_host = announce_host
        self.announce_port = int(announce_port)
        self.real_tibia = real_tibia
        self.debug = debug
        self.plugins = plugins

        # Try to request the TCP port from the operating system. Tell it that
        # it is going to be a reusable port, so that a sudden crash of the
        # program is not going to block the port forever for other processes.
        self.l_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.l_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l_s.bind((self.listen_login_host, self.listen_login_port))

        self.g_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.g_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.g_s.bind((self.listen_game_host, self.listen_game_port))
        self.characters = {}

    def handleLogin(self, conn, msg):
        """Handles the login communication, passing it to the destination host,
        modifying the server IPs and returning the modified character list to
        the user.

        Args:
            conn (socket): the already established connection.
            msg (NetworkMessage): the first message received.

        Returns None
        """
        xtea_key = LoginProtocol.parseFirstMessage(msg)

        # Connect to the destination host, send the request and read the reply.
        dest_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        log("Connecting to the destination host...")
        dest_s.connect((self.destination_login_host,
                        self.destination_login_port))
        if not self.real_tibia:
            dest_s.send(msg.getRaw())
        else:
            reencrypted = RSA.RSA_encrypt(RSA.RSA_decrypt(msg.getRaw()[28:]))
            unencrypted = msg.getRaw()[6:28]
            new_buf = ""
            new_buf += msg.getRaw()[:2]
            new_buf += struct.pack("<I",
                                   adlerChecksum(unencrypted+reencrypted))
            new_buf += unencrypted
            new_buf += reencrypted
            dest_s.send(new_buf)
        data = dest_s.recv(1024)
        if data == '':
            log("Server disconnected.")
            conn.close()
            return
        msg = NetworkMessage(data)
        reply = LoginProtocol.parseReply(msg, xtea_key)
        if reply is None:
            # The reply doesn't seem to contain character list - just forward
            # it.
            conn.send(data)
            conn.close()
            return

        for character in reply['characters']:
            self.characters[character['name']] = character

        # Replace the IP and port with the address to the proxy.
        client_reply = copy.deepcopy(reply)
        for world in client_reply['worlds']:
            world['hostname'] = self.announce_host
            world['port'] = self.announce_port
        client_reply_msg = LoginProtocol.prepareReply(client_reply)
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

        # send a bogus challenge = 109, timestamp = 1385139009
        conn.send(b'\x0c\x00@\x02!\x07\x06\x00\x1fA\x8b\x8fRm')

        data = conn.recv(2)
        size = struct.unpack("<H", data)[0]
        data += conn.recv(size)
        # Read the XTEA key from the player, pass on the original packet.
        msg = NetworkMessage(data)
        firstmsg_contents = GameProtocol.parseFirstMessage(msg)

        # Connect to the game server.
        dest_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        character = self.characters[firstmsg_contents['character_name']]
        game_host = character['world']['hostname']
        game_port = character['world']['port']
        log("Connecting to the game server (%s:%s)." % (game_host, game_port))
        dest_s.connect((game_host, game_port))
        size_raw = dest_s.recv(2)
        size = struct.unpack("<H", size_raw)[0]
        checksum = dest_s.recv(4)
        data = dest_s.recv(size)
        msg = NetworkMessage(data)

        challenge_data = GameProtocol.parseChallengeMessage(msg)

        xtea_key = firstmsg_contents['xtea_key']
        firstmsg_contents['timestamp'] = challenge_data['timestamp']
        firstmsg_contents['random_number'] = challenge_data['random_number']
        dest_s.send(GameProtocol.prepareReply(firstmsg_contents,
                                              self.real_tibia))

        conn_obj = Connection(conn, xtea_key)
        while True:
            # Wait until either the player or the server sent some data.
            has_data, _, _ = select.select([conn, dest_s], [], [])
            if conn in has_data:
                data = bytearray()
                size_raw = conn.recv(2)
                data += size_raw
                if size_raw == bytearray():
                    log("The client disconnected")
                    break
                size = struct.unpack("<H", size_raw)[0]
                data += conn.recv(size+4)
                msg = NetworkMessage(data)
                msg_size = msg.getU16()
                msg.getU32()  # skip the checksum validation
                if msg_size != len(data) - 2:
                    log("Strange packet from client: %s" % repr(data))
                    log("len(data)=%s, msg_size=%s" % (len(data), msg_size))
                    dest_s.send(data)
                    continue
                msg_buf = XTEA.XTEA_decrypt(msg.getRest(), xtea_key)
                msg = NetworkMessage(msg_buf)
                msg.getU16()
                packet_type = msg.getByte()
                if packet_type in GameProtocol.client_packet_types:
                    if self.debug:
                        log("C [%s] %s" % (hex(packet_type),
                            GameProtocol.client_packet_types[packet_type]))
                else:
                    log("Got a packet of type %s from client" % packet_type)
                should_forward = True
                if packet_type == 150:
                    # We got a player "say" request. Read what the player
                    # wanted to say, treat it like a Python expression and send
                    # the result back to the user.
                    msg.skipBytes(1)
                    player_said = msg.getString()
                    for plugin in self.plugins:
                        if 'on_client_say' in dir(plugin):
                            plugin_returned = plugin.on_client_say(conn_obj,
                                                                   player_said)

                            if plugin_returned:
                                should_forward = False

                if should_forward:
                    # Otherwise, just pass the packet to the server.
                    dest_s.send(data)
            if dest_s in has_data:
                # Server sent us some data.
                data = bytearray()
                size_raw = dest_s.recv(2)
                data += size_raw
                if data == bytearray():
                    conn.close()
                    log("The server disconnected")
                    break
                size = struct.unpack("<H", size_raw)[0]
                data += dest_s.recv(size+4)
                msg = NetworkMessage(data)
                msg_size = msg.getU16()
                msg.getU32()  # skip the checksum validation
                if msg_size != len(data) - 2:
                    log("Strange packet from server: %s" % repr(data))
                    log("len(data)=%s, msg_size=%s" % (len(data), msg_size))
                    conn.send(data)
                    continue
                msg_buf = XTEA.XTEA_decrypt(msg.getRest(), xtea_key)
                msg = NetworkMessage(msg_buf)
                msg.getU16()
                packet_type = msg.getByte()
                if packet_type in GameProtocol.server_packet_types:
                    if self.debug:
                        log("S [%s] %s" % (hex(packet_type),
                            GameProtocol.server_packet_types[packet_type]))
                else:
                    log("Got a packet of type %s from server" % packet_type)

                conn.send(data)

    def serveLogin(self, one_shot=False):
        """Listen for login server connections and handle them.

        Args:
            one_shot (bool): True if we want to handle a single connection, in
                             the main thread.

        Returns None
        """
        def accept_login_conn():
            conn, addr = self.l_s.accept()
            log("Received a login connection from %s:%s" % addr)
            data = conn.recv(1024)
            msg = NetworkMessage(data)
            if not self.debug:
                t = threading.Thread(target=self.handleLogin, args=[conn, msg])
                t.start()
            else:
                self.handleLogin(conn, msg)

        if one_shot:
            accept_login_conn()
            return
        else:
            while True:
                accept_login_conn()

    def serveGame(self, one_shot=False):
        """Listen for game server connections and handle them.

        Returns None
        """
        def accept_game_conn():
            conn, addr = self.g_s.accept()
            log("Received a game server connection from %s:%s" % addr)
            if not self.debug:
                t = threading.Thread(target=self.handleGame, args=[conn])
                t.start()
            else:
                self.handleGame(conn)

        if one_shot:
            accept_game_conn()
            return
        else:
            while True:
                accept_game_conn()

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

        if not self.debug:
            t_l = threading.Thread(target=self.serveLogin)
            g_l = threading.Thread(target=self.serveGame)

            t_l.daemon = True
            g_l.daemon = True

            t_l.start()
            g_l.start()
        else:
            self.serveLogin(True)
            self.serveGame(True)

        if not self.debug:
            # http://stackoverflow.com/q/3788208/1091116
            try:
                while True:
                    time.sleep(100)
            except (KeyboardInterrupt, SystemExit):
                sys.exit("Received keyboard interrupt, quitting")
