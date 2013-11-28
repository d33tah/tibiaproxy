"""
LoginProtocol.py - contains code needed to handle the login protocol.
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

from NetworkMessage import NetworkMessage
import RSA
import XTEA
from util import log


def create_login_world_entry(name, hostname, port):
    return {'name': name, 'hostname': hostname, 'port': port}


def create_login_character_entry(name, world):
    return {'name': name, 'world': world}


def create_login_reply_info(characters, motd, worlds):
    return {'characters': characters, 'motd': motd, 'worlds': worlds}


def parseFirstMessage(msg):
    """Parse the first (client's) message from the login protocol.

    Args:
        msg (NetworkMessage): the network message to be parsed.
        skip_bytes (int): the offset at which is the RSA-encrypted message.

    Returns list
    """
    msg.skipBytes(28)
    msg_buf = RSA.RSA_decrypt(msg.getRest()[:128])
    msg = NetworkMessage(msg_buf)
    # Extract the XTEA keys from the RSA-decrypted message.
    return [msg.getU32() for _ in range(4)]


def parseReply(msg, xtea_key):
    """Parse the reply from the login server.

    Args:
        msg (NetworkMessage): the network message to be parsed.

    Returns dict or None
    """
    size = msg.getU16()

    # someday perhaps I'll have enough time to even check the checksums!
    msg.skipBytes(4)

    msg_buf = XTEA.XTEA_decrypt(msg.getRest(), xtea_key)
    msg = NetworkMessage(msg_buf)
    #assert(len(msg.getWithHeader()) == size)
    decrypted_size = msg.getU16()
    #assert(decrypted_size == size - 5)

    packet_type = msg.getByte()
    if packet_type != 0x14:
        # The reply doesn't seem to contain character list.
        return None
    motd = msg.getString()

    assert(msg.getByte() == 0x64)

    num_worlds = msg.getByte()
    worlds = []
    for _ in range(num_worlds):
        world_id = msg.getByte()
        world_name = msg.getString()
        world_hostname = msg.getString()
        world_port = msg.getU16()
        log("Received server address %s:%s" % (world_hostname, world_port))
        msg.skipBytes(1)  # no idea what's that.
        worlds += [create_login_world_entry(name=world_name,
                                            hostname=world_hostname,
                                            port=world_port)]

    num_chars = msg.getByte()
    characters = []
    for _ in range(num_chars):
        world_num = msg.getByte()
        char_world = worlds[world_num]
        char_name = msg.getString()
        characters += [create_login_character_entry(name=char_name,
                                                    world=char_world)]

    return create_login_reply_info(characters, motd, worlds)


def prepareReply(login_reply):
    """Prepare the reply based on a LoginReply instance.

    Args:
        login_reply (dict): the login_reply structure used to build
            the response.

    Returns NetworkMessage
    """

    ret = NetworkMessage()
    ret.addByte(0x14)
    ret.addString(login_reply['motd'])
    ret.addByte(0x64)

    ret.addByte(len(login_reply['worlds']))
    world_id = 0
    for world in login_reply['worlds']:
        ret.addByte(world_id)
        ret.addString(world['name'])
        ret.addString(world['hostname'])
        ret.addU16(world['port'])
        ret.addByte(0)
        world_id += 1

    ret.addByte(len(login_reply['characters']))
    for char in login_reply['characters']:
        ret.addByte(login_reply['worlds'].index(char['world']))
        ret.addString(char['name'])
    ret.addByte(0x00)
    ret.addByte(0x00)
    return ret
