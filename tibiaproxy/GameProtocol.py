"""
GameProtocol.py - contains code needed to handle the game protocol.
"""

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
import RSA


def create_handshake_challenge(timestamp, random_number):
    return {'timestamp': timestamp, 'random_number': random_number}


def create_handshake_reply(xtea_key, account_number, password, character_name,
                           timestamp, random_number, challenge_pos, first_16,
                           decrypted_raw):
    return {'xtea_key': xtea_key,
            'account_number': account_number,
            'password': password,
            'character_name': character_name,
            'timestamp': timestamp,
            'random_number': random_number,
            'challenge_pos': challenge_pos,
            'first_16': first_16,
            'decrypted_raw': decrypted_raw}


def parseChallengeMessage(msg):
    """Parse the first (server's) message from the game protocol.

    Args:
        msg (NetworkMessage): the network message to be parsed.

    Returns list
    """
    assert(msg.getU16() == 6)
    assert(msg.getByte() == 0x1F)
    timestamp = msg.getU32()
    random_number = msg.getByte()
    return create_handshake_challenge(timestamp, random_number)


def parseFirstMessage(orig_msg):
    """Parse the first (client's) message from the game protocol.

    Args:
        orig_msg (NetworkMessage): the network message to be parsed.

    Returns list
    """
    orig_msg.skipBytes(16)
    msg_buf = RSA.RSA_decrypt(orig_msg.getRest()[:128])
    msg = NetworkMessage(msg_buf)
    # Extract the XTEA keys from the RSA-decrypted message.
    xtea_key = [msg.getU32() for i in range(4)]
    assert(msg.getByte() == 0)        # gamemaster flag
    account_number = msg.getString()  # account
    character_name = msg.getString()  # character name
    password = msg.getString()        # password
    challenge_pos = msg.getPos()
    timestamp = msg.getU32()
    random_number = msg.getByte()
    return create_handshake_reply(xtea_key=xtea_key,
                                  account_number=account_number,
                                  password=password,
                                  character_name=character_name,
                                  timestamp=timestamp,
                                  random_number=random_number,
                                  challenge_pos=challenge_pos,
                                  first_16=orig_msg.getRaw()[:16],
                                  decrypted_raw=msg_buf)
