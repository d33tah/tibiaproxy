"""
GameProtocol.py - contains classes needed to handle the game protocol.
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


class HandshakeChallenge:
    def __init__(self, timestamp, random_number):
        self.timestamp = timestamp
        self.random_number = random_number


class GameProtocol:
    """Handles building and parsing the login protocol network messages."""

    def parseChallengeMessage(self, msg):
        """Parse the first (server's) message from the game protocol.

        Args:
            msg (NetworkMessage): the network message to be parsed.

        Returns list
        """
        assert(msg.getU16() == 6)
        assert(msg.getByte() == 0x1F)
        timestamp = msg.getU32()
        random_number = msg.getByte()
        ret = HandshakeChallenge(timestamp, random_number)
        return ret

    def parseFirstMessage(self, msg):
        """Parse the first (client's) message from the game protocol.

        Args:
            msg (NetworkMessage): the network message to be parsed.

        Returns list
        """
        msg.skipBytes(16)
        msg_buf = RSA.RSA_decrypt(msg.getRest()[:128])
        msg = NetworkMessage(msg_buf)
        # Extract the XTEA keys from the RSA-decrypted message.
        return [msg.getU32() for i in range(4)]
