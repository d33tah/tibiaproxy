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


def toint(x):
    """Convert a string represented as an integer to an integer, removing all
    newline characters.

    Args:
        x (str): the string to be converted

    Returns int
    """
    return int(x.replace('\n', ''))

#OpenTibia keys
p = toint("""
142996239624163995200701773828988955507954033454661532174705160829347375827760
38882967213386204600674145392845853859217990626450972452084065728686565928113
""")

q = toint("""
763097919597040472189120184779200212553540129277912393720744757459669278851364
7179235335529307251350570728407373705564708871762033017096809910315212884101
""")

d = toint("""
467303302235841186221601800150368321487329868085193446752105552629402587398057
668602246106469196058602063280243267033616301098884178392419595075722472848070
352355696191737922927869078457919049551036016528225191219083671878855092700253
88641700821735345222087940578381210879116823013776808975766851829020659073
""")


def byte_to_hex(i):
    """Convert a character to the hexadecimal form, padding it with spaces.

    Args:
        i (str): the character to be converted

    Returns str
    """
    without_0x = hex(ord(i)).replace('0x', '')
    space_padded = "%2s" % without_0x
    zero_padded = space_padded.replace(' ', '0')
    return zero_padded


class RSA:
    """Handles RSA operations."""

    @classmethod
    def decrypt(cls, msg):
        """Decrypts an RSA-encrypted message with an OpenTibia key.

        Args:
            msg (str): the message to be decrypted

        Returns NetworkMessage
        """
        c_bin = msg.getRest()[:128]
        c_hex = ''.join([byte_to_hex(i) for i in c_bin])

        c = int(c_hex, 16)

        n = p*q
        # z = c^d % n, way faster than z = c**d % n
        z = pow(c, d, n)

        z_hex = "%x" % z
        if len(z_hex) % 2 != 0:
            z_hex = "0" + z_hex

        # Now, convert the hexadecimal form to a binary one.
        z_bin = ""
        for i in range(len(z_hex)/2):
            chunk = z_hex[i*2:(i+1)*2]
            z_bin += chr(int(chunk, 16))

        return NetworkMessage(z_bin)
