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


def buf_to_int(buf):
    """Converts the given buffer to a decimal form, ready for RSA operations.

    Args:
        buf (str): the buffer to be converted

    Returns int
    """
    # first, convert each character to hexadecimal.
    zero_padded = ""
    for i in buf:
        without_0x = hex(ord(i)).replace('0x', '')
        space_padded = "%2s" % without_0x
        zero_padded += space_padded.replace(' ', '0')

    # convert each byte to hex, then join it together and convert to int
    return int(zero_padded, 16)


def int_to_buf(num):
    """Converts the given buffer to a decimal form, ready for RSA operations.

    Args:
        buf (str): the buffer to be converted

    Returns int
    """
    # convert the string to hexadecimal
    num_hex = "%x" % num
    if len(num_hex) % 2 != 0:
        num_hex = "0" + num_hex

    # Now, convert the hexadecimal form to a binary one.
    num_bin = ""
    for i in range(len(num_hex)/2):
        chunk = num_hex[i*2:(i+1)*2]
        num_bin += chr(int(chunk, 16))

    return num_bin


def RSA_decrypt(c_bin):
    """Decrypts an RSA-encrypted message with an OpenTibia key.

    Args:
        c_bin (str): the message to be decrypted

    Returns str
    """
    # return z = c^d % n. pow(c,d,n) is way faster than z = c**d % n.
    return int_to_buf(pow(buf_to_int(c_bin), d, p*q))


def RSA_encrypt(m_bin):
    """Encrypts a message using RSA algorithm with an OpenTibia key.

    Args:
        m_bin (str): the message to be encrypted
        n (int): the public key used for encryption

    Return str
    """
    # return c = m^e mod n, where e = 65537
    return int_to_buf(pow(buf_to_int(m_bin), 65537, p*q))
