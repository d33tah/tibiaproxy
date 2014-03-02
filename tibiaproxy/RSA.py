"""
Pure-python RSA implementation, along with OpenTibia and Tibia keys.
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

import sys


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

otserv_n = p * q

tibia_n = toint("""
132127743205872284062295099082293384952776326496165507967876361843343953435544
496682053323833394351797728954155097012103928360786959821132214473291575712138
800495033169914814069637740318278150290733684032524174782740134357629699062987
023311132821016569775488792221429527047321331896351555606801473202394175817
""")


def buf_to_int(buf):
    """Converts the given buffer to a decimal form, ready for RSA operations.

    Args:
        buf (bytearray): the buffer to be converted

    Returns int
    """
    # first, convert each character to hexadecimal.
    zero_padded = ""
    for i in buf:
        without_0x = hex(i).replace('0x', '')
        space_padded = "%2s" % without_0x
        zero_padded += space_padded.replace(' ', '0')

    # convert each byte to hex, then join it together and convert to int
    return int(zero_padded, 16)


def int_to_buf(num):
    """Converts the given buffer to a decimal form, ready for RSA operations.

    Args:
        buf (bytearray): the buffer to be converted

    Returns int
    """
    # convert the string to hexadecimal
    num_hex = "%x" % num
    if len(num_hex) % 2 != 0:
        num_hex = "0" + num_hex

    # Now, convert the hexadecimal form to a binary one.

    if sys.version < '3':
        chr_to_buf_f = bytearray
    else:
        chr_to_buf_f = bytes

    num_bin = chr_to_buf_f()

    for i in range(int(len(num_hex)/2)):
        chunk = num_hex[i*2:(i+1)*2]
        num_bin += chr_to_buf_f([int(chunk, 16)])

    return num_bin


def RSA_decrypt(c_bin, n=otserv_n):
    """Decrypts an RSA-encrypted message with an OpenTibia key.

    Args:
        c_bin (bytearray): the message to be decrypted

    Returns bytearray
    """
    c = buf_to_int(c_bin)
    # z = c^d % n. pow(c,d,n) is way faster than z = c**d % n.
    z = pow(c, d, n)
    return int_to_buf(z)


def RSA_encrypt(m_bin, n=tibia_n, e=65537):
    """Encrypts a message using RSA algorithm with a key from the second
    argument (defaults to real Tibia key version 8.61+).

    Args:
        m_bin (bytearray): the message to be encrypted
        n (int): the public key used for encryption (default to real Tibia key)

    Return bytearray
    """
    # return c = m^e mod n
    m = buf_to_int(m_bin)
    c = pow(m, e, n)
    return int_to_buf(c)

if __name__ == "__main__":

    if len(sys.argv) <= 1:
        sys.exit("Usage: RSA.py <filename> <optional offset>")

    # Switch stdout to binary mode so that Python 3 doesn't complain
    import os
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'wb', 0)

    buf = bytearray(open(sys.argv[1], "rb").read())
    offset = 23
    if len(sys.argv) > 2:
        offset = int(sys.argv[2])
    decrypted = RSA_decrypt(buf[offset:offset+128])

    if decrypted[1] != 0:
        # Try to guess the offset.
        for offset in range(len(buf)):
            decrypted = RSA_decrypt(buf[offset:offset+128])
            sys.stderr.write("Trying %d.\n" % offset)
            if decrypted[1] == 0:
                sys.stderr.write("Try %d.\n" % offset)
                break
    else:
        sys.stdout.write(decrypted)
