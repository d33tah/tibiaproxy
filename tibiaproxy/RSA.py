from NetworkMessage import NetworkMessage


def toint(x):
    return int(x.replace('\n', ''))

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
    without_0x = hex(ord(i)).replace('0x', '')
    space_padded = "%2s" % without_0x
    zero_padded = space_padded.replace(' ', '0')
    return zero_padded


class RSA:

    @classmethod
    def decrypt(cls, msg):
        c_bin = msg.buf[msg.pos:]
        c_hex = ''.join([byte_to_hex(i) for i in c_bin])

        c = int(c_hex, 16)

        n = p*q
        z = pow(c, d, n)

        z_hex = "%x" % z
        if len(z_hex) % 2 != 0:
            z_hex = "0" + z_hex

        z_bin = ""
        for i in range(len(z_hex)/2):
            chunk = z_hex[i*2:(i+1)*2]
            z_bin += chr(int(chunk, 16))

        return NetworkMessage(z_bin)
