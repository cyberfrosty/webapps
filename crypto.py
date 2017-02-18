
from Crypto.Protocol import KDF

def derive_key(self, password, mcf='', bits=256):
    """ Derive key using PBKDF2 (Password-Based Key Derivation Function2, PKCS #5 v2.0)
        Accepts MCF format $pbkdf2$2500$salt$keydata or base64/hex encoded raw keydata
        Pass in keydata for password matching, $pbkdf2$2500$salt$$ for key generation
        Returns MCF for successful validation (or creation), returns '' for error
    Args:
        user password
    MCF formatted or base64/hex encoded current value, leave off or empty to create initial
        bits in key
    Return:
        MCF formatted current value
    """

    aes_key = ''
    salt = ''
    count = 2500
    if len(mcf) == 0:
        salt = os.urandom(8)
        aes_key = KDF.PBKDF2(password, salt, bits/8, count)
    elif mcf[0] == '$':
        fields = mcf.split('$')
        if len(fields) > 4 and fields[1] == 'pbkdf2':
            if len(fields[2]) == 0:
                count = 2500
            else:
                count = int(fields[2])
            if len(fields[3]) == 0:
                salt = os.urandom(8)
            else:
                salt = base64.b64decode(fields[3])
            aes_key = KDF.PBKDF2(password, salt, bits/8, count)
            # If matching value specified, check it
            if len(fields[4]) == 44:
                value = base64.b64decode(fields[4])
                if aes_key != value:
                    print 'password match failed'
                    return ''
    elif len(mcf) == 44 or len(mcf) == 64:
        hex_salt = '49734F616E6C5574'
        salt = base64.b16decode(hex_salt)
        aes_key = KDF.PBKDF2(password, salt, bits/8, count)
        if len(mcf) == 44:
            value = base64.b64decode(mcf)
            if aes_key != value:
                print 'password match failed'
                return ''
        else:
            value = base64.b16decode(mcf)
            if aes_key != value:
                print 'password match failed'
                return ''
    else:
        print 'unrecognized mcf'
        return ''
    return '$pbkdf2$' + str(count) + '$' + base64.b64encode(salt) + '$' + base64.b64encode(aes_key)

