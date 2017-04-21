import base64
import os
from crypto import derive_key, scrypt_key, hkdf_key, encrypt_aes_gcm, decrypt_aes_gcm, hmac_sha256

def test_encryption():
    mcf = derive_key ('Password1*')
    fields = mcf.split('$')
    newmcf = derive_key ('Password1*', '$pbkdf2$' + fields[2] + '$' + fields[3] + '$')
    assert (mcf == newmcf)

    mcf = derive_key ('Password1*', '', 128)
    fields = mcf.split('$')
    newmcf = derive_key ('Password1*', '$pbkdf2$' + fields[2] + '$' + fields[3] + '$', 128)
    assert (mcf == newmcf)

    #  Requires OpenSSL 1.1.0 or later
    #mcf = scrypt_key ('Password1*')
    #fields = mcf.split('$')
    #newmcf = scrypt_key ('Password1*', '$scrypt$' + fields[2] + '$' + fields[3] + '$')
    #assert (mcf == newmcf)

    iv = os.urandom(12)
    key = os.urandom(32)
    message = b'Hi there'
    cipher_text = encrypt_aes_gcm (key, iv, message)
    plain_text = decrypt_aes_gcm (key, iv, cipher_text)
    assert (plain_text == message)

    #salt = b'1234567890abcdefghijklmnopqrstuv'
    salt = base64.b64decode('MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXY=')
    key = hkdf_key(base64.b64decode('6EVdXfSkSX+I15ZXGCRRH4TnpBnt17ivih5Nd7DxkPQ='), b'yuki', salt)
    print base64.b64encode(key)

    key = hmac_sha256(base64.b64decode('6EVdXfSkSX+I15ZXGCRRH4TnpBnt17ivih5Nd7DxkPQ='), salt)
    print base64.b64encode(key)
    key = hmac_sha256(salt, base64.b64decode('6EVdXfSkSX+I15ZXGCRRH4TnpBnt17ivih5Nd7DxkPQ='))
    print base64.b64encode(key)

if __name__ == '__main__':
    test_encryption()
