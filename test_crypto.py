import os
from crypto import encrypt_aes_gcm, decrypt_aes_gcm

def test_encryption():
    print 'test_encryption'
    iv = os.rand(12)
    message = b'Hi there'
    cipher_text = encrypt_aes_gcm (key, iv, message)
    plain_text = decrypt_aes_gcm (key, iv, cipher_text)
    assert (plain_text == message)
