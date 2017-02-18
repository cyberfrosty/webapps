#!/usr/bin python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, Inc. All rights reserved.

Crypto functions
"""


import base64
import os
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend

def derive_key(password, mcf='', bits=256):
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

    key = ''
    salt = ''
    iterations = 100000
    # Derive key
    if len(mcf) == 0:
        salt = os.urandom(16) # NIST SP 800-132 recommends 128-bits or longer
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=bits/8,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password)
    # Verify key, or derive with specific iterations and/or salt
    elif mcf[0] == '$':
        fields = mcf.split('$')
        if len(fields) > 4 and fields[1] == 'pbkdf2':
            if len(fields[2]) == 0:
                iterations = 100000
            else:
                iterations = int(fields[2])
            if len(fields[3]) == 0:
                salt = os.urandom(16)
            else:
                salt = base64.b64decode(fields[3])
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=bits/8,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            key = kdf.derive(password)
            # If matching value specified, check it
            if len(fields[4]) > 20: # Expecting at least 128 bit key
                value = base64.b64decode(fields[4])
                if key != value:
                    print 'password match failed'
                    return ''
    else:
        return ''
    return '$pbkdf2$' + str(iterations) + '$' + base64.b64encode(salt) + '$' + base64.b64encode(key)

def hash_sha256(message):
    """ Hash using SHA-256
    Args:
        message
    Return:
        digest
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    return digest.finalize()

def hmac_sha256(key, message):
    """ HMAC using SHA-256
    Args:
        key
        message
    Return:
        digest
    """
    digest = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    digest.update(message)
    return digest.finalize()

def decrypt_aes_gcm(key, cipher_text, initial_value, aad=None):
    """ Decrypt using AES-GCM
    Args:
        aes encryption key
        cipher text and tag
        initial value
        additional authenticated data
    Return:
        (true, plain text)
    """

    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(initial_value, cipher_text[-16:]),
        backend=default_backend()
    ).decryptor()
    if aad:
        cipher.authenticate_additional_data(aad)
    try:
        plaintext = cipher.update(cipher_text[:-16]) + cipher.finalize()
        return plaintext
    except InvalidTag:
        print 'GCM decryption failed'

def encrypt_aes_gcm(key, plain_text, initial_value, aad=None):
    """ Encrypt using AES-GCM
    Args:
        aes encryption key
        plain_text to be encrypted
        initial value
        additional authenticated data
    Return:
        cipher text
    """

    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(initial_value),
        backend=default_backend()
    ).encryptor()
    if aad:
        cipher.authenticate_additional_data(aad)
    ciphertext = cipher.update(plain_text) + cipher.finalize()
    return ciphertext + cipher.tag

