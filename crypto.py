#!/usr/bin python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, Inc. All rights reserved.

Crypto functions
"""


import base64
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.exceptions import InvalidTag, InvalidKey, InvalidSignature
from cryptography.hazmat.backends import default_backend

def derive_key(password, mcf='', bits=256):
    """ Derive key using PBKDF2 (Password-Based Key Derivation Function2, PKCS #5 v2.0)
        Accepts MCF format $pbkdf2$100000$salt$keydata for validation
        Use $pbkdf2$100000$salt$$ for key generation with specific iterations and/or salt
        Returns MCF for successful validation (or creation), returns '' for error
    Args:
        user password
        MCF formatted value, leave off or empty to create initial
        bits in key
    Return:
        MCF formatted value
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

def scrypt_key(password, mcf='', bits=512):
    """
        RFC 7914 recommends values of r=8 and p=1 while scaling n as appropriate for your system.
        The scrypt paper suggests a minimum value of n=2**14 for interactive logins (t < 100ms),
        or n=2**20 for more sensitive files (t < 5s).
    """
    if len(mcf) == 0:
        salt = os.urandom(16) # NIST SP 800-132 recommends 128-bits or longer
        cost = 2**14
        kdf = Scrypt(
            salt=salt,
            length=bits/8,
            n=cost,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(password)
    # Verify key, or derive with specific iterations and/or salt
    elif mcf[0] == '$':
        fields = mcf.split('$')
        if len(fields) > 4 and fields[1] == 'scrypt':
            if len(fields[2]) == 0:
                cost = 2**14
            else:
                cost = int(fields[2])
            if len(fields[3]) == 0:
                salt = os.urandom(16)
            else:
                salt = base64.b64decode(fields[3])
            kdf = Scrypt(
                salt=salt,
                length=bits/8,
                n=cost,
                r=8,
                p=1,
                backend=default_backend()
            )
            try:
                kdf.verify(password, base64.b64decode(fields[4]))
            except InvalidKey:
                return ''
    return '$scrypt$' + str(cost) + '$' + base64.b64encode(salt) + '$' + base64.b64encode(key)

def hkdf_key(key, info, salt=None):
    """ HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
    Args:
        Key material
        Application specific context information
        Salt to randomize the KDF’s output, optional, but highly recommended and should be 32 bytes
    Return:
        Derived key
    """
    if salt is None:
        salt = os.urandom(32)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(key)

def generate_ec(curve=ec.SECP256R1()):
    """ Generate an EC keypair with a default curve NIST P-256
    Args:
        curve
    Return:
        private key
    """
    ec_key = ec.generate_private_key(curve, default_backend())
    return ec_key

def get_ec_public(ec_key):
    """ Get the EC public key from the private key in PEM format
    Return:
        public key in PEM format
    """
    public_key = ec_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    return pem

def load_ec_public(pem):
    """ Load EC public key from PEM
    Args:
        PEM format public key
    Return:
        EC public key
    """
    try:
        ec_key = serialization.load_pem_public_key(pem, backend=default_backend())
    except ValueError as inst:
        print inst
    return ec_key

def load_ec_private(pem, password=None):
    """ Load EC private key from PEM
    Args:
        PEM format private key
    Return:
        EC private key
    """
    try:
        ec_key = serialization.load_pem_private_key(pem, password, backend=default_backend())
    except (ValueError, TypeError) as inst:
        print inst
    return ec_key

def compute_ecdh_secret(ec_key, peer_public_key):
    """ Compute the ECDH shared secret
    Args:
        Peer's public key
    Return:
        shared secret for key derivation
    """
    secret = ec_key.exchange(ec.ECDH(), peer_public_key)
    return secret

def encrypt_ecdh(ec_key, pub_pem, payload, other_info):
    """ Encrypt a payload using ECDH shared secret to derive AES256-GCM key
    Args:
        My private key
        Peer's public key
        Payload to encrypt
        Application specific context information
    Return:
        Encrypted payload
    """
    peer_public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    secret = compute_ecdh_secret(ec_key, peer_public_key)
    ckdf = ConcatKDFHash(
        algorithm=hashes.SHA256(), length=32, otherinfo=other_info, backend=default_backend())
    key = ckdf.derive(secret)
    nonce = os.urandom(12)
    ciphertext = nonce + encrypt_aes_gcm(key, nonce, payload, other_info)
    return ciphertext

def decrypt_ecdh(ec_key, pub_pem, payload, other_info):
    """ Decrypt a payload using ECDH shared secret to derive AES256-GCM key
    Args:
        My private key
        Peer's public key
        Payload to decrypt
        Application specific context information
    Return:
        Decrypted payload
    """
    peer_public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    secret = compute_ecdh_secret(ec_key, peer_public_key)
    ckdf = ConcatKDFHash(
        algorithm=hashes.SHA256(), length=32, otherinfo=other_info, backend=default_backend())
    key = ckdf.derive(secret)
    plaintext = decrypt_aes_gcm(key, payload[:12], payload[12:])
    return plaintext

def sign_ecdsa(ec_key, message):
    """ Use ECDSA to sign message
    Args:
        My private key
        Message to sign
    Return:
        signature
    """
    signer = ec_key.signer(ec.ECDSA(hashes.SHA256()))
    signer.update(message)
    signature = signer.finalize()
    return signature

def verify_ecdsa(ec_key, signature, message):
    """ Use ECDSA to verify signed message
    Args:
        Peer's public key
        Signature of message
        Message to verify
    Return:
        true if verification succeeds
    """
    try:
        verifier = ec_key.verifier(signature, ec.ECDSA(hashes.SHA256()))
        verifier.update(message)
        ret = verifier.verify()
        return ret
    except InvalidSignature as inst:
        print inst
        return False

def hash_sha1(message):
    """ Hash using SHA-1
    Args:
        message
    Return:
        digest
    """
    if isinstance(message, unicode):
        message = message.encode('utf-8')
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(message)
    return digest.finalize()

def hash_sha256(message):
    """ Hash using SHA-256
    Args:
        message
    Return:
        digest
    """
    if isinstance(message, unicode):
        message = message.encode('utf-8')
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
    if isinstance(key, unicode):
        key = key.encode('utf-8')
    if isinstance(message, unicode):
        message = message.encode('utf-8')
    digest = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    digest.update(message)
    return digest.finalize()

def decrypt_aes_gcm(key, initial_value, cipher_text, aad=None):
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

def encrypt_aes_gcm(key, initial_value, plain_text, aad=None):
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

