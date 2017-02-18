#!/usr/bin python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, Inc. All rights reserved.

Utility methods
"""

import os
import base64
import random
import time
import simplejson as json
from Crypto.Hash import SHA, SHA256, HMAC
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer
import pyotp
from crypto import derive_key, encrypt_aes_gcm, decrypt_aes_gcm

# HOTP https://tools.ietf.org/html/rfc4226
# TOTP https://tools.ietf.org/html/rfc6238

def encrypt_pii(params, password):
    """ Encrypt PII parameters
    Args:
        params: dictionary
        password: to derive key from
    Returns:
        mcf encoded ciphertext for insert into DB
    """
    pjson = json.dumps(params)
    pad = len(pjson) % 16
    if pad > 0:
        pad = 16 - pad
    pii = pjson + '               '[0:pad]
    return encrypt_secret(pii, password)

def decrypt_pii(db_secret, password):
    """ Decrypt PII parameters
    Args:
        mcf encoded ciphertext from DB
        password: to derive key from
    Returns:
        params: dictionary
    """
    pii = decrypt_secret(db_secret, password)
    try:
        params = json.loads(pii.strip())
        return params
    except TypeError:
        return None

def encrypt_secret(secret, password):
    """ Encrypt secret with AES-GCM key derived from password
    Args:
        secret: to be encrypted
        password: to derive key from
    Return:
        encrypted secret for insert into server side DB
        $pbkdf2$500$2gi/BRPAZ29QI71IOiFQfw==$qdc+0X1ga/NgZR/OZZR+7N8kHqJxK25Gq2XfLu4jGREsBFR5$
    """
    if len(password) >= 6 and len(secret) >= 4:
        salt = base64.b64encode(os.urandom(16))
        mcf = '$pbkdf2$2500$' + salt + '$$'
        mcf = derive_key(password, mcf, 256)
        fields = mcf.split('$')
        if len(fields) > 4 and fields[1] == 'pbkdf2':
            key = base64.b64decode(fields[4])
            cipher_text = encrypt_aes_gcm(key, secret, base64.b64decode(salt))
            db_secret = '$pbkdf2$500$' + salt + '$' + base64.b64encode(cipher_text) +'$'
            return db_secret

def decrypt_secret(db_secret, password):
    """ Decrypt secret with AESHMAC key derived from password
    Args:
        password: to derive key from
        encrypted secret from server side DB
        $pbkdf2$500$2gi/BRPAZ29QI71IOiFQfw==$qdc+0X1ga/NgZR/OZZR+7N8kHqJxK25Gq2XfLu4jGREsBFR5$
    Return:
        secret: decrypted
    """
    fields = db_secret.split('$')
    if len(fields) > 4 and fields[1] == 'pbkdf2':
        rounds = fields[2]
        if len(rounds) < 4:
            rounds = '2500'
        salt = fields[3]
        mcf = '$pbkdf2$' + rounds + '$' + salt + '$$'
        mcf = derive_key(password, mcf, 256)
        kfields = mcf.split('$')
        if len(kfields) > 4 and kfields[1] == 'pbkdf2':
            key = base64.b64decode(kfields[4])
            secret = decrypt_aes_gcm(key, base64.b64decode(fields[4]), base64.b64decode(salt))
            return secret

def generate_otp_secret():
    """ Generate a Google authenticator compatible secret code for either HOTP or TOTP
    Return:
        secret: 16 character base32 secret
    """
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    return ''.join(random.choice(chars) for x in range(16))

def generate_hotp_code(secret, counter):
    """ Generate a Google authenticator compatible HOTP code
    Args:
        secret: 16 character base32 secret
        counter: unique integer value
    Return:
        code: 6 digit one time use code
    """
    hotp = pyotp.HOTP(secret)
    return hotp.at(counter)

def validate_hotp_code(secret, code, counter):
    """ Validate a Google authenticator compatible HOTP code
    Args:
        secret: 16 character base32 secret
        code: 6 digit one time use code
        counter: unique integer value
    Return:
        True if validation successful
    """
    hotp = pyotp.HOTP(secret)
    return hotp.verify(code, counter)

def generate_hotp_uri(secret, counter, email):
    """ Generate a Google authenticator compatible QR code provisioning URI
    Args:
        secret: 16 character base32 secret
        counter: unique integer value
        email: Authenticator email address
    Return:
        URI: otpauth://hotp/alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=0&issuer=IONU
    """
    hotp = pyotp.HOTP(secret)
    return hotp.provisioning_uri(email, counter, 'IONU')

def generate_totp_code(secret):
    """ Generate a Google authenticator compatible TOTP code
    Args:
        secret: 16 character base32 secret
    Return:
        code: 6 digit code that expires in 30 seconds
    """
    totp = pyotp.TOTP(secret)
    return totp.now()

def validate_totp_code(secret, code):
    """ Validate a Google authenticator compatible TOTP code
    Args:
        secret: 16 character base32 secret
        code: 6 digit code that expires in 30 seconds
    Return:
        True if validation successful
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def generate_totp_uri(secret, email):
    """ Generate a Google authenticator compatible QR provisioning URI
    Args:
        secret: 16 character base32 secret
        email: Authenticator email address
    Return:
        URI for QR code: otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=IONU
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(email, 'IONU')

def generate_code(secret):
    """ Generate a random access code, with HMAC, base64 encoded
    """
    code = os.urandom(25)
    hmac = HMAC.new(secret, code, SHA)
    access_code = base64.b64encode(code + hmac.digest(), '-_')
    return access_code

def validate_code(secret, access_code):
    """ Validate an access code
    """
    # The access code may come in as unicode, which has to be converted before b64decode
    if isinstance(access_code, unicode):
        code = access_code.encode('ascii', 'ignore')
    else:
        code = access_code
    try:
        code = base64.b64decode(code, '-_')
        hmac = HMAC.new(secret, code[:25], SHA)
        return code[25:] == hmac.digest()
    except TypeError:
        return False

def get_access_id(access_code):
    """ Hash the access code and generate a DB index
    Args:
        access_code: string
    """
    # The access code may come in as unicode, which has to be converted before b64decode
    if isinstance(access_code, unicode):
        code = access_code.encode('ascii', 'ignore')
    else:
        code = access_code
    try:
        hashed = SHA256.new(data=base64.b64decode(code, '-_')).digest()
        index = base64.b64encode(hashed[1:31], '-_')
        return index
    except TypeError:
        return None

def get_ip_address(request):
    """ Get the remote IP address if available, 'untrackable' if not
    Args:
        request: HTTP request
    """
    if 'X-Forwarded-For' in request.headers:
        remote_addr = request.headers.getlist("X-Forwarded-For")[0].rpartition(' ')[-1]
    else:
        remote_addr = request.remote_addr or 'untrackable'
    return remote_addr

def merge_dicts(dict1, dict2):
    """ Recursively merge dict2 into dict1
    """
    for key in dict2:
        if key in dict1 and isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
            merge_dicts(dict1[key], dict2[key])
        else:
            dict1[key] = dict2[key]
    return True

def merge_dicts_remove(dict1, dict2):
    """ Recursively merge dict2 into dict1, removing values from dict1 when dict2 value is None
    """
    for key in dict2:
        if key in dict1 and isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
            merge_dicts(dict1[key], dict2[key])
        elif key in dict1 and dict2[key] is None:
            del dict1[key]
        else:
            dict1[key] = dict2[key]
    return True

def generate_token(value, secret, salt):
    """ Generate a URL safe signature
        Args:
            value: string to be signed
            secret: secret key to use for signing
            salt: namespace or other known value
        Return:
            signature as string
    """
    serializer = URLSafeSerializer(secret)
    return serializer.dumps(value, salt=salt)

def validate_token(token, secret, salt):
    """ Validate a URL safe signature
        Args:
            secret: secret to use for signing
            salt: namespace or other known value
        Return:
            (validated, value): if validated == True, then value has the to be signed data
    """
    serializer = URLSafeSerializer(secret)
    try:
        return serializer.loads_unsafe(token, salt=salt)
    except:
        return (False, None)

def generate_timed_token(value, secret, salt):
    """ Generate a URL safe signature that expires
        Args:
            value: string to be signed
            secret: secret key to use for signing
            salt: namespace or other known value
        Return:
            signature as string
    """
    serializer = URLSafeTimedSerializer(secret)
    return serializer.dumps(value, salt=salt)

def validate_timed_token(token, secret, salt, expiration=3600):
    """ Validate a URL safe signature that expires
    Args:
        token: timed token to validate
        secret: secret key to use for signing
        salt: namespace or other known value
    Return:
        (validated, value): if validated == True, then value has the to be signed data
    """
    serializer = URLSafeTimedSerializer(secret)
    try:
        return serializer.loads_unsafe(token, salt=salt, max_age=expiration)
    except:
        return (False, None)

def generate_address_code(secret, identifier):
    """ Generate a random address for account, with partial HMAC, base32 encoded
    Args:
        secret: secret key to use for HMAC
        identifier: username and optionally device id
    Return:
        16 digit base32 code
    """
    code = os.urandom(5)
    hmac = HMAC.new(secret, code, SHA)
    hmac.update(identifier)
    address = base64.b32encode(code + hmac.digest()[:5])
    return address

def validate_address_code(secret, address, identifier):
    """ Validate an address code
    Args:
        secret: secret key to use for HMAC
        address: 16 digit base32 code
        identifier: username and optionally device id
    Return:
        True if the address code is valid for the user
    """
    # The address code may come in as unicode, which has to be converted before b64decode
    if isinstance(address, unicode):
        code = address.encode('ascii', 'ignore')
    else:
        code = address
    try:
        code = base64.b32decode(code)
        hmac = HMAC.new(secret, code[:5], SHA)
        hmac.update(identifier)
        return code[5:] == hmac.digest()[:5]
    except TypeError:
        return False

def generate_id(size=8, chars='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'):
    """ Generate a id, default is 8 characters base58
    """
    return ''.join(random.choice(chars) for x in range(size))

def main():
    """ Unit tests
    """
    secret = 'Poyj3ZIdLcSEjWagFBj3VQ9x'
    code = generate_code(secret)
    print code
    print get_access_id(code)
    if validate_code(secret, code):
        print 'validated'
    code = code[1:] + 'a'
    if validate_code(secret, code):
        print 'validated'
    if validate_code(secret, code[1:]):
        print 'validated'

    confirm_tok = generate_token('yuki@ionu.com', secret, 'confirm')
    print confirm_tok
    validated, value = validate_token(confirm_tok, secret, 'confirm')
    if validated:
        print value, 'confirmed'
    validated, value = validate_token(confirm_tok, secret, 'reset')
    if validated:
        print 'Error, not a reset token'
    validated, value = validate_timed_token(confirm_tok, secret, 'confirm')
    if validated:
        print 'Error, not a timed token'
    confirm_tok = confirm_tok[:-1] + 'l'
    validated, value = validate_token(confirm_tok, secret, 'confirm')
    if validated:
        print 'Error, not a reset token'

    confirm_tok = generate_timed_token('yuki@ionu.com', secret, 'confirm')
    print confirm_tok
    validated, value = validate_timed_token(confirm_tok, secret, 'confirm')
    if validated:
        print value, 'confirmed'
    validated, value = validate_token(confirm_tok, secret, 'confirm')
    if validated:
        print 'Error, this is a timed token'
    validated, value = validate_timed_token(confirm_tok, secret, 'reset')
    if validated:
        print 'Error, not a reset token'
    time.sleep(2)
    validated, value = validate_timed_token(confirm_tok, secret, 'confirm', expiration=1)
    if validated:
        print 'Error, timed token expired'

    secret = generate_otp_secret()
    code = generate_hotp_code(secret, 666)
    if validate_hotp_code(secret, code, 666):
        print 'HOTP validated', code
    print generate_hotp_uri(secret, 666, 'yuki@ionu.com')

    code = generate_totp_code(secret)
    if validate_totp_code(secret, code):
        print 'TOTP validated', code
    print generate_totp_uri(secret, 'yuki@ionu.com')

    otp = encrypt_secret(secret, 'madman')
    print decrypt_secret(otp, 'madman')
    pii = encrypt_pii({'email':'yuki@ionu.com', 'phone':'7754321238'}, 'madman')
    print decrypt_pii(pii, 'madman')

    code = generate_address_code(secret, 'yuki:dev1')
    if validate_address_code(secret, code, 'yuki:dev1'):
        print 'Address code validated', code

if __name__ == '__main__':
    main()
