#!/usr/bin python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2017 Alan Frost, Inc. All rights reserved.

Utility methods
"""

from datetime import datetime
import struct
import os
import base64
import re
import string
import time
import uuid
import pytz
import simplejson as json
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.twofactor import InvalidToken
from crypto import derive_key, hkdf_key, encrypt_aes_gcm, decrypt_aes_gcm, hash_sha256, hmac_sha256

# HOTP https://tools.ietf.org/html/rfc4226
# TOTP https://tools.ietf.org/html/rfc6238

HKDF_SALT = base64.b64decode('MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXY=')
HDKF_INFO = 'frosty.alan'
HMAC_INFO = 'FROSTY'

def generate_uuid():
    """ Generate a UUID, urn:uuid:239b6f01-51cf-4901-9af3-881f26a99f21
    """
    return uuid.uuid4().urn

# Bitcoin compatible base58 encoding
B58ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58encode_int(number, default_one=True):
    """ Encode an integer using base58
    Args:
        number: integer toi encode
    Return:
        base58 encoded string
    """
    if not number and default_one:
        return B58ALPHABET[0]
    encoded = ""
    while number:
        number, idx = divmod(number, 58)
        encoded = B58ALPHABET[idx] + encoded
    return encoded


def base58encode(source):
    """Encode a string using base58
    Args:
        string: to encode
    Return:
        base58 encoded string
    """
    if not isinstance(source, bytes):
        raise TypeError("a bytes-like object is required, not '%s'" %
                        type(string).__name__)

    pad = len(source)
    source = source.lstrip(b'\0')
    pad -= len(source)

    # Python 2.7 or 3 require different way to construct integer array
    iseq = lambda s: [ord(ordinal) for ordinal in s] if bytes == str else lambda s: s

    pos, acc = 1, 0
    for char in iseq(reversed(source)):
        acc += pos * char
        pos = pos << 8

    result = base58encode_int(acc, default_one=False)

    return B58ALPHABET[0] * pad + result

def base58decode_int(source):
    """ Decode a base58 encoded string as an integer
    Args:
        source: string to decode
    Return:
        integer value
    """

    if not isinstance(source, str):
        source = source.decode('ascii')

    decimal = 0
    for char in source:
        decimal = decimal * 58 + B58ALPHABET.index(char)
    return decimal


def base58decode(source):
    """ Decode a base58 encoded string
    Args:
        source: string to decode
    Return:
        string value
    """

    if not isinstance(source, str):
        source = source.decode('ascii')

    if not isinstance(source, str):
        raise TypeError("a source-like object is required (also bytes), not '%s'" %
                        type(source).__name__)

    origlen = len(source)
    source = source.lstrip(B58ALPHABET[0])
    newlen = len(source)

    acc = base58decode_int(source)

    result = []
    while acc > 0:
        acc, mod = divmod(acc, 256)
        result.append(mod)

    # Python 2.7 or 3 require different way to construct byte array
    bseq = lambda s: ''.join([chr(char) for char in s]) if bytes == str else bytes

    return b'\0' * (origlen - newlen) + bseq(reversed(result))


def base58encode_check(source):
    """ Encode a string using Base58 with a 4 character checksum
    Args:
        string: to encode
    Return:
        base58 encoded string
    """

    digest = hash_sha256(hash_sha256(source))
    return base58encode(source + digest[:4])

def base58decode_check(source):
    """ Decode and verify the checksum of a base58 encoded string
    Args:
        source: string to decode
    Return:
        string value
    """

    result = base58decode(source)
    result, check = result[:-4], result[-4:]
    digest = hash_sha256(hash_sha256(result))

    if check != digest[:4]:
        raise ValueError("Invalid checksum")

    return result

def preset_password(username, password):
    """ Preset password for a new user or password reset. HMAC is used to protect the actual password so
        that when passed from browser/app the password is not in clear text, and also ensures that 2 users
        with the same password do not pass the same value.
    Args:
        username
        password
    Return:
        mcf formatted entry for server side authentication
    """
    hashword = base64.b16encode(hmac_sha256(username, password)).lower()
    return derive_key(hashword)

def create_signed_request(secret, method, path, params, time_stamp):
    """ Create a signed HTTP request
    Args:
        shared secret
        HTTP method (GET, PUT...)
        path - HTTP request path with leading slash, e.g., '/api/camera.update'
        params - JSON for POST/PUT/PATCH, query string for GET/DELETE
        time stamp of request as Unix timestamp (integer seconds since Jan 1, 1970 UTC)
    """
    algorithm = 'HMAC_SHA256'
    key = get_hmac_signing_key(secret, str(time_stamp))
    param_hash = base64.b16encode(hash_sha256(params))
    msg = algorithm + '\n' + str(time_stamp) + '\n' + method + '\n' + path + '\n' + param_hash
    signature = base64.b16encode(hmac_sha256(key, msg))
    return signature
    #authorization_header = algorithm + ' ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
    #if method == 'POST' or method == 'PUT' or method == 'PATCH':
    #    headers = {'Content-Type':content_type,
    #               'X--Date':time_stamp,
    #               'Authorization':authorization_header}

def validate_signed_request(secret, method, path, params, time_stamp, signature):
    """ Validate a signed HTTP request
    Args:
        shared secret
        HTTP method (GET, PUT...)
        path - HTTP request path with leading slash, e.g., '/api/camera.update'
        params - JSON for POST/PUT/PATCH, query string for GET/DELETE
        time stamp of request as Unix timestamp (integer seconds since Jan 1, 1970 UTC)
        signature to validate
    """

    if not re.match(r'[0-9a-fA-F]{64}', signature):
        return False

    time_now = int((datetime.now(tz=pytz.utc) -
                    datetime(1970, 1, 1, tzinfo=pytz.utc)).total_seconds())
    time_diff = time_now - time_stamp
    if time_diff > 450 or time_diff < -450:
        return False
    algorithm = 'HMAC_SHA256'
    key = get_hmac_signing_key(secret, str(time_stamp))
    param_hash = base64.b16encode(hash_sha256(params))
    msg = algorithm + '\n' + str(time_stamp) + '\n' + method + '\n' + path + '\n' + param_hash
    signed = base64.b16encode(hmac_sha256(key, msg))
    return signed == signature


def get_hmac_signing_key(key, time_stamp):
    """ Get a unique signing key from shared secret and time stamp
    Args:
        shared secret
        time stamp
    Return:
        32 byte key
    """
    return hmac_sha256(HMAC_INFO + key, time_stamp)

def encrypt_pii(secret, params):
    """ Encrypt PII parameters
    Args:
        secret: to derive key from
        params: dictionary
    Returns:
        cipher text: bytes
    """
    iv = os.urandom(12)
    key = hkdf_key(secret, HDKF_INFO, HKDF_SALT)
    cipher_text = iv + encrypt_aes_gcm(key, iv, json.dumps(params))
    return cipher_text

def decrypt_pii(secret, cipher_text):
    """ Decrypt PII parameters
    Args:
        secret: to derive key from
        cipher text: bytes
    Returns:
        params: dictionary
    """
    key = hkdf_key(secret, HDKF_INFO, HKDF_SALT)
    plain_text = decrypt_aes_gcm(key, cipher_text[:12], cipher_text[12:])
    try:
        params = json.loads(plain_text)
        return params
    except TypeError:
        pass
    return None

def generate_otp_secret():
    """ Generate a Google authenticator compatible secret code for either HOTP or TOTP
    Return:
        secret: 16 character base32 secret (80 bit key)
    """
    return base64.b32encode(os.urandom(10))

def verify_hotp_code(secret, code, counter):
    """ Validate a Google authenticator compatible HOTP code
    Args:
        secret: 16 character base32 secret
        code: 6 digit code that expires in 30 seconds
        counter: matching integer value
    Return:
        True if validation successful
    """
    correct_counter = None

    key = base64.b32decode(secret)
    hotp = HOTP(key, 6, SHA1(), backend=default_backend(), enforce_key_length=False)
    for count in range(counter, counter + 3):
        try:
            hotp.verify(code, count)
            correct_counter = count
            break
        except InvalidToken:
            pass

    return correct_counter

def generate_hotp_code(secret, counter):
    """ Generate a Google authenticator compatible HOTP code
    Args:
        secret: 16 character base32 secret (80 bit key)
        counter: unique integer value
    Return:
        code: 6 digit one time use code
    """

    key = base64.b32decode(secret)
    hotp = HOTP(key, 6, SHA1(), backend=default_backend(), enforce_key_length=False)
    hotp_value = hotp.generate(counter)
    return hotp_value

def generate_hotp_uri(secret, counter, email):
    """ Generate a Google authenticator compatible QR code provisioning URI
    Args:
        secret: 16 character base32 secret
        counter: unique integer value
        email: Authenticator email address
    Return:
        URI: otpauth://hotp/alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=0&issuer=FROSTY
    """
    key = base64.b32decode(secret)
    hotp = HOTP(key, 6, SHA1(), backend=default_backend(), enforce_key_length=False)
    return hotp.get_provisioning_uri(email, counter, 'FROSTY')

def generate_totp_code(secret):
    """ Generate a Google authenticator compatible TOTP code
    Args:
        secret: 16 character base32 secret
    Return:
        code: 6 digit code that expires in 30 seconds
    """
    key = base64.b32decode(secret)
    totp = TOTP(key, 8, SHA1(), 30, backend=default_backend(), enforce_key_length=False)
    time_value = time.time()
    totp_value = totp.generate(time_value)
    return totp_value

def verify_totp_code(secret, code):
    """ Validate a Google authenticator compatible TOTP code
    Args:
        secret: 16 character base32 secret
        code: 6 digit code that expires in 30 seconds
    Return:
        True if validation successful
    """
    key = base64.b32decode(secret)
    totp = TOTP(key, 8, SHA1(), 30, backend=default_backend(), enforce_key_length=False)
    time_value = time.time()
    try:
        totp.verify(code, time_value)
        return True
    except InvalidToken:
        pass
    return False

def generate_totp_uri(secret, email):
    """ Generate a Google authenticator compatible QR provisioning URI
    Args:
        secret: 16 character base32 secret
        email: Authenticator email address
    Return:
        URI for QR code: otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=FROSTY
    """
    key = base64.b32decode(secret)
    totp = TOTP(key, 8, SHA1(), 30, backend=default_backend(), enforce_key_length=False)
    return totp.get_provisioning_uri(email, 'FROSTY')

def generate_code(secret):
    """ Generate a random access code, with HMAC, base64 encoded
    """
    code = os.urandom(28)
    access_code = base64.b64encode(code + hmac_sha256(secret, code), '-_')
    return access_code

def validate_code(secret, access_code):
    """ Validate an access code
    """
    # The access code may come in as unicode, which has to be converted before b64decode
    if isinstance(access_code, unicode):
        code = access_code.encode('utf-8')
    else:
        code = access_code
    try:
        code = base64.b64decode(code, '-_')
        return code[28:] == hmac_sha256(secret, code[:28])
    except TypeError:
        return False

def get_access_id(access_code):
    """ Hash the access code and generate a DB index
    Args:
        access_code: string
    """
    # The access code may come in as unicode, which has to be converted before b64decode
    if isinstance(access_code, unicode):
        code = access_code.encode('utf-8')
    else:
        code = access_code
    try:
        hashed = hash_sha256(base64.b64decode(code, '-_'))
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

def get_user_agent(request):
    """ Get the remote user agent, quick check for common browsers
    Args:
        request: HTTP request
    """
    if 'User-Agent' in request.headers:
        user_agent = request.headers.get('User-Agent')
        #print user_agent
        if 'Dolphin' in user_agent:
            remote_agent = 'Dolphin'
        elif 'Opera' in user_agent or 'OPR' in user_agent:
            remote_agent = 'Opera'
        elif 'Firefox' in user_agent or 'FxiOS' in user_agent:
            remote_agent = 'Firefox'
        elif 'Chrome' in user_agent:
            remote_agent = 'Chrome'
        elif 'bot' in user_agent or 'Bot' in user_agent or 'spider' in user_agent:
            remote_agent = 'Bot'
        elif 'Safari' in user_agent:
            remote_agent = 'Safari'
        else:
            remote_agent = 'Other'

        if 'Linux' in user_agent:
            remote_agent += ' Linux'
        elif 'iPad' in user_agent:
            remote_agent += ' iPhone'
        elif 'iPhone' in user_agent:
            remote_agent += ' iPhone'
        elif 'Mac OS' in user_agent:
            remote_agent += ' Mac OS'
        elif 'Windows' in user_agent:
            remote_agent += ' Windows'
    else:
        remote_agent = "No user agent"
    return remote_agent

def merge_dicts(dict1, dict2):
    """ Recursively merge dict2 into dict1
    Args:
        dict1 is the master copy
        dict2 contains the new/updated fields
    Returns:
        True if successful
    """
    if not isinstance(dict1, dict) or not isinstance(dict2, dict):
        return False
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
    address = base64.b32encode(code + hmac_sha256(secret, code + identifier)[:5])
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
        code = address.encode('utf-8')
    else:
        code = address
    try:
        code = base64.b32decode(code)
        digest = hmac_sha256(secret, code + identifier)
        return code[5:] == digest[:5]
    except TypeError:
        return False

def generate_random_int():
    """ Generate a random 32 bit integer
    """
    values = struct.unpack("I", os.urandom(4))
    return values[0]

def generate_random58_id(size=8):
    """ Generate a random id encoded as base58
    """
    return base58encode(os.urandom(size * 11 / 8))

def generate_random58_valid(size=8):
    """ Generate a random id encoded as base58 with 4 byte checksum
    """
    return base58encode_check(os.urandom(size * 11 / 8))


def generate_id(user):
    """ Hash user name to create a unique identifier
    Args:
        user name
    Returns:
        Generated 48 character base32 user id
    """
    if isinstance(user, unicode):
        user = user.encode('utf-8')
    digest = hash_sha256(user)
    return base64.b32encode(digest[0:30])

def generate_user_id(key, user):
    """ Use an HMAC to generate a user id to keep DB more secure. This prevents someone from
        looking up users by name or even hash of user name, without using the official API.
    Args:
        HMAC key
        user name
    Returns:
        Generated 48 character base32 user id
    """
    digest = hmac_sha256(key, user)
    return base64.b32encode(digest[0:30])

def contains_only(input_chars, valid_chars):
    """ Check a string to see if it contains only the specified character set
    """
    all_chars = string.maketrans('', '')
    has_only = lambda s, valid_chars: not s.translate(all_chars, valid_chars)
    return has_only(input_chars, valid_chars)

def main():
    """ Unit tests
    """
    print generate_uuid()
    print preset_password('yuki', 'Madman12')
    print generate_user_id('server secret to derive user id hmac key', 'yuki')

    secret = 'Poyj3ZIdLcSEjWagFBj3VQ9x'
    time_stamp = int((datetime.now(tz=pytz.utc) -
                      datetime(1970, 1, 1, tzinfo=pytz.utc)).total_seconds())
    old_time = 1477951388
    sig = create_signed_request(secret, 'GET', 'api/camera.info', 'camera=02:34', time_stamp)
    if validate_signed_request(secret, 'GET', 'api/camera.info', 'camera=02:34', time_stamp, sig):
        print 'validated HTTP request'
    if not validate_signed_request(secret, 'GET', 'api/camera.info', 'camera=42:34', time_stamp, sig):
        print 'invalid HTTP request parmscheck passed'
    if not validate_signed_request(secret, 'POST', 'api/camera.info', 'camera=42:34', time_stamp, sig):
        print 'invalid HTTP request method check passed'
    if not validate_signed_request(secret, 'POST', 'api/camera.info', 'camera=02:34', old_time, sig):
        print 'invalid HTTP old timerequest check passed'

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

    confirm_tok = generate_token('yuki@gmail.com', secret, 'confirm')
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

    confirm_tok = generate_timed_token('yuki@gmail.com', secret, 'confirm')
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
    counter = 666
    code = generate_hotp_code(secret, counter)
    counter = verify_hotp_code(secret, code, counter)
    if counter == 666:
        print 'HOTP validated', code
    if verify_hotp_code(secret, code, 667) is not None:
        print 'HOTP invalidated', code
    counter = verify_hotp_code(secret, code, 664)
    print counter
    print generate_hotp_uri(secret, 666, 'yuki@gmail.com')

    code = generate_totp_code(secret)
    if verify_totp_code(secret, code):
        print 'TOTP validated', code
    print generate_totp_uri(secret, 'yuki@gmail.com')

    pii = encrypt_pii('madman', {'email':'yuki@gmail.com', 'phone':'7754321238'})
    print decrypt_pii('madman', pii)

    code = generate_address_code(secret, 'yuki:dev1')
    if validate_address_code(secret, code, 'yuki:dev1'):
        print 'Address code validated', code

    code = base58encode("secrect code")
    print base58decode(code)
    code = base58encode_check("secrect code")
    print base58decode_check(code)
    print generate_random58_id(8)
    print generate_random58_id(12)
    print generate_random58_valid(8)
    b58code = generate_random58_valid(12)
    code = base58decode_check(b58code)
if __name__ == '__main__':
    main()
