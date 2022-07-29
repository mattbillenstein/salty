#!/usr/bin/env python3

import base64
import getpass
import hashlib
import os
import sys

import nacl.encoding
import nacl.exceptions
import nacl.secret
import nacl.utils

# uuidgen | sha256sum | awk '{print $1}'
# you should change this if you've forked...
_SALT = b'7cbbb992db5d800238a898459dc4e25e67773b5923d2a836cef718891e5c7f1f'

# Stream encryption is just 1MiB encrypted blocks concatenated -- to decrypt we
# need to read the message plus 40 bytes for the nonce and authenticator
_STREAM_BLOCK_SIZE = 1024 * 1024
_NONCE_SIZE = nacl.secret.SecretBox.NONCE_SIZE
_AUTHENTICATOR_SIZE = 16  # can't find where this is defined in nacl
_STREAM_BLOCK_SIZE_ENCRYPTED = _STREAM_BLOCK_SIZE + _NONCE_SIZE + _AUTHENTICATOR_SIZE


class CryptoError(Exception):
    pass


def encrypt(data, password):
    if isinstance(password, str):
        password = password.encode('utf8')

    if isinstance(data, str):
        data = data.encode('utf8')

    keybytes = hashlib.pbkdf2_hmac('sha256', password, _SALT, 4)
    noncebytes = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    secretbox = nacl.secret.SecretBox(keybytes)
    try:
        return secretbox.encrypt(data, noncebytes, encoder=nacl.encoding.URLSafeBase64Encoder)
    except nacl.exceptions.CryptoError as e:
        raise CryptoError(e)


def decrypt(data, password):
    if isinstance(password, str):
        password = password.encode('utf8')

    if isinstance(data, str):
        data = data.encode('utf8')

    keybytes = hashlib.pbkdf2_hmac('sha256', password, _SALT, 4)
    secretbox = nacl.secret.SecretBox(keybytes)
    try:
        return secretbox.decrypt(data, encoder=nacl.encoding.URLSafeBase64Encoder)
    except nacl.exceptions.CryptoError as e:
        raise CryptoError(e)


def encrypt_stream(fin, fout, password):
    if isinstance(password, str):
        password = password.encode('utf8')
    keybytes = hashlib.pbkdf2_hmac('sha256', password, _SALT, 4)
    noncebytes = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    secretbox = nacl.secret.SecretBox(keybytes)
    while 1:
        data = fin.read(_STREAM_BLOCK_SIZE)
        if not data:
            break
        fout.write(secretbox.encrypt(data, noncebytes, encoder=nacl.encoding.URLSafeBase64Encoder))
    fout.flush()


def decrypt_stream(fin, fout, password):
    if isinstance(password, str):
        password = password.encode('utf8')
    keybytes = hashlib.pbkdf2_hmac('sha256', password, _SALT, 4)
    secretbox = nacl.secret.SecretBox(keybytes)
    while 1:
        data = fin.read(_STREAM_BLOCK_SIZE_ENCRYPTED)
        if not data:
            break
        fout.write(secretbox.decrypt(data, encoder=nacl.encoding.URLSafeBase64Encoder))
    fout.flush()


def encrypt_string(data, password):
    return base64.b64encode(encrypt(data, password)).decode('utf8')

def decrypt_string(data, password):
    return decrypt(base64.b64decode(data), password).decode('utf8')

def decrypt_dict(d, password):
    for k, v in list(d.items()):
        if isinstance(v, dict):
            decrypt_dict(v, password)
        elif isinstance(v, str):
            if v.startswith('NACL['):
                d[k] = decrypt_string(v[5:-1], password)

def main():
    mode = sys.argv[1]

    password = os.environ.get('PASSWORD')
    if not password:
        password = getpass.getpass()

    if len(sys.argv) > 2:
        # files on the cli, or strings
        for arg in sys.argv[2:]:
            if mode == 'e':
                with open(arg, 'rb') as fin, open(arg + '.enc', 'wb') as fout:
                    encrypt_stream(fin, fout, password)
            elif mode == 'es':
                print(encrypt_string(arg, password))
            elif mode == 'd':
                with open(arg, 'rb') as fin, open(arg.replace('.enc', ''), 'wb') as fout:
                    decrypt_stream(fin, fout, password)
            elif mode == 'ds':
                print(decrypt_string(arg, password))
    else:
        # stdin/stdout
        if mode == 'e':
            encrypt_stream(sys.stdin.buffer, sys.stdout.buffer, password)
        elif mode == 'd':
            decrypt_stream(sys.stdin.buffer, sys.stdout.buffer, password)


if __name__ == '__main__':
    main()
