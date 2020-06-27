#!/usr/bin/env python3
# based on keyble - a coffe script implementation of the keyble
# License ISC
#
# a close 1:1 copy from the `keyble` code (coffe script code - isc)
# TODO: check if we can use AES/ECB with PKCS7 padding.
# TODO: do we have to support the 'other' encryption methods? In theory there might be other encryption than this one

import math
from struct import pack, unpack
from Crypto.Cipher import AES

def _aes_encrypt(key, data):
    """ encrypt data with key using aes 128 ecb """
    mode = AES.MODE_ECB
    encryptor = AES.new(bytes(key), mode)
    return bytearray(encryptor.encrypt(bytes(data)))

def _pad_array(data, step, minimum):
    _data = bytearray(data)

    length = _padding_length(len(_data), step, minimum)
    if len(_data) != length:
        _data.extend(0x0 * length - (len(_data)))
    return _data

def _padding_length(length, step, minimum):
    # Returns the smallest value equal or larger than <value> that equals (<minimum> + (x * <step>)) for a natural number x
    return math.ceil((length - minimum) / step) * step + minimum

def compute_nonce(message_type_id, session_open_nonce, security_counter):
    nonce = pack('<BQBBH', message_type_id, session_open_nonce, 0, 0, security_counter)
    return nonce

def xor_array(data, xor_data, xor_data_offset=0):
    """ XOR @data with the @xor_data """
    xorred = bytearray()
    for i in range(len(xorred)):
        xorred.append(data[i] ^ xor_data[(xor_data_offset + i) % len(xor_data)])
    return xorred

def crypt_data(message_data, message_type_id, session_open_nonce, security_counter, key):
    """ message_data does not contain the message_type_id """
    nonce = compute_nonce(message_type_id, session_open_nonce, security_counter)
    xor_data = bytearray()
    for index in range(_padding_length(len(message_data), 16, 0) // 16):
        tmp = bytearray()
        tmp.append(0x01)
        tmp.extend(nonce)
        tmp.extend(pack('<H', index + 1))
        xor_data.append(_aes_encrypt(key, tmp))
    return xor_array(message_data, xor_data)

def compute_authentication_value(message_data, message_type_id, session_nonce, security_counter, user_key):
    nonce = compute_nonce(message_type_id, session_nonce, security_counter)
    length = len(message_data)

    padded_length = _padding_length(length, 16, 0)
    padded_data = _pad_array(message_data, 16, 0)

    tmp = bytearray()
    tmp.append(0x09)
    tmp.extend(nonce)
    tmp.extend(pack('<H', padded_length))
    encrypted_xor_data = _aes_encrypt(user_key, tmp)

    for i in range(0, padded_length, 16):
        encrypted_xor_data = _aes_encrypt(user_key, xor_array(encrypted_xor_data, padded_data, i))

    # xor array
    tmp = bytearray()
    tmp.append(0x01)
    tmp.extend(nonce)
    tmp.append(0x00)
    tmp.append(0x00)
    tmp.extend(pack('<H', padded_length))
    return xor_array(
        encrypted_xor_data[0:4],
        _aes_encrypt(user_key, tmp)
    )

def encrypt_message(message, remote_nonce, local_security_counter, user_key):
    encoded = message.encode()
    body = encoded[1:]
    msg_type_id = encoded[0]

    padded_body = _pad_array(body, 15, 8)

    _crypt_data = crypt_data(padded_body, msg_type_id, remote_nonce, local_security_counter, user_key)
    auth = compute_authentication_value(padded_body, msg_type_id, remote_nonce, local_security_counter, user_key)

    tmp = bytearray()
    tmp.extend(_crypt_data)
    tmp.extend(pack('<H', local_security_counter))
    tmp.extend(auth)

    return tmp
