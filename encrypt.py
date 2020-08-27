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
        _data.extend(bytearray(length - (len(_data))))
    return _data

def _padding_length(length, step, minimum):
    # Returns the smallest value equal or larger than <value> that equals (<minimum> + (x * <step>)) for a natural number x
    return math.ceil((length - minimum) / step) * step + minimum

def compute_nonce(message_type_id, session_open_nonce, security_counter):
    nonce = pack('>BQBBH', message_type_id, session_open_nonce, 0, 0, security_counter)
    return nonce

def xor_array(data, xor_data, xor_data_offset=0):
    """ XOR @data with the @xor_data """
    xorred = bytearray()
    for i in range(len(data)):
        xorred.append(data[i] ^ xor_data[(xor_data_offset + i) % len(xor_data)])
    return xorred

def crypt_data(message_data, message_type_id, session_open_nonce, security_counter, key):
    """ message_data does not contain the message_type_id """
    nonce = compute_nonce(message_type_id, session_open_nonce, security_counter)
    xor_data = bytearray()
    # do 16 byte at once
    for index in range(_padding_length(len(message_data), 16, 0) // 16):
        tmp = bytearray()
        tmp.append(0x01)
        tmp.extend(nonce)
        tmp.extend(pack('>H', index + 1))
        tmp = _pad_array(tmp, 16, 0)
        xor_data.extend(_aes_encrypt(key, tmp))
    return xor_array(message_data, xor_data)

def compute_authentication_value(message_data, message_type_id, session_nonce, security_counter, user_key):
    nonce = compute_nonce(message_type_id, session_nonce, security_counter)
    length = len(message_data)

    padded_length = _padding_length(length, 16, 0)
    padded_data = _pad_array(message_data, 16, 0)

    tmp = bytearray()
    tmp.append(0x09)
    tmp.extend(nonce)
    tmp.extend(pack('>H', length))
    encrypted_xor_data = _aes_encrypt(user_key, tmp)

    for i in range(0, padded_length, 16):
        encrypted_xor_data = _aes_encrypt(user_key, xor_array(encrypted_xor_data, padded_data, i))

    # xor array
    tmp = bytearray()
    tmp.append(0x01)
    tmp.extend(nonce)
    tmp.append(0x00)
    tmp.append(0x00)
    tmp.extend(pack('>H', padded_length))
    tmp = _pad_array(tmp, 16, 0)
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
    tmp.append(msg_type_id)
    tmp.extend(_crypt_data)
    tmp.extend(pack('>H', local_security_counter))
    tmp.extend(auth)

    return tmp

def test_pad_array():
    pad = bytearray(8)
    pad = _pad_array(pad, 15, 8)
    assert(len(pad) == 8)

    pad = bytearray(0)
    pad = _pad_array(pad, 15, 8)
    assert(len(pad) == 8)

    pad = bytearray(15)
    pad = _pad_array(pad, 15, 8)
    assert(len(pad) == (15 + 8))

    pad = bytearray(2 * 15 + 8 - 1)
    pad = _pad_array(pad, 15, 8)
    assert(len(pad) == (2 * 15 + 8))

def test_xor_data():
    data = b'\x01\x02\x03\x04'
    xor = b'\x00\x00\x00\x00'
    xorred = xor_array(data, xor, 0)
    assert(xorred == data)

    data = b'\x01\x02\x03\x04'
    xor = b'\x00\x02\x00\x00'
    xorred = xor_array(data, xor, 0)
    expect = b'\x01\x00\x03\x04'
    assert(xorred == expect)

    data = b'\x01\x02\x03\x04'
    xor = b'\x00\x01\x00\x00'
    xorred = xor_array(data, xor, 1)
    expect = b'\x00\x02\x03\x04'
    assert(xorred == expect)

    data = b'\x01\x02\x03\x04'
    xor = b'\x00\x00\x00\x00\x01\x02\x03\x04'
    xorred = xor_array(data, xor, 0)
    assert(xorred == data)

def test_crypt_data():
    data = b'\x01\x02\x03\x04'
    key = b'\x00' * 16
    msg_type_id = 1
    remote_nonce = 0
    local_security_counter = 1
    _crypt_data = crypt_data(data, msg_type_id, remote_nonce, local_security_counter, key)
    assert(len(_crypt_data) == len(data))

def test_compute_auth():
    # nodejs test data
    # > r.utils.compute_authentication_value([1,2,3], 23, [1,2,3,4,5,6,7,8], 1, [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
    # [ 219, 223, 137, 233 ]
    nonce, = unpack('>Q', bytearray([1,2,3,4,5,6,7,8]))
    ret = compute_authentication_value(
            bytearray([1,2,3]),
            23,
            nonce,
            1,
            bytearray([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]))

    assert ret == bytearray([ 219, 223, 137, 233 ])

def test_compute_nonce():
    # nodejs test data
    # > r.utils.compute_nonce(23, [1,2,3,4,5,6,7,8], 42)
    # [ 23, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 42 ]
    nonce, = unpack('>Q', bytearray([1,2,3,4,5,6,7,8]))
    ret = compute_nonce(23, nonce, 42)
    assert ret == bytearray([23, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 42])

