#!/usr/bin/env python3
#
# 2019 Alexander 'lynxis' Couzens <lynxis@fe80.eu>
# GPLv3

import binascii
from exceptions import InvalidData
import logging

from struct import pack, unpack_from, calcsize
# local imports
from encrypt import compute_authentication_value, encrypt_message, crypt_data

MESSAGE_FRAGMENT_ACK = 0x01
MESSAGE_ANSWER_WITHOUT_SECURITY = 0x01
MESSAGE_CONNECTION_REQUEST = 0x02
MESSAGE_CONNECTION_INFO = 0x03
MESSAGE_PAIRING_REQUEST = 0x04
MESSAGE_STATUS_CHANGED = 0x05
MESSAGE_CONNECTION_CLOSE = 0x06
MESSAGE_ANSWER_WITH_SECURITY = 0x81
MESSAGE_STATUS_REQUEST = 0x82
MESSAGE_STATUS_INFO = 0x83
MESSAGE_COMMAND = 0x87
MESSAGE_USER_INFO = 0x8f
MESSAGE_USER_NAME_SET = 0x90

LOG = logging.getLogger("messages")

def encode_fragment(message):
    """ split the message into fragments.
        each Fragement contains 1 status byte and 15 payload bytes
    """
    fragments = []

    count = int(len(message) / 15)
    if len(message) % 15:
        count += 1

    if count > 0x7f:
        raise RuntimeError("The message is too big to encoded into fragments")

    for i in range(count):
        pdu = bytearray()

        # status byte
        status = 0x00
        if i == 0:
            status |= 0x80
        status |= (count - 1 - i) & 0x7f
        pdu.append(status)

        # payload
        start = i * 15
        end = (i + 1) * 15
        pdu.extend(message[start:end])

        LOG.debug("Before pad len pdu %d", len(pdu))

        # padding
        if len(pdu) < 16:
            pdu.extend((16 - (len(pdu) % 16)) * b'\x00')
        LOG.debug("After pad len pdu %d", len(pdu))

        fragments += [pdu]
    return fragments

def decode_fragment(pdus):
    """ combines fragment into messages
        pdus = list of pdus
        returns (messages, undecoded_pdus)
    """
    messages = []
    undecoded_pdus = []

    message = bytearray()
    length = 0
    for pdu in pdus:
        undecoded_pdus += [pdu]
        if pdu[0] & 0x80:
            # first pdu
            if message:
                raise RuntimeError("The message is broken in the middle")
            length = pdu[0] & 0x7f
        else:
            length -= 1
            if length != pdu[0] & 0x7f:
                raise RuntimeError("Message out of sequence received")

        message.extend(pdu[1:])
        if length == 0:
            messages += [message]
            message = bytearray()
            undecoded_pdus = []

    return (messages, undecoded_pdus)

def test_decode_fragment_one_fragment():
    pdu = bytearray(b'\x80\x03\x011\x0c\xe1{&\x1f\x82\x17\x00\x10\x17\x00\x00')
    pdus = [pdu]
    messages, remain = decode_fragment(pdus)
    assert messages
    assert not remain
    assert messages[0] == pdu[1:]

def test_decode_fragment_multiple_fragment():
    pdus = [
        '818f4d24bc21179af3dc74e0984c36b4',
        '00ce544580d09412264100030eedbc6b',
        ]
    pdus = [binascii.unhexlify(pdu) for pdu in pdus]
    correct_message = bytearray(pdus[0][1:] + pdus[1][1:])
    messages, remain = decode_fragment(pdus)
    assert messages
    assert not remain
    assert messages[0] == correct_message

def test_encode_fragment():
    correct_pdus = [
        '818f4d24bc21179af3dc74e0984c36b4',
        '00ce544580d09412264100030eedbc6b',
        ]
    correct_pdus = [binascii.unhexlify(pdu) for pdu in correct_pdus]
    message = bytearray(correct_pdus[0][1:] + correct_pdus[1][1:])
    pdus = encode_fragment(message)
    assert pdus
    assert pdus == correct_pdus

class Send():
    def encode(self):
        """ encode the class into a bytearray """
        raise NotImplementedError()

class Recv():
    @classmethod
    def decode(cls, data):
        """ decode the data into a class """
        raise NotImplementedError()

class Fragment():
    """ Fragments are the basic blocks. All messages are encoded in Fragments """
    def __init__(self, status, payload):
        # uint8 status
        self.status = status
        self.payload = payload

    @classmethod
    def decode(cls, data):
        return cls(data[0], data[1:])

# Message Types
class FragmentAck(Send, Recv):
    """ send a Ack to a received fragment back """
    msgtype = 0x00
    def __init__(self, fragmentid):
        # uint8
        if fragmentid > 255:
            raise InvalidData("fragmentid does not fit into a byte")
        self.fragmentid = fragmentid

    def encode(self):
        return pack('>BB', FragmentAck.msgtype, self.fragmentid)

    @classmethod
    def decode(cls, data):
        if data[0] != FragmentAck.msgtype:
            raise InvalidData("Wrong msgtype")

        _msgtype, fragmentid = unpack_from('>BB', data)
        return cls(fragmentid)

class AnswerWithoutSecurity(Send, Recv):
    """ An Answer to our last command """
    msgtype = 0x01
    def __init__(self, answer):
        # uint8
        if answer > 255:
            raise InvalidData("answer does not fit into a byte")
        self.answer = answer

    def encode(self):
        return pack('>BB', FragmentAck.msgtype, self.answer)

    @classmethod
    def decode(cls, data):
        if data[0] != AnswerWithoutSecurity.msgtype:
            raise InvalidData("Wrong msgtype")

        _msgtype, answer = unpack_from('>BB', data)
        return cls(answer)

class AnswerWithSecurity(Send, Recv):
    """ An Answer to our last command """
    msgtype = 0x81
    def __init__(self, answer):
        # uint8
        if answer:
            raise InvalidData("answer does not fit into a byte")
        self.answer = answer

    def encode(self):
        return pack('>BB', FragmentAck.msgtype, self.answer)

    @classmethod
    def decode(cls, data):
        if data[0] != AnswerWithoutSecurity.msgtype:
            raise InvalidData("Wrong msgtype")

        _msgtype, answer = unpack_from('>BB', data)
        return cls(answer)

class ConnectionInfoMessage(Send, Recv):
    msgtype = 0x03
    def __init__(self, userid, remote_session_nonce, bootloader, application):
        self.userid = userid
        self.remote_session_nonce = remote_session_nonce
        self.bootloader = bootloader
        self.application = application

    def encode(self):
        return pack(
            '>BBQBBB',
            ConnectionInfoMessage.msgtype,
            self.userid,
            self.remote_session_nonce,
            0x00, # unknown, pad it
            self.bootloader,
            self.application)

    @classmethod
    def decode(cls, data):
        if len(data) != 15:
            raise InvalidData("Input to short")

        if data[0] != ConnectionInfoMessage.msgtype:
            raise InvalidData("Wrong msgtype")

        _msgtype, userid, remote_session_nonce, _unknown, bootloader, application = unpack_from('>BBQBBB', data)
        return cls(userid, remote_session_nonce, bootloader, application)

class ConnectionRequestMessage(Send, Recv):
    msgtype = 0x02
    def __init__(self, userid, nonce):
        # uint8
        self.userid = userid
        # uint64
        self.nonce = nonce

    def encode(self):
        LOG.error("Encoding: '%s' '%s' '%s'", ConnectionRequestMessage.msgtype, self.userid, self.nonce)
        return pack(
            '>BBQ',
            ConnectionRequestMessage.msgtype,
            self.userid,
            self.nonce)

    @classmethod
    def decode(cls, data):
        if len(data) != 15:
            raise InvalidData("Input to short")

        if data[0] != cls.msgtype:
            raise InvalidData("Wrong msgtype")

        _msgtype, userid, nonce = unpack_from('>BBQBB', data)
        return cls(userid, nonce)

class StatusRequestMessage(Send, Recv):
    msgtype = 0x82
    def __init__(self, userid, nonce):
        # uint8
        self.userid = userid
        # uint64
        self.nonce = nonce

    def encode(self):
        return pack(
            '>BBQ',
            StatusRequestMessage.msgtype,
            self.userid,
            self.nonce)

    @classmethod
    def decode(cls, data):
        if len(data) != 15:
            raise InvalidData("Input to short")

        if data[0] != cls.msgtype:
            raise InvalidData("Wrong msgtype")

        _msgtype, userid, nonce = unpack_from('>BBQBB', data)
        return cls(userid, nonce)

class StatusInfoMessage(Send):
    msgtype = 0x83
    def __init__(self, userid, nonce):
        # uint8
        self.userid = userid
        # uint64
        self.nonce = nonce

    def encode(self):
        return pack(
            '>BBQ',
            StatusInfoMessage.msgtype,
            self.userid,
            self.nonce)

class StatusChangedMessage(Send):
    msgtype = 0x05
    def __init__(self, userid, nonce):
        pass

    def encode(self):
        return pack(
            '>B',
            StatusChangedMessage.msgtype)

class PairingRequestMessage(Send, Recv):
    msgtype = 0x04
    def __init__(self, userid, encrypted_pair_key, security_counter, authentication):
        self.userid = userid
        self.encrypted_pair_key = encrypted_pair_key
        self.security_counter = security_counter
        self.authentication = authentication

        if len(self.encrypted_pair_key) < 16:
            raise InvalidData("Encrypted pair key < 16")

        if len(self.encrypted_pair_key) > 22:
            raise InvalidData("Encrypted pair key > 22")

        length = len(self.encrypted_pair_key)
        if length < 22:
            self.encrypted_pair_key.extend(b'\x00' * (22 - length))

    def encode(self):
        head = pack('>BB', PairingRequestMessage.msgtype, self.userid)
        tail = pack('>H', self.security_counter) + self.authentication
        return head + self.encrypted_pair_key + tail

    @classmethod
    def decode(cls, data):
        if len(data) < 29:
            raise InvalidData("Input to short")

        if data[0] != cls.msgtype:
            raise InvalidData("Wrong msgtype")

        head = calcsize('>BB')
        tail = head + 22
        _msgtype, userid = unpack_from('>BB', data)
        encrypted_pair_key = data[head:tail]
        security_counter, = unpack_from('>H', data, tail)

        tail += 2
        authentication = data[tail:tail+4]

        return cls(userid, encrypted_pair_key, security_counter, authentication)

    @classmethod
    def create(cls, userid, userkey, remote_session_nonce, local_security_counter, card_key):
        # pad userkey- no?
        if len(userkey) != 16:
            raise RuntimeError("Invalid user key given")

        encrypted_pair_key = crypt_data(userkey, cls.msgtype, remote_session_nonce, local_security_counter, card_key)

        pad_userkey = bytearray(userkey)
        pad_userkey.extend(b'\x00' * 6)
        #    userkey.extend((22 - len(userkey)) * b'\x00')

        auth_data = bytearray()
        auth_data.append(userid)
        auth_data.extend(pad_userkey)
        authentication = compute_authentication_value(
            auth_data,
            PairingRequestMessage.msgtype,
            remote_session_nonce,
            local_security_counter,
            card_key)

        return cls(userid, encrypted_pair_key, local_security_counter, authentication)

MESSAGES = {
        0x00: FragmentAck,
        0x01: AnswerWithoutSecurity,
        0x02: ConnectionRequestMessage,
        0x03: ConnectionInfoMessage,
        0x04: PairingRequestMessage,
        0x05: StatusChangedMessage,
        0x81: AnswerWithSecurity,
        0x82: StatusRequestMessage,
        0x83: StatusInfoMessage,
}

def test_pairing_request():
    from pprint import pprint
    request = PairingRequestMessage.create(
            userid=0x1,
            userkey=b'\x00' * 16,
            remote_session_nonce=0,
            local_security_counter=1,
            card_key=b'\x00' * 16)
    encoded = request.encode()
    fragment = encode_fragment(encoded)

    pprint(fragment)
    pprint(len(encoded))
    assert(False)
