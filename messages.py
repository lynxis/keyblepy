#!/usr/bin/env python3
#
# 2019 Alexander 'lynxis' Couzens <lynxis@fe80.eu>
# GPLv3

from exceptions import InvalidData

from struct import pack, unpack

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
        start = count * 16
        end = (count + 1) * 16
        pdu.append(message[start:end])

        # padding
        if len(pdu) < 16:
            pdu.append((len(pdu) % 16) * 0x0)

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

        message.append(pdu[1:])
        if length == 0:
            messages += [message]
            message = bytearray()
            undecoded_pdus = []

    return (messages, undecoded_pdus)

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
        return pack('<BB', FragmentAck.msgtype, self.fragmentid)

    @classmethod
    def decode(cls, data):
        if data[0] != FragmentAck.msgtype:
            raise InvalidData("Wrong msgtype")

        _msgtype, fragmentid = unpack('<BB', data)
        return cls(fragmentid)

class ConnectionInfoMessage(Send, Recv):
    msgtype = 0x03
    def __init__(self, userid, remote_session_nonce, bootloader, application):
        self.userid = userid
        self.remote_session_nonce = remote_session_nonce
        self.bootloader = bootloader
        self.application = application

    def encode(self):
        return pack(
            '<BBQBB',
            ConnectionInfoMessage.msgtype,
            self.userid,
            self.remote_session_nonce,
            self.bootloader,
            self.application)

    @classmethod
    def decode(cls, data):
        if len(data) != 15:
            raise InvalidData("Input to short")

        if data[0] != ConnectionInfoMessage.msgtype:
            raise InvalidData("Wrong msgtype")

        _msgtype, userid, remote_session_nonce, bootloader, application = unpack('<BBQBB', data)
        return cls(userid, remote_session_nonce, bootloader, application)

class ConnectionRequestMessage(Send):
    msgtype = 0x02
    def __init__(self, userid, nonce):
        # uint8
        self.userid = userid
        # uint64
        self.nonce = nonce

    def encode(self):
        return pack(
            '<BBQ',
            ConnectionRequestMessage.msgtype,
            self.userid,
            self.nonce)

    @classmethod
    def decode(cls, data):
        if len(data) != 15:
            raise InvalidData("Input to short")

        if data[0] != cls.msgtype:
            raise InvalidData("Wrong msgtype")

        _msgtype, userid, nonce = unpack('<BBQBB', data)
        return cls(userid, nonce)

class StatusRequestMessage(Send):
    msgtype = 0x82
    def __init__(self, userid, nonce):
        # uint8
        self.userid = userid
        # uint64
        self.nonce = nonce

    def encode(self):
        return pack(
            '<BBQ',
            StatusRequestMessage.msgtype,
            self.userid,
            self.nonce)

    @classmethod
    def decode(cls, data):
        if len(data) != 15:
            raise InvalidData("Input to short")

        if data[0] != cls.msgtype:
            raise InvalidData("Wrong msgtype")

        _msgtype, userid, nonce = unpack('<BBQBB', data)
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
            '<BBQ',
            StatusInfoMessage.msgtype,
            self.userid,
            self.nonce)

class StatusChangedMessage(Send):
    msgtype = 0x05
    def __init__(self, userid, nonce):
        pass

    def encode(self):
        return pack(
            '<B',
            StatusChangedMessage.msgtype)

MESSAGES = {
        0x00: FragmentAck,
        0x02: ConnectionRequestMessage,
        0x03: ConnectionInfoMessage,
        0x05: StatusChangedMessage,
        0x82: StatusRequestMessage,
        0x83: StatusInfoMessage,
}
