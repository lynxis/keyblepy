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

    count = len(message) / 15
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

class Fragment():
    """ Fragments are the basic blocks. All messages are encoded in Fragments """
    def __init__(self, data):
        # uint8 status
        self.status = -1
        self.payload = []
        self.decode(data)

    def decode(self, data):
        self.status = data[0]
        self.payload = data[1:]

# Message Types
class FragmentAck(Send):
    """ send a Ack to a received fragment back """
    msgtype = 0x00
    def __init__(self, status):
        # uint8
        if status > 255:
            raise InvalidData("status does not fit into a byte")
        self.status = status

    def encode(self):
        return unpack('BB', FragmentAck.msgtype, self.status)

class Connection_Info_Message():
    pass

class ConnectionRequestMessage():
    def __init__(self, user_id, nounce):
        # uint8
        self.user_id = user_id
        # uint64
        self.nounce = nounce

MESSAGES = {
        0x00: FragmentAck,
}
