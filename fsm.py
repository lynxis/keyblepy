#!/usr/bin/env python3
#
# 2019 Alexander 'lynxis' Couzens <lynxis@fe80.eu>
# GPLv3

import logging
import threading
from exceptions import *
from messages import *
from encrypt import encrypt_message
import random
from lowerlayer import LowerLayer
from bluepy.btle import Peripheral, BTLEException
from transitions import Machine
from transitions.extensions.states import add_state_features, Timeout

from datetime import datetime

LOCK_SERVICE = '58e06900-15d8-11e6-b737-0002a5d5c51b'
LOCK_SEND_CHAR = '3141dd40-15db-11e6-a24b-0002a5d5c51b'
LOCK_RECV_CHAR = '359d4820-15db-11e6-82bd-0002a5d5c51b'

COMMAND_LOCK = 0
COMMAND_UNLOCK = 1
COMMAND_OPEN = 2

LOG = logging.getLogger("fsm")

@add_state_features(Timeout)
class TimeoutMachine(Machine):
    pass

class Device(object):
    states = [
            { 'name': 'disconnected'}, # complete disconnected
            { 'name': 'connected'}, # connected on the BLE level (connection oriented}
            { 'name': 'exchanged_nonce'}, # do authentication
            { 'name': 'secured'}, # on successful auth
            { 'name': 'unsecured'}, # on failed auth
            { 'name': "action"},
    ]

    transitions = [
        {
            'trigger': 'ev_connected',
            'source': 'disconnected',
            'dest': 'connected',
        },
        {
            'trigger': 'ev_nonce_received',
            'source': 'connected',
            'dest': 'exchanged_nonce',
        },
        {
            'trigger': 'ev_secured',
            'source': 'authenticate',
            'dest': 'secured',
        },
    ]

    def __init__(self, mac, userid, userkey=None):
        # should it raise Exception on invalid data?
        self.ignore_invalid = False
        self.mac = mac
        self.ll = None
        self.machine = TimeoutMachine(self,
                                      states=Device.states,
                                      transitions=Device.transitions,
                                      initial='disconnected')

        self.nonce = int(random.getrandbits(64))
        self.nonce_byte = bytearray(pack('>Q', self.nonce))

        self.remote_nonce = None
        self.remote_nonce_byte = None

        # The connection info
        self.connection_info = None

        self.security_counter = 1
        self.remote_security_counter = 0

        self.userid = userid
        self.userkey = userkey

        self.ready = threading.Event()
        self.ready.clear()

        # wait for a message
        self.msg = threading.Event()
        self.msg.clear()
        self.msg_type = None
        self.msg_pdu = None

    def _on_error(self, message):
        """ entrypoint when received an error from the lower layer """
        LOG.info("Receive error from lower layer %s", message)

    def _on_receive(self, message):
        """ entrypoint when received a message from the lower layer """
        LOG.info("Receive message %s", message)
        if isinstance(message, ConnectionInfoMessage):
            LOG.info("Receive ConnectionInfoMessage")
            self.remote_nonce = message.remote_session_nonce
            self.remote_nonce_byte = bytearray(pack('>Q', self.remote_nonce))
            self.connection_info = message
            if self.userid == 0xff:
                LOG.info("Using new Userid %d" % message.userid)
                self.userid = message.userid
            self.ev_nonce_received()
        elif isinstance(message, AnswerWithSecurity):
            pass
        elif isinstance(message, AnswerWithoutSecurity):
            pass
        elif isinstance(message, self.msg_type):
            self.msg_pdu = message
            self.msg.set()
        else:
            LOG.info("Unknown message %s", message)

    def _connect(self):
        if self.state != 'disconnected':
            return

        self.ll = LowerLayer(self.mac)
        self.ll.set_on_receive(self._on_receive)
        self.ll.set_on_error(self._on_error)
        self.ll.connect()
        self.ev_connected()

    def on_enter_connected(self):
        # if userid given, go to the next state
        self.ll.send(ConnectionRequestMessage(self.userid, self.nonce).encode())

    def on_enter_authenticate(self):
        # self.ll.send(Authenticate(self.userid, self.nonce).encode())
        pass

    def on_enter_exchanged_nonce(self):
        LOG.info("Exchanged nonce reached")
        self.ready.set()

    def on_enter_secured(self):
        pass

    def status_on_recv(self):
        pass

    def encrypt_message(self, message):
        """ :param message a Message object
        """
        pdu = encrypt_message(message, self.remote_nonce, self.security_counter, self.userkey)
        self.security_counter += 1
        return pdu

    def decrypt_message(self, data):
        """ a message is [1 byte id][x byte cryptdata][2 byte counter][4 byte auth] """
        # check message_security_counter
        # check authenticate_value

        if len(data) < 7:
            raise InvalidData("Message to short")

        message_id = data[0:1]
        message_counter = unpack('>H', data[-6, -4])
        message_auth = unpack_from('>Q', data[-4:])
        if message_counter <= self.remote_security_counter:
            log.info("Invalid message counter")
            return False

        self.remote_security_counter = message_counter
        pdu = crypt_data(data[1:-6], message_id, self.local_nonce, self.remote_security_counter, self.userkey)
        computed_authentication_value = compute_authentication_value(pdu, message_id, self.local_nonce, self.remote_security_counter, self.userkey)
        if compute_authentication_value != message_auth:
            log.info("Invalid message auth")
            return False

        return pdu

    # interface
    def pair(self, userkey, cardkey):
        """ :param user_key as bytearray (128 bit / 16 byte)
            :param card_Key the key from the card as bytearray (128 bit / 16 byte)

            a userid must be also given via the device class.
            """
        LOG.info("Starting to pair")

        self._connect()
        self.ready.wait()
        LOG.info("userkey: %s %s" % (userkey, str(type(userkey))))
        _userkey = bytearray(userkey)
        _cardkey = bytearray(cardkey)
        self.userkey = _userkey
        pdu = PairingRequestMessage.create(
            self.userid,
            _userkey,
            self.remote_nonce,
            self.security_counter,
            _cardkey).encode()
        self.ll.send(pdu)
        return True

    def wait_for(self, msg_type):
        self.msg_type = msg_type
        self.msg.clear()

    def wait(self, timeout=None):
        self.msg.wait(timeout)

    def discover(self):
        """ return bootloader and application info """
        if self.userid is None:
            raise RuntimeError("Missing user id!")

        self._connect()
        self.ready.wait()
        self.disconnect()
        return {"bootloader": self.connection_info.bootloader,
                "application": self.connection_info.application,}

    def disconnect(self):
        self.ll.disconnect()

    def status(self, timeout=10.0):
        """ returns the status of the lock or raise an exception """
        self.require_autenticate = True

        if self.state == 'disconnected':
            self._connect()

        if not self.ready.wait(timeout):
            LOG.warning("Failed to setup the connection")
            return False

        message = StatusRequestMessage(datetime.now())
        pdu = self.encrypt_message(message)

        self.wait_for(StatusInfoMessage)
        self.ll.send(pdu)
        if not self.wait(timeout):
            self.disconnect()
            return "failed to get the StatusInfoMessage"

        info = self.decrypt(self.msg_pdu)
        from pprint import pprint
        pprint(info)

        return "No Status Yet"

    def open(self):
        """ open it! """
        if self.state == 'disconnected':
            self._connect()
            self.ready.wait()

        message = CommandMessage(COMMAND_OPEN)
        pdu = self.encrypt_message(message)
        self.ll.send(pdu)

    def unlock(self):
        if self.state == 'disconnected':
            self._connect()
            self.ready.wait()

        pdu = CommandMessage(COMMAND_UNLOCK).encode()
        self.ll.send(pdu)

    def lock(self):
        if self.state == 'disconnected':
            self._connect()
            self.ready.wait()

        pdu = CommandMessage(COMMAND_LOCK).encode()
        self.ll.send(pdu)

    def register(self):
        """ Register a new user to the evlock. It requires the QR code. """
        pass
