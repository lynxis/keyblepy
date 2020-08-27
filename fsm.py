#!/usr/bin/env python3
#
# 2019 Alexander 'lynxis' Couzens <lynxis@fe80.eu>
# GPLv3

import logging
import threading
from exceptions import *
from messages import *
import random
from lowerlayer import LowerLayer
from bluepy.btle import Peripheral, BTLEException
from transitions import Machine
from transitions.extensions.states import add_state_features, Timeout

LOCK_SERVICE = '58e06900-15d8-11e6-b737-0002a5d5c51b'
LOCK_SEND_CHAR = '3141dd40-15db-11e6-a24b-0002a5d5c51b'
LOCK_RECV_CHAR = '359d4820-15db-11e6-82bd-0002a5d5c51b'

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
        else:
            LOG.info("Unknown message %s", message)


    def _connect(self):
        if self.state != 'disconnected':
            return

        self.ll = LowerLayer(self.mac)
        self.ll.set_on_receive(self._on_receive)
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
        pkg = PairingRequestMessage.create(
            self.userid,
            _userkey,
            self.remote_nonce,
            self.security_counter,
            _cardkey)
        self.ll.send(pkg)

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

    def status(self):
        """ returns the status of the lock or raise an exception """
        self.require_autenticate = True

        if self.state == 'disconnected':
            self._connect()

        return "No Status Yet"

    def register(self):
        """ Register a new user to the evlock. It requires the QR code. """
        pass
