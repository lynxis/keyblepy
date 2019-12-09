#!/usr/bin/env python3
#
# 2019 Alexander 'lynxis' Couzens <lynxis@fe80.eu>
# GPLv3

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
            'trigger': 'ev_nonce_exchanged',
            'source': 'connected',
            'dest': 'exchanged_nonce',
        },
        {
            'trigger': 'ev_secured',
            'source': 'authenticate',
            'dest': 'secured',
        },
    ]

    def __init__(self, mac, userid=None, userkey=None):
        # should it raise Exception on invalid data?
        self.ignore_invalid = False
        self.mac = mac
        self.ll = None
        self.machine = TimeoutMachine(self,
                                      states=Device.states,
                                      transitions=Device.transitions,
                                      initial='disconnected')

        self.nonce = int(random.getrandbits(64))
        self.nonce_byte = bytearray(pack('<Q', self.nonce))

        self.remote_nonce = None
        self.remote_nonce_byte = None

        self.security_counter = 1
        self.remote_security_counter = 0

        self.userid = userid
        self.userkey = userkey

        self.cv = threading.Condition(lock=threading.Lock())
        self.cv_finish = False

    def _connect(self):
        if self.state != 'disconnected':
            return

        self.ll = LowerLayer(self.mac)
        self.ll.connect()
        self.ev_connected()

    def _exchanged_nonce(self):
        if self.state == 'exchanged_nonce':
            return

    def on_enter_connected(self):
        # if userid given, go to the next state
        if self.userid:
            self.ll.send(ConnectionRequestMessage(self.userid, self.nonce))
            self.ev_authenticate()

    def on_enter_authenticate(self):
        # self.ll.send(Authenticate(self.userid, self.nonce))
        pass

    def on_enter_secured(self):
        pass

    def status_on_recv(self):
        pass

    # interface
    def pair(self, user_key, card_key):
        """ :param user_key as bytearray (128 bit / 16 byte)
            :param card_Key the key from the card as bytearray (128 bit / 16 byte)

            a user_id must be also given via the device class.
            """
        self._connect()
        self._exchanged_nonce()

    def on_discover_received(self, message):
        print(message)
        self.cv_finish = True
        self.cv.notify()

    def discover(self):
        if self.userid is None:
            raise RuntimeError("Missing user id!")

        self._connect()
        self.ll.set_on_receive(self.on_discover_received)
        self.ll.send(ConnectionRequestMessage(self.userid, self.nonce_byte))
        with self.cv:
            self.cv.wait_for(self.cv_finish)

    def status(self):
        """ returns the status of the lock or raise an exception """
        self.require_autenticate = True

        if self.state == 'disconnected':
            self._connect()

        return "No Status Yet"

    def register(self):
        """ Register a new user to the evlock. It requires the QR code. """
        pass
