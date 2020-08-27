#!/usr/bin/env python3
#
# 2019 Alexander 'lynxis' Couzens <lynxis@fe80.eu>
# GPLv3

# Create a Thread as lower layer to communicate with the BLE
# Communicate with Queues

import logging
import threading
import time
from queue import Queue
from bluepy.btle import Peripheral
from transitions import Machine
from transitions.extensions.states import add_state_features, Timeout

from exceptions import *
from messages import *

LOG = logging.getLogger("lowerlayer")

LOCK_SERVICE = '58e06900-15d8-11e6-b737-0002a5d5c51b'
LOCK_SEND_CHAR = '3141dd40-15db-11e6-a24b-0002a5d5c51b'
LOCK_RECV_CHAR = '359d4820-15db-11e6-82bd-0002a5d5c51b'
# '58e06900-15d8-11e6-b737-0002a5d5c51b' # 0x400-0x430 lock service
# '3141dd40-15db-11e6-a24b-0002a5d5c51b' # lock send char
# '359d4820-15db-11e6-82bd-0002a5d5c51b' # lock recv char
# '3aee5da0-15db-11e6-a29b-0002a5d5c51b' # 0xff00 - 0xff07 broadcom/cypress WICED Smart Upgrade Protocol
# |- 0xff01 -> '3f62328015db11e6afc60002a5d5c51b' (characteristics. ACL notify, indication, write)
#   |- 0xff02 value
# |- 0xff03 -> 3f62328015db11e6afc60002a5d5c51b (by Find Information Request)
# |- 0xff04 -> 4363968015db11e69b990002a5d5c51b (chr, ACL write, write wihtout resp)
#   |- 0xff05 value
# |- 0xff06 -> 4747fca015db11e69dd60002a5d5c51b (chr, ACL read)
#  |- 0xff07 -> value (software version)

MSG_CONNECT = 0
MSG_DISCONNECT = 1
MSG_SEND = 2

@add_state_features(Timeout)
class TimeoutMachine(Machine):
    pass

class LowerLayer(object):
    states = [
        {'name': 'disconnected'}, # no state is present with the device
        {'name': 'connected', 'on_enter': 'on_enter_connected', 'timeout': 5.0, 'on_timeout': 'on_enter_connected'}, # connected on BLE level
        {'name': 'send', 'on_enter': 'on_enter_send'}, # send a pdu
        {'name': 'wait_ack', 'on_enter': 'on_enter_wait_ack', 'timeout': 5.0, 'on_timeout': 'on_timeout_wait_ack'},
        {'name': 'wait_answer', 'on_enter': 'on_enter_wait_answer', 'timeout': 5.0, 'on_timeout': 'on_timeout_wait_answer'},
        {'name': 'error', 'on_enter': 'on_enter_error'}, # error state without any further operation
        {'name': 'disconnect'}, # error state without any further operation
    ]

    transitions = [
        {
            'trigger': 'ev_connected',
            'source': 'disconnected',
            'dest': 'connected'
        },
        {
            'trigger': 'ev_enqueue_message',
            'source': 'connected',
            'dest': 'send'
        },
        {
            'trigger': 'ev_send_fragment',
            'source': 'send',
            'dest': 'wait_ack'
        },
        {
            'trigger': 'ev_ack_received',
            'source': 'wait_ack',
            'dest': 'send'
        },
        {
            'trigger': 'ev_finished', # when everything was sent and received in queue
            'source': 'send',
            'dest': 'wait_answer'
        },
        {
            'trigger': 'ev_received', # when everything was sent and received in queue
            'source': 'wait_answer',
            'dest': 'connected'
        },
        {
            'trigger': 'ev_nothing_to_send', # when reaching state send, but nothing to send
            'source': 'send',
            'dest': 'connected'
        },
        {
            'trigger': 'ev_disconnect',
            'source': '*',
            'dest': 'disconnect'
        },
        {
            'trigger': 'ev_error',
            'source': '*',
            'dest': 'error'
        },
    ]

    def __init__(self, mac):
        self.state = None
        self.machine = TimeoutMachine(self,
                                      states=LowerLayer.states,
                                      transitions=LowerLayer.transitions,
                                      initial='disconnected')

        self.timeout = 1
        # should it raise Exception on invalid data?
        self.ignore_invalid = False

        # ble
        self._mac = mac
        self._ble_node = Peripheral()
        self._ble_node.setDelegate(self)
        # the ble service
        self._ble_service = None
        # the ble characteristic on the self._service
        self._ble_recv = None
        self._ble_send = None

        self._recv_fragments = []
        self._recv_fragment_index = 0
        self._recv_fragment_try = 1

        self._send_fragments = []
        self._send_fragment_index = 0
        self._send_fragment_try = 1

        self._send_messages = Queue()
        self._control = Queue()

        # The receive callback of the user
        self._recv_cb = None
        # The error callback of the user
        self._error_cb = None

        self._running = True
        self._thread = threading.Thread(target=self.work, name="lowerlayer")
        self._thread.start()

    def handleNotification(self, handle, data):
        """ called by the ble stack """

        LOG.info("Received on %x data : %s", handle, data)
        if not self._ble_recv:
            return
        if handle != self._ble_recv.getHandle():
            return
        if not data:
            return

        # TODO: split between Fragment/FragmentAck. Are there more messages to receive here?
        try:
            fragment = Fragment.decode(data)
        except InvalidData:
            if self.ignore_invalid:
                return
            raise

        # FragmentAck?
        # FIXME: hack
        if fragment.status == 0x80 and fragment.payload[0] == 0x00:
            if fragment.payload[1] != self._send_fragments[self._send_fragment_index][0]:
                LOG.err("Received unknown FragmentAck")
                return
            else:
                LOG.info("Received correct FragmentAck")
            self.ev_ack_received()
            return

        self.ev_received()

        self._recv_fragments += [data]
        message, self._recv_fragments = decode_fragment(self._recv_fragments)

        # this is not the last fragment, send an ack
        if not message:
            LOG.debug("Sending FragmentAck")
            self._send_pdu(FragmentAck(fragment.status).encode())
            return

        if len(message) > 1:
            raise RuntimeError("To many messages received")

        # try to decode message
        message = message[0]
        raw = message
        message_type = message[0]
        LOG.info("Received message type 0x%x", message_type)
        try:
            if not message_type in MESSAGES:
                self._error("Can not find Message")
                return
            message_cls = MESSAGES[message_type]
            message = message_cls.decode(message)
            LOG.info("Received decoded message %s <- %s", message, raw.hex())
        except Exception as exp:
            LOG.info("Receive exception %s", exp)
            if self.ignore_invalid:
                return

        if self._recv_cb:
            self._recv_cb(message)

    def _send_pdu(self, pdu):
        """ send a pdu (a byte array) """
        if not self._ble_send:
            raise RuntimeError("Can not send a message without a Connection")

        return self._ble_send.write(pdu, True)

    def _error(self, error):
        if self._error_cb:
            self._error_cb(error)

    def on_enter_connected(self):
        # reset send fragments
        self._send_fragments = []
        self._send_fragment_index = 0
        self._send_fragment_try = 1


    def on_enter_send(self):
        """ send the next fragment """
        # TODO: set timeout
        if not self._send_fragments:
            LOG.debug("OnSend: No fragment, try generating fragments")
            if not self._send_messages.empty():
                self._send_fragments = encode_fragment(self._send_messages.get())
                self._send_fragment_index = -1
                LOG.debug("OnSend: Encoded %d fragments", len(self._send_fragments))
            else:
                # No message or fragment left
                self.ev_nothing_to_send()
                return

        self._send_fragment_index += 1
        self._send_fragment_try = 0

        LOG.debug("send_fragment %d %d", len(self._send_fragments), self._send_fragment_index)

        if len(self._send_fragments) <= self._send_fragment_index + 1:
            self._send_pdu(self._send_fragments[self._send_fragment_index])
            # last message
            self.ev_finished()
        else:
            # when not the last message, we're expecting an FragmentAck
            self.ev_send_fragment()
            self._send_pdu(self._send_fragments[self._send_fragment_index])

    def on_timeout_wait_ack(self):
        # resend
        if self._send_fragment_try <= 3:
            self._send_pdu(self._send_fragments[self._send_fragment_index])
        else:
            self._error("Lock is not sending FragmentAcks!")
            self.ev_error()

    def on_timeout_wait_answer(self):
        """ when waiting for an answer, we might even have to re-send the last fragment """
        LOG.error("Timeout occured in wait answer, resending last fragment")
        if self._send_fragment_try <= 3:
            self._send_pdu(self._send_fragments[self._send_fragment_index])

    def on_enter_wait_answer(self):
        self._recv_fragment_index = 0
        self._recv_fragment_try = 1

    def on_enter_disconnect(self):
        self._ble_node.disconnect()
        self._ble_service = None
        self._ble_send = None
        self._ble_recv = None
        del self._ble_node
        self._ble_node = None

    def on_enter_wait_ack(self):
        pass

    def _connect(self):
        self._ble_node.connect(self._mac)
        self._ble_node.getServices()
        self._ble_service = self._ble_node.getServiceByUUID(LOCK_SERVICE)
        self._ble_send = self._ble_service.getCharacteristics(LOCK_SEND_CHAR)[0]
        self._ble_recv = self._ble_service.getCharacteristics(LOCK_RECV_CHAR)[0]
        self.ev_connected()

    def work(self):
        """ runs in a seperate thread """
        try:
            while self._running:
                if not self._control.empty():
                    control, payload = self._control.get()
                    if control == MSG_CONNECT:
                        LOG.debug("Connecting to BLE")
                        self._connect()
                    elif control == MSG_DISCONNECT:
                        LOG.debug("Disconnecting to BLE")
                        self.ev_disconnect()
                        break
                    elif control == MSG_SEND:
                        LOG.debug("Sending message to BLE")
                        self._send_messages.put(payload)
                        self.ev_enqueue_message()
                if self.state != "disconnected":
                    self._ble_node.waitForNotifications(self.timeout)
                else:
                    time.sleep(0.1)
        except Exception as e:
            self._error("Exception occured %s" % e)

    # user api functions
    def disconnect(self):
        self._control.put((MSG_DISCONNECT, None))

    def connect(self):
        self._control.put((MSG_CONNECT, None))

    def send(self, message):
        """ send messages. "Big" (> 31byte) messages must be splitted into multiple fragments """
        self._control.put((MSG_SEND, message))

    def set_on_receive(self, callback):
        """ sets the callback when a message has been received.
        The callback must have the signature callback(message), while message is a list of byte of one message. """
        self._recv_cb = callback

    def set_on_error(self, callback):
        """ sets the callback when a message has been received.
        The callback must have the signature callback(error). """
        self._error_cb = callback
