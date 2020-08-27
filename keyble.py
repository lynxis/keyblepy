#!/usr/bin/env python3
#
# 2019 Alexander 'lynxis' Couzens <lynxis@fe80.eu>
# GPLv3

import argparse
import binascii
import logging
import re

from bluepy.btle import Scanner, DefaultDelegate
from fsm import Device

def filter_keyble(devices):
    """ return only keyble locks """
    keyble = []
    for dev in devices:
        for (adtype, desc, value) in dev.getScanData():
            if desc == "Complete Local Name" and value == "KEY-BLE":
                keyble.append(dev)
    return keyble

def scan():
    """ scan via BLE for locks """
    scanner = Scanner()
    devices = scanner.scan(10.0)
    return filter_keyble(devices)

def ui_scan():
    devices = scan()
    if not devices:
        print("Could not found any devices")
        return

    print("Found keyble devices")
    for dev in devices:
        print("{}".format(dev.addr))

def ui_discover(device, userid=1):
    device = Device(device, userid=userid)
    infos = device.discover()
    print(infos)

def ui_pair(device, userid, userkey, cardkey):
    if userid == None:
        userid = 0xff

    # TODO: check userkey, cardkey, userid
    _userkey = binascii.unhexlify(userkey)
    if len(_userkey) != 16:
        raise RuntimeError("Userkey is too short or too long. Expecting 16 byte encode as hex (32 characters)")
    _cardkey = binascii.unhexlify(cardkey)
    if len(_cardkey) != 16:
        raise RuntimeError("Cardkey is too short or too long. Expecting 16 byte encode as hex (32 characters)")
    device = Device(device, userid=userid)
    device.pair(_userkey, _cardkey)

def ui_command(device, userid, userkey, command):
    _userkey = binascii.unhexlify(userkey)
    if len(_userkey) != 16:
        raise RuntimeError("Userkey is too short or too long. Expecting 16 byte encode as hex (32 characters)")

    device = Device(device, userid=userid, userkey=_userkey)

    if command == "open":
        device.open()
    elif command == "unlock":
        device.unlock()
    elif command == "lock":
        device.lock()

    print("device %s" % str(command))

def ui_status(device, userid, userkey):
    _userkey = binascii.unhexlify(userkey)
    if len(_userkey) != 16:
        raise RuntimeError("Userkey is too short or too long. Expecting 16 byte encode as hex (32 characters)")

    device = Device(device, userid=userid, userkey=_userkey)
    status = device.status()
    print("device status = %s" % str(status))

def main():
    parser = argparse.ArgumentParser(description='keybtle')
    parser.add_argument('--scan', dest='scan', action='store_true', help='Scan for KeyBLEs')
    parser.add_argument('--device', dest='device', help='Device MAC address')
    parser.add_argument('--discover', dest='discover', action='store_true', help='Ask the bootloader/app version')
    parser.add_argument('--user-id', dest='userid', help='The user id', type=int)
    parser.add_argument('--user-key', dest='userkey', help='The user key (a rsa key generated when registering the user)')
    parser.add_argument('--status', dest='status', action='store_true', help='Shows the status. Require --user-id --user-key --device.')
    parser.add_argument('--open', dest='open', action='store_true', help='Unlock and Open. Require --user-id --user-key --device.')
    parser.add_argument('--lock', dest='lock', action='store_true', help='Lock. Require --user-id --user-key --device.')
    parser.add_argument('--unlock', dest='unlock', action='store_true', help='Unlock. Require --user-id --user-key --device.')
    parser.add_argument('--register', dest='register', action='store_true', help='Register a new user. Require --qrdata, optional --user-name')
    parser.add_argument('--user-name', dest='username', help='The administrator will see this name when listing all users')
    parser.add_argument('--qrdata', dest='qrdata', help='The QR Code as data. This contains the mac,cardkey,serial.')
    parser.add_argument('--verbose', dest='verbose', action='store_true', help='Enable debug logging.')

    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(format="%(asctime)-15s %(levelname)-8s %(name)-22s %(message)s", level=logging.DEBUG)
    else:
        logging.basicConfig(format="%(asctime)-15s %(levelname)-8s %(name)-22s %(message)s", level=logging.ERROR)


    if args.scan:
        ui_scan()
    if args.status:
        ui_status(args.device, args.userid, args.userkey)
    if args.open:
        ui_command(args.device, args.userid, args.userkey, "open")
    if args.lock:
        ui_command(args.device, args.userid, args.userkey, "lock")
    if args.unlock:
        ui_command(args.device, args.userid, args.userkey, "unlock")
    if args.discover:
        ui_discover(args.device)
    if args.register:
        if not args.qrdata:
            raise RuntimeError("You need to specify --qrdata")

        # M001234556678K01234567890ABCDEF023456789ABCDEF0123456789
        rex = re.compile(r'^M([0-9A-F]{12})K([0-9A-F]{32})([0-9A-Z]{10})$')
        match = rex.match(args.qrdata)
        if not match:
            raise RuntimeError("Invalid QR Data")
        smac, cardkey, serial = match.groups()
        mac = ""
        for i in range(len(smac) >> 1):
            mac += smac[i*2]
            mac += smac[i*2+1]
            mac += ":"
        mac = mac[0:-1]

        ui_pair(mac, args.userid, args.userkey, cardkey)

if __name__ == '__main__':
    main()
