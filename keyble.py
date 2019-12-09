#!/usr/bin/env python3
#
# 2019 Alexander 'lynxis' Couzens <lynxis@fe80.eu>
# GPLv3

import argparse

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
    device = Device(device)
    device.discover(userid=userid)

def ui_status(device, userid, userkey):
    device = Device(device, userid=userid, userkey=userkey)
    status = device.status()
    print("device status = %s" % str(status))

def main():
    parser = argparse.ArgumentParser(description='keybtle')
    parser.add_argument('--scan', dest='scan', action='store_true', help='Scan for KeyBLEs')
    parser.add_argument('--device', dest='device', help='Device MAC address')
    parser.add_argument('--discover', dest='discover', action='store_true', help='Ask the bootloader/app version')
    parser.add_argument('--user-id', dest='userid', help='The user id')
    parser.add_argument('--user-key', dest='userkey', help='The user key (a rsa key generated when registering the user)')
    parser.add_argument('--status', dest='status', action='store_true', help='Shows the status. Require --user-id --user-key --device.')
    parser.add_argument('--open', dest='open', action='store_true', help='Unlock and Open. Require --user-id --user-key --device.')
    parser.add_argument('--lock', dest='lock', action='store_true', help='Lock. Require --user-id --user-key --device.')
    parser.add_argument('--unlock', dest='unlock', action='store_true', help='Unlock. Require --user-id --user-key --device.')
    parser.add_argument('--register', dest='register', action='store_true', help='Register a new user. Require --qrdata, optional --user-name')
    parser.add_argument('--user-name', dest='username', help='The administrator will see this name when listing all users')
    parser.add_argument('--qrdata', dest='qrdata', help='The QR Code as data. This contains the mac,secret,serial.')
    args = parser.parse_args()
    if args.scan:
        ui_scan()
    if args.status:
        ui_status(args.device, args.userid, args.userkey)
    if args.discover:
        ui_discover(args.device)

if __name__ == '__main__':
    main()
