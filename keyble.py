#!/usr/bin/env python3
#
# 2019 Alexander 'lynxis' Couzens <lynxis@fe80.eu>
# GPLv3

import argparse

from bluepy.btle import Scanner, DefaultDelegate, Peripheral

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

def ui_status(device):
    print(device)
    peripheral = Peripheral(device)
    while True:
        if Peripheral.waitForNotifications(1.0):
            # handleNotification() was called
            continue

class Keyble():
    def __init__(self, mac):
        self._pnode = Peripheral(mac)

    states = [
        "ble_idle",
        "ble_discover",
        "ble_connected",
        ]
    proto_state = [
        "idle",
        "connected",
        "action",
        ]

def main():
    parser = argparse.ArgumentParser(description='keybtle')
    parser.add_argument('--scan', dest='scan', action='store_true', help='Scan the BLE')
    parser.add_argument('--status', dest='status', action='store_true', help='')
    parser.add_argument('--device', dest='device', help='Device mac address')
    args = parser.parse_args()
    if args.scan:
        ui_scan()
    if args.status:
        ui_status(args.device)

if __name__ == '__main__':
    main()
