#!/usr/bin/env python3

import RPi.GPIO as GPIO
import time, os, subprocess

GPIO.setmode(GPIO.BCM)
GPIO.setup(17, GPIO.IN)
GPIO.setup(27, GPIO.OUT)

def trigger_door_close():
        print("Closing door by button")
        for i in range(0, 20):
            GPIO.output(27, GPIO.HIGH)
            time.sleep(0.25)
            GPIO.output(27, GPIO.LOW)
            time.sleep(0.25)

        subprocess.run('mosquitto_pub -t door -m lock'.split(), check=False)

GPIO.output(27, GPIO.LOW)
while True:
    if GPIO.input(17) == 1: 
        trigger_door_close()
    
    time.sleep(0.1)

