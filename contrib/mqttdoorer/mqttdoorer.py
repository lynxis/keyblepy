#!/usr/bin/env python3
#
# based on mqtt message it execute certain binaries.
# the design is synchronous to ensure the executed binaries are only called once without calling parallel

import logging
import subprocess
import paho.mqtt.client as mqtt

from config import keyblecmd, logging_config

LOG = logging.getLogger("mqttdoorer")

def keyble(action):
    cmd = keyblecmd.split()
    cmd += ['--%s' % action]
    rc = subprocess.run(cmd, check=False)
    if rc.returncode:
        LOG.warning("keyble '%s' exited with %d", action, rc.returncode)

def lock():
    keyble('lock')

def unlock():
    keyble('unlock')

def _open():
    keyble('open')

ACTIONS = {
        'lock': lock,
        'unlock': unlock,
        'open': _open,
        }

def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("door")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    try:
        action = str(msg.payload, 'utf-8')
    except:
        LOG.exception("On message")
        return

    if action in ACTIONS:
        ACTIONS[action]()
    else:
        LOG.warning("Unknown action '%s'", action)

if logging_config:
    import yaml
    configyaml = yaml.load(open(logging_config, 'r'))
    logging.config.dictConfig(configyaml)
else:
    logging.basicConfig(format="%(asctime)-15s %(levelname)-8s %(name)-22s %(message)s", level=logging.WARNING)

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect("localhost", 1883, 60)

client.loop_forever()
