#! /usr/bin/python3.6
"""The secure system heartbeat checks that a system is online and responding in a
cryptographically secure way to resist man-in-the-middle attacks attempting to spoof the
system being online. If the system is down or an incorrect response is received from the secure
system, an email alert will be generated. Setup of the SMTP server is left as an exercise to the
reader. Note that two systems can (and possibly should) monitor each other simultaneously.

This is the listener file for the secure system heartbeat. This script should run on the system
you want to monitor.

Be sure to change the constant values.

HOST is address of the remote monitoring server.

PORT is the port on this machine that will be listening for heartbeat requests.

KEY_1 and KEY_2 should be randomly selected 16 character values. They must match the values in 
monitor.py. DO NOT USE THE DEFAULTS EXCEPT FOR TESTING PURPOSES.

To avoid any extraneous alerts, run listener.py before running monitor.py.

Requires pycrypto (a non-standard library module) and python >= 3.6 for the secrets module.
"""


import socket
import time
from Crypto.Cipher import AES

HOST = '127.0.0.1'
PORT = 4555
KEY_1 = '1111222233334444'
KEY_2 = '4444333322221111'

address = (HOST, PORT)

encryptCipher = AES.new(KEY_2)
decryptCipher = AES.new(KEY_1)

s = socket.socket()
try:
    s.bind(address)
    s.listen(5)

    while True:
        c, addr = s.accept()
        message1 = decryptCipher.decrypt(c.recv(1024)) 
        c.send(encryptCipher.encrypt(message1))
        c.close()
except KeyboardInterrupt:
    s.shutdown(socket.SHUT_RDWR)
    s.close()
