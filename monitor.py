#! /usr/bin/python3.6
"""The secure system heartbeat checks that a system is online and responding in a
cryptographically secure way to resist man-in-the-middle attacks attempting to spoof the
system being online. If the system is down or an incorrect response is received from the secure
system, an email alert will be generated. Setup of the SMTP server is left as an exercise to the
reader. Note that two systems can (and possibly should) monitor each other simultaneously.

This is the monitor file for the secure system heartbeat. This script should run on the system
that will be monitoring the secure system.

Be sure to change the constant values.

HOST is address of the secure system to be monitored.

PORT is the port on the secure system that will be listening for heartbeat requests.

KEY_1 and KEY_2 should be randomly selected 16 character values. They must match the values in 
listener.py. DO NOT USE THE DEFAULTS EXCEPT FOR TESTING PURPOSES.

INTERVAL_SECONDS is the wait time after response is received (or an alert is generated) before a
new heartbeat request is sent. Note that due to the timeout timer, heartbeats may be sent at a
longer interval than this value.

TIMEOUT_SECONDS is the length of time the socket operations will wait before timeout. This will
trigger an alert. This value may need to be adjusted if your network is especially slow.

ALERT_EMAIL_TO is the email address where alerts will be sent.

ALERT_EMAIL_FROM is the email address where alerts will appear to be from. Optional.

ALERT_EMAIL_SUBJECT is the subject line for the alert emails. Optional.

SMTP_SERVER is the address of your SMTP server. localhost will suffice if you are running an SMTP
server on the same machine where monitor.py is running.

To avoid any extraneous alerts, run listener.py before running monitor.py.

Requires pycrypto (a non-standard library module) and python >= 3.6 for the secrets module.
"""


import socket
import time
import secrets
import smtplib
from Crypto.Cipher import AES
from email.mime.text import MIMEText

HOST = '127.0.0.1'
PORT = 4555
KEY_1 = '1111222233334444'
KEY_2 = '4444333322221111'
INTERVAL_SECONDS = 30
TIMEOUT_SECONDS = 5
ALERT_EMAIL_TO = 'example@example.com'
ALERT_EMAIL_FROM = 'noreply@yourdomain.com'
ALERT_EMAIL_SUBJECT = 'Security Alert - System Failure'
SMTP_SERVER = 'localhost'

def alertHandler(errorMessage):
    print(errorMessage)
    emailMessage = MIMEText('Your secure system has received an error:\n' + errorMessage)
    emailMessage['To'] = ALERT_EMAIL_TO
    emailMessage['From'] = ALERT_EMAIL_FROM
    emailMessage['Subject'] = ALERT_EMAIL_SUBJECT
    smtpServer = smtplib.SMTP(SMTP_SERVER)
    smtpServer.send_message(emailMessage)
    smtpServer.quit()

address = (HOST, PORT)

encryptCipher = AES.new(KEY_1)
decryptCipher = AES.new(KEY_2)

while True:
    message1 = secrets.token_bytes(16)
    s = socket.socket()

    s.settimeout(TIMEOUT_SECONDS)
    try:
        s.connect(address)
        s.send(encryptCipher.encrypt(message1))
        message2 = decryptCipher.decrypt(s.recv(1024))
    except ConnectionRefusedError:
        alertHandler('connection refused. possible system failure.')
    except socket.timeout:
        alertHandler('system response timed out. possible system failure.')
    else:
        print(message2)
        if secrets.compare_digest(message1, message2):
            print('ok.')
        else:
            alertHandler('messages different. possible mitm attack.')
    s.close()
    time.sleep(INTERVAL_SECONDS)
