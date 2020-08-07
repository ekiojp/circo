import threading
import collections
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class TRACEModule(threading.Thread):
    """
    Class to observe UDP packets (portrange 33434-33500)
    and decrypt credentials
    """
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.debug = conf['DEBUG']
        self.magic = conf['MAGIC']
        self.iface = conf['IFACE']
        self.seed1 = conf['SEED1']
        self.seed2 = conf['SEED2']
        self.seed3 = conf['SEED3']
        self.dic = {}
        self.pkttotal = 200
        self.pktlen = 0

    def pkt_callback(self, pkt):
        if pkt[IP].id == self.magic:
            self.q.put((self.magic, pkt[IP].src))
            self.join()
            return
        if pkt[IP].id >= self.seed1 and pkt[IP].id < self.seed2:
            self.pktlen = pkt[IP].id - self.seed1
            self.dic = {}
        elif pkt[IP].id >= self.seed2 and pkt[IP].id < self.seed3:
            self.pkttotal = pkt[IP].id - self.seed2
        elif pkt[IP].id >= self.seed3:
            self.dic[pkt[IP].id - self.seed3] = pkt[Raw].load[28:]

        if len(self.dic) == self.pkttotal:
            odic = collections.OrderedDict(sorted(self.dic.items()))
            final = ''
            for k, v in odic.items():
                final = final + v.decode()
            encrypted = final[:self.pktlen]
            self.q.put((encrypted, pkt[IP].src))
            self.dic = {}
            self.pkttotal = 200

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, store=0,
                  filter="(udp and dst portrange 33434-35000) and (not src port 53)")

    def join(self):
        self.stoprequest.set()
