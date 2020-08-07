import re
import threading
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class SIPHash(threading.Thread):
    """
    Class for sniff SIP packets and extract handshake
    """
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.iface = conf['IFACE']

    def parser(self, pkt):
        for line in pkt[Raw].load.split():
            m = re.findall(b'^username.*', line)
            if m:
                return m[0]

    def pkt_callback(self, pkt):
        for z in pkt[Raw].load.split():
            if re.search(b'REGISTER', z):
                cred = self.parser(pkt)
                if cred:
                    data = b'v,' + b','.join(x.split(b'=')[1].replace(b'"',b'') for x in cred.split(b',')).replace(b',MD5',b'')
                    self.q.put(data.decode())

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, filter='udp and port 5060', store=0)

    def join(self):
        self.stoprequest.set()
