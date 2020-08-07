import threading
import ipaddress
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class FindVictim(threading.Thread):
    """
    Sniff packets on IP-Phone port (eth1) and look for MAC/IP
    Use MAC/IP for exfiltration when using --spoof
    """
    def __init__(self, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = conf['IFACE']
        self.gw = conf['GWIP']
        self.spoofip = ''
        self.spoofmac = ''

    def pkt_callbak(self, pkt):
        mac_src = pkt[Ether].src
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if ipaddress.ip_address(ip_src).is_private and not ipaddress.ip_address(ip_dst).is_multicast and ip_src != self.gw:
            self.spoofip = ip_src
            self.spoofmac = mac_src
            self.join()

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callbak, filter='ip', store=0)

    def join(self):
        self.stoprequest.set()
        return self.spoofmac, self.spoofip
