import threading
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class StartSNMP(threading.Thread):
    """
    Class to sniff SNMP packets
    push to queue any community found
    """
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.iface = conf['IFACE']
        self.community = conf['SNMPC']

    def strtohex(self, ip):
        return ''.join('{:02x}'.format(int(char)) for char in ip.split('.'))

    def pkt_callback(self, pkt):
        if pkt.haslayer(SNMP) and pkt[SNMP].community:
            m = re.findall('\'(.*)\'', pkt[SNMP].community.strshow())
            if m:
                comm = m[0]
            srcip = self.strtohex(pkt[IP].src)
            if (comm != self.community):
                self.q.put('p,' + comm + ',' + srcip)

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, filter='udp port 161', store=0, count=1)

    def join(self):
        self.stoprequest.set()
