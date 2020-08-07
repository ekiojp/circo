import os
import threading
import zipfile
from scapy.all import *
from datetime import datetime

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class RTPSniff(threading.Thread):
    """
    Class for sniff SIP/RTP packets and generate .pcap
    """
    def __init__(self, iface):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.rtpcnt = 0
        self.sipcnt = 0
        self.dirout = 'Captures/'
        self.sipcap = self.dirout + datetime.now().strftime("%Y%m%d-%H%M%S") + '_SIP.pcap'
        self.rtpcap = self.dirout + datetime.now().strftime("%Y%m%d-%H%M%S") + '_RTP.pcap'

    def compress(sefl, filename):
        zipped = zipfile.ZipFile(filename + '.zip', mode='w', compression=zipfile.ZIP_DEFLATED)
        zipped.write(filename)
        zipped.close()
        os.remove(filename)

    def callback(self, pkt):
        if pkt[UDP].dport == 5060:
            if self.sipcnt >= 100000:
                _sipcap = self.sipcap
                self.sipcap = self.dirout + datetime.now().strftime("%Y%m%d-%H%M%S") + '_SIP.pcap'
                self.compress(_sipcap)
                self.sipcnt = 0
            wrpcap(self.sipcap, pkt, append=True)
            self.sipcnt += 1
        else:
            if self.rtpcnt >= 100000:
                _rtpcap = self.rtpcap
                self.rtpcap = self.dirout + datetime.now().strftime("%Y%m%d-%H%M%S") + '_RTP.pcap'
                self.compress(_rtpcap)
                self.rtpcnt = 0
            wrpcap(self.rtpcap, pkt, append=True)
            self.rtpcnt += 1

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.callback, filter='udp and (port 5060 or portrange 16384-32767)')

    def join(self):
        self.stoprequest.set()

