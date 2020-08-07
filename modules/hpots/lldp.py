import re
import threading
from scapy.all import *
load_contrib('lldp')

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class StartLLDP(threading.Thread):
    """
    Class to handle LLDP packets, will start in background and send
    packets every 30 seconds, pretend to be a Cisco Phone or Switch
    """
    def __init__(self, conf):
        # devicetype should be 'switch' or 'phone'
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = conf['IFACE']
        self.mac = conf['MAC']
        self.src_ip = conf['IP']
        self.name = conf['NAME']
        self.int = conf['INT']
        self.type = conf['TYPE']
        if self.type == 'switch':
            self.description = 'Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE, RELEASE SOFTWARE (fc1)\nTechnical Support: http://www.cisco.com/techsupport\nCopyright (c) 1986-2012 by Cisco Systems, Inc.\nCompiled Sat 28-Jul-12 00:29 by prod_rel_team'
        elif self.type == 'phone':
            self.description = 'SIP75.8-5-3SR1S'

    def generic(self):
        """
        Build Fake LLDP packet for a switch or phone
        """
        pkteth = Ether(dst='01:80:c2:00:00:0e', src=self.mac, type=35020)
        pktchass = LLDPDUChassisID(_type=1, subtype=4, _length=7, id=self.mac)
        pktportid = LLDPDUPortID(_type=2, subtype=5)
        pktportid.id = self.int[:2] + re.findall(r'[0-9/]+', self.int)[0]
        pktportid._length = len(pktportid[LLDPDUPortID].id) + 1
        pktttl = LLDPDUTimeToLive(_type=3, ttl=120, _length=2)
        pktsys = LLDPDUSystemName(_type=5, system_name=self.name)
        pktsys._length = len(pktsys[LLDPDUSystemName].system_name)
        pktdes = LLDPDUSystemDescription(_type=6)
        pktdes.description = self.description
        pktdes._length = len(pktdes[LLDPDUSystemDescription].description)
        pktport = LLDPDUPortDescription(_type=4, description=self.int)
        pktport._length = len(pktport[LLDPDUPortDescription].description)
        pktsyscap = LLDPDUSystemCapabilities(_type=7,
                                             _length=4,
                                             mac_bridge_available=1,
                                             mac_bridge_enabled=1)
        pktmgt = LLDPDUManagementAddress(_type=8, _length=12)
        pktmgt.management_address = bytes([int(x) for x in self.src_ip.split('.')])
        pktmgt._management_address_string_length = 5
        pktmgt.management_address_subtype = 1
        pktmgt.interface_numbering_subtype = 3
        pktmgt.interface_number = 100
        pktmgt._oid_string_length = 0
        pktmgt.object_id = b''
        pkt8021 = LLDPDUGenericOrganisationSpecific(_type=127,
                                                    _length=6,
                                                    org_code=32962,
                                                    subtype=1,
                                                    data=b'\x00d')
        pkt8023 = LLDPDUGenericOrganisationSpecific(_type=127,
                                                    _length=9,
                                                    org_code=4623,
                                                    subtype=1,
                                                    data=b'\x03l\x03\x00\x10')
        pktend = LLDPDUEndOfLLDPDU(_type=0, _length=0)
        pkt = pkteth / pktchass / pktportid / pktttl / pktsys / pktdes \
            / pktport / pktsyscap / pktmgt / pkt8021 / pkt8023 / pktend
        return pkt

    def run(self):
        while not self.stoprequest.isSet():
            sendp(self.generic(), iface=self.iface, verbose=0)
            time.sleep(30)

    def join(self):
        self.stoprequest.set()
