#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import sys
import netfilterqueue as nfqueue
from random import randint
from dpkt import *
from socket import AF_INET, inet_ntoa
sys.stderr = None
from scapy.all import *
sys.stderr = sys.__stderr__

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.6"

# Code below adapted from awesome tool OSfooler-ng 
# https://github.com/segofensiva/OSfooler-ng and https://github.com/moonbaseDelta/OSfooler-ng
# Authors: Jaime Sanchez (@segofensiva) and Simple_Not

# Config 
conf.L3socket = L3RawSocket
iface = sys.argv[1]

# Global
ICMP_PACKET = 0
ICMP_IPID = 0
IPID = 0

# TCP Flags
TH_FIN = 0x01          # end of data
TH_SYN = 0x02          # synchronize sequence numbers
TH_RST = 0x04          # reset connection
TH_PUSH = 0x08          # push
TH_ACK = 0x10          # acknowledgment number set
TH_URG = 0x20          # urgent pointer set
TH_ECE = 0x40          # ECN echo, RFC 3168
TH_CWR = 0x80          # congestion window reduced

# Nmap options
T1_opt1 = "03030a01020405b4080affffffff000000000402"
T1_opt2 = "020405780303000402080affffffff0000000000"
T1_opt3 = "080affffffff0000000001010303050102040280"
T1_opt4 = "0402080affffffff0000000003030a00"
T1_opt5 = "020402180402080affffffff0000000003030a00"
T1_opt6 = "020401090402080affffffff00000000"
T2_T6_opt = "03030a0102040109080affffffff000000000402"
T7_opt = "03030f0102040109080affffffff000000000402"
ECN_opt = "03030a01020405b404020101"

# Nmap payloads
udp_payload = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"


# Functions
def tcp_flags(flags):
  ret = ''
  if flags & TH_FIN:
    ret = ret + 'F'
  if flags & TH_SYN:
    ret = ret + 'S'
  if flags & TH_RST:
    ret = ret + 'R'
  if flags & TH_PUSH:
    ret = ret + 'P'
  if flags & TH_ACK:
    ret = ret + 'A'
  if flags & TH_URG:
    ret = ret + 'U'
  if flags & TH_ECE:
    ret = ret + 'E'
  if flags & TH_CWR:
    ret = ret + 'C'
  return ret

# ECN response
def ECN_reply(payload):
    global IPID
    pkt = ip.IP(payload.get_payload())
    IPID = IPID + 1
    newpkt = IP(id=IPID, dst=inet_ntoa(pkt.src), src=inet_ntoa(pkt.dst), flags=0, ttl=255)/ \
             TCP(sport=pkt.tcp.dport, dport=pkt.tcp.sport, window=4128, options=[('MSS', 1460)], flags='')
    send(newpkt, verbose=0, iface=iface)

# T1 response
def T1_reply(payload, num):
    global IPID
    pkt = ip.IP(payload.get_payload())
    FLAGS = 'AS'
    if num == 1:
        opts = [('MSS', 1460)]
    elif num == 2:
        opts = [('MSS', 1400)]
    elif num == 3:
        opts = [('MSS', 640)]
    elif num == 4 or num == 5:
        opts = [('MSS', 536)]
    elif num == 6:
        opts = [('MSS', 265)]
    newpkt = IP(dst=inet_ntoa(pkt.src), src=inet_ntoa(pkt.dst), flags=0, ttl=255)/ \
             TCP(sport=pkt.tcp.dport, dport=pkt.tcp.sport, seq=randint(1, 65535), ack=int(pkt.tcp.seq)+1, flags='AS', window=4128, options=opts)
    send(newpkt, verbose=0, iface=iface)

# T5 response
def T5_reply(payload):
    global IPID
    pkt = ip.IP(payload.get_payload())
    IPID = IPID + 1
    newpkt = IP(id=IPID, dst=inet_ntoa(pkt.src), src=inet_ntoa(pkt.dst), flags=0, ttl=255)/ \
             TCP(sport=pkt.tcp.dport, dport=pkt.tcp.sport, seq=int(pkt.tcp.ack), ack=int(pkt.tcp.seq)+1, window=0, options=[], flags='AR')
    send(newpkt, verbose=0, iface=iface)

# ECN response
def ECN_reply(payload):
    global IPID
    pkt = ip.IP(payload.get_payload())
    IPID = IPID + 1
    newpkt = IP(id=IPID, dst=inet_ntoa(pkt.src), src=inet_ntoa(pkt.dst), flags=0, ttl=255)/ \
             TCP(sport=pkt.tcp.dport, dport=pkt.tcp.sport, window=4128, options=[('MSS', 1460)], flags='')
    send(newpkt, verbose=0, iface=iface)

# ICMP response
def ICMP_reply(payload):
    global ICMP_PACKET
    global ICMP_IPID
    pkt = ip.IP(payload.get_payload())
    if (ICMP_PACKET % 2 == 0):
        fbit = 2
    else:
        fbit = 0
    ICMP_PACKET = ICMP_PACKET + 1
    i = randint(1, 1500)
    while (i < 1000) or (i % 256 == 0):
        i = randint(1, 1500)
    ICMP_IPID = ICMP_IPID + i
    if (ICMP_IPID > 65535):
        ICMP_IPID = ICMP_IPID - 65535
    newpkt = IP(id=ICMP_IPID, dst=inet_ntoa(pkt.src), src=inet_ntoa(pkt.dst), flags=fbit, ttl=255)/ \
             ICMP(id=pkt.icmp.data.id, seq=pkt.icmp.data.seq, code=pkt.icmp.code, type=0)
    send(newpkt, verbose=0, iface=iface)

# Nfqueue callback
def callback(pl):
    pkt = ip.IP(pl.get_payload())
    if pkt.p == ip.IP_PROTO_TCP:
        options = pkt.tcp.opts.encode('hex_codec')
        flags = tcp_flags(pkt.tcp.flags)
        if (flags == "S") and (pkt.tcp.win == 1) and (options == T1_opt1):
            pl.drop()
            T1_reply(pl, 1)
        elif (flags == "S") and (pkt.tcp.win == 63) and (options == T1_opt2):
            pl.drop()
            T1_reply(pl, 2)
        elif (flags == "S") and (pkt.tcp.win == 4) and (options == T1_opt3):
            pl.drop()
            T1_reply(pl, 3)
        elif (flags == "S") and (pkt.tcp.win == 4) and (options == T1_opt4):
            pl.drop()
            T1_reply(pl, 4)
        elif (flags == "S") and (pkt.tcp.win == 16) and (options == T1_opt5):
            pl.drop()
            T1_reply(pl, 5)
        elif (flags == "S") and (pkt.tcp.win == 512) and (options == T1_opt6):
            pl.drop()
            T1_reply(pl, 6)
        elif (flags == "") and (pkt.tcp.win == 128) and (options == T2_T6_opt):
            pl.drop()
        elif (flags == "FSPU") and (pkt.tcp.win == 256) and (options == T2_T6_opt):
            pl.drop()
        elif (flags == "A") and (pkt.tcp.win == 1024) and (options == T2_T6_opt):
            pl.drop()
        elif (flags == "S") and (pkt.tcp.win == 31337) and (options == T2_T6_opt):
            pl.drop()
            T5_reply(pl)
        elif (flags == "A") and (pkt.tcp.win == 32768) and (options == T2_T6_opt):
            pl.drop()
        elif (flags == "FPU") and (pkt.tcp.win == 65535) and (options == T7_opt):
            pl.drop()
        elif (flags == "SEC") and (pkt.tcp.win == 3) and (options == ECN_opt):
            pl.drop()
            ECN_reply(pl)
        else:
            pl.accept()
    elif pkt.p == ip.IP_PROTO_UDP:
        if (pkt.udp.data == udp_payload):
            pl.drop()
        else:
            pl.accept()
    elif pkt.p == ip.IP_PROTO_ICMP:
        if (pkt.icmp.code == 9) and (pkt.icmp.type == 8) and (len(pkt.icmp.data.data) == 120):
            pl.drop()
            ICMP_reply(pl)
        elif (pkt.icmp.code == 0) and (pkt.icmp.type == 8) and (len(pkt.icmp.data.data) == 150):
            pl.drop()
            ICMP_reply(pl)
        else:
            pl.accept()
    else:
        pl.accept()
        return 0

def main():
    #print('Starting...')
    os.system('iptables -F')
    os.system('iptables -A INPUT -i ' + iface + ' -j NFQUEUE --queue-num 4')
    q = nfqueue.NetfilterQueue()
    q.bind(4, callback)
    try:
        q.run()
    except KeyboardInterrupt:
        os.system('iptables -F')


# Call main
if __name__ == '__main__':
    main()
