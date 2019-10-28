#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import re
import sys
import os
import socket
import threading
import time
import random

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.5.1"

# Config
dirname = '/home/pi-enc/circo/circo/'
fd = dirname + 'cli.conf'
mastercred = sys.argv[1]
patterns = [r'^cl.*', r'^disa.*', r'^disc.*', r'^en.*', r'^ex.*', r'^he.*', r'^logi.*', r'^logo.*', r'^sh.*ve.*', r'^sh.*ip.*int.*', r'^sh.*inv.*', r'^sh.*in.*st.*', r'^sh.*ip.*ro.*', r'^wr.*me.*', r'^\?', r'^sh.*run.*', r'^sh.*star.*', r'^sh.*mac.*add.*', r'^sh.*vlan', r'^sh.*ip.*arp', r'^sh.*int.*des.*', r'sh.*cdp.*nei.*', r'sh.*lldp.*nei.*', r'term.*']


# Classes
class daemon(threading.Thread):
    """
    Fake IOS telnet service
    """
    def __init__(self, fd, (socket, address)):
        threading.Thread.__init__(self)
        self.socket = socket
        self.address = address
        self.cnt = 0
        self.USER = ''
        self.MOTD = ''
        self.cli = {}
        with open(fd, 'r') as sfile:
            m = sfile.readlines()
            for x in range(len(m)):
                q = re.findall('<(.*)>,(.*)', m[x])[0]
                self.cli[q[0]] = q[1]

        with open(fd, 'r') as sfile:
            for line in sfile:
                m = re.search('<NAME>,.*', line)
                if m:
                    self.NAME = m.group().split(',')[1]
                m = re.search('<IP>,.*', line)
                if m:
                    self.IP = m.group().split(',')[1]
                m = re.search('<MASK>,.*', line)
                if m:
                    self.MASK = m.group().split(',')[1]
                m = re.search('<MASKCIDR>,.*', line)
                if m:
                    self.MASKCIDR = m.group().split(',')[1]
                m = re.search('<MAC>,.*', line)
                if m:
                    self.MAC = m.group().split(',')[1]
                m = re.search('<NETIP>,.*', line)
                if m:
                    self.NETIP = m.group().split(',')[1]
                m = re.search('<GWIP>,.*', line)
                if m:
                    self.GWIP = m.group().split(',')[1]
                m = re.search('<GWMAC>,.*', line)
                if m:
                    self.GWMAC = m.group().split(',')[1]
                m = re.search('<SNMPC>,.*', line)
                if m:
                    self.SNMPC = m.group().split(',')[1]
                m = re.search('<SERIAL>,.*', line)
                if m:
                    self.SERIAL = m.group().split(',')[1]
                m = re.search('<SNPSU>,.*', line)
                if m:
                    self.SNPSU = m.group().split(',')[1]
                m = re.search('<CDPNAME>,.*', line)
                if m:
                    self.CDPNAME = m.group().split(',')[1]
                r = re.compile("(.*CDPINT.*),([a-zA-Z]+)([0-9].*)")
                m = r.match(line)
                if m:
                    self.CDPINT = m.group(2)[0:3] + ' ' + m.group(3)
                m = re.search('<CDPMODEL>,.*', line)
                if m:
                    self.CDPMODEL = m.group().split(',')[1]
                m = re.search('<LLDPNAME>,.*', line)
                if m:
                    self.LLDPNAME = m.group().split(',')[1]
                m = re.search('<LLDPINT>,.*', line)
                if m:
                    self.LLDPINT = m.group().split(',')[1]
                m = re.search('<INT>,.*', line)
                if m:
                    self.INT = m.group().split(',')[1]
                m = re.search('<MOTD>,.*', line)
                if m:
                    self.MOTD = m.group().split(',')[1]
                    self.MOTD = self.MOTD.replace('<CR>', '\r\n')
        self.enaprompt = False
        self.prompt = self.NAME+'>'
        self.promptenable = self.NAME+'#'

    def cmd(self, string):
        results = [re.findall(patterns[idx], string) for idx in range(len(
                                                                    patterns))]
        # ?,help
        if results[5] or results[14]:
            self.socket.send('?\r\n')
            with open(dirname + 'cli-cmd_help.txt', 'r') as shhelp:
                self.socket.send('Exec commands:\r\n')
                for line in shhelp:
                    self.socket.send('  ' + line.strip('\n') + '\r\n')

        # disable, disconnect, exit, logout
        elif results[1] or results[2] or results[4] or results[7]:
            self.socket.send('\r\n')
            self.socket.close()
            sys.exit(1)

        # show ip int brief
        elif results[9]:
            self.socket.send('\r\n')
            with open(dirname + 'cli-cmd_show_ip_int.txt', 'r') as ipbrief:
                for line in ipbrief:
                    tosend = line.replace('<IP>', self.IP)
                    self.socket.send(tosend.strip('\n') + '\r\n')

        # show inventory
        elif results[10]:
            self.socket.send('\r\n')
            with open(dirname + 'cli-cmd_show_inventory.txt', 'r') as inventory:
                for line in inventory:
                    tosend = line.replace('<SERIAL>', self.SERIAL)
                    self.socket.send(tosend.strip('\n') + '\r\n')

        # show interface status
        elif results[11]:
            self.socket.send('\r\n')
            with open(dirname + 'cli-cmd_show_int_status.txt', 'r') as intstatus:
                for line in intstatus:
                    self.socket.send(line.strip('\n') + '\r\n')

        # show ip route
        elif results[12]:
            self.socket.send('\r\n')
            with open(dirname + 'cli-cmd_show_ip_route.txt', 'r') as iproute:
                for line in iproute:
                    tosend = line.replace('<NETIP>', self.NETIP)
                    tosend = tosend.replace('<MASKCIDR>', self.MASKCIDR)
                    tosend = tosend.replace('<GWIP>', self.GWIP)
                    self.socket.send(tosend.strip('\n') + '\r\n')

        # clear
        elif results[0]:
            self.socket.send('\r\n')
            self.socket.send("\033[H\033[J")

        # show version
        elif results[8]:
            self.socket.send('\r\n')
            with open(dirname + 'cli-cmd_version.txt', 'r') as ver:
                for line in ver:
                    tosend = line.replace('<NAME>', self.NAME)
                    tosend = tosend.replace('<MAC>', self.MAC)
                    tosend = tosend.replace('<SERIAL>', self.SERIAL)
                    tosend = tosend.replace('<SNPSU>', self.SNPSU)
                    self.socket.send(tosend.strip('\n') + '\r\n')

        # show running
        elif (results[15] or results[16]) and self.enaprompt:
            self.socket.send('\r\n')
            with open(dirname + 'cli-cmd_show_run.txt', 'r') as ver:
                for line in ver:
                    tosend = line.replace('<NAME>', self.NAME)
                    tosend = tosend.replace('<USER>', self.USER)
                    tosend = tosend.replace('<IP>', self.IP)
                    tosend = tosend.replace('<MOTD>', self.MOTD)
                    tosend = tosend.replace('<MASK>', self.MASK)
                    tosend = tosend.replace('<GWIP>', self.GWIP)
                    tosend = tosend.replace('<SNMPC>', self.SNMPC)
                    self.socket.send(tosend.strip('\n') + '\r\n')

        # show mac address
        elif results[17]:
            self.socket.send('\r\n')
            with open(dirname + 'cli-cmd_show_mac_address.txt', 'r') as ver:
                for line in ver:
                    tosend = line.replace('<GWMAC>', self.GWMAC)
                    tosend = tosend.replace('<MAC>', self.MAC)
                    self.socket.send(tosend.strip('\n') + '\r\n')

        # show vlan
        elif results[18]:
            self.socket.send('\r\n')
            with open(dirname + 'cli-cmd_show_vlan.txt', 'r') as ver:
                for line in ver:
                    self.socket.send(line.strip('\n') + '\r\n')

        # show ip arp
        elif results[19]:
            self.socket.send('\r\n')
            with open(dirname + 'cli-cmd_show_ip_arp.txt', 'r') as ver:
                for line in ver:
                    tosend = line.replace('<IP>', self.IP)
                    tosend = tosend.replace('<MAC>', self.MAC)
                    tosend = tosend.replace('<GWIP>', self.GWIP)
                    tosend = tosend.replace('<GWMAC>', self.GWMAC)
                    self.socket.send(tosend.strip('\n') + '\r\n')

        # show int desc
        elif results[20]:
            self.socket.send('\r\n')
            with open(dirname + 'cli-cmd_show_int_desc.txt', 'r') as ver:
                for line in ver:
                    self.socket.send(line.strip('\n') + '\r\n')

        # show cdp nei
        elif results[21]:
            self.socket.send('\r\n')
            with open(dirname + 'cli-cmd_show_cdp_nei.txt', 'r') as ver:
                for line in ver:
                    tosend = line.replace('<CDPNAME>', self.CDPNAME)
                    tosend = tosend.replace('<CDPINT>', self.CDPINT)
                    tosend = tosend.replace('<CDPMODEL>', self.CDPMODEL)
                    tosend = tosend.replace('<NUM>',
                                            str(random.randint(10, 199)))
                    self.socket.send(tosend.strip('\n') + '\r\n')

        # show lldp nei
        elif results[22]:
            self.socket.send('\r\n')
            with open(dirname + 'cli-cmd_show_lldp_nei.txt', 'r') as ver:
                for line in ver:
                    tosend = line.replace('<LLDPNAME>', self.LLDPNAME)
                    tosend = tosend.replace('<LLDPINT>', self.LLDPINT)
                    tosend = tosend.replace('<INT>', self.INT)
                    tosend = tosend.replace('<NUM>',
                                            str(random.randint(10, 199)))
                    self.socket.send(tosend.strip('\n') + '\r\n')

        # terminal.*
        elif results[23] and self.enaprompt:
            self.socket.send('\r\n')

        # write memory
        elif results[13] and self.enaprompt:
            self.socket.send("\r\nBuilding configuration...\r\n")
            time.sleep(5)
            self.socket.send("Compressed configuration from 23479 bytes \
                             to 104927 bytes\r\n")
            self.socket.send("[OK]\r\n")

        # enable,login
        elif results[3] or results[6]:
            self.socket.send('\r\npassword: ')
            out = False
            buf = ''
            while True:
                data = self.socket.recv(1024)
                for x in range(len(data)):
                    if ord(data[x]) == 13 or ord(data[x]) == 10:
                        out = True
                if out:
                    text = 't,e,' + buf + ',' + strtohex(self.address[0])
                    find = re.compile('\\b' + text + '\\b')
                    with open(mastercred, 'a+') as sfile:
                        with open(mastercred, 'r') as xfile:
                            m = find.findall(xfile.read())
                            if not m:
                                sfile.write(text + '\n')
                    break
                buf = buf + data
            self.enaprompt = True
            self.socket.send('\r\n')

        # if any other command (unknow/not allowed)
        else:
            if self.enaprompt:
                self.socket.send('\r\nCommand authorization failed.\r\n')
            else:
                self.socket.send('\r\n% Unrecognized command\r\n')

        # Add prompt to end of each answer
        if self.enaprompt:
            self.socket.send(self.promptenable)
        else:
            self.socket.send(self.prompt)

    def run(self):

        # print client neg options (DEBUG)
        dd = self.socket.recv(1024)

        self.socket.send(
                        chr(0xff) +
                        chr(0xfb) +
                        chr(0x01) +
                        chr(0xff) +
                        chr(0xfb) +
                        chr(0x03) +
                        chr(0xff) +
                        chr(0xfd) +
                        chr(0x18) +
                        chr(0xff) +
                        chr(0xfd) +
                        chr(0x1f) 
                        )

        # recv the WILL (DEBUG)
        dd = self.socket.recv(1024)

        try:
            self.socket.send(self.MOTD + '\r\n\r\nUser Access Verification\r\n\r\nUsername: ')
        except:
            self.socket.close()

        # send IAC SB terminal type
        self.socket.send(
                        chr(0xff) +
                        chr(0xfa) +
                        chr(0x18) +
                        chr(0x01) +
                        chr(0xff) +
                        chr(0xf0)
                        )

        # send DONT terminal speed
        self.socket.send(
                        chr(0xff) +
                        chr(0xfe) +
                        chr(0x20)
                        )

        # receive terminal type
        dd = self.socket.recv(1024)

        # send DONT remote flow
        self.socket.send(
                        chr(0xff) +
                        chr(0xfe) +
                        chr(0x20)
                        )

        # send DONT Linemode
        self.socket.send(
                        chr(0xff) +
                        chr(0xfe) +
                        chr(0x22)
                        )

        # send DONT New Enviroment Option
        self.socket.send(
                        chr(0xff) +
                        chr(0xfe) +
                        chr(0x27)
                        )

        # send WONT Status
        self.socket.send(
                        chr(0xff) +
                        chr(0xfc) +
                        chr(0x05)
                        )

        buff = ''
        while(True):

            data = self.socket.recv(1024)

            if data and self.cnt == 0:
                if len(data) == 2 and '\r' in data:
                    self.cnt = 1
                    username = buff
                    self.USER = buff
                    self.socket.send('\r\nPassword: ')
                    buff = ''
                else:
                    # send ECHO
                    self.socket.send(data)
                    buff = buff + data
            elif data and self.cnt == 1:
                if len(data) == 2 and '\r' in data:
                    self.cnt = 2
                    password = buff
                    self.socket.send('\r\n' + self.prompt)
                    buff = ''
                    text = 't,' + username.strip() + ',' + password.strip() + ',' + strtohex(self.address[0])
                    find = re.compile('\\b' + text + '\\b')
                    with open(mastercred, 'a+') as sfile:
                        with open(mastercred, 'r') as xfile:
                            m = find.findall(xfile.read())
                            if not m:
                                sfile.write(text + '\n')
                else:
                    # no ECHO for password
                    buff = buff + data

            elif data:
                for x in range(len(data)):
                    if ord(data[x]) == 3:
                            if self.enaprompt:
                                self.socket.send('\r\n' + self.promptenable)
                            else:
                                self.socket.send('\r\n' + self.prompt)
                            buff = ''
                    elif ord(data[x]) == 127:
                            if len(buff) >= 1:
                                buff = buff[:-1]
                                self.socket.send(chr(8) + chr(32) + chr(8))
                    elif ord(data[x]) == 13 or ord(data[x]) == 10:
                        if len(buff) > 2:
                            self.cmd(buff)
                        else:
                            if self.enaprompt:
                                self.socket.send('\r\n' + self.promptenable)
                            else:
                                self.socket.send('\r\n' + self.prompt)
                        buff = ''
                    elif ord(data[x]) == 63:
                        self.cmd('?')
                        buff = ''
                    elif (45 <= ord(data[x]) <= 58 or
                          97 <= ord(data[x]) <= 122 or ord(data[x]) == 32):
                        buff = buff + data
                        self.socket.send(data)
        # close connection
        self.socket.close()


# Funtion
def strtohex(ip):
    return ''.join('{:02x}'.format(int(char)) for char in ip.split('.'))

# Main Function
def main():
    # Bind socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 23))
    s.listen(1)
    lock = threading.Lock()

    while True:
        daemon(fd, s.accept()).start()

# Call main
if __name__ == '__main__':
    main()
