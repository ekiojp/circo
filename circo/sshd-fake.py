#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import re
import os
import sys
import socket
import threading
import struct
import time
import random
import daemon
import subprocess
import base64
from binascii import hexlify
import traceback
import paramiko
from paramiko.py3compat import b, u, decodebytes

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.4"

# Config
dirname = '/home/pi/circo/circo/'
mastercred = sys.argv[1]
fd = dirname + 'cli.conf'
sshkey = dirname + 'ssh_rsa.key'
srcip = ''
welcome_message = '\r\n------------------------------------------------------------------------\r\n- Warning: These facilities are solely for the use of authorized       -\r\n- employees or agents of the Company, its subsidiaries and affiliates. -\r\n- Unauthorized use is prohibited and subject to criminal and civil     -\r\n- penalties. Subject to applicable law, individuals using this         -\r\n- computer system must have no expectation of privacy and are subject  -\r\n- to having all of their activities monitored and recorded.            -\r\n------------------------------------------------------------------------\r\n\r\n'
patterns = [r'^cl.*', r'^disa.*', r'^disc.*', r'^en.*', r'^ex.*', r'^he.*', r'^logi.*', r'^logo.*', r'^sh.*ve.*', r'^sh.*ip.*int.*', r'^sh.*inv.*', r'^sh.*in.*st.*', r'^sh.*ip.*ro.*', r'^wr.*me.*', r'^\?', r'^sh.*run.*', r'^sh.*star.*', r'^sh.*mac.*add.*', r'^sh.*vlan', r'^sh.*ip.*arp', r'^sh.*int.*des.*', r'sh.*cdp.*nei.*', r'sh.*lldp.*nei.*', r'term.*']


# Classes
class Server(paramiko.ServerInterface):
    """
    Paramiko Server Class, add extra function to get user
    """
    def __init__(self):
        self.event = threading.Event()
        self.USER = ''

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.USER = username.strip()
        text = 's,' + username.strip() + ',' + password.strip() + ',' + srcip
        find = re.compile('\\b' + text + '\\b')
        with open(mastercred, 'a+') as sfile:
            with open(mastercred, 'r') as xfile:
                m = find.findall(xfile.read())
                if not m:
                    sfile.write(text + '\n')
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True

    def get_user(self):
        return self.USER


class sshd(threading.Thread):
    """
    Fake IOS ssh daemon
    Build commands using cli.conf file
    """
    def __init__(self, fd, (socket, address)):
        threading.Thread.__init__(self)
        self.socket = socket
        self.address = address
        self.cnt = 0
        self.chan = ''
        self.USER = ''
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
                m = re.search('<CDPINT>,.*', line)
                if m:
                    self.CDPINT = m.group().split(',')[1]
                m = re.search('<CDPMODEL>,.*', line)
                if m:
                    self.CDPMODEL = m.group().split(',')[1]
                m = re.search('<INT>,.*', line)
                if m:
                    self.INT = m.group().split(',')[1]
                m = re.search('<LLDPNAME>,.*', line)
                if m:
                    self.LLDPNAME = m.group().split(',')[1]
                m = re.search('<LLDPINT>,.*', line)
                if m:
                    self.LLDPINT = m.group().split(',')[1]
        self.enaprompt = False
        self.prompt = self.NAME + '>'
        self.promptenable = self.NAME + '#'

    def cmd(self, string):
        results = [re.findall(patterns[idx], string) for idx in range(len(
                                                                    patterns))]
        # ?,help
        if results[5] or results[14]:
            self.chan.send('?\r\n')
            with open(dirname + 'cli-cmd_help.txt', 'r') as shhelp:
                self.chan.send('Exec commands:\r\n')
                for line in shhelp:
                    self.chan.send('  ' + line.strip() + '\r\n')

        # disable, disconnect, exit, logout
        elif results[1] or results[2] or results[4] or results[7]:
            self.chan.send('\r\n')
            self.chan.close()
            sys.exit(1)

        # show ip int brief
        elif results[9]:
            self.chan.send('\r\n')
            with open(dirname + 'cli-cmd_show_ip_int.txt', 'r') as ipbrief:
                for line in ipbrief:
                    tosend = line.replace('<IP>', self.IP)
                    self.chan.send(tosend.strip('\n') + '\r\n')

        # show inventory
        elif results[10]:
            self.chan.send('\r\n')
            with open(dirname + 'cli-cmd_show_inventory.txt', 'r') as inventory:
                for line in inventory:
                    tosend = line.replace('<SERIAL>', self.SERIAL)
                    self.chan.send(tosend.strip('\n') + '\r\n')

        # show interface status
        elif results[11]:
            self.chan.send('\r\n')
            with open(dirname + 'cli-cmd_show_int_status.txt', 'r') as intstatus:
                for line in intstatus:
                    self.chan.send(line.strip('\n') + '\r\n')

        # show ip route
        elif results[12]:
            self.chan.send('\r\n')
            with open(dirname + 'cli-cmd_show_ip_route.txt', 'r') as iproute:
                for line in iproute:
                    tosend = line.replace('<NETIP>', self.NETIP)
                    tosend = tosend.replace('<MASKCIDR>', self.MASKCIDR)
                    tosend = tosend.replace('<GWIP>', self.GWIP)
                    self.chan.send(tosend.strip('\n') + '\r\n')

        # clear
        elif results[0]:
            self.chan.send('\r\n')
            self.chan.send("\033[H\033[J")

        # show version
        elif results[8]:
            self.chan.send('\r\n')
            with open(dirname + 'cli-cmd_version.txt', 'r') as ver:
                for line in ver:
                    tosend = line.replace('<NAME>', self.NAME)
                    tosend = tosend.replace('<MAC>', self.MAC)
                    tosend = tosend.replace('<SERIAL>', self.SERIAL)
                    tosend = tosend.replace('<SNPSU>', self.SNPSU)
                    self.chan.send(tosend.strip('\n') + '\r\n')

        # show running
        elif (results[15] or results[16]) and self.enaprompt:
            self.chan.send('\r\n')
            with open(dirname + 'cli-cmd_show_run.txt', 'r') as ver:
                for line in ver:
                    tosend = line.replace('<NAME>', self.NAME)
                    tosend = tosend.replace('<IP>', self.IP)
                    tosend = tosend.replace('<USER>', self.USER)
                    tosend = tosend.replace('<MASK>', self.MASK)
                    tosend = tosend.replace('<GWIP>', self.GWIP)
                    tosend = tosend.replace('<SNMPC>', self.SNMPC)
                    self.chan.send(tosend.strip('\n') + '\r\n')

        # show mac address
        elif results[17]:
            self.chan.send('\r\n')
            with open(dirname + 'cli-cmd_show_mac_address.txt', 'r') as ver:
                for line in ver:
                    tosend = line.replace('<GWMAC>', self.GWMAC)
                    tosend = tosend.replace('<MAC>', self.MAC)
                    self.chan.send(tosend.strip('\n') + '\r\n')

        # show vlan
        elif results[18]:
            self.chan.send('\r\n')
            with open(dirname + 'cli-cmd_show_vlan.txt', 'r') as ver:
                for line in ver:
                    self.chan.send(line.strip('\n') + '\r\n')

        # show ip arp
        elif results[19]:
            self.chan.send('\r\n')
            with open(dirname + 'cli-cmd_show_ip_arp.txt', 'r') as ver:
                for line in ver:
                    tosend = line.replace('<IP>', self.IP)
                    tosend = tosend.replace('<MAC>', self.MAC)
                    tosend = tosend.replace('<GWIP>', self.GWIP)
                    tosend = tosend.replace('<GWMAC>', self.GWMAC)
                    self.chan.send(tosend.strip('\n') + '\r\n')

        # show int desc
        elif results[20]:
            self.chan.send('\r\n')
            with open(dirname + 'cli-cmd_show_int_desc.txt', 'r') as ver:
                for line in ver:
                    self.chan.send(line.strip('\n') + '\r\n')

        # show cdp neighbors
        elif results[21]:
            self.chan.send('\r\n')
            with open(dirname + 'cli-cmd_show_cdp_nei.txt', 'r') as ver:
                for line in ver:
                    tosend = line.replace('<CDPNAME>', self.CDPNAME)
                    tosend = tosend.replace('<CDPINT>', self.CDPINT)
                    tosend = tosend.replace('<CDPMODEL>', self.CDPMODEL)
                    tosend = tosend.replace('<NUM>',
                                            str(random.randint(10, 199)))
                    self.chan.send(tosend.strip('\n') + '\r\n')

        # show lldp neighbors
        elif results[22]:
            self.chan.send('\r\n')
            with open(dirname + 'cli-cmd_show_lldp_nei.txt', 'r') as ver:
                for line in ver:
                    tosend = line.replace('<LLDPNAME>', self.LLDPNAME)
                    tosend = tosend.replace('<LLDPINT>', self.LLDPINT)
                    tosend = tosend.replace('<INT>', self.INT)
                    tosend = tosend.replace('<NUM>',
                                            str(random.randint(10, 199)))
                    self.chan.send(tosend.strip('\n') + '\r\n')

	# terminal.*
        elif results[23]:
            self.chan.send('\r\n')

        # write memory
        elif results[13] and self.enaprompt:
            self.chan.send("\r\nBuilding configuration...\r\n")
            time.sleep(5)
            self.chan.send("Compressed configuration from 23479 bytes \
                           to 104927 bytes\r\n")
            self.chan.send("[OK]\r\n")

        # enable,login
        elif results[3] or results[6]:
            self.chan.send('\r\npassword: ')
            out = False
            buf = ''
            while True:
                dat = self.chan.recv(1024)
                for x in range(len(dat)):
                    if ord(dat[x]) == 13 or ord(dat[x]) == 10:
                        out = True
                if out:
                    text = 's,e,' + buf + ',' + srcip
                    find = re.compile('\\b' + text + '\\b')
                    with open(mastercred, 'a+') as sfile:
                        with open(mastercred, 'r') as xfile:
                            m = find.findall(xfile.read())
                            if not m:
                                sfile.write(text + '\n')
                    break
                buf = buf+dat
            self.enaprompt = True
            self.chan.send('\r\n')

        # if any other command (unknow/not allowed)
        else:
            if self.enaprompt:
                self.chan.send('\r\nCommand authorization failed.\r\n')
            else:
                self.chan.send('\r\n% Unrecognized command\r\n')

        # Add prompt to end of each answer
        if self.enaprompt:
            self.chan.send(self.promptenable)
        else:
            self.chan.send(self.prompt)

    def run(self):
        global srcip
        host_key = paramiko.RSAKey(filename=sshkey)
        t = paramiko.Transport(self.socket)
        t.local_version = 'SSH-2.0-Cisco-1.25'
        t.add_server_key(host_key)
        server = Server()
        try:
            srcip = strtohex(self.address[0])
            t.start_server(server=server)
        except:
            pass

        # wait for auth
        self.chan = t.accept(20)
        if self.chan is None:
            print('fake-sshd: No channel')
            sys.exit(1)

        server.event.wait(10)
        if not server.event.is_set():
            print('fake-sshd: Client never asked for a shell')
            sys.exit(1)

        # display welcome message and login prompt
        self.chan.send(welcome_message)
        self.chan.send(self.prompt)
        self.USER = server.get_user()
        buff = ''
        while t.is_active():
            # wait for keypress + enter
            data = self.chan.recv(1024)
            if data:
                for x in range(len(data)):
                    if ord(data[x]) == 3:
                            if self.enaprompt:
                                self.chan.send('\r\n' + self.promptenable)
                            else:
                                self.chan.send('\r\n' + self.prompt)
                            buff = ''
                    elif ord(data[x]) == 127:
                            if len(buff) >= 1:
                                buff = buff[:-1]
                                self.chan.send(chr(8) + chr(32) + chr(8))
                    elif ord(data[x]) == 13 or ord(data[x]) == 10:
                        if len(buff) > 2:
                            self.cmd(buff)
                        else:
                            if self.enaprompt:
                                self.chan.send('\r\n' + self.promptenable)
                            else:
			        self.chan.send('\r\n' + self.prompt)
                        buff = ''
                    elif ord(data[x]) == 63:
                        self.cmd('?')
                        buff = ''
                    elif (45 <= ord(data[x]) <= 58 or
                          97 <= ord(data[x]) <= 122 or ord(data[x]) == 32):
                        buff = buff + data
                        self.chan.send(data)
        # close connection
        self.chan.close()
	fdump.close()


# Functions
def strtohex(ip):
    return ''.join('{:02x}'.format(int(char)) for char in ip.split('.'))

# Main Function
def main():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', 22))
    except Exception as e:
        print('fake-sshd: Bind failed: ' + str(e))
        traceback.print_exc()
        sys.exit(1)

    sock.listen(100)

    if os.path.isfile(sshkey):
        subprocess.call(['/bin/rm', '-f', sshkey])
        subprocess.call("/usr/bin/ssh-keygen -b 1024 -t rsa -N '' -q -f "
                        + sshkey, shell=True)
    else:
        subprocess.call("/usr/bin/ssh-keygen -b 1024 -t rsa -N '' -q -f "
                        + sshkey, shell=True)

    while True:
        sshd(fd, sock.accept()).start()

# Call main
if __name__ == '__main__':
    main()
