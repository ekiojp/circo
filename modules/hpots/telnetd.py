import re
import sys
import os
import socket
import threading
import time
import random

# Me
__author__ = 'Emilio / @ekio_jp'
__version__ = '2.020'

# Config
dirname = '/home/pi/circo/modules/hpots/'
model = 'C2960'
patterns = [r'^cl.*', r'^disa.*', r'^disc.*', r'^en.*', r'^ex.*', r'^he.*', r'^logi.*', r'^logo.*', r'^sh.*ve.*', r'^sh.*ip.*int.*', r'^sh.*inv.*', r'^sh.*in.*st.*', r'^sh.*ip.*ro.*', r'^wr.*me.*', r'^\?', r'^sh.*run.*', r'^sh.*star.*', r'^sh.*mac.*add.*', r'^sh.*vlan', r'^sh.*ip.*arp', r'^sh.*int.*des.*', r'sh.*cdp.*nei.*', r'sh.*lldp.*nei.*', r'term.*']


class StartTelnet(threading.Thread):
    def __init__(self, q, cli):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.cli = cli

    class StartDaemon(threading.Thread):
        """
        Fake IOS telnet service
        """
        def __init__(self, qout, cli, socket, address):
            threading.Thread.__init__(self)
            self.socket = socket
            self.address = address
            self.qout = qout
            self.cnt = 0
            self.USER = ''
            self.MOTD = ''
            self.cli = cli
            self.prompt = cli['NAME'] + '>'

        def strtohex(self, ip):
            return ''.join('{:02x}'.format(int(char)) for char in ip.split('.'))

        def cmd(self, string):
            # Patter Matching
            results = [re.findall(patterns[idx], string) for idx in range(len(patterns))]

            # ?,help
            if results[5] or results[14]:
                self.socket.send(b'?\r\n')
                with open(dirname + model + '/help.txt', 'r') as shhelp:
                    self.socket.send(b'Exec commands:\r\n')
                    for line in shhelp:
                        self.socket.send(b'  ' + line.strip('\n').encode() + b'\r\n')

            # disable
            elif results[1]:
                self.prompt = self.prompt.replace('#', '>')
                self.socket.send(b'\r\n')

            # exit, logout
            elif results[1] or results[4] or results[7]:
                self.socket.send(b'\r\n')
                self.socket.close()
                sys.exit(1)

            # disconnect
            elif results[2]:
                self.socket.send(b'\r\n% No current connection\r\n')

            # show ip int brief
            elif results[9]:
                self.socket.send(b'\r\n')
                with open(dirname + model + '/show_ip_interface_brief.txt', 'r') as ipbrief:
                    for line in ipbrief:
                        tosend = line.replace('<IP>', self.cli['IP']).replace('\\t','\t')
                        self.socket.send(tosend.strip('\n').encode() + b'\r\n')

            # show inventory
            elif results[10]:
                self.socket.send(b'\r\n')
                with open(dirname + model + '/show_inventory.txt', 'r') as inventory:
                    for line in inventory:
                        tosend = line.replace('<SERIAL>', self.cli['SERIAL'])
                        self.socket.send(tosend.strip('\n').encode() + b'\r\n')

            # show interface status
            elif results[11]:
                self.socket.send(b'\r\n')
                with open(dirname + model + '/show_interface_status.txt', 'r') as intstatus:
                    for line in intstatus:
                        self.socket.send(line.strip('\n').encode() + b'\r\n')

            # show ip route
            elif results[12]:
                self.socket.send(b'\r\n')
                with open(dirname + model + '/show_ip_route.txt', 'r') as iproute:
                    for line in iproute:
                        tosend = line.replace('<NETIP>', self.cli['NETIP'])
                        tosend = tosend.replace('<MASKCIDR>', self.cli['MASKCIDR'])
                        tosend = tosend.replace('<GWIP>', self.cli['GWIP'])
                        self.socket.send(tosend.strip('\n').encode() + b'\r\n')

            # clear
            elif results[0]:
                self.socket.send(b'\r\n')
                self.socket.send(b'\033[H\033[J')

            # show version
            elif results[8]:
                self.socket.send(b'\r\n')
                with open(dirname + model + '/show_version.txt', 'r') as ver:
                    for line in ver:
                        tosend = line.replace('<NAME>', self.cli['NAME'])
                        tosend = tosend.replace('<MAC>', self.cli['MAC'])
                        tosend = tosend.replace('<SERIAL>', self.cli['SERIAL'])
                        tosend = tosend.replace('<SNPSU>', self.cli['SNPSU'])
                        self.socket.send(tosend.strip('\n').encode() + b'\r\n')

            # show running
            elif (results[15] or results[16]) and '#' in self.prompt:
                self.socket.send(b'\r\n')
                linecnt = 1
                with open(dirname + model + '/e_show_running.txt', 'r') as runn:
                    for line in runn:
                        tosend = line.replace('<NAME>', self.cli['NAME'])
                        tosend = tosend.replace('<USER>', self.USER)
                        tosend = tosend.replace('<IP>', self.cli['IP'])
                        tosend = tosend.replace('<MOTD>', self.MOTD)
                        tosend = tosend.replace('<MASK>', self.cli['MASK'])
                        tosend = tosend.replace('<GWIP>', self.cli['GWIP'])
                        tosend = tosend.replace('<SNMPC>', self.cli['SNMPC'])
                        if linecnt % 64 == 0:
                            self.socket.send(b' --More--- ')
                            keypress = self.socket.recv(1024)
                            if b'\r' in keypress:
                                self.socket.send(b'\x08' * 11 + b' ' * 11 + b'\x08' * 11)
                                self.socket.send(tosend.strip('\n').encode() + b'\r\n')
                                linecnt -= 1
                            elif b' ' in keypress:
                                self.socket.send(b'\x08' * 11 + b' ' * 11 + b'\x08' * 11)
                                pass
                            else:
                                self.socket.send(b'\r\n')
                                break
                        else:
                            self.socket.send(tosend.strip('\n').encode() + b'\r\n')
                        linecnt += 1

            # show mac address
            elif results[17]:
                self.socket.send(b'\r\n')
                with open(dirname + model + '/show_mac_address-table.txt', 'r') as shmac:
                    for line in shmac:
                        tosend = line.replace('<GWMACCISCO>', self.cli['GWMACCISCO'])
                        tosend = tosend.replace('<MACCISCO>', self.cli['MACCISCO'])
                        self.socket.send(tosend.strip('\n').encode() + b'\r\n')

            # show vlan
            elif results[18]:
                self.socket.send(b'\r\n')
                with open(dirname + model + '/show_vlan.txt', 'r') as shvlan:
                    for line in shvlan:
                        self.socket.send(line.strip('\n').encode() + b'\r\n')

            # show ip arp
            elif results[19]:
                self.socket.send(b'\r\n')
                with open(dirname + model + '/show_ip_arp.txt', 'r') as sharp:
                    for line in sharp:
                        tosend = line.replace('<IP>', self.cli['IP'])
                        tosend = tosend.replace('<MACCISCO>', self.cli['MACCISCO'])
                        tosend = tosend.replace('<GWIP>', self.cli['GWIP'])
                        tosend = tosend.replace('<GWMACCISCO>', self.cli['GWMACCISCO'])
                        self.socket.send(tosend.strip('\n').encode() + b'\r\n')

            # show int desc
            elif results[20]:
                self.socket.send(b'\r\n')
                with open(dirname + model + '/show_interface_description.txt', 'r') as shdes:
                    for line in shdes:
                        tosend = line.replace('<IP>', self.cli['IP']).replace('\\t','\t')
                        self.socket.send(tosend.strip('\n').encode() + b'\r\n')

            # show cdp neighbors
            elif results[21]:
                self.socket.send(b'\r\n')
                with open(dirname + model + '/show_cdp_neighbors.txt', 'r') as shcdp:
                    for line in shcdp:
                        tosend = line.replace('<CDPPEERNAME>', self.cli['CDPPEERNAME'])
                        tosend = tosend.replace('<CDPPEERINT>', self.cli['CDPPEERINT'])
                        tosend = tosend.replace('<CDPPEERMODEL>', self.cli['CDPPEERMODEL'])
                        r = re.compile('([a-zA-Z]+)([0-9].*)')
                        m = r.match(self.cli['INT'])
                        tosend = tosend.replace('<INT>', m.group(1)[0:3] + ' ' + m.group(2))
                        tosend = tosend.replace('<NUM>', str(random.randint(10, 199))).replace('\\t','\t')
                        self.socket.send(tosend.strip('\n').encode() + b'\r\n')

            # show lldp neighbors
            elif results[22]:
                self.socket.send(b'\r\n')
                with open(dirname + model + '/show_lldp_neighbors.txt', 'r') as shlldp:
                    for line in shlldp:
                        tosend = line.replace('<LLDPPEERNAME>', self.cli['LLDPPEERNAME'])
                        tosend = tosend.replace('<LLDPPEERINT>', self.cli['LLDPPEERINT'])
                        tosend = tosend.replace('<INT>', self.cli['INT'])
                        tosend = tosend.replace('<NUM>', str(random.randint(10, 199))).replace('\\t','\t')
                        self.socket.send(tosend.strip('\n').encode() + b'\r\n')

            # terminal.*
            elif results[23] and '#' in self.prompt:
                self.socket.send(b'\r\n')

            # write memory
            elif results[13] and '#' in self.prompt:
                self.socket.send(b'\r\nBuilding configuration...\r\n')
                time.sleep(5)
                self.socket.send(b'Compressed configuration from 23479 bytes to 104927 bytes\r\n')
                self.socket.send(b'[OK]\r\n')

            # enable,login
            elif results[3] or results[6]:
                self.socket.send(b'\r\npassword: ')
                buf = b''
                while True:
                    data = self.socket.recv(1024)
                    if len(data) == 2 and b'\r' in data:
                        text = 't,e,' + buf.decode() + ',' + self.strtohex(self.address[0])
                        self.qout.put(text)
                        break
                    buf = buf + data
                # Update prompt
                self.prompt = self.cli['NAME'] + '#'
                self.socket.send(b'\r\n')

            # if any other command (unknow/not allowed)
            else:
                if '#' in self.prompt:
                    self.socket.send(b'\r\nCommand authorization failed.\r\n')
                else:
                    self.socket.send(b'\r\n% Unrecognized command\r\n')

            # Send prompt
            self.socket.send(self.prompt.encode())

        def run(self):

            try:
                # client neg options
                dd = self.socket.recv(1024)
                self.socket.send(b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f')
                # recv the WILL
                dd = self.socket.recv(1024)
                self.socket.send(self.MOTD.encode() + b'\r\n\r\nUser Access Verification\r\n\r\nUsername: ')
                # send IAC SB terminal type
                self.socket.send(b'\xff\xfa\x18\x01\xff\xf0')
                # send DONT terminal speed
                self.socket.send(b'\xff\xfe\x20')
                # receive terminal type
                dd = self.socket.recv(1024)
                # send DONT remote flow
                self.socket.send(b'\xff\xfe\x20')
                # send DONT Linemode
                self.socket.send(b'\xff\xfe\x22')
                # send DONT New Enviroment Option
                self.socket.send(b'\xff\xfe\x27')
                # send WONT Status
                self.socket.send(b'\xff\xfc\x05')
            except:
                self.socket.close()

            buff = b''
            while True:

                try:
                    data = self.socket.recv(1024)

                    if data and self.cnt == 0:
                        if len(data) == 2 and b'\r' in data:
                            self.cnt = 1
                            self.USER = buff.decode()
                            self.socket.send(b'\r\nPassword: ')
                            buff = b''
                        else:
                            # send ECHO
                            self.socket.send(data)
                            buff = buff + data
                    elif data and self.cnt == 1:
                        if len(data) == 2 and b'\r' in data:
                            self.cnt = 2
                            self.socket.send(b'\r\n' + self.prompt.encode())
                            text = 't,' + self.USER + ',' + buff.decode() + ',' + self.strtohex(self.address[0])
                            self.qout.put(text)
                            buff = b''
                        else:
                            # no ECHO for password
                            buff = buff + data
                    elif data:
                        for ks in data:
                            if ks == 3:
                                self.socket.send(b'\r\n' + self.prompt.encode())
                                buff = b''
                            elif ks == 127:
                                if len(buff) >= 1:
                                    buff = buff[:-1]
                                    self.socket.send(b'\x08' + b' ' + b'\x08')
                            elif ks == 13 or ks == 10:
                                if len(buff) >= 1:
                                    self.cmd(buff.decode())
                                else:
                                    self.socket.send(b'\r\n' + self.prompt.encode())
                                buff = b''
                            elif ks == 63:
                                self.cmd('?')
                                buff = b''
                            elif (45 <= ks <= 58 or 97 <= ks <= 122 or ks == 32):
                                buff = buff + chr(ks).encode()
                                self.socket.send(chr(ks).encode())
                except:
                    self.socket.close()
            # close connection
            self.socket.close()

    def run(self):
        # Bind socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', 23))
        s.listen(1)
        lock = threading.Lock()

        while not self.stoprequest.isSet():
            sock, address = s.accept()
            dh = self.StartDaemon(self.q, self.cli, sock, address)
            dh.start()

    def join(self):
        self.stoprequest.set()
