#!/usr/bin/env python3

import re
import sys
import socket
import threading
import time
import random
import paramiko
import os
import subprocess
import logging
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("paramiko").propagate = False


# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"

# Config
dirname = '/home/pi/circo/modules/hpots/'
model = 'C2960'
sshkey = dirname + 'rsa-sshd.key'
patterns = [r'^cl.*', r'^disa.*', r'^disc.*', r'^en.*', r'^ex.*', r'^he.*', r'^logi.*', r'^logo.*', r'^sh.*ve.*', r'^sh.*ip.*int.*', r'^sh.*inv.*', r'^sh.*in.*st.*', r'^sh.*ip.*ro.*', r'^wr.*me.*', r'^\?', r'^sh.*run.*', r'^sh.*star.*', r'^sh.*mac.*add.*', r'^sh.*vlan', r'^sh.*ip.*arp', r'^sh.*int.*des.*', r'sh.*cdp.*nei.*', r'sh.*lldp.*nei.*', r'term.*']


class StartSSH(threading.Thread):
    def __init__(self, q, cli):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.cli = cli
        self.debug = self.cli['DEBUG']

    class StartDaemon(threading.Thread):
        """
        Fake IOS ssh daemon
        """
        def __init__(self, qout, cli, socket, address):
            threading.Thread.__init__(self)
            self.socket = socket
            self.address = address
            self.qout = qout
            self.cnt = 0
            self.chan = ''
            self.USER = ''
            self.MOTD = ''
            self.cli = cli
            self.prompt = cli['NAME'] + '>'

        # Classes
        class SSHServer(paramiko.ServerInterface):
            """
            Paramiko Server Class, add extra function to get user
            """
            def __init__(self, q, srcip):
                self.event = threading.Event()
                self.q = q
                self.srcip = srcip
                self.USER = ''

            def check_channel_request(self, kind, chanid):
                if kind == 'session':
                    return paramiko.OPEN_SUCCEEDED
                return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_auth_interactive(self, username, submethods):
                if username != "":
                    self.USER = username
                    return paramiko.InteractiveQuery('','',('Password: ', False))
                else:
                    return paramiko.AUTH_FAILED

            def check_auth_interactive_response(self, responses):
                if (len(responses) == 1):
                    text = 's,' + self.USER + ',' + responses[0] + ',' + self.srcip
                    self.q.put(text)
                    return paramiko.AUTH_SUCCESSFUL
                else:
                    return paramiko.AUTH_FAILED

            def get_allowed_auths(self, username):
                return 'keyboard-interactive'

            def check_channel_shell_request(self, channel):
                self.event.set()
                return True

            def check_channel_pty_request(self, channel, term, width, height,
                                          pixelwidth, pixelheight, modes):
                return True

            def get_user(self):
                return self.USER

        def strtohex(self, ip):
            return ''.join('{:02x}'.format(int(char)) for char in ip.split('.'))

        def cmd(self, string):
            # Patter Matching
            results = [re.findall(patterns[idx], string) for idx in range(len(patterns))]

            # ?,help
            if results[5] or results[14]:
                self.chan.send(b'?\r\n')
                with open(dirname + model + '/help.txt', 'r') as shhelp:
                    self.chan.send(b'Exec commands:\r\n')
                    for line in shhelp:
                        self.chan.send(b'  ' + line.strip().encode() + b'\r\n')

            # disable
            elif results[1]:
                self.prompt = self.prompt.replace('#', '>')
                self.chan.send(b'\r\n')

            # exit, logout
            elif results[1] or results[4] or results[7]:
                self.chan.send(b'\r\n')
                self.chan.close()
                sys.exit(1)

            # disconnect
            elif results[2]:
                self.chan.send(b'\r\n% No current connection\r\n')

            # show ip int brief
            elif results[9]:
                self.chan.send(b'\r\n')
                with open(dirname + model + '/show_ip_interface_brief.txt', 'r') as ipbrief:
                    for line in ipbrief:
                        tosend = line.replace('<IP>', self.cli['IP']).replace('\\t','\t')
                        self.chan.send(tosend.strip('\n').encode() + b'\r\n')

            # show inventory
            elif results[10]:
                self.chan.send(b'\r\n')
                with open(dirname + model + '/show_inventory.txt', 'r') as inventory:
                    for line in inventory:
                        tosend = line.replace('<SERIAL>', self.cli['SERIAL'])
                        self.chan.send(tosend.strip('\n').encode() + b'\r\n')

            # show interface status
            elif results[11]:
                self.chan.send(b'\r\n')
                with open(dirname + model + '/show_interface_status.txt', 'r') as intstatus:
                    for line in intstatus:
                        self.chan.send(line.strip('\n').encode() + b'\r\n')

            # show ip route
            elif results[12]:
                self.chan.send(b'\r\n')
                with open(dirname + model + '/show_ip_route.txt', 'r') as iproute:
                    for line in iproute:
                        tosend = line.replace('<NETIP>', self.cli['NETIP'])
                        tosend = tosend.replace('<MASKCIDR>', self.cli['MASKCIDR'])
                        tosend = tosend.replace('<GWIP>', self.cli['GWIP'])
                        self.chan.send(tosend.strip('\n').encode() + b'\r\n')

            # clear
            elif results[0]:
                self.chan.send(b'\r\n')
                self.chan.send(b'\033[H\033[J')

            # show version
            elif results[8]:
                self.chan.send(b'\r\n')
                with open(dirname + model + '/show_version.txt', 'r') as ver:
                    for line in ver:
                        tosend = line.replace('<NAME>', self.cli['NAME'])
                        tosend = tosend.replace('<MAC>', self.cli['MAC'])
                        tosend = tosend.replace('<SERIAL>', self.cli['SERIAL'])
                        tosend = tosend.replace('<SNPSU>', self.cli['SNPSU'])
                        self.chan.send(tosend.strip('\n').encode() + b'\r\n')

            # show running
            elif (results[15] or results[16]) and '#' in self.prompt:
                self.chan.send(b'\r\n')
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
                            self.chan.send(b' --More--- ')
                            keypress = self.chan.recv(1024)
                            if b'\r' in keypress:
                                self.chan.send(b'\x08' * 11 + b' ' * 11 + b'\x08' * 11)
                                self.chan.send(tosend.strip('\n').encode() + b'\r\n')
                                linecnt -= 1
                            elif b' ' in keypress:
                                self.chan.send(b'\x08' * 11 + b' ' * 11 + b'\x08' * 11)
                                pass
                            else:
                                self.chan.send(b'\r\n')
                                break
                        else:
                            self.chan.send(tosend.strip('\n').encode() + b'\r\n')
                        linecnt += 1

            # show mac address
            elif results[17]:
                self.chan.send(b'\r\n')
                with open(dirname + model + '/show_mac_address-table.txt', 'r') as shmac:
                    for line in shmac:
                        tosend = line.replace('<GWMACCISCO>', self.cli['GWMACCISCO'])
                        tosend = tosend.replace('<MACCISCO>', self.cli['MACCISCO'])
                        self.chan.send(tosend.strip('\n').encode() + b'\r\n')

            # show vlan
            elif results[18]:
                self.chan.send(b'\r\n')
                with open(dirname + model + '/show_vlan.txt', 'r') as shvlan:
                    for line in shvlan:
                        self.chan.send(line.strip('\n').encode() + b'\r\n')

            # show ip arp
            elif results[19]:
                self.chan.send(b'\r\n')
                with open(dirname + model + '/show_ip_arp.txt', 'r') as sharp:
                    for line in sharp:
                        tosend = line.replace('<IP>', self.cli['IP'])
                        tosend = tosend.replace('<MACCISCO>', self.cli['MACCISCO'])
                        tosend = tosend.replace('<GWIP>', self.cli['GWIP'])
                        tosend = tosend.replace('<GWMACCISCO>', self.cli['GWMACCISCO'])
                        self.chan.send(tosend.strip('\n').encode() + b'\r\n')

            # show int desc
            elif results[20]:
                self.chan.send(b'\r\n')
                with open(dirname + model + '/show_interface_description.txt', 'r') as shdes:
                    for line in shdes:
                        tosend = line.replace('<IP>', self.cli['IP']).replace('\\t','\t')
                        self.chan.send(tosend.strip('\n').encode() + b'\r\n')

            # show cdp neighbors
            elif results[21]:
                self.chan.send(b'\r\n')
                with open(dirname + model + '/show_cdp_neighbors.txt', 'r') as shcdp:
                    for line in shcdp:
                        tosend = line.replace('<CDPPEERNAME>', self.cli['CDPPEERNAME'])
                        tosend = tosend.replace('<CDPPEERINT>', self.cli['CDPPEERINT'])
                        tosend = tosend.replace('<CDPPEERMODEL>', self.cli['CDPPEERMODEL'])
                        r = re.compile("([a-zA-Z]+)([0-9].*)")
                        m = r.match(self.cli['INT'])
                        tosend = tosend.replace('<INT>', m.group(1)[0:3] + ' ' + m.group(2))
                        tosend = tosend.replace('<NUM>', str(random.randint(10, 199))).replace('\\t','\t')
                        self.chan.send(tosend.strip('\n').encode() + b'\r\n')

            # show lldp neighbors
            elif results[22]:
                self.chan.send(b'\r\n')
                with open(dirname + model + '/show_lldp_neighbors.txt', 'r') as shlldp:
                    for line in shlldp:
                        tosend = line.replace('<LLDPPEERNAME>', self.cli['LLDPPEERNAME'])
                        tosend = tosend.replace('<LLDPPEERINT>', self.cli['LLDPPEERINT'])
                        tosend = tosend.replace('<INT>', self.cli['INT'])
                        tosend = tosend.replace('<NUM>', str(random.randint(10, 199))).replace('\\t','\t')
                        self.chan.send(tosend.strip('\n').encode() + b'\r\n')

            # terminal.*
            elif results[23] and '#' in self.prompt:
                self.chan.send(b'\r\n')

            # write memory
            elif results[13] and '#' in self.prompt:
                self.chan.send(b'\r\nBuilding configuration...\r\n')
                time.sleep(5)
                self.chan.send(b'Compressed configuration from 23479 bytes to 104927 bytes\r\n')
                self.chan.send(b'[OK]\r\n')

            # enable,login
            elif results[3] or results[6]:
                self.chan.send(b'\r\npassword: ')
                buf = b''
                while True:
                    data = self.chan.recv(1024)
                    if b'\r' in data:
                        text = 's,e,' + buf.decode() + ',' + self.strtohex(self.address[0])
                        self.qout.put(text)
                        break
                    buf = buf + data
                # Update prompt
                self.prompt = self.cli['NAME'] + '#'
                self.chan.send(b'\r\n')

            # if any other command (unknow/not allowed)
            else:
                if '#' in self.prompt:
                    self.chan.send(b'\r\nCommand authorization failed.\r\n')
                else:
                    self.chan.send(b'\r\n% Unrecognized command\r\n')

            # Send prompt
            self.chan.send(self.prompt.encode())

        # StartDaemon thread run()
        def run(self):
            host_key = paramiko.RSAKey(filename=sshkey)
            t = paramiko.Transport(self.socket)
            t.local_version = 'SSH-2.0-Cisco-1.25'
            t.add_server_key(host_key)
            srcip = self.strtohex(self.address[0])
            server = self.SSHServer(self.qout, srcip)
            try:
                t.start_server(server=server)
            except:
                pass

            # wait for auth
            self.chan = t.accept(20)
            if self.chan is None:
                sys.exit(1)

            server.event.wait(10)
            if not server.event.is_set():
                sys.exit(1)

            # display login prompt
            self.chan.send(b'\n' + self.prompt.encode())
            self.USER = server.get_user()
            buff = b''
            while t.is_active():
                # wait for keypress + enter
                data = self.chan.recv(1024)
                for ks in data:
                    if ks == 3:
                        self.chan.send(b'\r\n' + self.prompt.encode())
                        buff = b''
                    elif ks == 127:
                        if len(buff) >= 1:
                            buff = buff[:-1]
                            self.chan.send(b'\x08' + b' ' + b'\x08')
                    elif ks == 13 or ks == 10:
                        if len(buff) >= 1:
                            self.cmd(buff.decode())
                        else:
                            self.chan.send(b'\r\n' + self.prompt.encode())
                        buff = b''
                    elif ks == 63:
                        self.cmd('?')
                        buff = b''
                    elif (45 <= ks <= 58 or 97 <= ks <= 122 or ks == 32):
                        self.chan.send(chr(ks))
                        buff = buff + chr(ks).encode()
            # close connection
            self.chan.close()


    # StartSSH thread run()
    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', 22))
        except Exception as e:
            print('fake-sshd: Bind failed: ' + str(e))
            sys.exit(1)

        s.listen(100)

        if not self.debug:
            if os.path.isfile(sshkey):
                subprocess.call(['/bin/rm', '-f', sshkey])
                subprocess.call("/usr/bin/ssh-keygen -b 1024 -t rsa -N '' -q -f " + sshkey, shell=True)
            else:
                subprocess.call("/usr/bin/ssh-keygen -b 1024 -t rsa -N '' -q -f " + sshkey, shell=True)

        while not self.stoprequest.isSet():
            sock, address = s.accept()
            dh = self.StartDaemon(self.q, self.cli, sock, address)
            dh.start()

    def join(self):
        self.stoprequest.set()
