import re
import time
import threading

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class NetCreds(threading.Thread):
    """
    Start net-creds.py (https://github.com/DanMcInerney/net-creds) from DanMcInerney
    """
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.iface = 'eth1'
        self.ip = conf['IP']
        self.cmd = ['/home/pi/circo/tools/net-creds/net-creds.py', '-i', self.iface, '-f', self.ip]
        self.credfile = '/home/pi/circo/tools/credentials.txt'

    def run(self):
        mailuser = ''
        httpuser = ''
        ftpuser = ''
        self.proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        while not self.stoprequest.isSet():
            if os.path.isfile(self.credfile):
                with open(self.credfile, 'r') as sfile:
                    for line in sfile:
                        mail = re.findall('> (.*)] Mail authentication: (.*)', line)
                        ntlmv1 = re.findall('> (.*)] NETNTLMv1: (.*)', line)
                        ntlmv2 = re.findall('> (.*)] NETNTLMv2: (.*)', line)
                        krb = re.findall('> (.*)] MS Kerberos: (.*)', line)
                        webauth = re.findall('> (.*)] Basic Authentication: (.*)', line)
                        ftpu = re.findall('> (.*)] FTP User: (.*)', line)
                        ftpp = re.findall('> (.*)] FTP Pass: (.*)', line)
                        httpu = re.findall('> (.*)] HTTP Username: (.*)', line)
                        httpp = re.findall('> (.*)] HTTP Password: (.*)', line)
                        snmp = re.findall('> (.*)] SMNPv[1-3] community string: (.*)', line)
                        irc = re.findall('> (.*)] IRC pass: (.*)', line)
                        if mail:
                            if mailuser:
                                ip, auth = mail[0]
                                self.q.put(','.join(['n', mailuser, auth, ip]))
                                mailuser = ''
                            else:
                                ip, mailuser = mail[0]
                        elif ntlmv1:
                            ip, auth = ntlmv1[0]
                            self.q.put(','.join(['n', auth, ip]))
                        elif ntlmv2:
                            ip, auth = ntlmv2[0]
                            self.q.put(','.join(['n', auth, ip]))
                        elif krb:
                            ip, auth = krb[0]
                            self.q.put(','.join(['n', auth, ip]))
                        elif webauth:
                            ip, auth = webauth[0]
                            self.q.put(','.join(['n', auth, ip]))
                        elif httpu:
                            ip, httpuser = httpu[0]
                        elif httpp:
                            if httpuser:
                                ip, auth = httpp[0]
                                self.q.put(','.join(['n', httpuser, auth, ip]))
                        elif ftpu:
                            ip, ftpuser = ftpu[0]
                        elif ftpp:
                            if ftpuser:
                                ip, auth = ftpp[0]
                                self.q.put(','.join(['n', ftpuser, auth, ip]))
                        elif snmp:
                            ip, auth = snmp[0]
                            self.q.put(','.join(['n', auth, ip]))
                        elif irc:
                            ip, auth = irc[0]
                            self.q.put(','.join(['n', auth, ip]))
                time.sleep(20)

    def join(self):
        self.proc.kill()
        os.remove(self.credfile)
        self.stoprequest.set()
