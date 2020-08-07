import re
import requests
import threading
import dns.resolver
from scapy.all import *
from modules.tools.dhcp import DHCPInformHandler
import logging
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("urllib3").propagate = False


class ProxyDiscovery(threading.Thread):
    """
    TODO
    """
    def __init__(self, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self._return = None
        self.wpad = conf['WPAD']
        self.iface = conf['IFACE']
        self.ip = conf['IP']
        self.mac = conf['MAC']
        self.dns = conf['DNS']
        self.domain = conf['DOMAIN']
        if conf['DEBUG']:
            logging.basicConfig(level=logging.DEBUG)

    def getpac(self, ip, url):
        """
        Connect to a potencial PAC URL and look for 'PROXY' lines, return a list
        """
        headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv11.0) like Gecko',
                'Accept-Enconding': ', '.join(('gzip', 'deflate')),
                'Accept': '*/*',
                'Connection': 'keep-alive'
        }

        ports = [80, 88, 1080, 8080, 8081, 8888, 9090]
        pacurls = []
        if b'PAD' in url:
            for p in ports:
                pacurls.append('http://' + ip + ':' + str(p) + '/wpad.dat')
        elif not url:
            for p in ports:
                pacurls.append('http://' + ip + ':' + str(p) + '/')
        else:
            pacurls.append(url)


        mm = []
        for u in pacurls:
            try:
                session = requests.get(u, headers=headers)
                if session.status_code == 200:
                    for x in session.content.split(b'\n'):
                        a = re.findall(b'PROXY ([0-9a-zA-Z.:-]+)', x)
                        for m in a:
                            if not re.search(b'127.0.0.1|localhost', m):
                                mm.append(a[0])
            except requests.exceptions.RequestException:
                return None
        return mm

    def run(self):
        prxlist = []

        # Discover WPAD via DHCP Inform (Option 252) if not already via initial DHCP Reply
        if not self.wpad:
            xid = random.randint(0, 0xFFFF)
            dhinform = DHCPInformHandler((self.iface, xid))
            dhinform.daemon = True
            dhinform.start()
            dhcpinform = (Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff') /
                    IP(src=self.ip, dst='255.255.255.255') /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=mac2str(self.mac), ciaddr=self.ip, xid=xid) /
                    DHCP(options=[('message-type', 'inform'), ('param_req_list', 252), 'end'])
                    )
            sendp(dhcpinform, iface=self.iface, verbose=0)
            time.sleep(10)
            self.wpad = dhinform.join()
            if self.wpad:
                logging.debug('Found DHCP option 252: {}'.format(self.wpad.decode()))
                prxlist = self.getpac('', self.wpad.decode())

            # No option 252, look for WPAD DNS entry
            if not self.wpad:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [ self.dns ]
                resolver.timeout = 1
                resolver.lifetime = 1
                try:
                    answer = resolver.query('wpad.' + self.domain.decode(), 'A')
                    logging.debug('Found WPAD DNS: {}'.format(answer[0]))
                    prxlist = self.getpac(str(answer[0]), 'PAD')
                except:
                    pass
        else:
            logging.debug('Found PAC via DHCP: {}'.format(self.wpad.decode()))
            prxlist = self.getpac('', self.wpad)

        if not prxlist:
            # Build a list for DNS lookups (~280)
            # Combine below keywords together, _ and -
            tryname = [ 'proxy', 'pac', 'wpad', 'pad', 'internet', 'inet', 'gw', 'gateway', 'prx', 'web' ]
            master_list = []
            for x in range(len(tryname)):
                master_list.append(tryname[x])
                for z in range(len(tryname)):
                    if not tryname[x] == tryname[z]:
                        master_list.append(tryname[x] + tryname[z])
                        master_list.append(tryname[x] + '-' + tryname[z])
                        master_list.append(tryname[x] + '_' + tryname[z])

            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ self.dns ]
            resolver.timeout = 1
            resolver.lifetime = 1
            for prx in master_list:
                try:
                    answer = resolver.query(prx + '.' + self.domain.decode(), 'A')
                    for rr in range(len(answer)):
                        logging.debug('Found DNS, looking for PAC files: {}'.format(prx + '.' + self.domain.decode() + ' = ' + str(answer[rr])))
                        prxlist = self.getpac(str(answer[rr]), '')
                        if prxlist:
                            break
                except:
                    pass

        self._return = prxlist

    def join(self):
        self.stoprequest.set()
        return self._return
