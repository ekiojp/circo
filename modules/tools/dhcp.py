import threading
from scapy.all import *

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class DHCPHandler(threading.Thread):
    """
    Class for DHCP responses, parse it and return the details
    """
    def __init__(self, iface):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface = iface
        self.offer = 1
        self._rtn_ip = None
        self._rtn_mask = None
        self._rtn_gwip = None
        self._rtn_dns_srv = None
        self._rtn_domain = None
        self._rtn_pac = None

    def pkt_callbak(self, pkt):
        if DHCP in pkt:
            mtype = pkt[DHCP].options[0][1]
            ipaddr = pkt[BOOTP].yiaddr
            sip = pkt[BOOTP].siaddr
            mac = get_if_hwaddr(self.iface)
            if (mtype == 2) and (self.offer <= 1) and (pkt[Ether].dst == mac):
                self.offer = self.offer + 1
                for opt in pkt[DHCP].options:
                    if 'router' in opt:
                        gwip = opt[1]
                    if 'subnet_mask' in opt:
                        netmask = opt[1]
                    if 'domain' in opt:
                        domain = opt[1]
                    if (('name_server' in opt) or
                       ('domain-name-servers' in opt)):
                        dns_srv = opt[1]
                    if opt[0] == 252:
                        pac = opt[1]
                self._rtn_ip = ipaddr
                self._rtn_mask = netmask
                self._rtn_gwip = gwip
                self._rtn_dns_srv = dns_srv
                self._rtn_domain = domain
                self._rtn_pac = pac
                request = (Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
                           IP(src='0.0.0.0', dst='255.255.255.255') /
                           UDP(sport=68, dport=67) /
                           BOOTP(chaddr=pkt[BOOTP].chaddr,
                                 xid=pkt[BOOTP].xid) /
                           DHCP(options=[('message-type', 'request'),
                                         ('server_id', sip),
                                         ('requested_addr', ipaddr),
                                         ('param_req_list', 0),
                                         ('end')
                                         ])
                           )
                sendp(request, iface=self.iface, verbose=0)
                self.join()

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callbak,
                  filter="udp and (port 68 or port 67)", store=0)

    def join(self):
        self.stoprequest.set()
        return self._rtn_ip, self._rtn_mask, self._rtn_gwip, self._rtn_dns_srv, self._rtn_domain, self._rtn_pac


class DHCPInformHandler(threading.Thread):
    """
    Class for DHCP Inform request to ask for Option 252
    """

    def __init__(self, args):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.iface, self.xid = args
        self._return = None
        self.ack = 1

    def pkt_callback(self, pkt):
        if DHCP in pkt:
            mtype = pkt[DHCP].options[0][1]
            xid = pkt[BOOTP].xid
            if (mtype == 5) and (self.ack <= 1) and (xid == self.xid):
                self.ack += 1
                for opt in pkt[DHCP].options:
                    if opt[0] == 252:
                        wpad = opt[1]
                        break
                self._return = wpad
                self.join()

    def run(self):
        while not self.stoprequest.isSet():
            sniff(iface=self.iface, prn=self.pkt_callback,
                  filter='udp and (port 68 or port 67)', store=0)

    def join(self):
        self.stoprequest.set()
        return self._return
