#!/usr/bin/env python3
import re
import sys
import time
import queue
import argparse
import pyaes
import pyscrypt
from pyfiglet import Figlet
from scapy.all import *

from modules.recv.ping import PINGModule
from modules.recv.trace import TRACEModule
from modules.recv.tcp import TCPModule
from modules.recv.ntp import NTPModule
from modules.recv.dns import DNSModule
from modules.recv.faraday import Faraday

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"

# Config
PHRASE = 'Waaaaa! awesome :)'
SALT = 'salgruesa'
CONF = {'DEBUG': False,
        'CCNAME': 'evil.sub.domain',
        'MAGIC': 666,
        'SEED1': 1000,
        'SEED2': 5000,
        'SEED3': 8000
       }

FCONF = {'FSERVER': 'http://127.0.0.1:5985',
         'FWS': 'demo',
         'FUSER': 'faraday',
         'FPASSWD': 'changeme'
        }

# Define Funtions
def decrypt(ciphertxt):
    key = pyscrypt.hash(PHRASE.encode(), SALT.encode(), 1024, 1, 1, 16)
    aes = pyaes.AESModeOfOperationCTR(key)
    cleartxt = aes.decrypt(bytes.fromhex(ciphertxt))
    return cleartxt.decode()

def hextoip(ip):
    n = 2
    return '.'.join([str(int(ip[i:i+n], 16)) for i in range(0, len(ip), n)])

def printer(fd, text):
    print(time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime()) + text)
    find = re.compile('\\b' + text + '\\b')
    with open(fd, 'a+') as sfile:
        with open(fd, 'r') as xfile:
            m = find.findall(xfile.read())
            if not m:
                sfile.write(time.strftime("%Y-%m-%d %H:%M:%S ",
                            time.gmtime()) + text + '\n')

def parsingopt():
    f = Figlet(font='standard')
    print(f.renderText('CARPA'))
    print('Author: {}'.format(__author__))
    print('Version: {}\n'.format(__version__))
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable Debugging')
    parser.add_argument('-i', required=True, metavar='<eth0>', dest='nic', help='Sniff Interface')
    parser.add_argument('--tcp', required=True, dest='tport', metavar='80', help='TCP exfiltration')
    parser.add_argument('-f', '--faraday', action='store_true', help='Faraday Integration')
    parser.add_argument('-l', required=True, metavar='<logfile>', dest='fd', help='Log File')
    if len(sys.argv) > 1:
        try:
            return parser.parse_args()
        except(argparse.ArgumentError):
            parser.error()
    else:
        parser.print_help()
        sys.exit(1)

# Main Function
def main():
    options = parsingopt()

    ping_q = queue.Queue()
    trace_q = queue.Queue()
    tcp_q = queue.Queue()
    ntp_q = queue.Queue()
    dns_q = queue.Queue()

    if options.verbose:
        CONF['DEBUG'] = True

    CONF['IFACE'] = options.nic

    # PING Thread
    pingdh = PINGModule(ping_q, CONF)
    pingdh.daemon = True
    pingdh.start()

    # TRACE Thread
    tracedh = TRACEModule(trace_q, CONF)
    tracedh.daemon = True
    tracedh.start()

    # WEB Thread
    tcpdh = TCPModule((tcp_q, int(options.tport)), CONF)
    tcpdh.daemon = True
    tcpdh.start()

    # NTP Thread
    ntpdh = NTPModule(ntp_q, CONF)
    ntpdh.daemon = True
    ntpdh.start()

    # DNS Thread
    dnsdh = DNSModule(dns_q, CONF)
    dnsdh.daemon = True
    dnsdh.start()

    # Faraday Thread
    if options.faraday:
        FCONF['FILE'] = options.fd
        faradh = Faraday(FCONF)
        faradh.daemon = True
        faradh.start()

    print('Listening.....')
    # Running loop 
    try:
        while True:
            if not ping_q.empty():
                (data, srcip) = ping_q.get()
                method = 'PING'
                if data == CONF['MAGIC']:
                    printer(options.fd, method + ':' + srcip + ':Alarm')
                else:
                    cleartxt = decrypt(data)
                    if cleartxt.startswith('v,') or cleartxt.startswith('n,'):
                        cleartxt = method + ':' + srcip + ':' + cleartxt
                    else:
                        hexip = cleartxt.split(',')[-1]
                        cleartxt = method + ':' + srcip + ':' + cleartxt.replace(hexip, hextoip(hexip))
                    printer(options.fd, cleartxt)
            elif not trace_q.empty():
                (data, srcip) = trace_q.get()
                method = 'TRACE'
                if data == CONF['MAGIC']:
                    printer(options.fd, method + ':' + srcip + ':Alarm')
                else:
                    cleartxt = decrypt(data)
                    if cleartxt.startswith('v,') or cleartxt.startswith('n,'):
                        cleartxt = method + ':' + srcip + ':' + cleartxt
                    else:
                        hexip = cleartxt.split(',')[-1]
                        cleartxt = method + ':' + srcip + ':' + cleartxt.replace(hexip, hextoip(hexip))
                    printer(options.fd, cleartxt)
            elif not tcp_q.empty():
                (data, srcip) = tcp_q.get()
                method = 'TCP_' + options.tport
                if data == CONF['MAGIC']:
                    printer(options.fd, method + ':' + srcip + ':Alarm')
                else:
                    cleartxt = decrypt(data)
                    if cleartxt.startswith('v,') or cleartxt.startswith('n,'):
                        cleartxt = method + ':' + srcip + ':' + cleartxt
                    else:
                        hexip = cleartxt.split(',')[-1]
                        cleartxt = method + ':' + srcip + ':' + cleartxt.replace(hexip, hextoip(hexip))
                    printer(options.fd, cleartxt)
            elif not ntp_q.empty():
                (data, srcip) = ntp_q.get()
                method = 'NTP'
                if data == CONF['MAGIC']:
                    printer(options.fd, method + ':' + srcip + ':Alarm')
                else:
                    cleartxt = decrypt(data)
                    if cleartxt.startswith('v,') or cleartxt.startswith('n,'):
                        cleartxt = method + ':' + srcip + ':' + cleartxt
                    else:
                        hexip = cleartxt.split(',')[-1]
                        cleartxt = method + ':' + srcip + ':' + cleartxt.replace(hexip, hextoip(hexip))
                    printer(options.fd, cleartxt)
            elif not dns_q.empty():
                (data, srcip, method) = dns_q.get()
                if data == str(CONF['MAGIC']):
                    printer(options.fd, method + ':' + srcip + ':Alarm')
                else:
                    cleartxt = decrypt(data)
                    if cleartxt.startswith('v,') or cleartxt.startswith('n,'):
                        cleartxt = method + ':' + srcip + ':' + cleartxt
                    else:
                        hexip = cleartxt.split(',')[-1]
                        cleartxt = method + ':' + srcip + ':' + cleartxt.replace(hexip, hextoip(hexip))
                    printer(options.fd, cleartxt)

    except KeyboardInterrupt:
        pingdh.join()
        tracedh.join()
        tcpdh.join()
        ntpdh.join()
        dnsdh.join()
        if options.faraday:
            faradh.join()
        sys.exit(0)

# Call main
if __name__ == '__main__':
    main()
