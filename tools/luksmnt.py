#!/usr/bin/env python3
import os
import time
import subprocess
from bluepy.btle import Scanner

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "2.020"

# config
BTLENAME = 'circo'

def btle():
    found = False
    scanner = Scanner()
    devices = scanner.scan(10.0)
    for dev in devices:
        for (adtype, desc, value) in dev.getScanData():
            if 'Complete Local Name' in desc:
                if BTLENAME in value:
                    found = True
                    break
    if found:
        for dev in devices:
            for (adtype, desc, value) in dev.getScanData():
                if 'Complete 128b Services' in desc:
                    subprocess.run(['losetup', '/dev/loop0', '/home/pi.enc'])
                    subprocess.call('echo ' +  value + ' | cryptsetup --batch-mode luksOpen /dev/loop0 pi.enc', shell=True)
                    subprocess.run(['mount', '/dev/mapper/pi.enc', '/home/pi-enc'])
                    return True

def main():
    while True:
        if os.path.ismount('/home/pi-enc'):
            time.sleep(300)
        else:
            btle()
            time.sleep(20)

if __name__ == '__main__':
    main()
