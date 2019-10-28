#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import subprocess
import time
from bluepy.btle import Scanner

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.5"

# config
btlename = 'circo'

def btle():
    findkey = False
    scanner = Scanner()
    devices = scanner.scan(10.0)
    for dev in devices:
        for (adtype, desc, value) in dev.getScanData():
            if findkey:
                if 'Complete 128b Services' in desc:
                    subprocess.call('umount /home/pi-enc 2>/dev/null', shell=True)
                    subprocess.call('cryptsetup close /dev/mapper/pi.enc 2>/dev/null', shell=True)
                    subprocess.call('losetup -D', shell=True)
                    subprocess.call('losetup /dev/loop0 /home/pi.enc 2>/dev/null', shell=True)
                    subprocess.call('echo ' + value +  ' | cryptsetup --batch-mode luksOpen /dev/loop0 pi.enc', shell=True)
                    subprocess.call('mount /dev/mapper/pi.enc /home/pi-enc', shell=True)
                    break
            if 'Complete Local Name' in desc:
                if btlename in value:
                    findkey = True

def main():
    sleep = 5
    while True:
        if os.path.ismount('/home/pi-enc'):
            sleep = 300
            pass
        else:
            btle()
        time.sleep(sleep)

if __name__ == '__main__':
    main()
