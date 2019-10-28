#!/bin/bash

losetup /dev/loop0 /home/pi.enc
cryptsetup luksOpen /dev/loop0 pi-enc
mount /dev/mapper/pi.enc /home/pi-enc
