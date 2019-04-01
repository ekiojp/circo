#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import sys
import os
import signal
import pygame

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.4"

# Config
WHITE = (255, 255, 255)

# Functions
def tftinit():
    os.putenv('SDL_FBDEV', '/dev/fb1')
    pygame.init()
    pygame.mouse.set_visible(False)
    lcd = pygame.display.set_mode((320, 240))
    lcd.fill((0, 0, 0))
    pygame.display.update()
    return lcd

def tftmsg(lcd, msg, pos, fsize):
    font_big = pygame.font.Font(None, fsize)
    txt = font_big.render(msg, True, WHITE)
    wh = txt.get_rect(center=pos)
    lcd.blit(txt, wh)
    pygame.display.update()

def kill_process(pstring):
    for line in os.popen("ps ax | grep " + pstring + " | grep -v grep"):
        fields = line.split()
        pid = fields[0]
        os.kill(int(pid), signal.SIGTERM)


# Main Function
def main():
    kill_process('fbi')
    tftinit()
    lcd = tftinit()
    while True:
        try:
            tftmsg(lcd, 'JAULA', (160, 120), 50)
        except KeyboardInterrupt:
            sys.exit(0)

# Call main
if __name__ == '__main__':
    main()
