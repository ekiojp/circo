#!/bin/bash

SDL_VIDEODRIVER=fbcon SDL_FBDEV=/dev/fb1 mplayer -loop 0 -noconsolecontrols -really-quiet -vo sdl -framedrop 2>/dev/null $1 &
