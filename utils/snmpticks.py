#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import sys
import re
import datetime

# Me
__author__ = "Emilio / @ekio_jp"
__version__ = "1.0"


if len(sys.argv) < 2:
	print('Usage: {} <input.snmpwalk> <output.snmpwalk>'.format(sys.argv[0]))
	sys.exit(0)
inputfd = sys.argv[1]
outputfd = sys.argv[2]


outfd = open(outputfd, 'w') 
with open(inputfd, 'r') as sfile :
	for line in sfile:
		if re.search('^.\d.+ = (\d+)', line):
			oid = line.split('=')[0]
			tick = line.split('=')[1].strip()
			ttime = str(datetime.timedelta(seconds=int(tick)/100))
			line = str(oid) + '= ' + 'Timeticks: (' + str(tick) + ') ' + ttime + '\n'
		outfd.write(line)

outfd.close()
