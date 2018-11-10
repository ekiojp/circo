#!/bin/bash

sudo /usr/bin/fbi -T 2 -d /dev/fb1 -noverbose -a $1 2>/dev/null
