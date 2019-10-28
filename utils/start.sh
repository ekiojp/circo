#!/bin/bash

while : ; do
if [ -f /home/pi-enc/circo/circo/circo.py ]; then
        /home/pi-enc/circo/circo/circo.py -b -A >/dev/null 2>&1 &
        break
else
        sleep 10
fi
done
