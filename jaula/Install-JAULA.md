# Install JAULA (Raspberry)
***
### Getting into
* Download [Raspbian](https://www.raspberrypi.org/downloads/raspbian/) Lite image (tested with 2018-11-13)
* Burn image to SD card (ie, [Balena Etcher](https://www.balena.io/etcher/))
* Insert SD card and create an empty file called `ssh` in `/boot` partition
* Connect the Raspberry Pi to your local network via LAN cable
* `ssh pi@raspberrypi` and password: `raspberry`
### Configure Raspberry Pi
* `raspi-config`
  * `1. Change User Password`
  * `7. Advance Options -> A1 Expand Filesystem`
  * `2. Network Options -> N1 Hostname`
  * `4. Localisation Options -> I1 Change Locale -> Deselect "en_GB.UTF-8 UTF-8" / Select "en_US.UTF-8 UTF-8"`
  * `5. Interfacing Options -> P2 SSH`
  * `8. Update`
  * `Finish`
* Disable IPv6
```
sudo bash -c 'echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf'
```
* Disable unnecessary services
```
sudo systemctl disable bluetooth avahi-daemon.service triggerhappy
sudo systemctl stop bluetooth avahi-daemon.service triggerhappy
```
* Install packages
```
sudo apt-get install -y python-pip git aircrack-ng libsdl-dev libsdl-image1.2-dev libsdl-mixer1.2-dev libsdl-ttf2.0-dev libsmpeg-dev libportmidi-dev libavformat-dev libswscale-dev
```
* Install Scapy > 2.3.3
```
git clone https://github.com/secdev/scapy
cd scapy
sudo python setup.py install && cd .. && sudo rm -rf scapy
```
## Download latest release
```
git clone https://github.com/ekiojp/circo
```
## Install Python Requirements (grab a coffee)
```
cd circo/jaula
sudo pip install -r requirements.txt
```

## Configure JAULA
### Stop DHCP client for wlan0 (wireless dongle)
```
sudo bash -c 'echo "denyinterfaces wlan0" >> /etc/dhcpcd.conf'
```
### Update JAULA #Config section
``` 
vi jaula.py
```
Look for section below `#Config`

* Change AES `PHRASE` and `SALT`, these need to match `circo.py`
```
PHRASE = 'Waaaaa! awesome :)'
SALT = 'salgruesa'
```
* Change wireless SSID and Channel
```
SSIDROOT = 'aterm-c17c02'
SSIDALARM = 'pacman'
WIFICHANNEL = '10'
```

## Starting automatically 
Add into `/etc/rc.local` 
```
sudo bash -c 'echo "sudo /bin/rm -f /home/pi/circo/jaula/CRED.txt" >> /etc/rc.local'
sudo bash -c 'echo "sudo /home/pi/circo/jaula/jaula_rpz.py -i wlan1 -f /home/pi/circo/jaula/CRED.txt &" >> /etc/rc.local'
```

## Notes
* WIFICHANNEL=10 is used by default between CIRCO and JAULA, if you want to change
  this, update both `circo.py` and `jaula_rpz.py` as below
