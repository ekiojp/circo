# Install CIRCO
***
### Getting into
* Download [Raspbian Stretch Lite](http://ftp.jaist.ac.jp/pub/raspberrypi/raspbian_lite/images/raspbian_lite-2018-11-15/2018-11-13-raspbian-stretch-lite.zip) 
* SHA256: 47ef1b2501d0e5002675a50b6868074e693f78829822eef64f3878487953234d
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
sudo sed -i 's/-w/-w -4/' /etc/systemd/system/dhcpcd.service.d/wait.conf
```
* Change default TTL packets
```
sudo bash -c 'echo "net.ipv4.ip_default_ttl = 255" >> /etc/sysctl.conf'
```
* Disable unnecessary services
```
sudo systemctl disable systemd-timesyncd avahi-daemon.service triggerhappy 
sudo systemctl stop systemd-timesyncd avahi-daemon.service triggerhappy
```
* Install packages
```
sudo apt-get install -y python-pip git libffi-dev macchanger tcpdump python-nfqueue libglib2.0-dev cryptsetup
```
* Install Scapy > 2.3.3
```
git clone https://github.com/secdev/scapy
cd scapy
sudo python setup.py install && cd .. && sudo rm -rf scapy
```
* Install TwistedSNMP (snmposter dependency) 
```
wget http://downloads.sourceforge.net/project/twistedsnmp/twistedsnmp/0.3.13/TwistedSNMP-0.3.13.tar.gz
tar -xzf TwistedSNMP-0.3.13.tar.gz
cd TwistedSNMP-0.3.13
sudo python setup.py install && cd .. && sudo rm -rf TwistedSNMP-0.3.13*
```
* Install PySNMP-SE (snmposter dependency)
```
wget http://downloads.sourceforge.net/project/twistedsnmp/pysnmp-se/3.5.2/pysnmp-se-3.5.2.tar.gz
tar -xzf pysnmp-se-3.5.2.tar.gz
cd pysnmp-se-3.5.2
sudo python setup.py install && cd .. && sudo rm -rf pysnmp-se-3.5.2*
```
* Install snmposter (forked)
```
git clone https://github.com/ekiojp/snmposter
cd snmposter
sudo python setup.py install && cd .. && sudo rm -rf snmposter
```
## Encrypted $HOME
* Create filesystem (ie, 250Mb size)
```
sudo dd of=/home/pi.enc bs=1 count=0 seek=250M
```
* LUSK format file and create MASTER passphrase
```
sudo losetup /dev/loop0 /home/pi.enc
sudo cryptsetup -y luksFormat /dev/loop0
WARNING! ======== This will overwrite data on /dev/loop0 irrevocably.
Are you sure? (Type uppercase yes): YES
Enter passphrase:
Verify passphrase:
```
* Create filesystem and mount it
```
sudo cryptsetup luksOpen /dev/loop0 pi-enc
Enter passphrase for /home/pi.enc:
sudo mkfs.ext4 /dev/mapper/pi-enc
sudo mkdir /home/pi-enc
sudo mount -t ext4 /dev/mapper/pi-enc /home/pi-enc
```
* Add extra Bluetooth Key (128bits)
* Format (hex lowecase) ie, 41ceea0a-3311-4322-9bef-923664d11a08
```
sudo cryptsetup luksAddKey /dev/loop0
```
## Download CIRCO latest release
```
cd /home/pi-enc
git clone https://github.com/ekiojp/circo
```
## CIRCO Python Requirements (grab a coffee)
```
cd circo/circo
sudo pip install -r requirements.txt
```
## LUKS Service
```
sudo cp luks.service /etc/systemd/system/
sudo cp luksmnt.py /home/
sudo systemctl enable luks.service
sudo systemctl start luks.service
```
## Configure CIRCO
### Using onboard wifi for management (testing environment)
* Add local wireless SSID
```
sudo vi /etc/wpa_supplicant/wpa_supplicant.conf
network={
    ssid="YOUR_SSID_HERE"
    psk="YOUR_WIFI_PASSPHRASE_HERE"
}
```
* Change SSH listening port from 22 to 2222
```
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```
### Stop DHCP client for eth0, eth1 and wlan1 (wireless dongle)
```
sudo bash -c 'echo "denyinterfaces eth0" >> /etc/dhcpcd.conf'
sudo bash -c 'echo "denyinterfaces eth1" >> /etc/dhcpcd.conf'
sudo bash -c 'echo "denyinterfaces wlan1" >> /etc/dhcpcd.conf'
```
### Update CIRCO #Config section
``` 
vi circo.py
```
Look for section below `#Config`

* Change AES `PHRASE` and `SALT`, these need to match `carpa.py` and `jaula_rpz.py` config
```
PHRASE = 'Waaaaa! awesome :)'
SALT = 'salgruesa'
```
* Define Cisco IP-Phone and Cisco Switch MAC address (use Cisco Vendor OUI 10:8C:CF & 00:8E:73)
* 00:07:B4:00:FA:DE is a Cisco virtual MAC whitelisted by default normally in NAC 
```
phonemac = '10:8C:CF:AA:BB:CC'
switchmac = '00:07:B4:00:FA:DE'
```
* Define switchport of our fake switch (depend Cisco platform to emulate)
```
switchport = 'FastEthernet1/0/3'
```
* Define Fake Cisco Switch Serial Number and PSU Serial Number
```
serial = 'FCW1831C1AA'
snpsu = 'LIT18300QBB'
```
* Define SNMP community
```
snmpcommunity = 'public'
```
* Define CARPA public IP
```
cchost = '172.16.2.1'
```
* Define `domain/sub-domain` controlled by CARPA (NS Server IP must be CARPA Public IP)
```
ccname = 'evil.sub.domain'
```
* Change relative path of CIRCO 
```
dirname = '/home/pi-enc/circo/circo/'
```
* Change Wireless SSID (Exfiltration and Alarm) and channel also MAC of fake wireless router
```
SSIDroot = 'aterm-c17c02'
SSIDalarm = 'pacman'
WIFICHANNEL = '10'
wifimac = '98:f1:99:c1:7c:02'
```

## Notes
* You need a valid snmpwalk of a Cisco Switch to emulate (Cisco 2960 included)
* Check snmpwalk [Wiki](https://github.com/ekiojp/circo/wiki/SNMP-Walks) for instructions
