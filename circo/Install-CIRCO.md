# Install CIRCO
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
sudo apt-get install -y python-pip git aircrack-ng libffi-dev macchanger tcpdump
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
## Download latest release
```
git clone https://github.com/ekiojp/circo
```
## Install Python Requirements (grab a coffee)
```
cd circo/circo
sudo pip install -r requirements.txt
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
### Filter packets on eth0
* Add IPTables rules to `/etc/iptables.rules`
```
sudo bash
sudo iptables -F INPUT
sudo iptables -A INPUT -i eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -i eth0 -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED  -j ACCEPT 
sudo iptables -A INPUT -i eth0 -p tcp --dport 23 -m conntrack --ctstate NEW,ESTABLISHED  -j ACCEPT
sudo iptables -A INPUT -i eth0 -p udp --dport 161 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -i eth0 -p icmp --icmp-type 8 -j ACCEPT
sudo iptables -A INPUT -i eth0 -j DROP
sudo bash -c 'iptables-save > /etc/iptables.rules'
sudo bash -c 'echo "iptables-restore /etc/iptables.rules" >> /etc/rc.local'
```
### Stop DHCP client for eth0 and wlan1 (wireless dongle)
```
sudo bash -c 'echo "denyinterfaces eth0" >> /etc/dhcpcd.conf'
sudo bash -c 'echo "denyinterfaces wlan1" >> /etc/dhcpcd.conf'
```
### Update CIRCO #Config section
``` 
vi circo.py
```
Look for section below `#Config`

* Change AES `passphrase` and `salt`, these need to match `carpa.py` and `jaula.py` config
```
phrase = 'Waaaaa! awesome :)'
salt = 'salgruesa'
```
* Define Cisco IP-Phone and Cisco Switch MAC address (keep same Vendor OUI 10:8C:CF & 00:8E:73)
```
phonemac = '10:8C:CF:AA:BB:CC'
switchmac = '00:8E:73:DD:EE:FF'
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
* Change relative path of CIRCO (optional)
```
dirname = '/home/pi/circo/circo/'
```

## Notes
* You need a valid snmpwalk of a Cisco Switch to emulate (Cisco 2960 included)
* Check snmpwalk [Wiki](https://github.com/ekiojp/circo/wiki/SNMP-Walks) for instructions
