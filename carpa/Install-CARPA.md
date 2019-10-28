# Install CARPA
***
### Install/Update Packages
* Install packages
```
sudo apt-get install -y python-pip git tcpdump
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
cd circo/carpa
sudo pip install -r requirements.txt
```
## Configure CARPA
### Filter packets on public interface to avoid RST & ICMP packets out, block ping response
```
sudo iptables -A INPUT -i eth0 -p icmp -j DROP
sudo iptables -A OUTPUT -o eth0 -p tcp --tcp-flags RST RST -j DROP
sudo iptables -A OUTPUT -o eth0 -p icmp --icmp-type port-unreachable -j DROP
```
### Update CARPA #Config section
``` 
vi carpa.py
```
Look for section below `#Config`

* Change AES `PHRASE` and `SALT`, these need to match `circo.py` config
```
PHRASE = 'Waaaaa! awesome :)'
SALT = 'salgruesa'
```
* Define `domain/sub-domain` (NS Server IP must be CARPA Public IP)
```
CCNAME = 'evil.sub.domain'
```

## Notes
* There are free/pay DNS sub domain services like [afraid](https://afraid.org)
