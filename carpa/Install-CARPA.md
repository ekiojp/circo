# Install CARPA
***
### Install/Update Packages
* Install packages
```
sudo apt-get install -y python-pip git
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

* Change AES `passphrase` and `salt`, these need to match `circo.py` config
```
phrase = 'Waaaaa! awesome :)'
salt = 'salgruesa'
```
* Define `domain/sub-domain` (NS Server IP must be CARPA Public IP)
```
ccname = 'evil.sub.domain'
```
* Change relative path of CARPA (optional)
```
dirname = '/home/ekio/circo/carpa/'
```

## Notes
* There are free/pay DNS sub domain services like [afraid](https://afraid.org)
