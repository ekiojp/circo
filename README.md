# CIRCO

## Cisco Implant Raspberry Controlled Operations

Designed under Raspberry Pi and aimed for Red Team Ops, we take advantage of “Sec/Net/Dev/Ops” enterprise tools to capture network credentials in a stealth mode.<br>
Using a low profile hardware & electronics camouflaged as simple network outlet box to be sitting under/over a desk.<br>
CIRCO include different techniques for network data exfiltration to avoid detection.<br>
This tool gather information and use a combination of honeypots to trick Automation Systems to give us their network credentials!

----

## Hardware

The specific hardware will depend on size and features you want, as an example,
you can run CIRCO on a Raspberry Pi Zero without Wireless Extraction feature or
you could be using a Raspberry Pi 3B with a wireless dongle.

The main constrain is physical space to fit CIRCO.

You will also need some Cat 5 twisted cable, pliers, RJ45, soldering/desoldering tools,
wires, glue-gun, zip-ties, etc

Be creative!

---

## Software

There are 3 main elements that make CIRCO:

- The implant main program called `circo.py` which also run `sshd-fake.py` and `telnetd-fake.py` daemons (honeypots)<br>
To emulate a Cisco Switch SNMP Agent, we are using forked version of [snmposter](https://github.com/ekiojp/snmposter)
- To receive extracted credentials via different techniques, we use `carpa.py`
  on an Internet Server, as long is has a public IP and no firewalls in
front preventing traffic to reach it. We also need a domain pointing NS
records to our public IP
- Specific for wireless exfiltration we have `jaula.py`, been tested on a
  Raspberry Pi Zero with a wireless dongle but should run different hardware
without issues

Most of the packet manipulation and crafting is been done with
[Scapy](https://github.com/secdev/scapy) as it has enought flexibility with some
exceptions (did I say I hate DHCP handshake?)

Has been developed and tested under Python 2.x,
will start soon to test Python 3.x. and confirm Python 3.x has no dependecies issues

----

## Installation

The [Wiki](https://github.com/ekiojp/circo/wiki) has step-by-step instruction to install
each element

Inside each directory also is the `Install` file
```
/circo/Install-CIRCO.md
/carpa/Install-CARPA.md
/jaula/Install-JAULA.md
```

----

## Usage

Examples/Screenshots/Videos added to [Wiki](https://github.com/ekiojp/circo/wiki)

---

# Credentials Exfiltration Format

We use `t` (*telnet*), `s` (*ssh*) and `p` (*snmp*) to idenfiy the protocol used for the credentials obtained.

For Telnet/SSH `enable` passwords we `e` as 2nd key identifier

Included from version 1.4, we add Source IP address where the connection to our
honeypots came from, to save bits the Dotted IP format has been converted to Hex
The exfiltration programs `carpa.py` or `jaula.py` will convert back to Dotted
IP format before display/writing output file

### Telnet
```
t,<user>,<password>,<src_ip>
t,e,<enable>,<src_ip>
```

### SSH
```
s,<user>,<password>,<src_ip>
s,e,<enable>,<src_ip>
```

### SNMP
```
p,<community>,<src_ip>
```

----

# Presentations

[BlackHat Asia Arsenal (Mar-2019)](https://speakerdeck.com/ekio_jp/circo-blackhat-asia-2019-arsenal)

[濱せっく / HamaSec (Feb-2019)](https://speakerdeck.com/ekio_jp/circo-hamasec-feb-2019)

[YOROZU SECCON (Dec-2018)](https://speakerdeck.com/ekio_jp/circo-yorozu-seccon-2018)

[HIVE AV Tokyo (Nov-2018)](https://speakerdeck.com/ekio_jp/circo-hive-av-tokyo-2018)

----

# ToDo

- [x] Add LLDP Support
- [x] Include Automation SRC IP in the exfiltration
- [x] Work on WPAD discovery module
- [ ] [Faraday](https://github.com/infobyte/faraday) API Integration
- [ ] Python 3.x Support
- [ ] Include Implant ID on exfiltration
- [ ] Destroy Switch
- [ ] LTE Support
- [ ] Work on No-DHCP module
- [ ] Wifi Pineapple Module for `jaula.py`
- [ ] Improve performace for [snmposter](https://github.com/ekiojp/snmposter) and support *any* community
- [ ] Make the code nicer

----
# Disclaimer

The tool is provided for educational, research or testing purposes.<br>
Using this tool against network/systems without prior permission is illegal.<br>
The author is not liable for any damages from misuse of this tool, techniques or code.

----

# Author

Emilio / [@ekio_jp](https://twitter.com/ekio_jp)

----

# Licence

Please see [LICENSE](https://github.com/ekiojp/circo/blob/master/LICENSE).
