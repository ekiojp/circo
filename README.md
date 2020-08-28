[![Black Hat Arsenal](https://rawgit.com/toolswatch/badges/master/arsenal/asia/2019.svg)](http://www.toolswatch.org/2019/01/black-hat-arsenal-asia-2019-lineup-announced)

# CIRCO

## Cisco Implant Raspberry Controlled Operations

## Red Teams
Designed under Raspberry Pi, we take advantage of “Sec/Net/Dev/Ops” enterprise tools to capture network credentials in a stealth mode.  
Using a low profile hardware & electronics camouflaged as simple network outlet box or PSU injector to be sitting under/over a desk.  
CIRCO include different techniques for network data exfiltration to avoid detection.  
This tool gather information and use a combination of honeypots to trick Automation Systems to give us their network credentials!  
In `bridge` mode, you can also sniff (MiTM) credentials/hashes from an IP-Phone and PC cascade to the phone.  

## Blue Teams
The perfect and cheapeast way to deploy a Cisco honeypot, just deploy either using Raspberry or any other hardware on the network and integrate logging/alarms to your SOC.  
Could be sitting outside, inside or DMZ of your network.  


----

## Hardware

The specific hardware will depend on size and features you want, as an example, you can run CIRCO on a Raspberry Pi Zero without Wireless Extraction feature or you could be using a Raspberry Pi 3B with a wireless dongle.

The main constrain could be physical space to fit CIRCO.

You will also need some Cat 5 twisted cable, pliers, RJ45, soldering/desoldering tools, wires, glue-gun, zip-ties, etc

Be creative!

---

## Software

There are 3 main elements that make CIRCO:

- The implant main program called `circo.py` to be deployed in the Raspberry Pi hardware  
To emulate a Cisco Switch SNMP Agent, we are using forked version of [snmposter](https://github.com/ekiojp/snmposter)  

- To receive extracted credentials via different techniques, we use `carpa.py` on an Internet Server, as long is has a public IP and no firewalls in front preventing traffic to reach it.  
We also need a domain pointing NS records to our public IP  

- Specific for wireless or SDR exfiltration we have `jaula.py`, this can run on a laptop with a Wireless adaptor supporting `monitor mode`, also an SDR receiver (like RTL-SDR, HackRF, etc)  

All packet manipulation and crafting is been done mainly with [Scapy](https://github.com/secdev/scapy) as it has enough flexibility with some exceptions (did I say I hate DHCP handshake?)  

CIRCO v2 has been coded in Python 3.7  

----

## Installation

The [Wiki](https://github.com/ekiojp/circo/wiki) has step-by-step instruction to install it

----

## Usage

Examples/Screenshots/Videos added to [Wiki](https://github.com/ekiojp/circo/wiki)

---

# Credentials Exfiltration Format

We use `t` (*telnet*), `s` (*ssh*) and `p` (*snmp*) to identifiy the protocol used for the credentials obtained via honeypots.

For Telnet/SSH `enable` passwords we `e` as 2nd key identifier

honeypots came from, to save bits the Dotted IP format has been converted to Hex
The exfiltration programs `carpa.py` or `jaula.py` will convert back to Dotted
IP format before display/writing output file

From version 2, we sniff credentials using [Net-Creds](https://github.com/DanMcInerney/net-creds) and also capture SIP hashes

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

### [Net-Creds](https://github.com/DanMcInerney/net-creds)
```
n,<credential/hash>,<dst_ip>
```

### VoIP
```
v,<hash>
```

----

# Presentations

[DEF CON 28 Demo Labs (Aug-2020)](https://media.defcon.org/DEF%20CON%2028/DEF%20CON%20Safe%20Mode%20demo%20labs/DEF%20CON%20Safe%20Mode%20-%20Demo%20Labs%20-%20Emilio%20Couto%20-%20CIRCO%20v2.pdf)

[AV Tokyo HIVE (Nov-2019)](https://speakerdeck.com/ekio_jp/circo-av-tokyo-2019)

[Code Blue Bluebox (Oct-2019)](https://speakerdeck.com/ekio_jp/circo-code-blue-2019-bluebox)

[HITB GSEC Armory (Aug-2019)](https://speakerdeck.com/ekio_jp/circo-hitb-gsec)

[Def CON 27 Packet Hacking Village (Aug-2019)](https://speakerdeck.com/ekio_jp/circo-def-con-27-phv-11-aug-2019)

[Def CON 27 Demo Labs (Aug-2019)](https://speakerdeck.com/ekio_jp/circo-def-con-27-demo-labs)

[Hackers Party Booth (Jul-2019)](https://speakerdeck.com/ekio_jp/circo-hackers-party)

[BlackHat Asia Arsenal (Mar-2019)](https://speakerdeck.com/ekio_jp/circo-blackhat-asia-2019-arsenal)

[濱せっく / HamaSec (Feb-2019)](https://speakerdeck.com/ekio_jp/circo-hamasec-feb-2019)

[YOROZU SECCON (Dec-2018)](https://speakerdeck.com/ekio_jp/circo-yorozu-seccon-2018)

[HIVE AV Tokyo (Nov-2018)](https://speakerdeck.com/ekio_jp/circo-hive-av-tokyo-2018)

----

# ToDo

- [ ] Automatic Installation script (circo/jaula/carpa)
- [ ] Include implant ID on exfiltration
- [ ] Work on No-DHCP module
- [ ] Migrate net-creds to python3
- [ ] Code new SNMP agent in python3
- [ ] Extra exfiltration methods
- [ ] Deploy Blue Team mode
- [ ] Make the code much more nicer

----

# Disclaimer

The tool is provided for educational, research or testing purposes.  
Using this tool against network/systems without prior permission is illegal.  
Radio waves are regulated per each country, before any radio wave transmission, make sure you complain within your country regulations (power, frequencies, bandwidth, etc.)  
The author is not liable for any damages from misuse of this tool, techniques or code.  

----

# Author

Emilio / [@ekio_jp](https://twitter.com/ekio_jp)

----

# Licence

Please see [LICENSE](https://github.com/ekiojp/circo/blob/master/LICENSE).
