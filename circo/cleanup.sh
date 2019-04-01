#!/bin/bash
# Small script to clean up after testing & running circo_v1.py

kill -9 `ps ax | grep telnetd-fake | grep -v grep | awk '{print $1}'` 2>/dev/null
kill -9 `ps ax | grep sshd-fake | grep -v grep | awk '{print $1}'` 2>/dev/null
kill -9 `ps ax | grep snmposter | grep -v grep | awk '{print $1}'` 2>/dev/null
rm Cisco_2960-fake.snmpwalk *CRED.txt cli.conf agent.csv ssh_rsa.key.pub ssh_rsa.key 2>/dev/null
ip addr flush dev eth0
airmon-ng stop wlan1mon >/dev/null
ifconfig eth0 down >/dev/null
macchanger -p eth0 >/dev/null
ifconfig eth0 up 2>/dev/null
iptables -F INPUT
iptables -A INPUT -i eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED  -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --dport 23 -m conntrack --ctstate NEW,ESTABLISHED  -j ACCEPT
iptables -A INPUT -i eth0 -p udp --dport 161 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p ICMP --icmp-type 8 -j ACCEPT
iptables -A INPUT -i eth0 -j DROP
