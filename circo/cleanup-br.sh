#!/bin/bash
# Small script to clean up after testing & running circo.py (bridge mode)

kill -9 `ps ax | grep telnetd-fake | grep -v grep | awk '{print $1}'` 2>/dev/null
kill -9 `ps ax | grep sshd-fake | grep -v grep | awk '{print $1}'` 2>/dev/null
kill -9 `ps ax | grep snmposter | grep -v grep | awk '{print $1}'` 2>/dev/null
kill -9 `ps ax | grep nmap | grep -v grep | awk '{print $1}'` 2>/dev/null
rm Cisco_2960-fake.snmpwalk *CRED.txt cli.conf agent.csv ssh_rsa.key.pub ssh_rsa.key 2>/dev/null
ip link set wlan1 down > /dev/null 2>&1
iw wlan1 set type managed > /dev/null 2>&1
ip link set wlan1 up > /dev/null 2>&1
ifconfig br0 down 2>/dev/null
ifconfig eth0 down >/dev/null
ifconfig eth1 down >/dev/null
brctl delbr br0 2>/dev/null
macchanger -p eth0 >/dev/null
macchanger -p eth1 >/dev/null
iptables -F 
