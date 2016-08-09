#!/bin/bash

iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X 

iptables -A FORWARD -o wlp3s0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A POSTROUTING -t nat -j MASQUERADE

echo 1 > /proc/sys/net/ipv4/ip_forward
