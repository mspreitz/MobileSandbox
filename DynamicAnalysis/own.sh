#!/bin/bash
IFACE_IN='vboxnet0'
IFACE_OUT='enp0s25'
SUBNET='192.168.56.0/24'
# Forward traffic from IFACE_IN to IFACE_OUT in SUBNET, using the conntrack module. If matches, it [j]umps directly to the ACCEPT chain in the filter table
iptables -A FORWARD -o "$IFACE_OUT" -i "$IFACE_IN" -s "$SUBNET" -m conntrack --ctstate NEW -j ACCEPT
# Accept and Forward all currently established and related (?) traffic to the ACCEPT chain in the filter table
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# ???
iptables -A POSTROUTING -t nat -j MASQUERADE

echo 1 > /proc/sys/net/ipv4/ip_forward
