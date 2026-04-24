#!/bin/bash
# AutoShield iptables rules — generated 2026-04-22T10:57:09.340292+00:00
# Blocks 99 malicious IPs
# Run as root: sudo bash iptables_rules.sh

set -e

# Create ipset if it doesn't exist
ipset create autoshield_blocklist hash:ip -exist
ipset flush autoshield_blocklist

# Add all IPs to the set
ipset add autoshield_blocklist 101.47.156.17
ipset add autoshield_blocklist 102.54.243.199
ipset add autoshield_blocklist 103.106.188.32
ipset add autoshield_blocklist 103.146.23.145
ipset add autoshield_blocklist 103.186.1.59
ipset add autoshield_blocklist 103.217.144.161
ipset add autoshield_blocklist 103.74.123.88
ipset add autoshield_blocklist 110.25.114.7
ipset add autoshield_blocklist 118.219.64.66
ipset add autoshield_blocklist 121.204.171.142
ipset add autoshield_blocklist 122.176.122.24
ipset add autoshield_blocklist 125.23.183.126
ipset add autoshield_blocklist 128.14.225.253
ipset add autoshield_blocklist 129.153.121.56
ipset add autoshield_blocklist 138.2.232.2
ipset add autoshield_blocklist 138.204.127.54
ipset add autoshield_blocklist 147.203.255.20
ipset add autoshield_blocklist 159.89.12.99
ipset add autoshield_blocklist 160.119.76.30
ipset add autoshield_blocklist 164.90.228.79
ipset add autoshield_blocklist 169.63.253.37
ipset add autoshield_blocklist 172.212.200.29
ipset add autoshield_blocklist 179.48.54.162
ipset add autoshield_blocklist 180.76.183.253
ipset add autoshield_blocklist 182.253.171.123
ipset add autoshield_blocklist 182.95.178.206
ipset add autoshield_blocklist 183.182.105.73
ipset add autoshield_blocklist 183.241.254.205
ipset add autoshield_blocklist 184.105.139.118
ipset add autoshield_blocklist 185.246.128.133
ipset add autoshield_blocklist 192.253.248.90
ipset add autoshield_blocklist 193.24.211.95
ipset add autoshield_blocklist 193.32.162.13
ipset add autoshield_blocklist 193.37.32.180
ipset add autoshield_blocklist 193.37.32.194
ipset add autoshield_blocklist 194.88.98.87
ipset add autoshield_blocklist 194.88.98.88
ipset add autoshield_blocklist 195.178.110.15
ipset add autoshield_blocklist 195.184.76.213
ipset add autoshield_blocklist 195.184.76.244
ipset add autoshield_blocklist 195.184.76.35
ipset add autoshield_blocklist 196.0.120.211
ipset add autoshield_blocklist 2.57.121.112
ipset add autoshield_blocklist 2.57.121.25
ipset add autoshield_blocklist 2.57.122.189
ipset add autoshield_blocklist 2.57.122.190
ipset add autoshield_blocklist 2.57.122.192
ipset add autoshield_blocklist 2.57.122.193
ipset add autoshield_blocklist 2.57.122.195
ipset add autoshield_blocklist 2.59.162.146
ipset add autoshield_blocklist 20.118.209.70
ipset add autoshield_blocklist 20.203.42.204
ipset add autoshield_blocklist 201.6.100.191
ipset add autoshield_blocklist 204.76.203.224
ipset add autoshield_blocklist 209.38.122.37
ipset add autoshield_blocklist 209.99.184.143
ipset add autoshield_blocklist 211.180.105.241
ipset add autoshield_blocklist 212.73.148.15
ipset add autoshield_blocklist 213.209.159.159
ipset add autoshield_blocklist 213.35.119.176
ipset add autoshield_blocklist 27.79.1.60
ipset add autoshield_blocklist 27.79.46.194
ipset add autoshield_blocklist 34.173.239.49
ipset add autoshield_blocklist 34.32.31.166
ipset add autoshield_blocklist 36.255.97.103
ipset add autoshield_blocklist 36.255.97.178
ipset add autoshield_blocklist 36.33.167.165
ipset add autoshield_blocklist 41.203.213.8
ipset add autoshield_blocklist 45.144.233.56
ipset add autoshield_blocklist 45.148.10.134
ipset add autoshield_blocklist 45.148.10.141
ipset add autoshield_blocklist 45.148.10.147
ipset add autoshield_blocklist 45.148.10.151
ipset add autoshield_blocklist 45.148.10.152
ipset add autoshield_blocklist 45.194.21.148
ipset add autoshield_blocklist 46.105.39.49
ipset add autoshield_blocklist 46.250.234.129
ipset add autoshield_blocklist 47.254.125.182
ipset add autoshield_blocklist 52.205.222.214
ipset add autoshield_blocklist 54.37.229.48
ipset add autoshield_blocklist 62.60.130.75
ipset add autoshield_blocklist 8.219.79.215
ipset add autoshield_blocklist 85.217.149.11
ipset add autoshield_blocklist 85.217.149.16
ipset add autoshield_blocklist 85.217.149.33
ipset add autoshield_blocklist 87.251.64.144
ipset add autoshield_blocklist 87.251.64.145
ipset add autoshield_blocklist 87.251.64.147
ipset add autoshield_blocklist 87.251.64.149
ipset add autoshield_blocklist 88.149.145.190
ipset add autoshield_blocklist 88.151.34.214
ipset add autoshield_blocklist 91.230.168.190
ipset add autoshield_blocklist 91.230.168.192
ipset add autoshield_blocklist 92.118.39.196
ipset add autoshield_blocklist 92.118.39.23
ipset add autoshield_blocklist 92.118.39.235
ipset add autoshield_blocklist 92.118.39.236
ipset add autoshield_blocklist 92.33.193.44
ipset add autoshield_blocklist 98.26.115.52

# Apply DROP rule (idempotent)
iptables -I INPUT  -m set --match-set autoshield_blocklist src -j DROP 2>/dev/null || true
iptables -I OUTPUT -m set --match-set autoshield_blocklist dst -j DROP 2>/dev/null || true

echo "AutoShield: 99 IPs blocked."
