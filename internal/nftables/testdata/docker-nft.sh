#!/bin/sh
# Regenerates docker-nft.json in a private network namespace:
#   unshare -rn sh docker-nft.sh > docker-nft.json
# The native half comes from docker-nft.nft; the xtables half is what docker
# writes through iptables-nft on start (its chains and hooks, FORWARD DROP).
set -e
nft -f docker-nft.nft
iptables -N DOCKER-USER
iptables -N DOCKER-FORWARD
iptables -A FORWARD -j DOCKER-USER
iptables -A FORWARD -j DOCKER-FORWARD
iptables -A DOCKER-FORWARD -i docker0 -j ACCEPT
iptables -P FORWARD DROP
nft -j -a list ruleset
