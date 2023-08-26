#!/bin/sh
unshare -r -n -m --propagation=slave sh -c '
set -eu
ip link set lo up
ip6tables -t mangle -A PREROUTING -p tcp -d "fedb:1200:4500:7800::/64" -j TPROXY --on-ip "::ffff:127.0.0.20" --on-port 1
ip route add local "fedb:1200:4500:7800::/64" dev lo table main
mount -t tmpfs none -o mode=0755 /proc/sysvipc
mkdir /proc/sysvipc/user
mount --rbind /run/user /proc/sysvipc/user
mount --move /proc/sysvipc /run || :
mkdir /run/pdns
mount -t overlay -o "upperdir=src/pdns_overlay,workdir=src/pdns_overlay_work,lowerdir=/etc" none /etc
exec /bin/bash'
