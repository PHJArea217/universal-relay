#!/bin/sh
set -eu

case "$0" in
	*/*)
		cd "${0%/*}"
		;;
esac
export PATH="$PATH:/usr/sbin:/sbin"
unshare -r -n -m --propagation=slave sh -eu -c 'ip link set lo up
ip route add local "fedb:1200:4500:7800::/64" dev lo
ip6tables-nft -t mangle -A PREROUTING -p tcp -d "fedb:1200:4500:7800::/64" -j TPROXY --on-ip "::" --on-port 80
mkdir -p pdns_overlay_work
mount -t overlay -o lowerdir=/etc,upperdir=pdns_overlay,workdir=pdns_overlay_work,userxattr none /etc
mount -t tmpfs -o mode=0755 none /run
printf "Type pdns_server & to start PowerDNS\n"
printf "In another terminal, run ./test-exampleWithFilters.sh %d\n" "$$"
exec /bin/bash -i'
