#!/bin/sh
set -eu
unshare --fork -r -m -p --propagation=slave --mount-proc "${CTRTOOL:-ctrtool}" launcher -n --alloc-tty --script-is-shell --no-clear-groups --no-set-id --script='./test-exampleWithFilters.sh self/fd/"$2" "" X &' sh -eu -c '
ip link set lo up
ip route add local "fedb:1200:4500:7800::/64" dev lo
ip6tables-nft -t mangle -A PREROUTING -p tcp -d "fedb:1200:4500:7800::/64" -j TPROXY --on-ip "::" --on-port 80
mkdir -p pdns_overlay_work
mount -t overlay -o lowerdir=/etc,upperdir=pdns_overlay,workdir=pdns_overlay_work,userxattr none /etc
mount -t tmpfs -o mode=0755 none /proc/sysvipc
mkdir /proc/sysvipc/user
[ -d /run/user ] && mount --rbind /run/user /proc/sysvipc/user
busybox mount --move /proc/sysvipc /run
sleep 2
pdns_server &
exec "$@" 2>&1' _ "$@"
