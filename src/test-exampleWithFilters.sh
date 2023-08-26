#!/bin/sh
set -eu
if [ ".$3" = ".X" ]; then
	N=""
else
	N="-U"
fi
# N="${2:--U}"
exec "$CTRTOOL" ns_open_file -o 9 \
	-m -P "/proc/$1/ns/net" -O rdonly -O nonblock -O noctty -s0,i \
	-n -d inet -4 127.0.0.10,81,a -l4096 -i 0,n $N \
	-n -6 ::,80,ato -l4096 -i 0,n $N \
	-n -6 '::,1080,a' -l4096 -i 0,n $N \
	node example.js
