#!/bin/sh
set -eu
exec "$CTRTOOL" ns_open_file -o 9 \
	-m -P "/proc/$1/ns/net" -O rdonly -O nonblock -O noctty -s0,i \
	-n -d inet -4 127.0.0.10,81,a -l4096 -i 0,n -U \
	-n -6 ::,80,ato -l4096 -i 0,n -U \
	-n -6 '::,1080,a' -l4096 -i 0,n -U \
	node example.js
