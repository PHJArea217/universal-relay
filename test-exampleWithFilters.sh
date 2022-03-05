#!/bin/sh
set -eu
exec "$CTRTOOL" ns_open_file \
	-m -P "/proc/$1/ns/net" -O rdonly -O nonblock -O noctty -s0,i \
	-n -6 ::,80,ato -l4096 -i 0,n -U \
	-n -6 ::,443,ao -l4096 -i 0,n -U \
	-n -6 ::,8080,ao -l4096 -i 0,n -U \
	-n -d inet -4 127.0.0.10,81,a -l4096 -i 0,n -U \
	node test.js
