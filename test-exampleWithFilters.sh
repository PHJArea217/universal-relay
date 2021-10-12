#!/bin/sh
set -eu
exec "$CTRTOOL" ns_open_file \
	-m -P "/proc/$1/ns/net" -O rdonly -O nonblock -O noctty -s0,i \
	-n -6 ::,80,a -l4096 -i 0,n -U \
	-n -6 ::,443,a -l4096 -i 0,n -U \
	-n -6 ::,53,at -l4096 -i 0,n -U \
	node exampleWithFilters.js
