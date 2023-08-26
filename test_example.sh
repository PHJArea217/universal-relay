#!/bin/sh
set -eu
exec ctrtool ns_open_file -o 100 -nN "$1" -d inet -4 '127.0.0.10,81,a' -l4096 -U -nN "$1" -6 '::ffff:127.0.0.20,1,at' -l4096 -U node example_new.js

