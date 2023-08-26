#!/bin/sh
set -eu
case "$0" in
	*/*)
		cd "${0%/*}"
		;;
esac
exec node example.js '{"pdns_fd": false, "socks_fd": {"host": "127.0.0.140", "port": 1080}, "transparent_fd": false}'
