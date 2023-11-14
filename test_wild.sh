#!/bin/sh
set -eu
# this is still vulnerable to injection
export SKBOX_DIRECTORY_ROOT2="$1"
case "$0" in
	*/*)
		cd "${0%/*}"
		;;
esac
shift 1
mkdir -p "$SKBOX_DIRECTORY_ROOT2/00000"
exec node index.js '--optjson=listeners=[
	{"l": {"host": "fe8f::3:0:0", "port": 1}},
	{"listener_opts": {"unix_path": "'"$SKBOX_DIRECTORY_ROOT2/socks"'"}, "forced_iid": ["0x5ff7007c0a8ffc0", 1080]},
	{"listener_opts": {"unix_path": "'"$SKBOX_DIRECTORY_ROOT2/pp2"'"}, "forced_iid": ["0x5ff7007c0a8ffc0", 8081]},
]' '--optjson=dns_listener={"unix_path": "'"$SKBOX_DIRECTORY_ROOT2/dns"'"}' \
	'--optjson=ipv4_handlers=[{"ipv4_iid_offset": "0x5ff700100000040", "ipv4_net": "0xc0a8ffc0", "ipv4_mask": "0xffffffc0"}]' "$@"
