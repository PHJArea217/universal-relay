#!/bin/sh
export SKBOX_DIRECTORY_ROOT2="$XDG_RUNTIME_DIR/skbox_ec"
exec unshare -r -n -m --propagation=slave sh -eu -c 'export SKBOX_ENABLE_CONNECT=1;mount --bind tools/skbox_ec_hosts /etc/hosts;echo "Set LD_PRELOAD to the path of libsocketbox-preload.so in the socketbox repository." >&2;exec "$@"' _ "$@"
