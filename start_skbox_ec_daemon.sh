#!/bin/sh
MY_DIR="$XDG_RUNTIME_DIR/skbox_ec/00016"
mkdir -p "$MY_DIR"
exec URELAY_SKBOX_EC_ROOT="$MY_DIR" node example_skbox_ec.js
