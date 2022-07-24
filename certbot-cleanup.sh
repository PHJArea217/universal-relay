#!/bin/sh
set -eu
curl --unix-socket='/home/henrie/gitprojects/universal-relay/test/acme.sock' -X POST --data-urlencode "k=${CERTBOT_DOMAIN##_acme-challenge.}" --data-urlencode "c=clear" http://localhost/add
