#!/bin/sh
set -eu
if [ ! -f /etc/powerdns/dnssec.db ]; then
	sed -i '/^launch=remote$/claunch=gsqlite3,remote\ngsqlite3-dnssec=yes\ngsqlite3-database=/etc/powerdns/dnssec.db' /etc/powerdns/pdns.conf
	sqlite3 /etc/powerdns/dnssec.db <"${1:-/usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql}"
	sqlite3 /etc/powerdns/dnssec.db 'INSERT INTO domains (name, type) VALUES (".", "NATIVE");'
	pdnsutil secure-zone . || :
	pdnsutil set-nsec3 . '1 0 0 -' narrow
	pdnsutil show-zone .
else
	printf 'DNSSEC already configured, run rm -f /etc/powerdns/dnssec.db to redo\n' >&2
fi
