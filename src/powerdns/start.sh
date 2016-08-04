#!/usr/bin/env bash

# Give time to database to boot up
sleep 10

# Import schema structure
if [ -e "pdns.sql" ]; then
	mysql --host=$PDNS_MDB_HOST --user=$PDNS_MDB_USER --password=$PDNS_MDB_PASS --database=$PDNS_DB < pdns.sql
fi

/usr/sbin/pdns_server \
	--launch=gmysql --gmysql-host=$PDNS_MDB_HOST --gmysql-user=$PDNS_MDB_USER --gmysql-dbname=$PDNS_DB --gmysql-password=$PDNS_MDB_PASS \
	--webserver=yes --webserver-address=0.0.0.0 --webserver-port=80 \
	--experimental-json-interface=yes --experimental-api-key=changeme
