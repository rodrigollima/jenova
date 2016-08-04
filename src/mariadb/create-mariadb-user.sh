#!/bin/bash
/usr/bin/mysqld_safe > /dev/null 2>&1 &

RET=1  
while [[ RET -ne 0 ]]; do  
    #sleep 1
    mysql -uroot -e "status" > /dev/null 2>&1
    RET=$?
done

echo "Creating Users for webapp..."
mysql -uroot -e "GRANT ALL ON *.* TO '$JNV_MDB_USER'@'localhost' IDENTIFIED BY '$JNV_MDB_PASS'"  
mysql -uroot -e "GRANT ALL ON *.* TO '$JNV_MDB_USER'@'%' IDENTIFIED BY '$JNV_MDB_PASS'"  
mysql -uroot -e "CREATE DATABASE $JNV_DB"
mysql -uroot -e "CREATE DATABASE $PDNS_DB"

mysqladmin -uroot shutdown  
