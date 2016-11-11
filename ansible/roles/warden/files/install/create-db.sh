#!/bin/bash

# Check for existing database
echo "SELECT * FROM mysql.user;" | mysql | grep warden > /dev/null
if [ $? -eq 0 ]; then
	touch "/tmp/warden/db.created"
fi

mysql <<SQL
  CREATE USER "warden"@"localhost" IDENTIFIED BY '';
  CREATE DATABASE warden3;
  GRANT ALL ON warden3.* TO "warden"@"localhost";
  FLUSH PRIVILEGES;
  use warden3;
  source /tmp/warden/warden_3.0.sql
  
SQL

if [ $? -eq 0 ]; then
	touch "/tmp/warden/db.created"
fi
