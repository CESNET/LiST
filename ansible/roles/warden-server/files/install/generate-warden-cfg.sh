#!/bin/bash

HOSTNAME=`hostname -f`
mkdir /etc/warden
python3 /opt/warden_server_3/warden_server.py register -n com.example.list_vagrant.nemea.filer -h "$HOSTNAME" -r list@example.com --write --valid --notest

