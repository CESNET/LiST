#!/bin/bash

HOSTNAME=`hostname -f`
mkdir /etc/warden

# test if the name is not registered
/opt/warden_server_3/warden_server.py list | grep -q com.example.list_vagrant.nemea.filer;
if [ $? -ne 0 ]; then
# register local warden client
python3 /opt/warden_server_3/warden_server.py register -n com.example.list_vagrant.nemea.filer -h "$HOSTNAME" -r list@example.com --write --valid --notest
fi

