#!/bin/bash

HOSTNAME=`hostname -f`
HOSTNAME_=${HOSTNAME//-/_}
mkdir /etc/nemea/warden
for name in hoststats vportscan amplification ipblacklist bruteforce voipfraud dnstunnel; do
	secret=`tr -dc '[a-zA-Z0-9]' </dev/urandom | head -c10`
	/opt/warden_server_3/warden_server.py register -n $HOSTNAME_.$name --valid --write --notest --debug -h $HOSTNAME -r staas@cesnet.cz -s "$secret"
	cat > /etc/nemea/warden/$name.cfg <<CONF
{
    "url": "https://$HOSTNAME:8443/warden3",
    "certfile": "/opt/warden_server_3/keys/client.crt",
    "keyfile": "/opt/warden_server_3/keys/client.key",
    "cafile": "/opt/warden_server_3/ca/rootCA.pem",
    "syslog": {"level": "debug"},
    "name": "$HOSTNAME_.$name",
    "secret": "$secret"
}
CONF
done
