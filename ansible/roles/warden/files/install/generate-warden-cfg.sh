#!/bin/bash

HOSTNAME=`hostname -f`
mkdir /etc/warden
for name in hoststats vportscan amplificationdetector ipblacklist bruteforce voipfraud_detection dnstunnel; do
	secret=`tr -dc '[:alnum:]' </dev/urandom | head -c10`
	/opt/warden_server_3/warden_server.py register -n cz.cesnet.nemea.$name --valid --write --notest --debug -h $HOSTNAME -r staas@cesnet.cz -s "$secret"
	cat > /etc/warden/$name.cfg <<CONF
{
    "url": "https://$HOSTNAME:8443/warden3",
    "certfile": "/opt/warden_server_3/keys/client.crt",
    "keyfile": "/opt/warden_server_3/keys/client.key",
    "cafile": "/opt/warden_server_3/ca/rootCA.pem",
    "syslog": {"level": "debug"},
    "name": "cz.cesnet.nemea.$name",
    "secret": "$secret"
}
CONF
done
