#!/bin/bash

HOSTNAME=`hostname -f`
secret=`tr -dc '[a-zA-Z0-9]' </dev/urandom | head -c10`
/opt/warden_server_3/warden_server.py register -n cz.cesnet.list.warden_filer --valid --write --notest --debug -h $HOSTNAME -r list@cesnet.cz -s "$secret"
cat > /etc/warden/warden_filer.cfg <<CONF
{
    "warden": {
        "url": "https://$HOSTNAME:8443/warden3",
        "certfile": "/opt/warden_server_3/keys/client.crt",
        "keyfile": "/opt/warden_server_3/keys/client.key",
        "cafile": "/opt/warden_server_3/ca/rootCA.pem",
        "timeout": 10,
        "errlog": {"level": "debug"},
        "filelog": {"level": "debug"},
        "syslog": {"level": "debug"},
        "name": "cz.cesnet.list.warden_filer",
        "secret": "$secret"
    },
    "receiver": {
        "dir": "/var/www/html/warden_receiver"
    }
}
CONF
# "idstore": "myclient.id",
