#!/bin/bash

mkdir -p /opt/warden_server_3/{keys,ca}
cd /opt/warden_server_3/ca
# generate CA
openssl genrsa -out rootCA.key 2048
echo -e "CZ\nCzech Republic\nPrague\nCESNET - STaaS\n\n`hostname -f`\n\nstaas@cesnet.cz\n" | openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem

cd /opt/warden_server_3/keys
for i in server client; do
	openssl genrsa -out $i.key 2048
	echo -e "CZ\nCzech Republic\n\n\n\n"`hostname -f`"\n\n\n" |
	openssl req -new -key $i.key -out $i.csr
	openssl x509 -req -in $i.csr -CA ../ca/rootCA.pem -CAkey ../ca/rootCA.key -CAcreateserial -CAserial ../ca/serial -days 365 -out $i.crt
done