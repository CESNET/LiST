#!/bin/sh
#
# Copyright (C) 2011-2015 Cesnet z.s.p.o
# Use of this source is governed by a 3-clause BSD-style license, see LICENSE file.

if [ "$#" -ne 6 ]; then
    echo "Run me like:"
    echo "${0##*/} 'https://warden-hub.example.org/warden3' org.example.warden.client 'ToPsEcReT' key.pem cert.pem tcs-ca-bundle.pem"
    exit 1
fi


url="$1"
client="$2"
secret="$3"
keyfile="$4"
certfile="$5"
cafile="$6"

echo "Test  404"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/blefub?client=$client&secret=$secret"
echo

echo "Test  404"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/?client=$client&secret=$secret"
echo

echo "Test  403 - no secret"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getEvents?client=$client"
echo

echo "Test  403 - no client, no secret"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getEvents"
echo

echo "Test  403 - wrong client"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getEvents?client=asdf.blefub"
echo

echo "Test  403 - wrong client, right secret"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getEvents?client=asdf.blefub&secret=$secret"
echo

echo "Test  403 - right client, wrong secret"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getEvents?client=$client&secret=ASDFblefub"
echo

echo "Test - no client, but secret, should be ok"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getEvents?secret=$secret"
echo

echo "Test  Deserialization"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    --data '{#$%^' \
    "$url/getEvents?client=$client&secret=$secret"
echo

echo "Test  Called with unknown category"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getEvents?client=$client&secret=$secret&cat=bflm"
echo

echo "Test  Called with both cat and nocat"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getEvents?client=$client&secret=$secret&cat=Other&nocat=Test"
echo

echo "Test  Invalid data for getEvents - silently discarded"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    --data '[1]' \
    "$url/getEvents?client=$client&secret=$secret"
echo

echo "Test  Called with internal args - just in log"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getEvents?client=$client&secret=$secret&self=test"
echo

echo "Test  Called with superfluous args - just in log"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getEvents?client=$client&secret=$secret&bad=guy"
echo

echo "Test  getEvents with no args - should be OK"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getEvents?client=$client&secret=$secret"
echo

echo "Test  getEvents - should be OK"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getEvents?client=$client&secret=$secret&count=3&id=10"
echo

echo "Test  getDebug"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getDebug?client=$client&secret=$secret"
echo

echo "Test  getInfo"
curl \
    --key $keyfile \
    --cert $certfile \
    --cacert $cafile \
    --connect-timeout 3 \
    --request POST \
    "$url/getInfo?client=$client&secret=$secret"
echo
