#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2015 Cesnet z.s.p.o
# Use of this source is governed by a 3-clause BSD-style license, see LICENSE file.

import string
from time import time
from uuid import uuid4
from pprint import pprint
from random import randint, randrange, choice, random
from base64 import b64encode
from warden_client import Client, Error, read_cfg, format_timestamp

def gen_min_idea():

    return {
       "Format": "IDEA0",
       "ID": str(uuid4()),
       "DetectTime": format_timestamp(),
       "Category": ["Test"],
    }

def gen_random_idea(client_name="cz.example.warden.test"):

    def geniprange(gen):

        def iprange():
            u = v = 0
            while u==v:
                u, v = gen(), gen()
            u, v = min(u, v), max(u, v)
            return "%s-%s" % (u, v)

        return iprange

    def rand4ip():
        return "%s%d" % ('192.0.2.', randint(1, 254))

    def rand4cidr():
        return "%s%d/%d" % ('192.0.2.', randint(1, 254), randint(24, 31))

    def randip4():
        return [rand4ip, geniprange(rand4ip), rand4cidr][randint(0, 2)]()

    def rand6ip():
        return "2001:DB8:%s" % ":".join("%x" % randint(0, 65535) for i in range(6))

    def rand6cidr():
        m = randint(0, 5)
        return "2001:DB8%s%s::/%d" % (":" if m else "", ":".join("%x" % randint(0, 65535) for i in range(m)), (m+2)*16)

    def randip6():
        return [rand6ip, geniprange(rand6ip), rand6cidr][randint(0, 2)]()

    def randstr(charlist=string.ascii_letters, maxlen=32, minlen=1):
        return ''.join(choice(charlist) for i in range(randint(minlen, maxlen)))

    event = {
       "Format": "IDEA0",
       "ID": str(uuid4()),
       "CreateTime": format_timestamp(),
       "DetectTime": format_timestamp(),
       "WinStartTime": format_timestamp(),
       "WinEndTime": format_timestamp(),
       "EventTime": format_timestamp(),
       "CeaseTime": format_timestamp(),
       #"Category": ["Abusive.Spam","Abusive.Harassment","Malware","Fraud.Copyright","Test","Fraud.Phishing","Fraud.Scam"],
       # "Category": ["Abusive.Spam","Fraud.Copyright"],
       "Category": [choice(["Abusive.Spam","Abusive.Harassment","Malware","Fraud.Copyright","Test","Fraud.Phishing","Fraud.Scam"]) for dummy in range(randint(1, 3))],
       "Ref": ["cve:CVE-%s-%s" % (randstr(string.digits, 4), randstr()), "http://www.example.com/%s" % randstr()],
       "Confidence": random(),
       "Note": "Random event",
       "ConnCount": randint(0, 65535),
#       "ConnCount": choice([randint(0, 65535), "asdf"]),    # Send wrong event sometimes
       "Source": [
          {
             "Type": ["Phishing"],
             "IP4": [randip4() for i in range(randrange(1, 5))],
             "IP6": [randip6() for i in range(randrange(1, 5))],
             "Hostname": ["example.com"],
             "Port": [randint(1, 65535) for i in range(randrange(1, 3))],
             "AttachHand": ["att1"],
             "Netname": ["arin:TEST-NET-1"]
          }
       ],
       "Target": [
          {
             "IP4": [randip4() for i in range(randrange(1, 5))],
             "IP6": [randip6() for i in range(randrange(1, 5))],
             "URL": ["http://example.com/%s" % randstr()],
             "Proto": ["tcp", "http"],
             "Netname": ["arin:TEST-NET-1"]
          }
       ],
       "Attach": [
          {
             "Handle": "att1",
             "FileName": [randstr()],
             "Type": ["Malware"],
             "ContentType": "application/octet-stream",
             "Hash": ["sha1:%s" % randstr(string.hexdigits, 24)],
             "Size": 46,
             "Ref": ["cve:CVE-%s-%s" % (randstr(string.digits, 4), randstr())],
             "ContentEncoding": "base64",
             "Content": b64encode(randstr().encode('ascii')).decode("ascii")
          }
       ],
       "Node": [
          {
             "Name": client_name,
             "Type": [choice(["Data", "Protocol", "Honeypot", "Heuristic", "Log"]) for dummy in range(randint(1, 3))],
             "SW": ["Kippo"],
             "AggrWin": "00:05:00"
          },
          {
             "Name": "org.example.warden.client",
             "Type": [choice(["Connection", "Datagram"]) for dummy in range(randint(1, 2))],
          }
       ]
    }

    return event

def main():
    wclient = Client(**read_cfg("warden_client.cfg"))
    # Also inline arguments are possible:
    # wclient = Client(
    #     url  = 'https://warden.example.com/warden3',
    #     keyfile  = '/opt/warden3/etc/key.pem',
    #     certfile = '/opt/warden3/etc/cert.pem',
    #     cafile = '/opt/warden3/etc/tcs-ca-bundle.pem',
    #     timeout=10,
    #     errlog={"level": "debug"},
    #     filelog={"level": "debug"},
    #     idstore="MyClient.id",
    #     name="cz.example.warden.test")

    print("=== Debug ===")
    info = wclient.getDebug()
    pprint(info)

    # All methods return something.
    # If you want to catch possible errors (for example implement some
    # form of persistent retry, or save failed events for later, you may
    # check for Error instance and act based on contained info.
    # If you want just to be informed, this is not necessary, just
    # configure logging correctly and check logs.
    if isinstance(info, Error):
        print(info)

    print("=== Server info ===")
    info = wclient.getInfo()

    print("=== Sending 10 event(s) ===")
    start = time()
    ret = wclient.sendEvents([gen_random_idea(client_name=wclient.name) for i in range(10)])
    print(ret)
    print("Time: %f" % (time()-start))

    print("=== Getting 10 events ===")
    start = time()

    # cat = ['Availability', 'Abusive.Spam','Attempt.Login']
    # cat = ['Attempt', 'Information','Fraud.Scam','Malware.Virus']
    # cat = ['Fraud', 'Abusive.Spam']
    # nocat = ['Availability', 'Information', 'Fraud.Scam']
    cat = []
    nocat = []

    #tag = ['Log', 'Data']
    #notag = ['Flow', 'Datagram']
    tag = []
    notag = []

    #group = ['cz.tul.ward.kippo','cz.vsb.buldog.kippo']
    #nogroup = ['cz.zcu.civ.afrodita','cz.vutbr.net.bee.hpscan']
    group = []
    nogroup = []

    ret = wclient.getEvents(count=10, cat=cat, nocat=nocat, tag=tag, notag=notag, group=group, nogroup=nogroup)
    print("Time: %f" % (time()-start))
    print("Got %i events" % len(ret))
    for e in ret:
        print(e.get("Category"), e.get("Node")[0].get("Type"), e.get("Node")[0].get("Name"))

if __name__ == "__main__":
    main()
