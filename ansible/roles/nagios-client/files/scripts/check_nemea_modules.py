#!/usr/bin/env python
# -*- coding: utf-8 -*- vim:fileencoding=utf-8:
# vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab


import os
import sys
import json

check_modules = [
    "ipfixcol",
    "hoststatsnemea",
    "vportscan_detector",
    "bruteforce_detector",
    "sip_bf_detector",
    "link_traffic",
    "proto_traffic",
    "warden_hoststats2idea",
    "warden_amplification2idea",
    "warden_ipblacklist2idea",
    "warden_vportscan2idea",
    "warden_bruteforce2idea",
    "reporter_leaktest",
    "warden_booterfilter2idea",
    "warden_haddrscan2idea",
    "warden_sipbruteforce2idea",
    "warden_venom2idea"
]

with os.popen("supcli -i") as f:
    data = f.read()
    f.close()

errors = []
jd = json.loads(data)
for module in check_modules:
    if module not in jd or (module in jd and jd[module]["status"] != "running"):
        errors.append(module)

if not errors:
    print("All monitored modules are running")
    sys.exit(0)
else:
    print("Stopped modules: " + ", ".join(errors))
    sys.exit(2)

