#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2013 Cesnet z.s.p.o
# Use of this source is governed by a 3-clause BSD-style license, see LICENSE file.

from sys import path
from os.path import dirname, join

path.append(dirname(__file__))
from warden_server import build_server

## JSON configuration with line comments (trailing #)
from warden_server import read_cfg
application = build_server(read_cfg(join(dirname(__file__), "warden_server.cfg")))
