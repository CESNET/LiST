#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2015 Cesnet z.s.p.o
# Use of this source is governed by a 3-clause BSD-style license, see LICENSE file.

from __future__ import print_function

import sys
import os
from os import path
import logging
import logging.handlers
import json
import re
import email.utils
from traceback import format_tb
from collections import namedtuple
from time import sleep
from random import randint
import M2Crypto.X509
import MySQLdb as my
import MySQLdb.cursors as mycursors

if sys.version_info[0] >= 3:
    import configparser as ConfigParser
    from urllib.parse import parse_qs
else:
    import ConfigParser
    from urlparse import parse_qs

# for local version of up to date jsonschema
sys.path.append(path.join(path.dirname(__file__), "..", "lib"))

from jsonschema import Draft4Validator


VERSION = "3.0-beta2"


class Error(Exception):

    def __init__(self, method=None, req_id=None, errors=None, **kwargs):
        self.method = method
        self.req_id = req_id
        self.errors = [kwargs] if kwargs else []
        if errors:
            self.errors.extend(errors)

    def append(self, _events=None, **kwargs):
        self.errors.append(kwargs)

    def get_http_err_msg(self):
        try:
            err = self.errors[0]["error"]
            msg = self.errors[0]["message"].replace("\n", " ")
        except (IndexError, KeyError):
            err = 500
            msg = "There's NO self-destruction button! Ah, you've just found it..."
        for e in self.errors:
            next_err = e.get("error", 500)
            if err != next_err:
                # errors not same, round to basic err code (400, 500)
                # and use the highest one
                err = max(err//100, next_err//100)*100
            next_msg = e.get("message", "Unknown error").replace("\n", " ")
            if msg != next_msg:
                msg = "Multiple errors"
        return err, msg

    def __str__(self):
        return "\n".join(self.str_err(e) for e in self.errors)

    def log(self, logger, prio=logging.ERROR):
        for e in self.errors:
            logger.log(prio, self.str_err(e))
            info = self.str_info(e)
            if info:
                logger.info(info)
            debug = self.str_debug(e)
            if debug:
                logger.debug(debug)

    def str_err(self, e):
        out = []
        out.append("Error(%s) %s " % (e.get("error", 0), e.get("message", "Unknown error")))
        if "exc" in e and e["exc"]:
            out.append("(cause was %s: %s)" % (e["exc"][0].__name__, str(e["exc"][1])))
        return "".join(out)

    def str_info(self, e):
        ecopy = dict(e)    # shallow copy
        ecopy.pop("req_id", None)
        ecopy.pop("method", None)
        ecopy.pop("error", None)
        ecopy.pop("message", None)
        ecopy.pop("exc", None)
        if ecopy:
            out = "Detail: %s" % (json.dumps(ecopy, default=lambda v: str(v)))
        else:
            out = ""
        return out

    def str_debug(self, e):
        out = []
        if not e.get("exc"):
            return ""
        exc_tb = e["exc"][2]
        if exc_tb:
            out.append("Traceback:\n")
            out.extend(format_tb(exc_tb))
        return "".join(out)

    def to_dict(self):
        errlist = []
        for e in self.errors:
            ecopy = dict(e)
            ecopy.pop("exc", None)
            errlist.append(ecopy)
        d = {
            "method": self.method,
            "req_id": self.req_id,
            "errors": errlist
        }
        return d


def get_clean_root_logger(level=logging.INFO):
    """ Attempts to get logging module into clean slate state """

    # We want to be able to set up at least stderr logger before any
    # configuration is read, and then later get rid of it and set up
    # whatever administrator requires.
    # However, there can exist only one logger, but we want to get a clean
    # slate everytime we initialize StreamLogger or FileLogger... which
    # is not exactly supported by logging module.
    # So, we look directly inside logger class and clean up handlers/filters
    # manually.
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    while logger.handlers:
        logger.removeHandler(logger.handlers[0])
    while logger.filters:
        logger.removeFilter(logger.filters[0])
    logger.propagate = False
    return logger


def StreamLogger(stream=sys.stderr, level=logging.DEBUG):
    """ Fallback handler just for setup, not meant to be used from
        configuration file because during wsgi query stdout/stderr
        is forbidden.
    """

    fhand = logging.StreamHandler(stream)
    fform = logging.Formatter('%(asctime)s %(filename)s[%(process)d]: (%(levelname)s) %(message)s')
    fhand.setFormatter(fform)
    logger = get_clean_root_logger(level)
    logger.addHandler(fhand)
    return logger


class LogRequestFilter(logging.Filter):
    """ Filter class, instance of which is added to logger class to add
        info about request automatically into every logline, no matter
        how it came into existence.
    """

    def __init__(self, req):
        logging.Filter.__init__(self)
        self.req = req

    def filter(self, record):
        if self.req.env:
            record.req_preamble = "%08x/%s: " % (self.req.req_id or 0, self.req.path)
        else:
            record.req_preamble = ""
        return True


def FileLogger(req, filename, level=logging.INFO):

    fhand = logging.FileHandler(filename)
    fform = logging.Formatter('%(asctime)s %(filename)s[%(process)d]: (%(levelname)s) %(req_preamble)s%(message)s')
    fhand.setFormatter(fform)
    ffilt = LogRequestFilter(req)
    logger = get_clean_root_logger(level)
    logger.addFilter(ffilt)
    logger.addHandler(fhand)
    logger.info("Initialized FileLogger(req=%r, filename=\"%s\", level=%s)" % (req, filename, level))
    return logger


def SysLogger(req, socket="/dev/log", facility=logging.handlers.SysLogHandler.LOG_DAEMON, level=logging.INFO):

    fhand = logging.handlers.SysLogHandler(address=socket, facility=facility)
    fform = logging.Formatter('%(filename)s[%(process)d]: (%(levelname)s) %(req_preamble)s%(message)s')
    fhand.setFormatter(fform)
    ffilt = LogRequestFilter(req)
    logger = get_clean_root_logger(level)
    logger.addFilter(ffilt)
    logger.addHandler(fhand)
    logger.info("Initialized SysLogger(req=%r, socket=\"%s\", facility=\"%d\", level=%s)" % (req, socket, facility, level))
    return logger


Client = namedtuple("Client", [
    "id", "registered", "requestor", "hostname", "name",
    "secret", "valid", "read", "debug", "write", "test", "note"])


class Object(object):

    def __str__(self):
        attrs = self.__init__.func_code.co_varnames[1:self.__init__.func_code.co_argcount]
        eq_str = ["%s=%r" % (attr, getattr(self, attr, None)) for attr in attrs]
        return "%s(%s)" % (type(self).__name__, ", ".join(eq_str))


class Request(Object):
    """ Simple container for info about ongoing request.
        One instance gets created before server startup, and all other
        configured objects get it as parameter during instantiation.

        Server then takes care of populating this instance on the start
        of wsgi request (and resetting at the end). All other objects
        then can find this actual request info in their own self.req.

        However, only Server.wsgi_app, handler (WardenHandler) exposed
        methods and logging related objects should use self.req directly.
        All other objects should use self.req only as source of data for
        error/exception handling/logging, and should take/return
        necessary data as arguments/return values for clarity on
        which data their main codepaths work with.
    """

    def reset(self, env=None, client=None, path=None, req_id=None):
        self.env = env
        self.client = client
        self.path = path or ""
        if req_id is not None:
            self.req_id = req_id
        else:
            self.req_id = 0 if env is None else randint(0x00000000, 0xFFFFFFFF)

    __init__ = reset

    def error(self, **kwargs):
        return Error(self.path, self.req_id, **kwargs)


class ObjectBase(Object):

    def __init__(self, req, log):
        Object.__init__(self)
        self.req = req
        self.log = log


class PlainAuthenticator(ObjectBase):

    def __init__(self, req, log, db):
        ObjectBase.__init__(self, req, log)
        self.db = db

    def authenticate(self, env, args, hostnames=None, check_secret=True):
        name = args.get("client", [None])[0]
        secret = args.get("secret", [None])[0] if check_secret else None

        client = self.db.get_client_by_name(hostnames, name, secret)

        if not client:
            self.log.info("authenticate: client not found by name: \"%s\", secret: %s, hostnames: %s" % (
                name, secret, str(hostnames)))
            return None

        # Clients with 'secret' set must get authenticated by it.
        # No secret turns secret auth off for this particular client.
        if client.secret is not None and secret is None and check_secret:
            self.log.info("authenticate: missing secret argument")
            return None

        self.log.info("authenticate: %s" % str(client))

        # These args are not for handler
        args.pop("client", None)
        args.pop("secret", None)

        return client

    def authorize(self, env, client, path, method):
        if method.debug:
            if not client.debug:
                self.log.info("authorize: failed, client does not have debug enabled")
                return None
            return client

        if method.read:
            if not client.read:
                self.log.info("authorize: failed, client does not have read enabled")
                return None
            return client

        if method.write:
            if not (client.write or client.test):
                self.log.info("authorize: failed, client is not allowed to write or test")
                return None

        return client


class X509Authenticator(PlainAuthenticator):

    def get_cert_dns_names(self, pem):

        cert = M2Crypto.X509.load_cert_string(pem)

        subj = cert.get_subject()
        commons = [n.get_data().as_text() for n in subj.get_entries_by_nid(subj.nid["CN"])]

        try:
            extstrs = cert.get_ext("subjectAltName").get_value().split(",")
        except LookupError:
            extstrs = []
        extstrs = [val.strip() for val in extstrs]
        altnames = [val[4:] for val in extstrs if val.startswith("DNS:")]

        # bit of mangling to get rid of duplicates and leave commonname first
        firstcommon = commons[0]
        return [firstcommon] + list(set(altnames+commons) - set([firstcommon]))

    def is_verified_by_apache(self, env, args):
        # Allows correct work while SSLVerifyClient both "optional" and "required"
        verify = env.get("SSL_CLIENT_VERIFY")
        if verify == "SUCCESS":
            return True
        exception = self.req.error(
            message="authenticate: certificate verification failed",
            error=403, args=args, ssl_client_verify=verify, cert=env.get("SSL_CLIENT_CERT"))
        exception.log(self.log)
        return False

    def authenticate(self, env, args):
        if not self.is_verified_by_apache(env, args):
            return None

        try:
            cert_names = self.get_cert_dns_names(env["SSL_CLIENT_CERT"])
        except:
            exception = self.req.error(
                message="authenticate: cannot get or parse certificate from env",
                error=403, exc=sys.exc_info(), env=env)
            exception.log(self.log)
            return None

        return PlainAuthenticator.authenticate(self, env, args, hostnames=cert_names)


class X509NameAuthenticator(X509Authenticator):

    def authenticate(self, env, args):
        if not self.is_verified_by_apache(env, args):
            return None

        try:
            cert_name = env["SSL_CLIENT_S_DN_CN"]
        except:
            exception = self.req.error(
                message="authenticate: cannot get or parse certificate from env",
                error=403, exc=sys.exc_info(), env=env)
            exception.log(self.log)
            return None

        if cert_name != args.setdefault("client", [cert_name])[0]:
            exception = self.req.error(
                message="authenticate: client name does not correspond with certificate",
                error=403, cn=cert_name, args=args)
            exception.log(self.log)
            return None

        return PlainAuthenticator.authenticate(self, env, args, check_secret=False)


class X509MixMatchAuthenticator(X509Authenticator):

    def __init__(self, req, log, db):
        PlainAuthenticator.__init__(self, req, log, db)
        self.hostname_auth = X509Authenticator(req, log, db)
        self.name_auth = X509NameAuthenticator(req, log, db)

    def authenticate(self, env, args):
        if not self.is_verified_by_apache(env, args):
            return None

        try:
            cert_name = env["SSL_CLIENT_S_DN_CN"]
        except:
            exception = self.req.error(
                message="authenticate: cannot get or parse certificate from env",
                error=403, exc=sys.exc_info(), env=env)
            exception.log(self.log)
            return None
        name = args.get("client", [None])[0]
        secret = args.get("secret", [None])[0]

        # Client names are in reverse notation than DNS, client name should
        # thus never be the same as machine hostname (if it is, client
        # admin does something very amiss).

        # So, if client sends the same name in query as in the certificate,
        # or sends no name or secret (which is necessary for hostname auth),
        # use X509NameAuthenticator. Otherwise (names are different and there
        # is name and/or secret in query) use (hostname) X509Authenticator.

        if name == cert_name or (name is None and secret is None):
            auth = self.name_auth
        else:
            auth = self.hostname_auth

        self.log.info("MixMatch is choosing %s (name: %s, cert_name: %s)" % (type(auth).__name__, name, cert_name))
        return auth.authenticate(env, args)


class NoValidator(ObjectBase):

    def __init__(self, req, log):
        ObjectBase.__init__(self, req, log)

    def check(self, event):
        return []


class JSONSchemaValidator(NoValidator):

    def __init__(self, req, log, filename=None):
        NoValidator.__init__(self, req, log)
        self.path = filename or path.join(path.dirname(__file__), "idea.schema")
        with open(self.path) as f:
            self.schema = json.load(f)
        self.validator = Draft4Validator(self.schema)

    def check(self, event):

        def sortkey(k):
            """ Treat keys as lowercase, prefer keys with less path segments """
            return (len(k.path), "/".join(str(k.path)).lower())

        res = []
        for error in sorted(self.validator.iter_errors(event), key=sortkey):
            res.append({
                "error": 460,
                "message": "Validation error: key \"%s\", value \"%s\"" % (
                    "/".join(str(v) for v in error.path),
                    error.instance
                ),
                "expected": error.schema.get('description', 'no additional info')
            })

        return res


class MySQL(ObjectBase):

    def __init__(
            self, req, log, host, user, password, dbname, port, retry_count,
            retry_pause, event_size_limit, catmap_filename, tagmap_filename):
        ObjectBase.__init__(self, req, log)
        self.host = host
        self.user = user
        self.password = password
        self.dbname = dbname
        self.port = port
        self.retry_count = retry_count
        self.retry_pause = retry_pause
        self.retry_attempt = 0
        self.event_size_limit = event_size_limit
        self.catmap_filename = catmap_filename
        self.tagmap_filename = tagmap_filename

        with open(catmap_filename, "r") as catmap_fd:
            self.catmap = json.load(catmap_fd)
            self.catmap_other = self.catmap["Other"]    # Catch error soon, avoid lookup later

        with open(tagmap_filename, "r") as tagmap_fd:
            self.tagmap = json.load(tagmap_fd)
            self.tagmap_other = self.catmap["Other"]    # Catch error soon, avoid lookup later

        self.con = None

    def connect(self):
        self.con = my.connect(
            host=self.host, user=self.user, passwd=self.password,
            db=self.dbname, port=self.port, cursorclass=mycursors.DictCursor)

    def close(self):
        try:
            if self.con:
                self.con.close()
        except Exception:
            pass
        self.con = None

    __del__ = close

    def repeat(self):
        """ Allows for graceful repeating of transactions self.retry_count
            times. Unsuccessful attempts wait for self.retry_pause until
            next attempt.

            Meant for usage with context manager:

            for attempt in self.repeat():
                with attempt as db:
                    crs = db.query(...)
                    # do something with crs

            Note that it's not reentrant (as is not underlying MySQL
            connection), so avoid nesting on the same MySQL object.
        """
        self.retry_attempt = self.retry_count
        while self.retry_attempt:
            if self.retry_attempt != self.retry_count:
                sleep(self.retry_pause)
            self.retry_attempt -= 1
            yield self

    def __enter__(self):
        """ Context manager protocol. Guarantees that transaction will
            get either commited or rolled back in case of database
            exception. Can be used with self.repeat(), or alone as:

            with self as db:
                crs = db.query(...)
                # do something with crs

            Note that it's not reentrant (as is not underlying MySQL
            connection), so avoid nesting on the same MySQL object.
        """
        if not self.retry_attempt:
            self.retry_attempt = 0
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """ Context manager protocol. If db exception is fired and
            self.retry_attempt is not zero, it is only logged and
            does not propagate, otherwise it propagates up. Also
            open transaction is rolled back.
            In case of no exception, transaction gets commited.
        """
        if not exc_type:
            self.con.commit()
            self.retry_attempt = 0
        else:
            try:
                if self.con:
                    self.con.rollback()
            except my.Error:
                pass
            try:
                self.close()
            except my.Error:
                pass
            if self.retry_attempt:
                self.log.info("Database error (%d attempts left): %s %s" % (self.retry_attempt, exc_type.__name__, exc_val))
                return True

    def query(self, *args, **kwargs):
        if not self.con:
            self.connect()
        crs = self.con.cursor()
        self.log.debug("execute: %s %s" % (args, kwargs))
        crs.execute(*args, **kwargs)
        return crs

    def _get_comma_perc(self, l):
        return ','.join(['%s'] * len(l))

    def _get_not(self, b):
        return "" if b else "NOT"

    def get_client_by_name(self, cert_names=None, name=None, secret=None):
        query = ["SELECT * FROM clients WHERE valid = 1"]
        params = []
        if name:
            query.append(" AND name = %s")
            params.append(name.lower())
        if secret:
            query.append(" AND secret = %s")
            params.append(secret)
        if cert_names:
            query.append(" AND hostname IN (%s)" % self._get_comma_perc(cert_names))
            params.extend(n.lower() for n in cert_names)

        for attempt in self.repeat():
            with attempt as db:
                rows = db.query("".join(query), params).fetchall()
                if len(rows) > 1:
                    self.log.warn(
                        "get_client_by_name: query returned more than one result (cert_names = %s, name = %s, secret = %s): %s" % (
                            cert_names, name, secret, ", ".join([str(Client(**row)) for row in rows])))
                    return None

                return Client(**rows[0]) if rows else None

    def get_clients(self, id=None):
        query = ["SELECT * FROM clients"]
        params = []
        if id:
            query.append("WHERE id = %s")
            params.append(id)
        query.append("ORDER BY id")
        for attempt in self.repeat():
            with attempt as db:
                rows = db.query(" ".join(query), params).fetchall()
                return [Client(**row) for row in rows]

    def add_modify_client(self, id=None, **kwargs):
        query = []
        params = []
        uquery = []
        if id is None:
            query.append("INSERT INTO clients SET")
            uquery.append("registered = now()")
        else:
            query.append("UPDATE clients SET")
        for attr in set(Client._fields) - set(["id", "registered"]):
            val = kwargs.get(attr, None)
            if val is not None:
                if attr == "secret" and val == "":  # disable secret
                    val = None
                uquery.append("`%s` = %%s" % attr)
                params.append(val)
        if not uquery:
            return id
        query.append(", ".join(uquery))
        if id is not None:
            query.append("WHERE id = %s")
            params.append(id)
        for attempt in self.repeat():
            with attempt as db:
                crs = db.query(" ".join(query), params)
                newid = crs.lastrowid if id is None else id
                return newid

    def get_debug(self):
        for attempt in self.repeat():
            with attempt as db:
                rows = db.query("SELECT VERSION() AS VER").fetchall()
                tablestat = db.query("SHOW TABLE STATUS").fetchall()
                return {
                    "db": "MySQL",
                    "version": rows[0]["VER"],
                    "tables": tablestat
                }

    def getMaps(self, section, variables):
        maps = []
        for v in variables:
            try:
                mapped = section[v]
            except KeyError:
                raise self.req.error(
                    message="Wrong tag or category used in query.",
                    error=422, exc=sys.exc_info(), key=v)
            maps.append(mapped)
        return set(maps)    # unique

    def fetch_events(
            self, client, id, count,
            cat=None, nocat=None,
            tag=None, notag=None,
            group=None, nogroup=None):

        if cat and nocat:
            raise self.req.error(
                message="Unrealizable conditions. Choose cat or nocat option.",
                error=422, cat=cat, nocat=nocat)
        if tag and notag:
            raise self.req.error(
                message="Unrealizable conditions. Choose tag or notag option.",
                error=422, tag=tag, notag=notag)
        if group and nogroup:
            raise self.req.error(
                message="Unrealizable conditions. Choose group or nogroup option.",
                error=422, group=group, nogroup=nogroup)

        query = ["SELECT e.id, e.data FROM clients c RIGHT JOIN events e ON c.id = e.client_id WHERE e.id > %s"]
        params = [id or 0]

        if cat or nocat:
            cats = self.getMaps(self.catmap, (cat or nocat))
            query.append(
                " AND e.id %s IN (SELECT event_id FROM event_category_mapping WHERE category_id IN (%s))" % (
                    self._get_not(cat), self._get_comma_perc(cats)))
            params.extend(cats)

        if tag or notag:
            tags = self.getMaps(self.tagmap, (tag or notag))
            query.append(
                " AND e.id %s IN (SELECT event_id FROM event_tag_mapping WHERE tag_id IN (%s))" % (
                    self._get_not(tag), self._get_comma_perc(tags)))
            params.extend(tags)

        if group or nogroup:
            subquery = []
            for name in (group or nogroup):
                subquery.append("c.name = %s")      # exact client
                params.append(name)
                subquery.append("c.name LIKE %s")   # whole subtree
                params.append(name + ".%")

            query.append(" AND %s (%s)" % (self._get_not(group), " OR ".join(subquery)))

        query.append(" AND e.valid = 1 LIMIT %s")
        params.append(count)

        query_string = "".join(query)

        row = None
        for attempt in self.repeat():
            with attempt as db:
                row = db.query(query_string, params).fetchall()

        if row:
            maxid = max(r['id'] for r in row)
        else:
            maxid = self.getLastEventId()

        events = []
        for r in row:
            try:
                e = json.loads(r["data"])
            except Exception:
                # Note that we use Error object just for proper formatting,
                # but do not raise it; from client perspective invalid
                # events get skipped silently.
                err = self.req.error(
                    message="Unable to deserialize JSON event from db, id=%s" % r["id"],
                    error=500, exc=sys.exc_info(), id=r["id"])
                err.log(self.log, prio=logging.WARNING)
            events.append(e)

        return {
            "lastid": maxid,
            "events": events
        }

    def store_events(self, client, events, events_raw):
        try:
            for attempt in self.repeat():
                with attempt as db:
                    for event, raw_event in zip(events, events_raw):
                        lastid = db.query(
                            "INSERT INTO events (received,client_id,data) VALUES (NOW(), %s, %s)",
                            (client.id, raw_event)).lastrowid

                        catlist = event.get('Category', ["Other"])
                        cats = set(catlist) | set(cat.split(".", 1)[0] for cat in catlist)
                        for cat in cats:
                            cat_id = self.catmap.get(cat, self.catmap_other)
                            db.query("INSERT INTO event_category_mapping (event_id,category_id) VALUES (%s, %s)", (lastid, cat_id))

                        nodes = event.get('Node', [])
                        tags = []
                        for node in nodes:
                            tags.extend(node.get('Type', []))
                        for tag in set(tags):
                            tag_id = self.tagmap.get(tag, self.tagmap_other)
                            db.query("INSERT INTO event_tag_mapping (event_id,tag_id) VALUES (%s, %s)", (lastid, tag_id))
                    return []
        except Exception as e:
            exception = self.req.error(message="DB error", error=500, exc=sys.exc_info(), env=self.req.env)
            exception.log(self.log)
            return [{"error": 500, "message": "DB error %s" % type(e).__name__}]

    def insertLastReceivedId(self, client, id):
        self.log.debug("insertLastReceivedId: id %i for client %i(%s)" % (id, client.id, client.hostname))
        for attempt in self.repeat():
            with attempt as db:
                db.query("INSERT INTO last_events(client_id, event_id, timestamp) VALUES(%s, %s, NOW())", (client.id, id))

    def getLastEventId(self):
        for attempt in self.repeat():
            with attempt as db:
                row = db.query("SELECT MAX(id) as id FROM events").fetchall()[0]
                return row['id'] or 1

    def getLastReceivedId(self, client):
        for attempt in self.repeat():
            with attempt as db:
                res = db.query(
                    "SELECT event_id as id FROM last_events WHERE client_id = %s ORDER BY last_events.id DESC LIMIT 1",
                    (client.id,)).fetchall()
                try:
                    row = res[0]
                except IndexError:
                    id = None
                    self.log.debug("getLastReceivedId: probably first access, unable to get id for client %i(%s)" % (
                        client.id, client.hostname))
                else:
                    id = row["id"]
                    self.log.debug("getLastReceivedId: id %i for client %i(%s)" % (id, client.id, client.hostname))

                return id

    def load_maps(self):
        with self as db:
            db.query("DELETE FROM tags")
            for tag, num in self.tagmap.iteritems():
                db.query("INSERT INTO tags(id, tag) VALUES (%s, %s)", (num, tag))
            db.query("DELETE FROM categories")
            for cat_subcat, num in self.catmap.iteritems():
                catsplit = cat_subcat.split(".", 1)
                category = catsplit[0]
                subcategory = catsplit[1] if len(catsplit) > 1 else None
                db.query(
                    "INSERT INTO categories(id, category, subcategory, cat_subcat) VALUES (%s, %s, %s, %s)",
                    (num, category, subcategory, cat_subcat))

    def purge_lastlog(self, days):
        with self as db:
            return db.query(
                "DELETE FROM last_events "
                " USING last_events LEFT JOIN ("
                "    SELECT MAX(id) AS last FROM last_events"
                "    GROUP BY client_id"
                " ) AS maxids ON last=id"
                " WHERE timestamp < DATE_SUB(CURDATE(), INTERVAL %s DAY) AND last IS NULL",
                (days,)).rowcount

    def purge_events(self, days):
        with self as db:
            affected = 0
            id_ = db.query(
                "SELECT MAX(id) as id"
                "  FROM events"
                "  WHERE received < DATE_SUB(CURDATE(), INTERVAL %s DAY)",
                (days,)
            ).fetchall()[0]["id"]
            if id_ is None:
                return 0
            affected = db.query("DELETE FROM events WHERE id <= %s", (id_,)).rowcount
            db.query("DELETE FROM event_category_mapping WHERE event_id <= %s", (id_,))
            db.query("DELETE FROM event_tag_mapping WHERE event_id <= %s", (id_,))
            return affected


def expose(read=1, write=0, debug=0):

    def expose_deco(meth):
        meth.exposed = True
        meth.read = read
        meth.write = write
        meth.debug = debug
        if not hasattr(meth, "arguments"):
            meth.arguments = meth.func_code.co_varnames[:meth.func_code.co_argcount]
        return meth

    return expose_deco


class Server(ObjectBase):

    def __init__(self, req, log, auth, handler):
        ObjectBase.__init__(self, req, log)
        self.auth = auth
        self.handler = handler

    def sanitize_args(self, path, func, args, exclude=["self", "post"]):
        # silently remove internal args, these should never be used
        # but if somebody does, we do not expose them by error message
        intargs = set(args).intersection(exclude)
        for a in intargs:
            del args[a]
        if intargs:
            self.log.info("sanitize_args: Called with internal args: %s" % ", ".join(intargs))

        # silently remove surplus arguments - potential forward
        # compatibility (unknown args will get ignored)
        badargs = set(args) - set(func.arguments)
        for a in badargs:
            del args[a]
        if badargs:
            self.log.info("sanitize_args: Called with superfluous args: %s" % ", ".join(badargs))

        return args

    def wsgi_app(self, environ, start_response, exc_info=None):
        path = environ.get("PATH_INFO", "").lstrip("/")
        self.req.reset(env=environ, path=path)
        output = ""
        status = "200 OK"
        headers = [('Content-type', 'application/json')]
        exception = None

        try:
            try:
                method = getattr(self.handler, path)
                method.exposed    # dummy access to trigger AttributeError
            except Exception:
                raise self.req.error(message="You've fallen off the cliff.", error=404)

            self.req.args = args = parse_qs(environ.get('QUERY_STRING', ""))

            self.req.client = client = self.auth.authenticate(environ, args)
            if not client:
                raise self.req.error(message="I'm watching. Authenticate.", error=403)

            auth = self.auth.authorize(self.req.env, self.req.client, self.req.path, method)
            if not auth:
                raise self.req.error(message="I'm watching. Not authorized.", error=403, client=client.name)

            args = self.sanitize_args(path, method, args)

            try:
                post_data = environ['wsgi.input'].read()
            except:
                raise self.req.error(message="Data read error.", error=408, exc=sys.exc_info())

            headers, output = method(post_data, **args)

        except Error as e:
            exception = e
        except Exception as e:
            exception = self.req.error(message="Server exception", error=500, exc=sys.exc_info())

        if exception:
            status = "%d %s" % exception.get_http_err_msg()
            output = json.dumps(exception.to_dict(), default=lambda v: str(v))
            exception.log(self.log)

        # Make sure everything is properly encoded - JSON and various function
        # may spit out unicode instead of str and it gets propagated up (str
        # + unicode = unicode). However, the right thing would be to be unicode
        # correct among whole source and always decode on input (json module
        # does that for us) and on output here.
        if isinstance(status, unicode):
            status = status.encode("utf-8")
        if isinstance(output, unicode):
            output = output.encode("utf-8")
        headers.append(('Content-Length', str(len(output))))
        start_response(status, headers)
        self.req.reset()
        return [output]

    __call__ = wsgi_app


def json_wrapper(method):

    def meth_deco(self, post, **args):
        if "events" in method.func_code.co_varnames[0:method.func_code.co_argcount]:
            try:
                events = json.loads(post) if post else None
            except Exception as e:
                raise self.req.error(
                    message="Deserialization error.", error=400,
                    exc=sys.exc_info(), args=post, parser=str(e))
            if events:
                args["events"] = events

        result = method(self, **args)   # call requested method

        try:
            # 'default': takes care of non JSON serializable objects,
            # which could (although shouldn't) appear in handler code
            output = json.dumps(result, default=lambda v: str(v))
        except Exception as e:
            raise self.req.error(message="Serialization error", error=500, exc=sys.exc_info(), args=str(result))

        return [('Content-type', 'application/json')], output

    try:
        meth_deco.arguments = method.arguments
    except AttributeError:
        meth_deco.arguments = method.func_code.co_varnames[:method.func_code.co_argcount]
    return meth_deco


class WardenHandler(ObjectBase):

    def __init__(
            self, req, log, validator, db, auth,
            send_events_limit=500, get_events_limit=1000,
            description=None):

        ObjectBase.__init__(self, req, log)
        self.auth = auth
        self.db = db
        self.validator = validator
        self.send_events_limit = send_events_limit
        self.get_events_limit = get_events_limit
        self.description = description

    @expose(read=1, debug=1)
    @json_wrapper
    def getDebug(self):
        return {
            "environment": self.req.env,
            "client": self.req.client.__dict__,
            "database": self.db.get_debug(),
            "system": {
                "uname": os.uname()
            },
            "process": {
                "cwd": os.getcwdu(),
                "pid": os.getpid(),
                "ppid": os.getppid(),
                "pgrp": os.getpgrp(),
                "uid": os.getuid(),
                "gid": os.getgid(),
                "euid": os.geteuid(),
                "egid": os.getegid(),
                "groups": os.getgroups()
            }
        }

    @expose(read=1)
    @json_wrapper
    def getInfo(self):
        info = {
            "version": VERSION,
            "send_events_limit": self.send_events_limit,
            "get_events_limit": self.get_events_limit
        }
        if self.description:
            info["description"] = self.description
        return info

    @expose(read=1)
    @json_wrapper
    def getEvents(
            self, id=None, count=None,
            cat=None, nocat=None,
            tag=None, notag=None,
            group=None, nogroup=None):

        try:
            id = int(id[0])
        except (ValueError, TypeError, IndexError):
            id = None

        if id is None:
            # If client was already here, fetch server notion of his last id
            try:
                id = self.db.getLastReceivedId(self.req.client)
            except Exception as e:
                self.log.info("cannot getLastReceivedId - " + type(e).__name__ + ": " + str(e))

        if id is None:
            # First access, remember the guy and get him last id
            id = self.db.getLastEventId()
            self.db.insertLastReceivedId(self.req.client, id)
            return {
                "lastid": id,
                "events": []
            }

        if id <= 0:
            # Client wants to get only last N events and reset server notion of last id
            id += self.db.getLastEventId()
            if id < 0: id = 0

        try:
            count = int(count[0])
        except (ValueError, TypeError, IndexError):
            count = self.get_events_limit

        if self.get_events_limit:
            count = min(count, self.get_events_limit)

        res = self.db.fetch_events(self.req.client, id, count, cat, nocat, tag, notag, group, nogroup)

        self.db.insertLastReceivedId(self.req.client, res['lastid'])

        self.log.info("sending %d events, lastid is %i" % (len(res["events"]), res["lastid"]))

        return res

    def check_node(self, event, name):
        try:
            ev_id = event['Node'][0]['Name'].lower()
        except (KeyError, TypeError, IndexError):
            # Event does not bear valid Node attribute
            return [{"error": 422, "message": "Event does not bear valid Node attribute"}]
        if ev_id != name:
            return [{"error": 422, "message": "Node does not correspond with saving client"}]
        return []

    def add_event_nums(self, ilist, events, errlist):
        for err in errlist:
            err.setdefault("events", []).extend(ilist)
            ev_ids = err.setdefault("events_id", [])
            for i in ilist:
                event = events[i]
                try:
                    id = event["ID"]
                except (KeyError, TypeError, ValueError):
                    id = None
                ev_ids.append(id)
        return errlist

    @expose(write=1)
    @json_wrapper
    def sendEvents(self, events=[]):
        if not isinstance(events, list):
            raise self.req.error(message="List of events expected.", error=400)

        errs = []
        if len(events) > self.send_events_limit:
            errs.extend(self.add_event_nums(range(self.send_events_limit, len(events)), events, [
                {"error": 507, "message": "Too much events in one batch.", "send_events_limit": self.send_events_limit}]))

        saved = 0
        events_tosend = []
        events_raw = []
        events_nums = []
        for i, event in enumerate(events[0:self.send_events_limit]):
            v_errs = self.validator.check(event)
            if v_errs:
                errs.extend(self.add_event_nums([i], events, v_errs))
                continue

            node_errs = self.check_node(event, self.req.client.name)
            if node_errs:
                errs.extend(self.add_event_nums([i], events, node_errs))
                continue

            if self.req.client.test and 'Test' not in event.get('Category', []):
                errs.extend(
                    self.add_event_nums([i], events, [{
                        "error": 422,
                        "message": "You're allowed to send only messages, containing \"Test\" among categories.",
                        "categories": event.get('Category', [])}]))
                continue

            raw_event = json.dumps(event)
            if len(raw_event) >= self.db.event_size_limit:
                errs.extend(
                    self.add_event_nums([i], events, [
                        {"error": 413, "message": "Event too long (>%i B)" % self.db.event_size_limit}
                    ]))
                continue

            events_tosend.append(event)
            events_raw.append(raw_event)
            events_nums.append(i)

        db_errs = self.db.store_events(self.req.client, events_tosend, events_raw)
        if db_errs:
            errs.extend(self.add_event_nums(events_nums, events_tosend, db_errs))
            saved = 0
        else:
            saved = len(events_tosend)

        self.log.info("Saved %i events" % saved)
        if errs:
            raise self.req.error(errors=errs)

        return {"saved": saved}


def read_ini(path):
    c = ConfigParser.RawConfigParser()
    res = c.read(path)
    if not res or path not in res:
        # We don't have loggin yet, hopefully this will go into webserver log
        raise Error(message="Unable to read config: %s" % path)
    data = {}
    for sect in c.sections():
        for opts in c.options(sect):
            lsect = sect.lower()
            if lsect not in data:
                data[lsect] = {}
            data[lsect][opts] = c.get(sect, opts)
    return data


def read_cfg(path):
    with open(path, "r") as f:
        stripcomments = "\n".join((l for l in f if not l.lstrip().startswith(("#", "//"))))
        conf = json.loads(stripcomments)

    # Lowercase keys
    conf = dict((
        sect.lower(), dict(
            (subkey.lower(), val) for subkey, val in subsect.iteritems())
    ) for sect, subsect in conf.iteritems())

    return conf


def fallback_wsgi(environ, start_response, exc_info=None):

    # If server does not start, set up simple server, returning
    # Warden JSON compliant error message
    error = 503
    message = "Server not running due to initialization error"
    headers = [('Content-type', 'application/json')]

    logline = "Error(%d): %s" % (error, message)
    status = "%d %s" % (error, message)
    output = '{"errors": [{"error": %d, "message": "%s"}]}' % (
        error, message)

    logging.getLogger(__name__).critical(logline)
    start_response(status, headers)
    return [output]


# Order in which the base objects must get initialized
section_order = ("log", "db", "auth", "validator", "handler", "server")

# List of sections and objects, configured by them
# First object in each object list is the default one, otherwise
# "type" keyword in section may be used to choose other
section_def = {
    "log": [FileLogger, SysLogger],
    "db": [MySQL],
    "auth": [X509Authenticator, PlainAuthenticator, X509NameAuthenticator, X509MixMatchAuthenticator],
    "validator": [JSONSchemaValidator, NoValidator],
    "handler": [WardenHandler],
    "server": [Server]
}

# Object parameter conversions and defaults
param_def = {
    FileLogger: {
        "req": {"type": "obj", "default": "req"},
        "filename": {"type": "filepath", "default": path.join(path.dirname(__file__), path.splitext(path.split(__file__)[1])[0] + ".log")},
        "level": {"type": "loglevel", "default": "info"},
    },
    SysLogger: {
        "req": {"type": "obj", "default": "req"},
        "socket": {"type": "filepath", "default": "/dev/log"},
        "facility": {"type": "facility", "default": "daemon"},
        "level": {"type": "loglevel", "default": "info"}
    },
    PlainAuthenticator: {
        "req": {"type": "obj", "default": "req"},
        "log": {"type": "obj", "default": "log"},
        "db": {"type": "obj", "default": "db"}
    },
    X509Authenticator: {
        "req": {"type": "obj", "default": "req"},
        "log": {"type": "obj", "default": "log"},
        "db": {"type": "obj", "default": "db"}
    },
    X509NameAuthenticator: {
        "req": {"type": "obj", "default": "req"},
        "log": {"type": "obj", "default": "log"},
        "db": {"type": "obj", "default": "db"}
    },
    X509MixMatchAuthenticator: {
        "req": {"type": "obj", "default": "req"},
        "log": {"type": "obj", "default": "log"},
        "db": {"type": "obj", "default": "db"}
    },
    NoValidator: {
        "req": {"type": "obj", "default": "req"},
        "log": {"type": "obj", "default": "log"},
    },
    JSONSchemaValidator: {
        "req": {"type": "obj", "default": "req"},
        "log": {"type": "obj", "default": "log"},
        "filename": {"type": "filepath", "default": path.join(path.dirname(__file__), "idea.schema")}
    },
    MySQL: {
        "req": {"type": "obj", "default": "req"},
        "log": {"type": "obj", "default": "log"},
        "host": {"type": "str", "default": "localhost"},
        "user": {"type": "str", "default": "warden"},
        "password": {"type": "str", "default": ""},
        "dbname": {"type": "str", "default": "warden3"},
        "port": {"type": "natural", "default": 3306},
        "retry_pause": {"type": "natural", "default": 3},
        "retry_count": {"type": "natural", "default": 3},
        "event_size_limit": {"type": "natural", "default": 5*1024*1024},
        "catmap_filename": {"type": "filepath", "default": path.join(path.dirname(__file__), "catmap_mysql.json")},
        "tagmap_filename": {"type": "filepath", "default": path.join(path.dirname(__file__), "tagmap_mysql.json")}
    },
    WardenHandler: {
        "req": {"type": "obj", "default": "req"},
        "log": {"type": "obj", "default": "log"},
        "validator": {"type": "obj", "default": "validator"},
        "db": {"type": "obj", "default": "DB"},
        "auth": {"type": "obj", "default": "auth"},
        "send_events_limit": {"type": "natural", "default": 500},
        "get_events_limit": {"type": "natural", "default": 1000},
        "description": {"type": "str", "default": ""}
    },
    Server: {
        "req": {"type": "obj", "default": "req"},
        "log": {"type": "obj", "default": "log"},
        "auth": {"type": "obj", "default": "auth"},
        "handler": {"type": "obj", "default": "handler"}
    }
}


def build_server(conf, section_order=section_order, section_def=section_def, param_def=param_def):

    objects = {}    # Already initialized objects

    # Functions for validation and conversion of config values
    def facility(name):
        return int(getattr(logging.handlers.SysLogHandler, "LOG_" + name.upper()))

    def loglevel(name):
        return int(getattr(logging, name.upper()))

    def natural(name):
        num = int(name)
        if num < 1:
            raise ValueError("Not a natural number")
        return num

    def filepath(name):
        # Make paths relative to dir of this script
        return path.join(path.dirname(__file__), name)

    def obj(name):
        return objects[name.lower()]

    # Typedef dictionary
    conv_dict = {
        "facility": facility,
        "loglevel": loglevel,
        "natural": natural,
        "filepath": filepath,
        "obj": obj,
        "str": str
    }

    def init_obj(sect_name):
        config = conf.get(sect_name, {})
        sect_name = sect_name.lower()
        sect_def = section_def[sect_name]

        try:    # Object type defined?
            objtype = config["type"]
            del config["type"]
        except KeyError:    # No, fetch default object type for this section
            cls = sect_def[0]
        else:  # Yes, get corresponding class/callable
            names = [o.__name__ for o in sect_def]
            try:
                idx = names.index(objtype)
            except ValueError:
                raise KeyError("Unknown type %s in section %s" % (objtype, sect_name))
            cls = sect_def[idx]

        params = param_def[cls]

        # No surplus parameters? Disallow also 'obj' attributes, these are only
        # to provide default referenced section
        for name in config:
            if name not in params or (name in params and params[name]["type"] == "obj"):
                raise KeyError("Unknown key %s in section %s" % (name, sect_name))

        # Process parameters
        kwargs = {}
        for name, definition in params.iteritems():
            raw_val = config.get(name, definition["default"])
            try:
                type_callable = conv_dict[definition["type"]]
                val = type_callable(raw_val)
            except Exception:
                raise KeyError("Bad value \"%s\" for %s in section %s" % (raw_val, name, sect_name))
            kwargs[name] = val

        try:
            obj_inst = cls(**kwargs)         # run it
        except Exception as e:
            raise KeyError("Cannot initialize %s from section %s: %s" % (
                cls.__name__, sect_name, str(e)))

        objects[sect_name] = obj_inst
        if isinstance(obj_inst, Object):
            # Log only objects here, functions must take care of themselves
            objects["log"].info("Initialized %s" % str(obj_inst))

        return obj_inst

    # Init logging with at least simple stderr StreamLogger
    # Dunno if it's ok within wsgi, but we have no other choice, let's
    # hope it at least ends up in webserver error log
    objects["log"] = StreamLogger()

    # Shared container for common data of ongoing WSGI request
    objects["req"] = Request()

    try:
        # Now try to init required objects
        for o in section_order:
            init_obj(o)
    except Exception as e:
        objects["log"].critical(str(e))
        objects["log"].debug("", exc_info=sys.exc_info())
        return fallback_wsgi

    objects["log"].info("Server ready")

    return objects["server"]


# Command line utilities

def check_config():
    # If we got so far, server object got set up fine
    print("Looks clear.", file=sys.stderr)
    return 0


def list_clients(id=None):
    clients = server.handler.db.get_clients(id)
    lines = [[str(getattr(client, col)) for col in Client._fields] for client in clients]
    col_width = [max(len(val) for val in col) for col in zip(*(lines+[Client._fields]))]
    divider = ["-" * l for l in col_width]
    for line in [Client._fields, divider] + lines:
        print(" ".join([val.ljust(width) for val, width in zip(line, col_width)]))
    return 0


def register_client(**kwargs):
    # argparse does _always_ return something, so we cannot rely on missing arguments
    if kwargs["valid"] is None: kwargs["valid"] = 1
    if kwargs["read"] is None: kwargs["read"] = 1
    if kwargs["write"] is None: kwargs["write"] = 0
    if kwargs["debug"] is None: kwargs["debug"] = 0
    if kwargs["test"] is None: kwargs["test"] = 1
    return modify_client(id=None, **kwargs)


def modify_client(**kwargs):

    def isValidHostname(hostname):
        if len(hostname) > 255:
            return False
        if hostname.endswith("."):  # A single trailing dot is legal
            hostname = hostname[:-1]  # strip exactly one dot from the right, if present
        disallowed = re.compile(r"[^A-Z\d-]", re.IGNORECASE)
        return all(  # Split by labels and verify individually
            (label and len(label) <= 63  # length is within proper range
             and not label.startswith("-") and not label.endswith("-")  # no bordering hyphens
             and not disallowed.search(label))  # contains only legal characters
            for label in hostname.split("."))

    def isValidNSID(nsid):
        allowed = re.compile(r"^(?:[a-zA-Z_][a-zA-Z0-9_]*\.)*[a-zA-Z_][a-zA-Z0-9_]*$")
        return allowed.match(nsid)

    def isValidEmail(mail):
        mails = (email.utils.parseaddr(m) for m in mail.split(","))
        allowed = re.compile(r"^[a-zA-Z0-9_.%!+-]+@[a-zA-Z0-9-.]+$")  # just basic check
        valid = (allowed.match(ms[1]) for ms in mails)
        return all(valid)

    def isValidID(id):
        client = server.handler.db.get_clients(id)
        return client and True or False

    if kwargs["name"] is not None:
        kwargs["name"] = kwargs["name"].lower()
        if not isValidNSID(kwargs["name"]):
            print("Invalid client name \"%s\"." % kwargs["name"], file=sys.stderr)
            return 254

    if kwargs["hostname"] is not None:
        kwargs["hostname"] = kwargs["hostname"].lower()
        if not isValidHostname(kwargs["hostname"]):
            print("Invalid hostname \"%s\"." % kwargs["hostname"], file=sys.stderr)
            return 253

    if kwargs["requestor"] is not None and not isValidEmail(kwargs["requestor"]):
        print("Invalid requestor email \"%s\"." % kwargs["requestor"], file=sys.stderr)
        return 252

    if kwargs["id"] is not None and not isValidID(kwargs["id"]):
        print("Invalid id \"%s\"." % kwargs["id"], file=sys.stderr)
        return 251

    for c in server.handler.db.get_clients():
        if kwargs["name"] is not None and kwargs["name"].lower() == c.name:
            print("Clash with existing name: %s" % str(c), file=sys.stderr)
            return 250
        if kwargs["secret"] is not None and kwargs["secret"] == c.secret:
            print("Clash with existing secret: %s" % str(c), file=sys.stderr)
            return 249

    newid = server.handler.db.add_modify_client(**kwargs)

    return list_clients(id=newid)


def load_maps():
    server.handler.db.load_maps()
    return 0


def purge(days=30, lastlog=None, events=None):
    if lastlog is None and events is None:
        lastlog = events = True
    if lastlog:
        count = server.handler.db.purge_lastlog(days)
        print("Purged %d lastlog entries." % count)
    if events:
        count = server.handler.db.purge_events(days)
        print("Purged %d events." % count)
    return 0


def add_client_args(subargp, mod=False):
    subargp.add_argument("--help", action="help", help="show this help message and exit")
    if mod:
        subargp.add_argument(
            "-i", "--id", required=True, type=int,
            help="client id")
    subargp.add_argument(
        "-n", "--name", required=not mod,
        help="client name (in dotted reverse path notation)")
    subargp.add_argument(
        "-h", "--hostname", required=not mod,
        help="client FQDN hostname")
    subargp.add_argument(
        "-r", "--requestor", required=not mod,
        help="requestor email")
    subargp.add_argument(
        "-s", "--secret",
        help="authentication token (use explicit empty string to disable)")
    subargp.add_argument(
        "--note",
        help="client freetext description")

    reg_valid = subargp.add_mutually_exclusive_group(required=False)
    reg_valid.add_argument(
        "--valid", action="store_const", const=1, default=None,
        help="valid client (default)")
    reg_valid.add_argument("--novalid", action="store_const", const=0, dest="valid", default=None)

    reg_read = subargp.add_mutually_exclusive_group(required=False)
    reg_read.add_argument(
        "--read", action="store_const", const=1, default=None,
        help="client is allowed to read (default)")
    reg_read.add_argument("--noread", action="store_const", const=0, dest="read", default=None)

    reg_write = subargp.add_mutually_exclusive_group(required=False)
    reg_write.add_argument(
        "--nowrite", action="store_const", const=0, dest="write", default=None,
        help="client is allowed to send (default - no)")
    reg_write.add_argument("--write", action="store_const", const=1, default=None)

    reg_debug = subargp.add_mutually_exclusive_group(required=False)
    reg_debug.add_argument(
        "--nodebug", action="store_const", const=0, dest="debug", default=None,
        help="client is allowed receive debug output (default - no)")
    reg_debug.add_argument("--debug", action="store_const", const=1, default=None)

    reg_test = subargp.add_mutually_exclusive_group(required=False)
    reg_test.add_argument(
        "--test", action="store_const", const=1, default=None,
        help="client is yet in testing phase (default - yes)")
    reg_test.add_argument("--notest", action="store_const", const=0, dest="test", default=None)


def get_args():
    import argparse
    argp = argparse.ArgumentParser(
        description="Warden server " + VERSION, add_help=False)
    argp.add_argument(
        "--help", action="help",
        help="show this help message and exit")
    argp.add_argument(
        "-c", "--config",
        help="path to configuration file")
    subargp = argp.add_subparsers(title="commands")

    subargp_check = subargp.add_parser(
        "check", add_help=False,
        description="Try to setup server based on configuration file.",
        help="check configuration")
    subargp_check.set_defaults(command=check_config)
    subargp_check.add_argument(
        "--help", action="help",
        help="show this help message and exit")

    subargp_reg = subargp.add_parser(
        "register", add_help=False,
        description="Add new client registration entry.",
        help="register new client")
    subargp_reg.set_defaults(command=register_client)
    add_client_args(subargp_reg)

    subargp_mod = subargp.add_parser(
        "modify", add_help=False,
        description="Modify details of client registration entry.",
        help="modify client registration")
    subargp_mod.set_defaults(command=modify_client)
    add_client_args(subargp_mod, mod=True)

    subargp_list = subargp.add_parser(
        "list", add_help=False,
        description="List details of client registration entries.",
        help="list registered clients")
    subargp_list.set_defaults(command=list_clients)
    subargp_list.add_argument(
        "--help", action="help",
        help="show this help message and exit")
    subargp_list.add_argument(
        "--id", action="store", type=int,
        help="client id", default=None)

    subargp_purge = subargp.add_parser(
        "purge", add_help=False,
        description=(
            "Purge old events or lastlog records."
            " Note that lastlog purge retains at least one newest record for each"
            " client, even if it is more than number of 'days' old."),
        help="purge old events or lastlog records")
    subargp_purge.set_defaults(command=purge)
    subargp_purge.add_argument(
        "--help", action="help",
        help="show this help message and exit")
    subargp_purge.add_argument(
        "-l", "--lastlog", action="store_true", dest="lastlog", default=None,
        help="purge lastlog records")
    subargp_purge.add_argument(
        "-e", "--events", action="store_true", dest="events", default=None,
        help="purge events")
    subargp_purge.add_argument(
        "-d", "--days", action="store", dest="days", type=int, default=30,
        help="records older than 'days' back from today will get purged")

    subargp_loadmaps = subargp.add_parser(
        "loadmaps", add_help=False,
        description=(
            "Load 'categories' and 'tags' table from 'catmap_mysql.json' and 'tagmap_mysql.json'."
            " Note that this is NOT needed for server at all, load them into db at will,"
            " should you need to run your own specific SQL queries on data directly."
            " Note also that previous content of both tables will be lost."),
        help="load catmap and tagmap into db")
    subargp_loadmaps.set_defaults(command=load_maps)
    subargp_loadmaps.add_argument(
        "--help", action="help",
        help="show this help message and exit")

    return argp.parse_args()


if __name__ == "__main__":
    args = get_args()
    config = path.join(path.dirname(__file__), args.config or "warden_server.cfg")
    server = build_server(read_cfg(config))
    command = args.command
    subargs = vars(args)
    del subargs["command"]
    del subargs["config"]
    if not server or server is fallback_wsgi:
        print("Failed initialization, check configured log targets for reasons.", file=sys.stderr)
        sys.exit(255)
    sys.exit(command(**subargs))
