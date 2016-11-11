#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2015 Cesnet z.s.p.o
# Use of this source is governed by a 3-clause BSD-style license, see LICENSE file.

import sys
import os
import logging
import logging.handlers
import ConfigParser
from traceback import format_tb
import M2Crypto.X509
import json
import MySQLdb as my
import MySQLdb.cursors as mycursors
import re
import email.utils
from collections import namedtuple
from time import sleep
from urlparse import parse_qs
from os import path
from random import randint

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
            msg = self.errors[0]["message"]
        except (IndexError, KeyError):
            err = 500
            msg = "There's NO self-destruction button! Ah, you've just found it..."
        for e in self.errors:
            next_err = e.get("error", 500)
            if err != next_err:
                # errors not same, round to basic err code (400, 500)
                # and use the highest one
                err = max(err//100, next_err//100)*100
            next_msg = e.get("message", "Unknown error")
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
        if not "exc" in e or not e["exc"]:
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
    logger = logging.getLogger()  # no need to create new
    logger.setLevel(level)
    while logger.handlers:
        logger.removeHandler(logger.handlers[0])
    while logger.filters:
        logger.removeFilter(logger.filters[0])
    return logger



def StreamLogger(stream=sys.stderr, level=logging.INFO):
    """ Fallback handler just for setup, not meant to be used from
        configuration file because during wsgi query stdout/stderr
        is forbidden.
    """

    fhand = logging.StreamHandler(stream)
    fform = logging.Formatter('%(asctime)s %(filename)s[%(process)d]: (%(levelname)s) %(message)s')
    fhand.setFormatter(fform)
    logger = get_clean_root_logger(level)
    logger.addHandler(fhand)



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
    logging.info("Initialized FileLogger(req=%s, filename=\"%s\", level=\"%d\")" % (type(req).__name__, filename, level))



def SysLogger(req, socket="/dev/log", facility=logging.handlers.SysLogHandler.LOG_DAEMON, level=logging.INFO):

    fhand = logging.handlers.SysLogHandler(address=socket, facility=facility)
    fform = logging.Formatter('%(filename)s[%(process)d]: (%(levelname)s) %(message)s')
    fhand.setFormatter(fform)
    ffilt = LogRequestFilter(req)
    logger = get_clean_root_logger(level)
    logger.addFilter(ffilt)
    logger.addHandler(fhand)
    logging.info("Initialized SysLogger(req=%s, socket=\"%s\", facility=\"%d\", level=\"%d\")" % (type(req).__name__, socket, facility, level))



Client = namedtuple("Client",
    ["id", "registered", "requestor", "hostname", "name", "note",
    "valid", "secret", "read", "debug", "write", "test"])



class Object(object):

    def __str__(self):
        return "%s()" % type(self).__name__



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

    def __init__(self):
        Object.__init__(self)
        self.reset()


    def __str__(self):
        return "%s()" % (type(self).__name__, str(self.env), str(self.client))


    def reset(self, env=None, client=None, path=None, req_id=None):
        self.env = env
        self.client = client
        self.path = path or ""
        if req_id is not None:
            self.req_id = req_id
        else:
            self.req_id = 0 if env is None else randint(0x00000000, 0xFFFFFFFF)


    def error(self, **kwargs):
        return Error(self.path, self.req_id, **kwargs)



class ObjectReq(Object):

    def __init__(self, req):
        Object.__init__(self)
        self.req = req


    def __str__(self):
        return "%s(req=%s)" % (type(self).__name__, type(self.req).__name__)



class NoAuthenticator(ObjectReq):

    def __init__(self, req):
        ObjectReq.__init__(self, req)


    def authenticate (self, env, args):
        return "anybody"    # or None


    def authorize(self, env, client, path, method):
        return (client is not None)



class X509Authenticator(NoAuthenticator):

    def __init__(self, req, db):
        NoAuthenticator.__init__(self, req)
        self.db = db


    def __str__(self):
        return "%s(req=%s, db=%s)" % (type(self).__name__, type(self.req).__name__, type(self.db).__name__)


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


    def authenticate (self, env, args):
        try:
            cert_names = self.get_cert_dns_names(env["SSL_CLIENT_CERT"])
        except:
            exception = self.req.error(message="authenticate: cannot get or parse certificate from env", error=403, exc=sys.exc_info(), env=env)
            exception.log(logging.getLogger())
            return None

        name = args.get("client", [None])[0]
        secret =  args.get("secret", [None])[0]

        client = self.db.get_client_by_name(cert_names, name, secret)

        if not client:
            logging.info("authenticate: client not found by name: \"%s\", secret: %s, cert_names: %s" % (
                name, secret, str(cert_names)))
            return None
        
        # Clients with 'secret' set muset get authorized by it.
        # No secret turns auth off for this particular client.
        if client.secret is not None and secret is None:
            logging.info("authenticate: missing secret argument")
            return None

        logging.info("authenticate: %s" % str(client))

        return client


    def authorize(self, env, client, path, method):
        if method.debug:
            if not client.debug:
                logging.info("authorize: failed, client does not have debug enabled")
                return None
            return client

        if method.read:
            if not client.read:
                logging.info("authorize: failed, client does not have read enabled")
                return None
            return client

        if method.write:
            if not (client.write or client.test):
                logging.info("authorize: failed, client is not allowed to write or test")
                return None

        return client
        

class NoValidator(ObjectReq):

    def __init__(self, req):
        ObjectReq.__init__(self, req)


    def __str__(self):
        return "%s(req=%s)" % (type(self).__name__, type(self.req).__name__)


    def check(self, event):
        return []


class JSONSchemaValidator(NoValidator):

    def __init__(self, req, filename=None):
        NoValidator.__init__(self, req)
        self.path = filename or path.join(path.dirname(__file__), "idea.schema")
        with open(self.path) as f:
            self.schema = json.load(f)
        self.validator = Draft4Validator(self.schema)


    def __str__(self):
        return "%s(req=%s, filename=\"%s\")" % (type(self).__name__, type(self.req).__name__, self.path)


    def check(self, event):

        def sortkey(k):
            """ Treat keys as lowercase, prefer keys with less path segments """
            return (len(k.path), "/".join(str(k.path)).lower())

        res = []
        for error in sorted(self.validator.iter_errors(event), key=sortkey):
            res.append({"error": 460,
                "message": "Validation error: key \"%s\", value \"%s\", expected - %s" % (
                    "/".join(str(v) for v in error.path),
                    error.instance,
                    error.schema.get('description', 'no additional info'))})

        return res



class MySQL(ObjectReq):

    def __init__(self, req, host, user, password, dbname, port, retry_count,
            retry_pause, event_size_limit, catmap_filename, tagmap_filename):
        ObjectReq.__init__(self, req)
        self.host = host
        self.user = user
        self.password = password
        self.dbname = dbname
        self.port = port
        self.retry_count = retry_count
        self.retry_pause = retry_pause
        self.event_size_limit = event_size_limit
        self.catmap_filename = catmap_filename
        self.tagmap_filename = tagmap_filename

        with open(catmap_filename, "r") as catmap_fd:
            self.catmap = json.load(catmap_fd)
            self.catmap_other = self.catmap["Other"]    # Catch error soon, avoid lookup later

        with open(tagmap_filename, "r") as tagmap_fd:
            self.tagmap = json.load(tagmap_fd)
            self.tagmap_other = self.catmap["Other"]    # Catch error soon, avoid lookup later

        self.con = self.crs = None

        self.connect()


    def __str__(self):
        return "%s(req=%s, host='%s', user='%s', dbname='%s', port=%d, retry_count=%d, retry_pause=%d, catmap_filename=\"%s\", tagmap_filename=\"%s\")" % (
            type(self).__name__, type(self.req).__name__, self.host, self.user, self.dbname, self.port, self.retry_count, self.retry_pause, self.catmap_filename, self.tagmap_filename)


    def connect(self):
        self.con = my.connect(host=self.host, user=self.user, passwd=self.password,
            db=self.dbname, port=self.port, cursorclass=mycursors.DictCursor)
        self.crs = self.con.cursor()


    def close(self):
        try:
            if self.crs:
                self.crs.close()
            if self.con:
                self.con.close()
        except Exception:
            pass


    __del__ = close
    
    
    def log_transactions(self):
        self.crs.execute("SHOW ENGINE INNODB STATUS")
        res = self.crs.fetchall()
        self.con.commit()
        tolog = [l for l in res[0]["Status"].split("\n") if "thread id" in l]
        for l in tolog:
            logging.debug(l)


    def query(self, *args, **kwargs):
        """ Execute query on self.con, reconnecting if necessary """
        success = False
        countdown = self.retry_count
        res = None
        dml = kwargs.pop("dml", False)
        while not success:
            try:
                self.crs.execute(*args, **kwargs)
                if not dml:
                    res = self.crs.fetchall()
                    self.con.commit()
                success = True
            except my.OperationalError:
                if not countdown:
                    raise
                logging.info("execute: Database down, trying to reconnect (%d attempts left)..." % countdown)
                if countdown<self.retry_count:
                    sleep(self.retry_pause)    # no need to melt down server on longer outage
                self.close()
                self.connect()
                countdown -= 1
        return res

    def _get_comma_perc(self, l):
        return ','.join(['%s'] * len(l))


    def _get_not(self, b):
        return "" if b else "NOT"


    def get_client_by_name(self, cert_names, name=None, secret=None):
        query = ["SELECT id, registered, requestor, hostname, note, valid, name, secret, `read`, debug, `write`, test FROM clients WHERE valid = 1"]
        params = []
        if name:
            query.append(" AND name = %s")
            params.append(name.lower())
        if secret:
            query.append(" AND secret = %s")
            params.append(secret)
        query.append(" AND hostname IN (%s)" % self._get_comma_perc(cert_names))
        params.extend(n.lower() for n in cert_names)
        rows = self.query("".join(query), params)

        if len(rows)>1:
            logging.warn("get_client_by_name: query returned more than one result: %s" % ", ".join(
                [str(Client(**row)) for row in rows]))
            return None

        return Client(**rows[0]) if rows else None


    def get_clients(self, id=None):
        query = ["SELECT id, registered, requestor, hostname, note, valid, name, secret, `read`, debug, `write`, test FROM clients"]
        params = []
        if id:
            query.append("WHERE id = %s")
            params.append(id)
        query.append("ORDER BY id")
        rows = self.query(" ".join(query), params)
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
        for attr in ["name", "hostname", "requestor", "secret", "note",
                      "valid", "read", "write", "debug", "test"]:
            val = kwargs.get(attr, None)
            if val is not None:
                if attr in ["name", "hostname"]:
                    val = val.lower()
                uquery.append("`%s` = %%s" % attr)
                params.append(val)
        if not uquery:
            return id
        query.append(", ".join(uquery))
        if id is not None:
            query.append("WHERE id = %s")
            params.append(id)
        self.query(" ".join(query), params)
        return self.crs.lastrowid if id is None else id


    def get_debug(self):
        rows = self.query("SELECT VERSION() AS VER")
        tablestat = self.query("SHOW TABLE STATUS")
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
                raise self.req.error(message="Wrong tag or category used in query.", error=422,
                    exc=sys.exc_info(), key=v)
            maps.append(mapped)
        return set(maps)    # unique


    def fetch_events(self, client, id, count,
            cat=None, nocat=None,
            tag=None, notag=None,
            group=None, nogroup=None):
       
        logging.debug("fetch_events: id=%i, count=%i, cat=%s, nocat=%s, tag=%s, notag=%s, group=%s, nogroup=%s" % (id, count, str(cat), str(nocat), str(tag), str(notag), str(group), str(nogroup)))

        if cat and nocat:
            raise self.req.error(message="Unrealizable conditions. Choose cat or nocat option.", error=422,
                        cat=cat, nocat=nocat)
        if tag and notag:
            raise self.req.error(message="Unrealizable conditions. Choose tag or notag option.", error=422,
                        tag=tag, notag=notag)
        if group and nogroup:
            raise self.req.error(message="Unrealizable conditions. Choose group or nogroup option.", error=422,
                        group=group, nogroup=nogroup)

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
        logging.debug("fetch_events: query - %s" % query_string)
        logging.debug("fetch_events: params - %s", str(params))

        row = self.query(query_string, params)

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
                err = self.req.error(message="Unable to deserialize JSON event from db, id=%s" % r["id"], error=500,
                    exc=sys.exc_info(), id=r["id"])
                err.log(logging.getLogger(), prio=logging.WARNING)
            events.append(e)

        return {
            "lastid": maxid,
            "events": events
        }


    def store_event(self, client, event):
        json_event = json.dumps(event)
        if len(json_event) >= self.event_size_limit:
            return [{"error": 413, "message": "Event too long (>%i B)" % self.event_size_limit}]
        try:
            self.query("INSERT INTO events (received,client_id,data) VALUES (NOW(), %s, %s)",
                (client.id, json_event), dml=True)
            lastid = self.crs.lastrowid

            catlist = event.get('Category', ["Other"])
            cats = set(catlist) | set(cat.split(".", 1)[0] for cat in catlist)
            for cat in cats:
                cat_id = self.catmap.get(cat, self.catmap_other)
                self.query("INSERT INTO event_category_mapping (event_id,category_id) VALUES (%s, %s)", (lastid, cat_id), dml=True)
                
            nodes = event.get('Node', [])
            tags = []
            for node in nodes:
                tags.extend(node.get('Type', []))
            for tag in set(tags):
                tag_id = self.tagmap.get(tag, self.tagmap_other)
                self.query("INSERT INTO event_tag_mapping (event_id,tag_id) VALUES (%s, %s)", (lastid, tag_id), dml=True)

            self.con.commit()
            return []
        except Exception as e:
            self.con.rollback()
            return [{"error": 500, "message": type(e).__name__}]


    def insertLastReceivedId(self, client, id):
        logging.debug("insertLastReceivedId: id %i for client %i(%s)" % (id, client.id, client.hostname))
        try:
            self.query("INSERT INTO last_events(client_id, event_id, timestamp) VALUES(%s, %s, NOW())", (client.id, id), dml=True)
            self.con.commit()
        except Exception as e:
            self.con.rollback()
            raise


    def getLastEventId(self):
        row = self.query("SELECT MAX(id) as id FROM events")[0]

        return row['id'] or 0


    def getLastReceivedId(self, client):
        row = self.query("SELECT event_id as id FROM last_events WHERE client_id = %s ORDER BY last_events.id DESC LIMIT 1", [client.id])[0]

        id = row['id'] if row is not None else 0
        logging.debug("getLastReceivedId: id %i for client %i(%s)" % (id, client.id, client.hostname))

        return id


    def load_maps(self):
        try:
            self.query("DELETE FROM tags", dml=True)
            for tag, num in self.tagmap.iteritems():
                self.query("INSERT INTO tags(id, tag) VALUES (%s, %s)", (num, tag), dml=True)
            self.query("DELETE FROM categories", dml=True)
            for cat_subcat, num in self.catmap.iteritems():
                catsplit = cat_subcat.split(".", 1)
                category = catsplit[0]
                subcategory = catsplit[1] if len(catsplit)>1 else None
                self.query("INSERT INTO categories(id, category, subcategory, cat_subcat) VALUES (%s, %s, %s, %s)",
                    (num, category, subcategory, cat_subcat), dml=True)
            self.con.commit()
        except Exception as e:
            self.con.rollback()
            raise


    def purge_lastlog(self, days):
        try:
            self.query(
                "DELETE FROM last_events "
                " USING last_events LEFT JOIN ("
                "    SELECT MAX(id) AS last FROM last_events"
                "    GROUP BY client_id"
                " ) AS maxids ON last=id"
                " WHERE timestamp < DATE_SUB(CURDATE(), INTERVAL %s DAY) AND last IS NULL",
                days, dml=True)
            affected = self.con.affected_rows()
            self.con.commit()
        except Exception as e:
            self.con.rollback()
            raise
        return affected


    def purge_events(self, days):
        try:
            self.query(
                "DELETE FROM events WHERE received < DATE_SUB(CURDATE(), INTERVAL %s DAY)",
                days, dml=True)
            affected = self.con.affected_rows()
            self.con.commit()
        except Exception as e:
            self.con.rollback()
            raise
        return affected



def expose(read=1, write=0, debug=0):

    def expose_deco(meth):
        meth.exposed = True
        meth.read = read
        meth.write = write
        meth.debug = debug
        return meth

    return expose_deco


class Server(ObjectReq):

    def __init__(self, req, auth, handler):
        ObjectReq.__init__(self, req)
        self.auth = auth
        self.handler = handler


    def __str__(self):
        return "%s(req=%s, auth=%s, handler=%s)" % (type(self).__name__, type(self.req).__name__, type(self.auth).__name__, type(self.handler).__name__)


    def sanitize_args(self, path, func, args, exclude=["self"]):
        # silently remove internal args, these should never be used
        # but if somebody does, we do not expose them by error message
        intargs = set(args).intersection(exclude)
        for a in intargs:
            del args[a]
        if intargs:
            logging.info("sanitize_args: Called with internal args: %s" % ", ".join(intargs))

        # silently remove surplus arguments - potential forward
        # compatibility (unknown args will get ignored)
        badargs = set(args) - set(func.func_code.co_varnames[0:func.func_code.co_argcount])
        for a in badargs:
            del args[a]
        if badargs:
            logging.info("sanitize_args: Called with superfluous args: %s" % ", ".join(badargs))

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
                injson = environ['wsgi.input'].read()
            except:
                raise self.req.error(message="Data read error.", error=408, exc=sys.exc_info())

            try:
                method = getattr(self.handler, path)
                method.exposed    # dummy access to trigger AttributeError
            except Exception:
                raise self.req.error(message="You've fallen of the cliff.", error=404)

            self.req.args = args = parse_qs(environ.get('QUERY_STRING', ""))

            self.req.client = client = self.auth.authenticate(environ, args)
            if not client:
                raise self.req.error(message="I'm watching. Authenticate.", error=403)

            try:
                events = json.loads(injson) if injson else None
            except Exception as e:
                raise self.req.error(message="Deserialization error.", error=400,
                    exc=sys.exc_info(), args=injson, parser=str(e))
            if events:
                args["events"] = events

            auth = self.auth.authorize(self.req.env, self.req.client, self.req.path, method)
            if not auth:
                raise self.req.error(message="I'm watching. Not authorized.", error=403, client=client.name)

            # These args are not for handler
            args.pop("client", None)
            args.pop("secret", None)

            args = self.sanitize_args(path, method, args)
            result = method(**args)   # call requested method

            try:
                # 'default': takes care of non JSON serializable objects,
                # which could (although shouldn't) appear in handler code
                output = json.dumps(result, default=lambda v: str(v))
            except Exception as e:
                raise self.req.error(message="Serialization error", error=500,
                    exc=sys.exc_info(), args=str(result))

        except Error as e:
            exception = e
        except Exception as e:
            exception = self.req.error(message="Server exception", error=500, exc=sys.exc_info())

        if exception:
            status = "%d %s" % exception.get_http_err_msg()
            output = json.dumps(exception.to_dict(), default=lambda v: str(v))
            exception.log(logging.getLogger())

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



class WardenHandler(ObjectReq):

    def __init__(self, req, validator, db, auth,
            send_events_limit=500, get_events_limit=1000,
            description=None):

        ObjectReq.__init__(self, req)
        self.auth = auth
        self.db = db
        self.validator = validator
        self.send_events_limit = send_events_limit
        self.get_events_limit = get_events_limit
        self.description = description


    def __str__(self):
        return "%s(req=%s, validator=%s, db=%s, send_events_limit=%s, get_events_limit=%s, description=\"%s\")" % (
            type(self).__name__, type(self.req).__name__, type(self.validator).__name__, type(self.db).__name__,
            self.get_events_limit, self.send_events_limit, self.description)


    @expose(read=1, debug=1)
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
    def getEvents(self, id=None, count=None,
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
            except Exception, e:
                logging.info("cannot getLastReceivedId - " + type(e).__name__ + ": " + str(e))
                
        if id is None:
            # First access, remember the guy and get him last id
            id = self.db.getLastEventId()
            self.db.insertLastReceivedId(self.req.client, id)
            return {
                "lastid": id,
                "events": []
            }

        if id<=0:
            # Client wants to get only last N events and reset server notion of last id
            id += self.db.getLastEventId()
            if id<0: id=0

        try:
            count = int(count[0])
        except (ValueError, TypeError, IndexError):
            count = self.get_events_limit

        if self.get_events_limit:
            count = min(count, self.get_events_limit)

        res = self.db.fetch_events(self.req.client, id, count, cat, nocat, tag, notag, group, nogroup)

        self.db.insertLastReceivedId(self.req.client, res['lastid'])

        logging.info("sending %d events, lastid is %i" % (len(res["events"]), res["lastid"]))

        return res


    def check_node(self, event, name):
        try:
            ev_id = event['Node'][0]['Name'].lower()
        except (KeyError, TypeError):
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
                id = event.get("ID", None)
                ev_ids.append(id)
        return errlist


    @expose(write=1)
    def sendEvents(self, events=[]):
        if not isinstance(events, list):
            raise self.req.error(message="List of events expected.", error=400)

        errs = []
        if len(events)>self.send_events_limit:
            errs.extend(
                self.add_event_nums(range(self.send_events_limit, len(events)), events,
                    [{"error": 507, "message": "Too much events in one batch.",
                      "send_events_limit": self.send_events_limit}]))

        saved = 0
        for i, event in enumerate(events[0:self.send_events_limit]):
            v_errs = self.validator.check(event)
            if v_errs:
                errs.extend(self.add_event_nums([i], events, v_errs))
                continue

            node_errs = self.check_node(event, self.req.client.name)
            if node_errs:
                errs.extend(self.add_event_nums([i], events, node_errs))
                continue

            if self.req.client.test and not 'Test' in event.get('Category', []):
                errs.extend(self.add_event_nums([i], events, [{"error": 422,
                    "message": "You're allowed to send only messages, containing \"Test\" among categories.",
                    "categories": event.get('Category', [])}]))
                continue

            db_errs = self.db.store_event(self.req.client, event)
            if db_errs:
                errs.extend(self.add_event_nums([i], events, db_errs))
                continue

            saved += 1

        logging.info("Saved %i events" % saved)
        if errs:
            raise self.req.error(errors=errs)

        return {"saved": saved}



def read_ini(path):
    c = ConfigParser.RawConfigParser()
    res = c.read(path)
    if not res or not path in res:
        # We don't have loggin yet, hopefully this will go into webserver log
        raise Error(message="Unable to read config: %s" % path)
    data = {}
    for sect in c.sections():
        for opts in c.options(sect):
            lsect = sect.lower()
            if not lsect in data:
                data[lsect] = {}
            data[lsect][opts] = c.get(sect, opts)
    return data


def read_cfg(path):
    with open(path, "r") as f:
        stripcomments = "\n".join((l for l in f if not l.lstrip().startswith(("#", "//"))))
        conf = json.loads(stripcomments)

    # Lowercase keys
    conf = dict((sect.lower(), dict(
        (subkey.lower(), val) for subkey, val in subsect.iteritems())
    ) for sect, subsect in conf.iteritems())

    return conf


def fallback_wsgi(environ, start_response, exc_info=None):

    # If server does not start, set up simple server, returning
    # Warden JSON compliant error message
    error=503
    message="Server not running due to initialization error"
    headers = [('Content-type', 'application/json')]

    logline = "Error(%d): %s" % (error, message)
    status = "%d %s" % (error, message)
    output = '{"errors": [{"error": %d, "message": "%s"}]}' % (
        error, message)

    logging.critical(logline)
    start_response(status, headers)
    return [output]


def build_server(conf):

    # Functions for validation and conversion of config values
    def facility(name):
        return int(getattr(logging.handlers.SysLogHandler, "LOG_" + name.upper()))

    def loglevel(name):
        return int(getattr(logging, name.upper()))

    def natural(name):
        num = int(name)
        if num<1:
            raise ValueError("Not a natural number")
        return num

    def filepath(name):
        # Make paths relative to dir of this script
        return path.join(path.dirname(__file__), name)

    def objdef(name):
        return objects[name.lower()]

    obj = objdef    # Draw into local namespace for init_obj

    objects = {}    # Already initialized objects

    # List of sections and objects, configured by them
    # First object in each object list is the default one, otherwise
    # "type" keyword in section may be used to choose other
    section_def = {
        "log": ["FileLogger", "SysLogger"],
        "db": ["MySQL"],
        "auth": ["X509Authenticator", "NoAuthenticator"],
        "validator": ["JSONSchemaValidator", "NoValidator"],
        "handler": ["WardenHandler"],
        "server": ["Server"]
    }

    # Object parameter conversions and defaults
    param_def = {
        "FileLogger": {
            "req": {"type": obj, "default": "req"},
            "filename": {"type": filepath, "default": path.join(path.dirname(__file__), path.splitext(path.split(__file__)[1])[0] + ".log")},
            "level": {"type": loglevel, "default": "info"},
        },
        "SysLogger": {
            "req": {"type": obj, "default": "req"},
            "socket": {"type": filepath, "default": "/dev/log"},
            "facility": {"type": facility, "default": "daemon"},
            "level": {"type": loglevel, "default": "info"}
        },
        "NoAuthenticator": {
            "req": {"type": obj, "default": "req"}
        },
        "X509Authenticator": {
            "req": {"type": obj, "default": "req"},
            "db": {"type": obj, "default": "db"}
        },
        "NoValidator": {
            "req": {"type": obj, "default": "req"},
        },
        "JSONSchemaValidator": {
            "req": {"type": obj, "default": "req"},
            "filename": {"type": filepath, "default": path.join(path.dirname(__file__), "idea.schema")}
        },
        "MySQL": {
            "req": {"type": obj, "default": "req"},
            "host": {"type": str, "default": "localhost"},
            "user": {"type": str, "default": "warden"},
            "password": {"type": str, "default": ""},
            "dbname": {"type": str, "default": "warden3"},
            "port": {"type": natural, "default": 3306},
            "retry_pause": {"type": natural, "default": 5},
            "retry_count": {"type": natural, "default": 3},
            "event_size_limit": {"type": natural, "default": 5*1024*1024},
            "catmap_filename": {"type": filepath, "default": path.join(path.dirname(__file__), "catmap_mysql.json")},
            "tagmap_filename": {"type": filepath, "default": path.join(path.dirname(__file__), "tagmap_mysql.json")}
        },
        "WardenHandler": {
            "req": {"type": obj, "default": "req"},
            "validator": {"type": obj, "default": "validator"},
            "db": {"type": obj, "default": "DB"},
            "auth": {"type": obj, "default": "auth"},
            "send_events_limit": {"type": natural, "default": 500},
            "get_events_limit": {"type": natural, "default": 1000},
            "description": {"type": str, "default": ""}
        },
        "Server": {
            "req": {"type": obj, "default": "req"},
            "auth": {"type": obj, "default": "auth"},
            "handler": {"type": obj, "default": "handler"}
        }
    }

    def init_obj(sect_name):
        config = conf.get(sect_name, {})
        sect_name = sect_name.lower()
        sect_def = section_def[sect_name]

        try:    # Object type defined?
            objtype = config["type"]
            del config["type"]
        except KeyError:    # No, fetch default object type for this section
            objtype = sect_def[0]
        else:
            if not objtype in sect_def:
                raise KeyError("Unknown type %s in section %s" % (objtype, sect_name))

        params = param_def[objtype]

        # No surplus parameters? Disallow also 'obj' attributes, these are only
        # to provide default referenced section
        for name in config:
            if name not in params or (name in params and params[name]["type"] is objdef):
                raise KeyError("Unknown key %s in section %s" % (name, sect_name))

        # Process parameters
        kwargs = {}
        for name, definition in params.iteritems():
            raw_val = config.get(name, definition["default"])
            try:
                val = definition["type"](raw_val)
            except Exception:
                raise KeyError("Bad value \"%s\" for %s in section %s" % (raw_val, name, sect_name))
            kwargs[name] = val

        cls = globals()[objtype]   # get class/function type
        try:
            obj = cls(**kwargs)         # run it
        except Exception as e:
            raise KeyError("Cannot initialize %s from section %s: %s" % (
                objtype, sect_name, str(e)))

        if isinstance(obj, Object):
            # Log only objects here, functions must take care of themselves
            logging.info("Initialized %s" % str(obj))

        objects[sect_name] = obj
        return obj

    # Init logging with at least simple stderr StreamLogger
    # Dunno if it's ok within wsgi, but we have no other choice, let's
    # hope it at least ends up in webserver error log
    StreamLogger()

    # Shared container for common data of ongoing WSGI request
    objects["req"] = Request()

    try:
        # Now try to init required objects
        for o in ("log", "db", "auth", "validator", "handler", "server"):
            init_obj(o)
    except Exception as e:
        logging.critical(str(e))
        logging.debug("", exc_info=sys.exc_info())
        return fallback_wsgi

    logging.info("Server ready")

    return objects["server"]



# Command line utilities

def check_config():
    # If we got so far, server object got set up fine
    print >>sys.stderr, "Looks clear."
    return 0


def list_clients(id=None):
    clients = server.handler.db.get_clients(id)
    order = ["id", "registered", "requestor", "hostname", "name",
             "secret", "valid", "read", "debug", "write", "test", "note"]
    lines = [[str(getattr(client, col)) for col in order] for client in clients]
    col_width = [max(len(val) for val in col) for col in zip(*(lines+[order]))]
    divider = ["-" * l for l in col_width]
    for line in [order, divider] + lines:
        print " ".join([val.ljust(width) for val, width in zip(line, col_width)])


def register_client(name, hostname, requestor, secret, note, valid, read, write, debug, test):
    # argparse does _always_ return something, so we cannot rely on missing arguments
    if valid is None: valid = 1
    if read is None: read = 1
    if write is None: write = 0
    if debug is None: debug = 0
    if test is None: test = 1
    modify_client(id=None,
            name=name, hostname=hostname, requestor=requestor, secret=secret,
            note=note, valid=valid, read=read, write=write, debug=debug, test=test)


def modify_client(id, name, hostname, requestor, secret, note, valid, read, write, debug, test):

    def isValidHostname(hostname):
        if len(hostname) > 255:
            return False
        if hostname.endswith("."): # A single trailing dot is legal
            hostname = hostname[:-1] # strip exactly one dot from the right, if present
        disallowed = re.compile("[^A-Z\d-]", re.IGNORECASE)
        return all( # Split by labels and verify individually
            (label and len(label) <= 63 # length is within proper range
             and not label.startswith("-") and not label.endswith("-") # no bordering hyphens
             and not disallowed.search(label)) # contains only legal characters
            for label in hostname.split("."))

    def isValidNSID(nsid):
        allowed = re.compile("^(?:[a-zA-Z_][a-zA-Z0-9_]*\\.)*[a-zA-Z_][a-zA-Z0-9_]*$")
        return allowed.match(nsid)

    def isValidEmail(mail):
        split = email.utils.parseaddr(mail)
        allowed = re.compile("^[a-zA-Z0-9_.%!+-]+@[a-zA-Z0-9-.]+$") # just basic check
        return allowed.match(split[1])

    def isValidID(id):
        client = server.handler.db.get_clients(id)
        return client and True or False


    if name is not None and not isValidNSID(name):
        print >>sys.stderr, "Invalid client name \"%s\"." % name

    if hostname is not None and not isValidHostname(hostname):
        print >>sys.stderr, "Invalid hostname \"%s\"." % hostname
        return 254

    if requestor is not None and not isValidEmail(requestor):
        print >>sys.stderr, "Invalid requestor email \"%s\"." % requestor
        return 254

    if id is not None and not isValidID(id):
        print >>sys.stderr, "Invalid id \"%s\"." % id
        return 254

    for c in server.handler.db.get_clients():
        if name is not None and name.lower()==c.name:
            print >>sys.stderr, "Clash with existing name: %s" % str(c)
            return 254
        if secret is not None and secret==c.secret:
            print >>sys.stderr, "Clash with existing secret: %s" % str(c)
            return 254

    newid = server.handler.db.add_modify_client(
        id=id, name=name, hostname=hostname,
        requestor=requestor, secret=secret, note=note, valid=valid,
        read=read, write=write, debug=debug, test=test)

    list_clients(id=newid)


def load_maps():
    server.handler.db.load_maps()


def purge(days=30, lastlog=None, events=None):
    if lastlog is None and events is None:
        lastlog = events = True
    if lastlog:
        count = server.handler.db.purge_lastlog(days)
        print "Purged %d lastlog entries." % count
    if events:
        count = server.handler.db.purge_events(days)
        print "Purged %d events." % count


def add_client_args(subargp, mod=False):
    subargp.add_argument("--help", action="help", help="show this help message and exit")
    if mod:
        subargp.add_argument("-i", "--id", required=True, type=int,
            help="client id")
    subargp.add_argument("-n", "--name", required=not mod,
        help="client name (in dotted reverse path notation)")
    subargp.add_argument("-h", "--hostname", required=not mod,
        help="client FQDN hostname")
    subargp.add_argument("-r", "--requestor", required=not mod,
        help="requestor email")
    subargp.add_argument("-s", "--secret",
        help="authentication token")
    subargp.add_argument("--note",
        help="client freetext description")

    reg_valid = subargp.add_mutually_exclusive_group(required=False)
    reg_valid.add_argument("--valid", action="store_const", const=1, default=None,
        help="valid client (default)")
    reg_valid.add_argument("--novalid", action="store_const", const=0, dest="valid", default=None)

    reg_read = subargp.add_mutually_exclusive_group(required=False)
    reg_read.add_argument("--read", action="store_const", const=1, default=None,
        help="client is allowed to read (default)")
    reg_read.add_argument("--noread", action="store_const", const=0, dest="read", default=None)

    reg_write = subargp.add_mutually_exclusive_group(required=False)
    reg_write.add_argument("--nowrite", action="store_const", const=0, dest="write", default=None,
        help="client is allowed to send (default - no)")
    reg_write.add_argument("--write", action="store_const", const=1, default=None)

    reg_debug = subargp.add_mutually_exclusive_group(required=False)
    reg_debug.add_argument("--nodebug", action="store_const", const=0, dest="debug", default=None,
        help="client is allowed receive debug output (default - no)")
    reg_debug.add_argument("--debug", action="store_const", const=1, default=None)

    reg_test = subargp.add_mutually_exclusive_group(required=False)
    reg_test.add_argument("--test", action="store_const", const=1, default=None,
        help="client is yet in testing phase (default - yes)")
    reg_test.add_argument("--notest", action="store_const", const=0, dest="test", default=None)


def get_args():
    import argparse
    argp = argparse.ArgumentParser(
        description="Warden server " + VERSION, add_help=False)
    argp.add_argument("--help", action="help",
        help="show this help message and exit")
    argp.add_argument("-c", "--config",
        help="path to configuration file")
    subargp = argp.add_subparsers(title="commands")

    subargp_check = subargp.add_parser("check", add_help=False,
        description="Try to setup server based on configuration file.",
        help="check configuration")
    subargp_check.set_defaults(command=check_config)
    subargp_check.add_argument("--help", action="help",
        help="show this help message and exit")

    subargp_reg = subargp.add_parser("register", add_help=False,
        description="Add new client registration entry.",
        help="register new client")
    subargp_reg.set_defaults(command=register_client)
    add_client_args(subargp_reg)

    subargp_mod = subargp.add_parser("modify", add_help=False,
        description="Modify details of client registration entry.",
        help="modify client registration")
    subargp_mod.set_defaults(command=modify_client)
    add_client_args(subargp_mod, mod=True)

    subargp_list = subargp.add_parser("list", add_help=False,
        description="List details of client registration entries.",
        help="list registered clients")
    subargp_list.set_defaults(command=list_clients)
    subargp_list.add_argument("--help", action="help",
        help="show this help message and exit")
    subargp_list.add_argument("--id", action="store", type=int,
        help="client id", default=None)

    subargp_purge = subargp.add_parser("purge", add_help=False,
        description=
            "Purge old events or lastlog records."
            " Note that lastlog purge retains at least one newest record for each"
            " client, even if it is more than number of 'days' old.",
        help="purge old events or lastlog records")
    subargp_purge.set_defaults(command=purge)
    subargp_purge.add_argument("--help", action="help",
        help="show this help message and exit")
    subargp_purge.add_argument("-l", "--lastlog", action="store_true", dest="lastlog", default=None,
        help="purge lastlog records")
    subargp_purge.add_argument("-e", "--events", action="store_true", dest="events", default=None,
        help="purge events")
    subargp_purge.add_argument("-d", "--days", action="store", dest="days", type=int, default=30,
        help="records older than 'days' back from today will get purged")

    subargp_loadmaps = subargp.add_parser("loadmaps", add_help=False,
        description=
            "Load 'categories' and 'tags' table from 'catmap_mysql.json' and 'tagmap_mysql.json'."
            " Note that this is NOT needed for server at all, load them into db at will,"
            " should you need to run your own specific SQL queries on data directly."
            " Note also that previous content of both tables will be lost.",
        help="load catmap and tagmap into db")
    subargp_loadmaps.set_defaults(command=load_maps)
    subargp_loadmaps.add_argument("--help", action="help",
        help="show this help message and exit")

    return argp.parse_args()


if __name__=="__main__":
    args = get_args()
    config = path.join(path.dirname(__file__), args.config or "warden_server.cfg")
    server = build_server(read_cfg(config))
    command = args.command
    subargs = vars(args)
    del subargs["command"]
    del subargs["config"]
    if not server or server is fallback_wsgi:
        print >>sys.stderr, "Failed initialization, check configured log targets for reasons."
        sys.exit(255)
    sys.exit(command(**subargs))
