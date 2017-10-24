#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2015 Cesnet z.s.p.o
# Use of this source is governed by a 3-clause BSD-style license, see LICENSE file.

from warden_client import Client, Error, read_cfg
import json
import string
import os
import sys
import errno
import socket
import time
import logging
import signal
import resource
import atexit
import argparse
from os import path, mkdir
from random import choice, randint;

VERSION = "3.0-beta2"

class NamedFile(object):
    """ Wrapper class for file objects, which allows and tracks filename
        changes.
    """

    def __init__(self, pth, name, fd=None):
        self.name = name
        self.path = pth
        if fd:
            self.f = os.fdopen(fd, "w+b")
        else:
            self.f = None


    def __str__(self):
        return "%s(%s, %s)" % (type(self).__name__, self.path, self.name)


    def get_path(self, basepath=None, name=None):
        return path.join(basepath or self.path, name or self.name)


    def open(self, mode):
        return open(self.get_path(), mode)


    def moveto(self, destpath):
        os.rename(self.get_path(), self.get_path(basepath=destpath))
        self.path = destpath


    def rename(self, newname):
        os.rename(self.get_path(), self.get_path(name=newname))
        self.name = newname


    def remove(self):
        os.remove(self.get_path())



class SafeDir(object):
    """ Maildir like directory for safe file exchange.
        - Producers are expected to drop files into "temp" under globally unique
          filename and rename it into "incoming" atomically (newfile method)
        - Workers pick files in "incoming", rename them into "temp",
          do whatever they want, and either discard them or move into
          "errors" directory
    """

    def __init__(self, p):
        self.path = self._ensure_path(p)
        self.incoming = self._ensure_path(path.join(self.path, "incoming"))
        self.errors = self._ensure_path(path.join(self.path, "errors"))
        self.temp = self._ensure_path(path.join(self.path, "temp"))
        self.hostname = socket.gethostname()
        self.pid = os.getpid()


    def __str__(self):
        return "%s(%s)" % (type(self).__name__, self.path)


    def _ensure_path(self, p):
        try:
            mkdir(p)
        except OSError:
            if not path.isdir(p):
                raise
        return p


    def _get_new_name(self, device=0, inode=0):
        return "%s.%d.%f.%d.%d.idea" % (
            self.hostname, self.pid, time.time(), device, inode)


    def newfile(self):
        """ Creates file with unique filename within this SafeDir.
            - hostname takes care of network filesystems
            - pid distinguishes two daemons on one machine
              (we are not multithreaded, so this is enough)
            - time in best precision supported narrows window within process
            - device/inode makes file unique on particular filesystem
            In fact, device/inode is itself enough for uniqueness, however
            if we mandate wider format, users can use simpler form with
            random numbers instead of device/inode, if they choose to,
            and it will still ensure reasonable uniqueness.
        """

        # Note: this simpler device/inode algorithm replaces original,
        #       which checked uniqueness among all directories by atomic
        #       links.

        # First find and open name unique within temp
        tmpname = None
        while not tmpname:
            tmpname = self._get_new_name()
            try:
                fd = os.open(path.join(self.temp, tmpname), os.O_CREAT | os.O_RDWR | os.O_EXCL)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise   # other errors than duplicates should get noticed
                tmpname = None
        # Now we know device/inode, rename to make unique within system
        stat = os.fstat(fd)
        newname = self._get_new_name(stat.st_dev, stat.st_ino)
        nf = NamedFile(self.temp, tmpname, fd)
        nf.rename(newname)
        return nf


    def get_incoming(self):
        return [NamedFile(self.incoming, n) for n in os.listdir(self.incoming)]



def receiver(config, wclient, sdir, oneshot):
    poll_time = config.get("poll_time", 5)
    node = config.get("node", None)
    conf_filt = config.get("filter", {})
    filt = {}
    # Extract filter explicitly to be sure we have right param names for getEvents
    for s in ("cat", "nocat", "tag", "notag", "group", "nogroup"):
        filt[s] = conf_filt.get(s, None)

    while running_flag:
        events = wclient.getEvents(**filt)
        count_ok = count_err = 0
        while events:
            for event in events:
                if node:
                    nodelist = event.setdefault("Node", [])
                    nodelist.insert(0, node)
                try:
                    nf = None
                    nf = sdir.newfile()
                    with nf.f as f:
                        data = json.dumps(event)
                        f.write(data)
                    nf.moveto(sdir.incoming)
                    count_ok += 1
                except Exception as e:
                    Error(message="Error saving event", exc=sys.exc_info(), file=str(nf),
                          event_ids=[event.get("ID")], sdir=sdir.path).log(wclient.logger)
                    count_err += 1
            wclient.logger.info(
                "warden_filer: received %d, errors %d"
                % (count_ok, count_err))
            events = wclient.getEvents(**filt)
            count_ok = count_err = 0
        if oneshot:
            if not events:
                terminate_me(None, None)
        else:
            time.sleep(poll_time)



def match_event(event, cat=None, nocat=None, tag=None, notag=None, group=None, nogroup=None):

    cat_match = tag_match = group_match = True

    if cat or nocat:
        event_cats = event.get("Category")
        event_full_cats = set(event_cats) | set(cat.split(".", 1)[0] for cat in event_cats)
        cat_match = set(cat or nocat) & event_full_cats
        cat_match = not cat_match if nocat else cat_match

    try:
        event_node = event.get("Node", [])[0]
    except IndexError:
        event_node = {}

    if tag or notag:
        event_tags = set(event_node.get("Type", []))
        tag_match = set(tag or notag) & event_tags
        tag_match = not tag_match if notag else tag_match

    if group or nogroup:
        event_name = event_node.get("Name")
        namesplit = event_name.split(".")
        allnames = set([".".join(namesplit[0:l]) for l in range(1, len(namesplit)+1)])
        group_match = set(group or nogroup) & allnames
        group_match = not group_match if nogroup else group_match

    return cat_match and tag_match and group_match



def get_dir_list(sdir, owait_poll_time, owait_timeout, nfchunk, oneshot):
    nflist = sdir.get_incoming()
    if oneshot and not nflist:
        terminate_me(None, None)
    timeout = time.time() + owait_timeout
    while len(nflist)<nfchunk and time.time()<timeout and running_flag:
        time.sleep(owait_poll_time)
        nflist = sdir.get_incoming()
    return nflist



def sender(config, wclient, sdir, oneshot):
    poll_time = config.get("poll_time", 5)
    owait_poll_time = config.get("owait_poll_time", 1)
    owait_timeout = config.get("owait_timeout", poll_time)
    node = config.get("node", None)
    done_dir = config.get("done_dir", None)
    conf_filt = config.get("filter", {})
    filt = {}
    # Extract filter explicitly to be sure we have right param names for match_event
    for s in ("cat", "nocat", "tag", "notag", "group", "nogroup"):
        filt[s] = conf_filt.get(s, None)

    nfchunk = wclient.send_events_limit
    while running_flag:
        nflist = get_dir_list(sdir, owait_poll_time, owait_timeout, nfchunk, oneshot)
        if oneshot and not nflist:
            terminate_me(None, None)
        while running_flag and not nflist:
            # No new files, wait and try again
            time.sleep(poll_time)
            nflist = get_dir_list(sdir, owait_poll_time, owait_timeout, nfchunk, oneshot)

        # Loop over all chunks. However:
        # - omit the last loop, if there is less data than the optimal window;
        #   next get_dir_list will still get it again, possibly together with
        #   new files, which may have appeared meanwhile
        # - unless it's the sole loop (so that at least _something_ gets sent)
        nfindex = 0
        while nfindex<len(nflist) and ((len(nflist)-nfindex>=nfchunk) or not nfindex):
            events = []
            nf_sent = []
            count_ok = count_err = count_unmatched = count_local = 0
            for nf in nflist[nfindex:nfindex+nfchunk]:
                # prepare event array from files
                try:
                    nf.moveto(sdir.temp)
                except Exception:
                    continue    # Silently go to next filename, somebody else might have interfered
                try:
                    with nf.open("rb") as fd:
                        data = fd.read()
                        event = json.loads(data)
                        if not match_event(event, **filt):
                            wclient.logger.debug("Unmatched event: %s" % data)
                            count_unmatched += 1
                            nf.remove()
                            continue
                        if node:
                            nodelist = event.setdefault("Node", [])
                            nodelist.insert(0, node)
                        events.append(event)
                        nf_sent.append(nf)
                except Exception as e:
                    Error(message="Error loading event", exc=sys.exc_info(), file=str(nf),
                          sdir=sdir.path).log(wclient.logger)
                    nf.moveto(sdir.errors)
                    count_local += 1

            res = wclient.sendEvents(events)

            if isinstance(res, Error):
                for e in res.errors:
                    errno = e["error"]
                    evlist = e.get("events", range(len(nf_sent)))  # None means all
                    for i in evlist:
                        if nf_sent[i]:
                            nf_sent[i].moveto(sdir.errors)
                            nf_sent[i] = None
                            count_err += 1

            # Cleanup rest - the succesfully sent events
            for name in nf_sent:
                if name:
                    if done_dir:
                        name.moveto(done_dir)
                    else:
                        name.remove()
                    count_ok += 1
            wclient.logger.info(
                "warden_filer: saved %d, warden errors %d, local errors %d, unmatched %d" % (count_ok, count_err, count_local, count_unmatched))

            nfindex += nfchunk  # skip to next chunk of files
            nfchunk = wclient.send_events_limit # might get changed by server



def get_logger_files(logger):
    """ Return file objects of loggers """
    files = []
    for handler in logger.handlers:
        if hasattr(handler, 'stream') and hasattr(handler.stream, 'fileno'):
            files.append(handler.stream)
        if hasattr(handler, 'socket') and hasattr(handler.socket, 'fileno'):
            files.append(handler.socket)
    return files



def daemonize(
        work_dir = None, chroot_dir = None,
        umask = None, uid = None, gid = None,
        pidfile = None, files_preserve = [], signals = {}):
    # Dirs, limits, users
    if chroot_dir is not None:
        os.chdir(chroot_dir)
        os.chroot(chroot_dir)
    if umask is not None:
        os.umask(umask)
    if work_dir is not None:
        os.chdir(work_dir)
    if gid is not None:
        os.setgid(gid)
    if uid is not None:
        os.setuid(uid)
    # Doublefork, split session
    if os.fork()>0:
        os._exit(0)
    os.setsid()
    if os.fork()>0:
        os._exit(0)
    # Setup signal handlers
    for (signum, handler) in signals.items():
        signal.signal(signum, handler)
    # Close descriptors
    descr_preserve = set(f.fileno() for f in files_preserve)
    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if maxfd==resource.RLIM_INFINITY:
        maxfd = 65535
    for fd in range(maxfd, 3, -1):  # 3 means omit stdin, stdout, stderr
        if fd not in descr_preserve:
            try:
                os.close(fd)
            except Exception:
                pass
    # Redirect stdin, stdout, stderr to /dev/null
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in range(3):
        os.dup2(devnull, fd)
    # PID file
    if pidfile is not None:
        pidd = os.open(pidfile, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_TRUNC)
        os.write(pidd, str(os.getpid())+"\n")
        os.close(pidd)
        # Define and setup atexit closure
        @atexit.register
        def unlink_pid():
            try:
                os.unlink(pidfile)
            except Exception:
                pass



running_flag = True     # Daemon cleanly exits when set to False

def terminate_me(signum, frame):
    global running_flag
    running_flag = False



class DummyContext(object):
    """ In one shot mode we use this instead of DaemonContext """
    def __enter__(self): pass
    def __exit__(self, *exc): pass



def get_args():
    argp = argparse.ArgumentParser(
        description="Save Warden events as files or send files to Warden")
    argp.add_argument("func",
        choices=["sender", "receiver"],
        action="store",
        help="choose direction: sender picks up files and submits them to "
              "Warden, receiver pulls events from Warden and saves them as files")
    argp.add_argument("-c", "--config",
        default=path.splitext(__file__)[0]+".cfg",
        dest="config",
        help="configuration file path")
    argp.add_argument("-o", "--oneshot",
        default=False,
        dest="oneshot",
        action="store_true",
        help="don't daemonise, run just once")
    argp.add_argument("-d", "--daemon",
        default=False,
        dest="daemon",
        action="store_true",
        help="daemonize")
    argp.add_argument("-p", "--pid_file",
        default=None,
        dest="pid_file",
        action="store",
        help="create PID file with this name")
    return argp.parse_args()



def get_configs():
    config = read_cfg(args.config)

    # Allow inline or external Warden config
    wconfig = config.get("warden", "warden_client.cfg")
    if isinstance(wconfig, basestring):
        wconfig = read_cfg(wconfig)

    fconfig = config.get(args.func, {})

    return wconfig, fconfig



if __name__ == "__main__":

    args = get_args()

    function = sender if args.func=="sender" else receiver

    wconfig, fconfig = get_configs()

    wclient = Client(**wconfig)

    try:
        if args.daemon:
            daemonize(
                work_dir = fconfig.get("work_dir", "."),
                chroot_dir = fconfig.get("chroot_dir"),
                umask = fconfig.get("umask"),
                uid = fconfig.get("uid"),
                gid = fconfig.get("gid"),
                pidfile = args.pid_file,
                files_preserve = get_logger_files(wclient.logger),
                signals = {
                    signal.SIGTERM: terminate_me,
                    signal.SIGINT: terminate_me,
                    signal.SIGHUP: signal.SIG_IGN,
                    signal.SIGTTIN: signal.SIG_IGN,
                    signal.SIGTTOU: signal.SIG_IGN})

        safe_dir = SafeDir(fconfig.get("dir", args.func))
        wclient.logger.info("Starting %s" % args.func)
        function(fconfig, wclient, safe_dir, args.oneshot)
        wclient.logger.info("Exiting %s" % args.func)

    except Exception as e:
        Error(message="%s daemon error" % args.func, exc=sys.exc_info()).log(wclient.logger)
