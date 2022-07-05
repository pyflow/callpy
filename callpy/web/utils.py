# -*- coding: utf-8 -*-

import os
import sys
import json

from urllib.parse import urljoin
from urllib.parse import urlencode, quote as urlquote, unquote as urlunquote

import socket


def get_remote_addr(transport):
    socket_info = transport.get_extra_info("socket")
    if socket_info is not None:
        try:
            info = socket_info.getpeername()
        except OSError:
            # This case appears to inconsistently occur with uvloop
            # bound to a unix domain socket.
            family = None
            info = None
        else:
            family = socket_info.family

        if family in (socket.AF_INET, socket.AF_INET6):
            return (str(info[0]), int(info[1]))
        return None
    info = transport.get_extra_info("peername")
    if info is not None and isinstance(info, (list, tuple)) and len(info) == 2:
        return (str(info[0]), int(info[1]))
    return None


def get_local_addr(transport):
    socket_info = transport.get_extra_info("socket")
    if socket_info is not None:
        info = socket_info.getsockname()
        family = socket_info.family
        if family in (socket.AF_INET, socket.AF_INET6):
            return (str(info[0]), int(info[1]))
        return None
    info = transport.get_extra_info("sockname")
    if info is not None and isinstance(info, (list, tuple)) and len(info) == 2:
        return (str(info[0]), int(info[1]))
    return None


def is_ssl(transport):
    return bool(transport.get_extra_info("sslcontext"))


def get_client_addr(scope):
    client = scope.get("client")
    if not client:
        return ""
    return "%s:%d" % client


def get_path_with_query_string(scope):
    path_with_query_string = scope.get("root_path", "") + scope["path"]
    if scope["query_string"]:
        path_with_query_string = "{}?{}".format(
            path_with_query_string, scope["query_string"].decode("ascii")
        )
    return path_with_query_string


def reraise(tp, value, tb=None):
    if value.__traceback__ is not tb:
        raise value.with_traceback(tb)
    raise value


# Some helpers for string/byte handling
def to_bytes(s, enc='utf8'):
    if s is None:
        return None
    return s.encode(enc) if isinstance(s, str) else bytes(s)


def to_unicode(s, enc='utf8', err='strict'):
    if s is None:
        return None
    if isinstance(s, bytes):
        return s.decode(enc, err)
    else:
        return str(s)

def urldecode(qs):
    r = []
    for pair in qs.replace(';', '&').split('&'):
        if not pair: continue
        nv = pair.split('=', 1)
        if len(nv) != 2: nv.append('')
        key = urlunquote(nv[0].replace('+', ' '), encoding='utf-8')
        value = urlunquote(nv[1].replace('+', ' '), encoding='utf-8')
        r.append((key, value))
    return r

class ConfigDict(dict):
    def __contains__(self, k):
        try:
            return dict.__contains__(self, k) or hasattr(self, k)
        except:
            return False

    # only called if k not found in normal places
    def __getattr__(self, k):
        try:
            # Throws exception if not in prototype chain
            return object.__getattribute__(self, k)
        except AttributeError:
            try:
                return self[k]
            except KeyError:
                raise AttributeError(k)

    def __setattr__(self, k, v):
        try:
            # Throws exception if not in prototype chain
            object.__getattribute__(self, k)
        except AttributeError:
            try:
                self[k] = v
            except:
                raise AttributeError(k)
        else:
            object.__setattr__(self, k, v)

    def __delattr__(self, k):
        try:
            # Throws exception if not in prototype chain
            object.__getattribute__(self, k)
        except AttributeError:
            try:
                del self[k]
            except KeyError:
                raise AttributeError(k)
        else:
            object.__delattr__(self, k)


class cached_property(object):
    """ A property that is only computed once per instance and then replaces
        itself with an ordinary attribute. Deleting the attribute resets the
        property. """

    def __init__(self, func):
        self.__doc__ = getattr(func, '__doc__')
        self.func = func

    def __get__(self, obj, cls=None):
        if obj is None: return self
        if self.func.__name__ not in obj.__dict__:
            obj.__dict__[self.func.__name__] = self.func(obj)
        value = obj.__dict__[self.func.__name__]
        return value
