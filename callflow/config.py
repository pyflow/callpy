import asyncio
import inspect
import logging
import logging.config
import os
import socket
import ssl
import sys
from typing import List
from basepy.log import logger

logger.add('stdout')

# Fallback to 'ssl.PROTOCOL_SSLv23' in order to support Python < 3.5.3.
SSL_PROTOCOL_VERSION = getattr(ssl, "PROTOCOL_TLS", ssl.PROTOCOL_SSLv23)


def create_ssl_context(certfile, keyfile, ssl_version, cert_reqs, ca_certs, ciphers):
    ctx = ssl.SSLContext(ssl_version)
    ctx.load_cert_chain(certfile, keyfile)
    ctx.verify_mode = cert_reqs
    if ca_certs:
        ctx.load_verify_locations(ca_certs)
    if ciphers:
        ctx.set_ciphers(ciphers)
    return ctx


class ServerConfig:
    def __init__(
        self,
        app,
        host="127.0.0.1",
        port=8000,
        debug=False,
        workers=None,
        root_path="",
        limit_concurrency=None,
        limit_max_requests=None,
        backlog=2048,
        timeout_keep_alive=5,
        timeout_notify=30,
        callback_notify=None,
        ssl_keyfile=None,
        ssl_certfile=None,
        ssl_version=SSL_PROTOCOL_VERSION,
        ssl_cert_reqs=ssl.CERT_NONE,
        ssl_ca_certs=None,
        ssl_ciphers="TLSv1",
        headers=None,
    ):
        self.app = app
        self.host = host
        self.port = port
        self.debug = debug
        self.workers = workers or 1
        self.root_path = root_path
        self.limit_concurrency = limit_concurrency
        self.limit_max_requests = limit_max_requests
        self.backlog = backlog
        self.timeout_keep_alive = timeout_keep_alive
        self.timeout_notify = timeout_notify
        self.callback_notify = callback_notify
        self.ssl_keyfile = ssl_keyfile
        self.ssl_certfile = ssl_certfile
        self.ssl_version = ssl_version
        self.ssl_cert_reqs = ssl_cert_reqs
        self.ssl_ca_certs = ssl_ca_certs
        self.ssl_ciphers = ssl_ciphers
        self.headers = headers if headers else []  # type: List[str]
        self.encoded_headers = None  # type: List[Tuple[bytes, bytes]]

        self.loaded = False


    @property
    def is_ssl(self) -> bool:
        return bool(self.ssl_keyfile or self.ssl_certfile)

    def load(self):
        assert not self.loaded

        if self.is_ssl:
            self.ssl = create_ssl_context(
                keyfile=self.ssl_keyfile,
                certfile=self.ssl_certfile,
                ssl_version=self.ssl_version,
                cert_reqs=self.ssl_cert_reqs,
                ca_certs=self.ssl_ca_certs,
                ciphers=self.ssl_ciphers,
            )
        else:
            self.ssl = None

        encoded_headers = [
            (key.lower().encode("latin1"), value.encode("latin1"))
            for key, value in self.headers
        ]
        self.encoded_headers = (
            encoded_headers
            if b"server" in dict(encoded_headers)
            else [(b"server", b"callflow")] + encoded_headers
        )  # type: List[Tuple[bytes, bytes]]

        self.loaded = True

    def bind_socket(self):
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.host, self.port))
        except OSError as exc:
            logger.error(exc)
            sys.exit(1)
        sock.set_inheritable(True)

        message = "Callflow running on %s://%s:%d (Press CTRL+C to quit)"
        protocol_name = "https" if self.is_ssl else "http"
        logger.info(
            message,
            protocol_name,
            self.host,
            self.port
        )
        return sock
