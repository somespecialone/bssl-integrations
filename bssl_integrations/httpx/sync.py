"""
Transport for httpx.Client, dedicated bssl.ClientContext for each Client
Supports HTTP/2
"""

from typing import Iterable
from base64 import b64encode

from httpcore import (
    NetworkStream,
    URL,
    ConnectionPool,
    SOCKET_OPTION,
    HTTP11Connection,
)
from httpcore._sync.connection import (
    HTTPConnection,
    exponential_backoff,
    RETRIES_BACKOFF_FACTOR,
    Trace,
    logger,
    ConnectError,
    ConnectTimeout,
)
from httpx._transports.default import DEFAULT_LIMITS, HTTPTransport, Limits

from bssl import *

from ..ssl import DEF_BSSL_CONTEXT

from .proxy import Proxy


class BSSLNetworkStream(NetworkStream):
    def __init__(self, sock: TLSSocket):
        self._sock = sock

    def read(self, max_bytes, timeout=None):
        return self._sock.recv(max_bytes)

    def write(self, buffer, timeout=None):
        self._sock.send(buffer)

    def close(self):
        self._sock.close(True)


class BSSLHTTPConnection(HTTPConnection):
    _ssl_context: ClientContext

    def _connect(self, request):
        if self._origin.scheme not in (b"https", b"wss"):  # proceed with original method if not https
            return super()._connect(request)

        sni_hostname = request.extensions.get("sni_hostname", None)

        retries_left = self._retries
        delays = exponential_backoff(factor=RETRIES_BACKOFF_FACTOR)

        while True:
            try:
                kwargs = {
                    "address": (sni_hostname or self._origin.host.decode("ascii"), self._origin.port),
                }
                with Trace("start_tls", logger, request, kwargs) as trace:
                    sock = self._ssl_context.connect(**kwargs)
                    stream = BSSLNetworkStream(sock)
                    trace.return_value = stream

                return stream

            except (ConnectError, ConnectTimeout):
                if retries_left <= 0:
                    raise
                retries_left -= 1
                delay = next(delays)
                with Trace("retry", logger, request, kwargs) as trace:
                    self._network_backend.sleep(delay)

    def handle_request(self, request):
        if not self.can_handle_request(request.url.origin):
            raise RuntimeError(f"Attempted to send request to {request.url.origin} on connection to {self._origin}")

        try:
            with self._request_lock:
                if self._connection is None:
                    stream = self._connect(request)

                    http2_negotiated = (
                        isinstance(stream, BSSLNetworkStream)
                        and NextProtocol(stream._sock.negotiated_protocol()) is NextProtocol.HTTP2
                    )
                    if http2_negotiated or (self._http2 and not self._http1):
                        from httpcore._sync.http2 import HTTP2Connection

                        self._connection = HTTP2Connection(
                            origin=self._origin,
                            stream=stream,
                            keepalive_expiry=self._keepalive_expiry,
                        )
                    else:
                        self._connection = HTTP11Connection(
                            origin=self._origin,
                            stream=stream,
                            keepalive_expiry=self._keepalive_expiry,
                        )
        except BaseException as exc:
            self._connect_failed = True
            raise exc

        return self._connection.handle_request(request)


class BSSLConnectionPool(ConnectionPool):
    _ssl_context: ClientContext
    _proxy: Proxy | None

    def create_connection(self, origin):
        if self._proxy is not None:
            raise NotImplementedError("Proxy functionality for BSSLConnectionPool yet not implemented")

        return BSSLHTTPConnection(
            origin=origin,
            ssl_context=self._ssl_context,
            keepalive_expiry=self._keepalive_expiry,
            http1=self._http1,
            http2=self._http2,
            retries=self._retries,
            local_address=self._local_address,
            network_backend=self._network_backend,
            socket_options=self._socket_options,
        )


class BSSLTransport(HTTPTransport):
    def __init__(
        self,
        tls_config: TLSClientConfiguration | None = None,
        http1: bool = True,
        http2: bool = False,
        limits: Limits = DEFAULT_LIMITS,
        proxy: URL | str | Proxy | None = None,
        local_address: str | None = None,
        retries: int = 0,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ):
        proxy = Proxy(url=proxy) if isinstance(proxy, (str, URL)) else proxy
        ssl_context = ClientContext(tls_config) if tls_config is not None else DEF_BSSL_CONTEXT

        if proxy:
            raise NotImplementedError("BSSLTransport doesn't support proxy yet")

        if proxy is None:
            self._pool = BSSLConnectionPool(
                ssl_context=ssl_context,
                max_connections=limits.max_connections,
                max_keepalive_connections=limits.max_keepalive_connections,
                keepalive_expiry=limits.keepalive_expiry,
                http1=http1,
                http2=http2,
                local_address=local_address,
                retries=retries,
                socket_options=socket_options,
            )


# proxy support need TLSBuffer as memory buffer to be wrapped around standard socket within lib's Stream
