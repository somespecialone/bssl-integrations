"""
Connector for aiohttp.ClientSession, dedicated bssl.ClientContext for each session
All ssl.SSLContext passed to request methods and session will be ignored
"""

import asyncio

from python_socks.async_.asyncio.v2._proxy import (
    AsyncioProxy,
    Resolver,
    ProxyConnectionError,
    ProxyError,
    ReplyError,
    AsyncioSocketStream,
    create_connector,
)
from aiohttp_socks import ProxyConnector, ProxyType
from aiohttp_socks.connector import NoResolver, TCPConnector, _ResponseHandler, _BaseProxyConnector

from bssl import *

from .ssl import DEF_BSSL_CONTEXT, BSSLProtocol

__all__ = (
    "BSSLAsyncProxy",
    "BSSLProxyConnector",
)


class BSSLStreamWriter(asyncio.StreamWriter):
    _loop: asyncio.AbstractEventLoop

    async def _loop_start_tls(
        self,
        transport,
        protocol,
        sslcontext: ClientContext,
        *,
        server_side=False,
        server_hostname=None,
        ssl_handshake_timeout=None,
        ssl_shutdown_timeout=None,
    ):
        waiter = self._loop.create_future()
        ssl_protocol = BSSLProtocol(
            self._loop,
            protocol,
            waiter,
            server_side,
            server_hostname,
            ssl_handshake_timeout=ssl_handshake_timeout,
            ssl_shutdown_timeout=ssl_shutdown_timeout,
            bssl_ctx=sslcontext,
            call_connection_made=False,
        )

        transport.pause_reading()

        transport.set_protocol(ssl_protocol)
        conmade_cb = self._loop.call_soon(ssl_protocol.connection_made, transport)
        resume_cb = self._loop.call_soon(transport.resume_reading)

        try:
            await waiter
        except BaseException:
            transport.close()
            conmade_cb.cancel()
            resume_cb.cancel()
            raise

        return ssl_protocol._app_transport

    async def start_tls(
        self,
        sslcontext: ClientContext,
        *,
        server_hostname=None,
        ssl_handshake_timeout=None,
        ssl_shutdown_timeout=None,
    ):
        protocol = self._protocol
        await self.drain()
        new_transport = await self._loop_start_tls(
            self._transport,
            protocol,
            sslcontext,
            server_hostname=server_hostname,
            ssl_handshake_timeout=ssl_handshake_timeout,
            ssl_shutdown_timeout=ssl_shutdown_timeout,
        )
        self._transport = new_transport
        protocol._replace_writer(self)


class BSSLAsyncProxy(AsyncioProxy):
    def __init__(
        self,
        proxy_type,
        host,
        port,
        username=None,
        password=None,
        rdns=None,
        proxy_ssl: ClientContext = None,
        forward: "BSSLAsyncProxy" = None,
    ):
        self._loop = asyncio.get_event_loop()

        self._proxy_type = proxy_type
        self._proxy_host = host
        self._proxy_port = port
        self._username = username
        self._password = password
        self._rdns = rdns

        self._proxy_ssl = proxy_ssl
        self._forward = forward

        self._resolver = Resolver(loop=self._loop)

    async def _connect(self, dest_host, dest_port, dest_ssl: ClientContext = None, local_addr=None):
        if self._forward is None:
            try:
                # asyncio.streams.open_connection
                reader = asyncio.StreamReader(limit=asyncio.streams._DEFAULT_LIMIT, loop=self._loop)
                protocol = asyncio.StreamReaderProtocol(reader, loop=self._loop)
                transport, _ = await self._loop.create_connection(
                    lambda: protocol,
                    self._proxy_host,
                    self._proxy_port,
                    local_addr=local_addr,
                )
                writer = BSSLStreamWriter(transport, protocol, reader, self._loop)

                # python_socks.async_.asyncio.v2._connect.connect_tcp
                stream = AsyncioSocketStream(
                    loop=self._loop,
                    reader=reader,
                    writer=writer,
                )

            except OSError as e:
                raise ProxyConnectionError(
                    e.errno,
                    "Couldn't connect to proxy" f" {self._proxy_host}:{self._proxy_port} [{e.strerror}]",
                ) from e

        else:
            stream = await self._forward.connect(
                dest_host=self._proxy_host,
                dest_port=self._proxy_port,
            )

        try:
            if self._proxy_ssl is not None:
                stream = await stream.start_tls(hostname=self._proxy_host, ssl_context=self._proxy_ssl)

            connector = create_connector(
                proxy_type=self._proxy_type,
                username=self._username,
                password=self._password,
                rdns=self._rdns,
                resolver=self._resolver,
            )

            await connector.connect(stream=stream, host=dest_host, port=dest_port)

            if dest_ssl is not None:
                stream = await stream.start_tls(hostname=dest_host, ssl_context=dest_ssl)
        except ReplyError as e:
            await stream.close()
            raise ProxyError(e, error_code=e.error_code)
        except (asyncio.CancelledError, Exception):
            await stream.close()
            raise

        return stream


class BSSLProxyConnector(ProxyConnector):
    def __init__(
        self,
        host: str,
        port: int,
        proxy_type: ProxyType = ProxyType.SOCKS5,
        username: str | None = None,
        password: str | None = None,
        rdns: bool | None = None,
        proxy_tls_config: TLSClientConfiguration | None = None,
        dest_tls_config: TLSClientConfiguration | None = None,
        **kwargs,
    ):
        kwargs["resolver"] = NoResolver()
        super(_BaseProxyConnector, self).__init__(**kwargs)

        self._proxy_type = proxy_type
        self._proxy_host = host
        self._proxy_port = port
        self._proxy_username = username
        self._proxy_password = password
        self._rdns = rdns

        self._proxy_ssl = ClientContext(proxy_tls_config) if proxy_tls_config is not None else None
        self._dest_ssl = ClientContext(dest_tls_config) if dest_tls_config is not None else DEF_BSSL_CONTEXT

    async def _connect_via_proxy(self, host, port, ssl=None, timeout=None):
        proxy = BSSLAsyncProxy(
            proxy_type=self._proxy_type,
            host=self._proxy_host,
            port=self._proxy_port,
            username=self._proxy_username,
            password=self._proxy_password,
            rdns=self._rdns,
            proxy_ssl=self._proxy_ssl,
        )

        stream = await proxy.connect(
            dest_host=host,
            dest_port=port,
            dest_ssl=self._dest_ssl if ssl else None,
            timeout=timeout,
        )

        transport = stream.writer.transport
        protocol = _ResponseHandler(loop=self._loop, writer=stream.writer)

        transport.set_protocol(protocol)
        protocol.connection_made(transport)

        return transport, protocol
