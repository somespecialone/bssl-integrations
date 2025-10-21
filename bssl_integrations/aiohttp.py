"""
Connector for aiohttp.ClientSession, separate bssl.ClientContext for each session
All ssl.SSLContext passed to request methods and session will be ignored
"""

import asyncio
import socket
import ssl
import collections
import itertools

import aiohappyeyeballs

from aiohttp.connector import (
    ClientConnectorDNSError,
    TCPConnector,
    ClientConnectorError,
    ceil_timeout,
    cert_errors,
    ClientConnectorCertificateError,
    ClientConnectorSSLError,
    ssl_errors,
    AbstractResolver,
    sentinel,
    SocketFactoryType,
    DefaultResolver,
    _DNSCacheTable,
    ResolveResult,
    ClientConnectionError,
)

from bssl import *

from .ssl import DEF_BSSL_CONTEXT, BSSLProtocol

__all__ = ("BSSLConnector",)


class BSSLConnector(TCPConnector):
    def __init__(
        self,
        tls_config: TLSClientConfiguration | None = None,
        *,
        use_dns_cache: bool = True,
        ttl_dns_cache: int | None = 10,
        family: socket.AddressFamily = socket.AddressFamily.AF_UNSPEC,
        local_addr: tuple[str, int] | None = None,
        resolver: AbstractResolver | None = None,
        keepalive_timeout: None | float | object = sentinel,
        force_close: bool = False,
        limit: int = 100,
        limit_per_host: int = 0,
        enable_cleanup_closed: bool = False,
        loop: asyncio.AbstractEventLoop | None = None,
        timeout_ceil_threshold: float = 5,
        happy_eyeballs_delay: float | None = 0.25,
        interleave: int | None = None,
        socket_factory: SocketFactoryType | None = None,
        ssl_shutdown_timeout: float | None = None,
    ):
        super(TCPConnector, self).__init__(
            keepalive_timeout=keepalive_timeout,
            force_close=force_close,
            limit=limit,
            limit_per_host=limit_per_host,
            enable_cleanup_closed=enable_cleanup_closed,
            loop=loop,
            timeout_ceil_threshold=timeout_ceil_threshold,
        )

        self._ssl = ClientContext(tls_config) if tls_config is not None else DEF_BSSL_CONTEXT

        self._resolver: AbstractResolver
        if resolver is None:
            self._resolver = DefaultResolver(loop=self._loop)
            self._resolver_owner = True
        else:
            self._resolver = resolver
            self._resolver_owner = False

        self._use_dns_cache = use_dns_cache
        self._cached_hosts = _DNSCacheTable(ttl=ttl_dns_cache)
        self._throttle_dns_futures: dict[tuple[str, int], set["asyncio.Future[None]"]] = {}
        self._family = family
        self._local_addr_infos = aiohappyeyeballs.addr_to_addr_infos(local_addr)
        self._happy_eyeballs_delay = happy_eyeballs_delay
        self._interleave = interleave
        self._resolve_host_tasks: set["asyncio.Task[list[ResolveResult]]"] = set()
        self._socket_factory = socket_factory
        self._ssl_shutdown_timeout = ssl_shutdown_timeout

    def _get_ssl_context(self, req) -> ClientContext | None:
        if not req.is_ssl():
            return None
        else:
            return self._ssl

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
            # call_connection_made=False,  # aiohttp.TCPConnector doesn't call loop.start_tls for non-proxied requests
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

    async def _create_direct_connection(self, req, traces, timeout, *, client_error=ClientConnectorError):
        sslcontext = self._get_ssl_context(req)

        host = req.url.raw_host
        assert host is not None
        if host.endswith(".."):
            host = host.rstrip(".") + "."
        port = req.port
        assert port is not None
        try:
            hosts = await self._resolve_host(host, port, traces=traces)
        except OSError as exc:
            if exc.errno is None and isinstance(exc, asyncio.TimeoutError):
                raise
            raise ClientConnectorDNSError(req.connection_key, exc) from exc

        last_exc = None
        addr_infos = self._convert_hosts_to_addr_infos(hosts)
        while addr_infos:
            server_hostname = (req.server_hostname or host).rstrip(".") if sslcontext else None

            try:
                try:
                    async with ceil_timeout(timeout.sock_connect, ceil_threshold=timeout.ceil_threshold):
                        sock = await aiohappyeyeballs.start_connection(
                            addr_infos=addr_infos,
                            local_addr_infos=self._local_addr_infos,
                            happy_eyeballs_delay=self._happy_eyeballs_delay,
                            interleave=self._interleave,
                            loop=self._loop,
                            socket_factory=self._socket_factory,
                        )

                        transport, protocol = await self._loop.create_connection(self._factory, sock=sock)

                        if sslcontext:
                            transport = await self._loop_start_tls(
                                transport,
                                protocol,
                                sslcontext,
                                ssl_handshake_timeout=timeout.total,
                                server_hostname=server_hostname,
                                ssl_shutdown_timeout=self._ssl_shutdown_timeout,
                            )
                        return transport, protocol

                except cert_errors as exc:
                    raise ClientConnectorCertificateError(req.connection_key, exc) from exc
                except ssl_errors as exc:
                    raise ClientConnectorSSLError(req.connection_key, exc) from exc
                except OSError as exc:
                    if exc.errno is None and isinstance(exc, asyncio.TimeoutError):
                        raise
                    raise client_error(req.connection_key, exc) from exc

            except (ClientConnectorError, asyncio.TimeoutError) as exc:
                last_exc = exc
                aiohappyeyeballs.pop_addr_infos_interleave(addr_infos, self._interleave)
                continue

        else:
            assert last_exc is not None
            raise last_exc

    async def close(self, *, abort_ssl=False) -> None:
        if self._resolver_owner:
            await self._resolver.close()
        await super().close(abort_ssl=abort_ssl or not self._ssl_shutdown_timeout)

    async def _start_tls_connection(
        self,
        underlying_transport,
        req,
        timeout,
        client_error=ClientConnectorError,
    ):
        tls_proto = self._factory()  # Create a brand new proto for TLS
        sslcontext = self._get_ssl_context(req)

        try:
            async with ceil_timeout(timeout.sock_connect, ceil_threshold=timeout.ceil_threshold):
                try:
                    tls_transport = await self._loop_start_tls(
                        underlying_transport,
                        tls_proto,
                        sslcontext,
                        server_hostname=req.server_hostname or req.host,
                        ssl_handshake_timeout=timeout.total,
                        ssl_shutdown_timeout=self._ssl_shutdown_timeout,
                    )

                except BaseException:
                    if not self._ssl_shutdown_timeout:
                        underlying_transport.abort()
                    else:
                        underlying_transport.close()
                    raise

        except cert_errors as exc:
            raise ClientConnectorCertificateError(req.connection_key, exc) from exc
        except ssl_errors as exc:
            raise ClientConnectorSSLError(req.connection_key, exc) from exc
        except OSError as exc:
            if exc.errno is None and isinstance(exc, asyncio.TimeoutError):
                raise
            raise client_error(req.connection_key, exc) from exc
        except TypeError as type_err:
            raise ClientConnectionError(
                "Cannot initialize a TLS-in-TLS connection to host "
                f"{req.host!s}:{req.port:d} through an underlying connection "
                f"to an HTTPS proxy {req.proxy!s} ssl:{req.ssl or 'default'} "
                f"[{type_err!s}]"
            ) from type_err
        else:
            if tls_transport is None:
                msg = "Failed to start TLS (possibly caused by closing transport)"
                raise client_error(req.connection_key, OSError(msg))
            tls_proto.connection_made(tls_transport)  # Kick the state machine of the new TLS protocol

        return tls_transport, tls_proto
