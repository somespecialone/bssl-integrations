# BSSL Integrations

[![Made in Ukraine](https://img.shields.io/badge/made_in-ukraine-ffd700.svg?labelColor=0057b7)](https://stand-with-ukraine.pp.ua)
[![license](https://img.shields.io/github/license/somespecialone/bssl-integrations)](https://github.com/somespecialone/bssl-integrations/blob/main/LICENSE)
[![pypi](https://img.shields.io/pypi/v/bssl-integrations)](https://pypi.org/project/bssl-integrations)
[![python versions](https://img.shields.io/pypi/pyversions/bssl-integrations)](https://pypi.org/project/bssl-integrations)
[![CI](https://github.com/somespecialone/bssl-integrations/actions/workflows/ci.yml/badge.svg)](https://github.com/somespecialone/bssl-integrations/actions/workflows/ci.yml)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)

[BSSL](https://github.com/somespecialone/bssl) project integration with existing http clients

## Supported projects

* [aiohttp](https://github.com/aio-libs/aiohttp)
* [aiohttp-socks](https://github.com/romis2012/aiohttp-socks)
* [httpx](https://github.com/encode/httpx) sync `Client` without proxy support (yet)

## Installation

Project is available on [PyPI](https://pypi.org/project/bssl-integrations) (now in _prerelease_ stage,
so you need to allow _prerelease_ installation).

```sh
pip install --pre bssl-integrations
poetry add --allow-prereleases bssl-integrations
uv add --prerelease if-necessary bssl-integrations  # explicitly allow prelease
```

❗Note that the HTTP client libraries must be installed separately.

## Usage

### Aiohttp

Module expose `BSSLConnector` class, which is a subclass of `aiohttp.TCPConnector` with `bssl` context.

```py
import aiohttp
import bssl
from bssl_integrations.aiohttp import BSSLConnector

my_tls_config = bssl.TLSClientConfiguration(...)

connector = BSSLConnector(my_tls_config)
session = aiohttp.ClientSession(connector=connector)

# do with session whatever you want
```

### Aiohttp-socks

As `aiohttp` connector above, but with `socks` proxy support.
See [aiohttp-socks](https://github.com/romis2012/aiohttp-socks) for more info.

```py
import aiohttp
import bssl
from bssl_integrations.aiohttp_socks import BSSLProxyConnector

my_tls_config = bssl.TLSClientConfiguration(...)

connector = BSSLProxyConnector(
    host="127.0.0.1",
    port=1080,
    username="user",
    password="password",
    dest_tls_config=my_tls_config,
)
# OR
connector = BSSLProxyConnector.from_url("socks5://user:password@127.0.0.1:1080", dest_tls_config=my_tls_config)
session = aiohttp.ClientSession(connector=connector)

# do with session whatever you want
```

❗ Note that you need `aiohttp-socks` to be installed.

### Httpx

```py
import httpx
import bssl
from bssl_integrations.httpx import BSSLTransport

my_tls_config = bssl.TLSClientConfiguration(...)

transport = BSSLTransport(my_tls_config)
client = httpx.Client(transport=transport)

# do with client whatever you want
```

## Credits

* [bssl](https://github.com/somespecialone/bssl)
* [tls.peet.ws](https://tls.peet.ws) - TLS fingerprinting API
* [jsonip.com](https://jsonip.com) - IP API
