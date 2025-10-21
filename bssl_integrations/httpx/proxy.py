from httpcore._models import HeadersAsMapping, HeadersAsSequence
from httpx._config import Proxy as Proxy_, URL, HeaderTypes, Headers

from bssl import ClientContext


class Proxy(Proxy_):
    ssl_context: ClientContext

    def __init__(
        self,
        url: URL | str,
        *,
        ssl_context: ClientContext | None = None,
        auth: tuple[str, str] | None = None,
        headers: HeaderTypes | None = None,
    ) -> None:
        url = URL(url)
        headers = Headers(headers)

        if url.scheme not in ("http", "https", "socks5", "socks5h"):
            raise ValueError(f"Unknown scheme for proxy URL {url!r}")

        if url.username or url.password:
            # Remove any auth credentials from the URL.
            auth = (url.username, url.password)
            url = url.copy_with(username=None, password=None)

        self.url = url
        self.auth = auth
        self.headers = headers
        self.ssl_context = ssl_context
