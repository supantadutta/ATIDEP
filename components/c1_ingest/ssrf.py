"""SSRF-safe HTTPS fetcher (blueprint §19.2).

Three layers, applied to the first request and again to every redirect:

1. URL policy: HTTPS on port 443, no embedded credentials, host on the domain allowlist.
2. Address policy: the host is resolved once; *every* returned address must be public, otherwise
   the whole host is refused (a mixed answer is a classic bypass).
3. Pinned connection: the TCP connection goes to the validated address while TLS verification
   and the ``Host`` header use the original host name, so a second, different DNS answer
   (DNS rebinding) cannot redirect the request.

Also enforced: a redirect limit, a response-size limit, a total deadline, a content-type
allowlist, no cookies, no compression (``Accept-Encoding: identity``).
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol
from urllib.parse import urljoin, urlsplit

USER_AGENT = "ATIDEP/0.1 (research prototype)"
DEFAULT_CONTENT_TYPES = frozenset({
    "text/html", "text/plain", "text/xml", "application/xml", "application/rss+xml",
    "application/atom+xml", "application/json", "application/feed+json", "application/pdf"})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# NAT64 well-known prefix: embeds an IPv4 address, so it is not treated as public.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class FetchCode(StrEnum):
    URL_SCHEME = "URL_SCHEME"
    URL_INVALID = "URL_INVALID"
    HOST_NOT_ALLOWED = "HOST_NOT_ALLOWED"
    DNS_FAILURE = "DNS_FAILURE"
    ADDRESS_NOT_PUBLIC = "ADDRESS_NOT_PUBLIC"
    TOO_MANY_REDIRECTS = "TOO_MANY_REDIRECTS"
    TOO_LARGE = "TOO_LARGE"
    CONTENT_TYPE = "CONTENT_TYPE"
    HTTP_STATUS = "HTTP_STATUS"
    TIMEOUT = "TIMEOUT"
    CONNECTION = "CONNECTION"


class FetchError(Exception):
    def __init__(self, code: FetchCode, message: str) -> None:
        super().__init__(f"{code.value}: {message}")
        self.code = code


def is_public_address(value: str) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_public_address(str(ip.ipv4_mapped))
        if ip in _NAT64 or ip.sixtofour is not None or ip.teredo is not None:
            return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified or not ip.is_global)


def host_allowed(host: str, allowed_domains: Iterable[str]) -> bool:
    """Exact match or a true subdomain of an allowlisted domain (``evilexample.com`` does not
    match ``example.com``)."""
    host = host.rstrip(".").lower()
    for domain in allowed_domains:
        d = domain.rstrip(".").lower()
        if host == d or host.endswith("." + d):
            return True
    return False


@dataclass(frozen=True)
class Target:
    url: str
    host: str
    path: str


def check_url(url: str, allowed_domains: Iterable[str]) -> Target:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise FetchError(FetchCode.URL_INVALID, str(exc)) from exc
    if parts.scheme != "https":
        raise FetchError(FetchCode.URL_SCHEME, "only https is allowed")
    if parts.username is not None or parts.password is not None:
        raise FetchError(FetchCode.URL_INVALID, "credentials in the URL are not allowed")
    if port not in (None, 443):
        raise FetchError(FetchCode.URL_INVALID, "only port 443 is allowed")
    host = (parts.hostname or "").strip()
    if not host:
        raise FetchError(FetchCode.URL_INVALID, "missing host")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise FetchError(FetchCode.URL_INVALID, "invalid host name") from exc
    if not host_allowed(host, allowed_domains):
        raise FetchError(FetchCode.HOST_NOT_ALLOWED, f"{host} is not on the allowlist")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(url=url, host=host, path=path)


Resolver = Callable[[str], list[str]]


def system_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchError(FetchCode.DNS_FAILURE, f"cannot resolve {host}") from exc
    return list(dict.fromkeys(info[4][0] for info in infos))


def resolve_public(host: str, resolver: Resolver) -> str:
    """Resolve once; require every address to be public; return the one to connect to."""
    addresses = resolver(host)
    if not addresses:
        raise FetchError(FetchCode.DNS_FAILURE, f"no addresses for {host}")
    bad = [a for a in addresses if not is_public_address(a)]
    if bad:
        raise FetchError(FetchCode.ADDRESS_NOT_PUBLIC, f"{host} resolves to non-public {bad}")
    return addresses[0]


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes = b""


class Transport(Protocol):
    def get(self, ip: str, host: str, path: str, headers: dict[str, str], timeout: float,
            max_bytes: int, deadline: float) -> Response: ...


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a fixed address but verifies TLS and sends SNI for the original host."""

    def __init__(self, host: str, ip: str, port: int, timeout: float,
                 context: ssl.SSLContext) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = ip

    def connect(self) -> None:  # noqa: D102 - override
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class PinnedTransport:
    def __init__(self, context: ssl.SSLContext | None = None, port: int = 443) -> None:
        self._context = context or ssl.create_default_context()
        self._port = port

    def get(self, ip, host, path, headers, timeout, max_bytes, deadline) -> Response:
        conn = PinnedHTTPSConnection(host, ip, self._port, timeout, self._context)
        try:
            conn.request("GET", path, headers={**headers, "Host": host})
            resp = conn.getresponse()
            declared = resp.getheader("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise FetchError(FetchCode.TOO_LARGE, f"declared length {declared}")
            chunks: list[bytes] = []
            total = 0
            while True:
                if time.monotonic() > deadline:
                    raise FetchError(FetchCode.TIMEOUT, "total deadline exceeded")
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(FetchCode.TOO_LARGE, f"more than {max_bytes} bytes")
                chunks.append(chunk)
            return Response(resp.status, {k.lower(): v for k, v in resp.getheaders()},
                            b"".join(chunks))
        except TimeoutError as exc:
            raise FetchError(FetchCode.TIMEOUT, "network timeout") from exc
        except (ssl.SSLError, OSError, http.client.HTTPException) as exc:
            raise FetchError(FetchCode.CONNECTION, f"{type(exc).__name__}: {exc}") from exc
        finally:
            conn.close()


@dataclass
class FetchResult:
    url: str
    status: int
    content_type: str
    body: bytes
    redirects: list[str] = field(default_factory=list)


class SafeFetcher:
    def __init__(self, allowed_domains: Iterable[str], *, resolver: Resolver = system_resolver,
                 transport: Transport | None = None, max_redirects: int = 3,
                 max_bytes: int = 10 * 1024 * 1024, timeout: float = 15.0,
                 total_timeout: float = 30.0,
                 content_types: frozenset[str] = DEFAULT_CONTENT_TYPES) -> None:
        self.allowed_domains = tuple(allowed_domains)
        self.resolver = resolver
        self.transport = transport or PinnedTransport()
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes
        self.timeout = timeout
        self.total_timeout = total_timeout
        self.content_types = content_types

    def fetch(self, url: str) -> FetchResult:
        deadline = time.monotonic() + self.total_timeout
        visited: list[str] = []
        current = url
        for _hop in range(self.max_redirects + 1):
            target = check_url(current, self.allowed_domains)
            ip = resolve_public(target.host, self.resolver)
            resp = self.transport.get(
                ip, target.host, target.path,
                {"User-Agent": USER_AGENT, "Accept-Encoding": "identity",
                 "Accept": ", ".join(sorted(self.content_types))},
                self.timeout, self.max_bytes, deadline)
            if resp.status in REDIRECT_STATUSES:
                location = resp.headers.get("location")
                if not location:
                    raise FetchError(FetchCode.HTTP_STATUS, "redirect without Location")
                visited.append(current)
                current = urljoin(current, location)
                continue
            if resp.status != 200:
                raise FetchError(FetchCode.HTTP_STATUS, f"status {resp.status}")
            if len(resp.body) > self.max_bytes:
                raise FetchError(FetchCode.TOO_LARGE, f"more than {self.max_bytes} bytes")
            ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            if ctype not in self.content_types:
                raise FetchError(FetchCode.CONTENT_TYPE, f"content type {ctype!r} not allowed")
            return FetchResult(current, resp.status, ctype, resp.body, visited)
        raise FetchError(FetchCode.TOO_MANY_REDIRECTS, f"more than {self.max_redirects}")
