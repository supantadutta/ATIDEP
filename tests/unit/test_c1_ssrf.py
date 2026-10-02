import http.server
import shutil
import socket
import ssl
import subprocess
import threading

import pytest

from components.c1_ingest.ssrf import (
    FetchCode,
    FetchError,
    PinnedTransport,
    Response,
    SafeFetcher,
    check_url,
    host_allowed,
    is_public_address,
    resolve_public,
)

ALLOWED = ["example.org"]


# ---- address policy ----------------------------------------------------------------------
@pytest.mark.parametrize("addr", [
    "93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111",
])
def test_public_addresses_are_accepted(addr):
    assert is_public_address(addr)


@pytest.mark.parametrize("addr", [
    "127.0.0.1", "127.1.2.3", "10.0.0.5", "172.16.0.1", "172.31.255.254", "192.168.1.1",
    "169.254.169.254",          # cloud metadata
    "100.64.0.1", "100.100.100.200",   # carrier-grade NAT (some clouds' metadata)
    "0.0.0.0", "224.0.0.1", "255.255.255.255", "240.0.0.1",
    "192.0.2.1", "198.51.100.7", "203.0.113.9",  # documentation ranges
    "::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
    "64:ff9b::7f00:1",          # NAT64 embedding 127.0.0.1
    "2002:7f00:1::",            # 6to4 embedding 127.0.0.1
    "not-an-ip", "",
])
def test_non_public_addresses_are_refused(addr):
    assert not is_public_address(addr)


# ---- URL policy --------------------------------------------------------------------------
def test_host_matching_is_exact_or_true_subdomain():
    assert host_allowed("example.org", ALLOWED)
    assert host_allowed("feeds.example.org", ALLOWED)
    assert host_allowed("EXAMPLE.ORG.", ALLOWED)
    assert not host_allowed("evilexample.org", ALLOWED)
    assert not host_allowed("example.org.evil.test", ALLOWED)
    assert not host_allowed("example.com", ALLOWED)


@pytest.mark.parametrize("url,code", [
    ("http://example.org/feed", FetchCode.URL_SCHEME),
    ("ftp://example.org/feed", FetchCode.URL_SCHEME),
    ("file:///etc/passwd", FetchCode.URL_SCHEME),
    ("https://user:pw@example.org/feed", FetchCode.URL_INVALID),
    ("https://example.org:8443/feed", FetchCode.URL_INVALID),
    ("https://example.org:80/feed", FetchCode.URL_INVALID),
    ("https:///feed", FetchCode.URL_INVALID),
    ("https://127.0.0.1/feed", FetchCode.HOST_NOT_ALLOWED),
    ("https://2130706433/feed", FetchCode.HOST_NOT_ALLOWED),   # decimal form of 127.0.0.1
    ("https://0x7f.0.0.1/feed", FetchCode.HOST_NOT_ALLOWED),
    ("https://[::1]/feed", FetchCode.HOST_NOT_ALLOWED),
    ("https://evilexample.org/feed", FetchCode.HOST_NOT_ALLOWED),
    ("https://example.org@evil.test/feed", FetchCode.URL_INVALID),
])
def test_bad_urls_are_refused(url, code):
    with pytest.raises(FetchError) as err:
        check_url(url, ALLOWED)
    assert err.value.code is code


def test_good_url_keeps_path_and_query():
    t = check_url("https://Feeds.Example.ORG/a/b?x=1", ALLOWED)
    assert t.host == "feeds.example.org" and t.path == "/a/b?x=1"


# ---- resolution policy -------------------------------------------------------------------
def test_mixed_answers_are_refused():
    with pytest.raises(FetchError) as err:
        resolve_public("example.org", lambda h: ["93.184.216.34", "10.0.0.1"])
    assert err.value.code is FetchCode.ADDRESS_NOT_PUBLIC


def test_empty_answer_is_refused():
    with pytest.raises(FetchError) as err:
        resolve_public("example.org", lambda h: [])
    assert err.value.code is FetchCode.DNS_FAILURE


# ---- fetcher with a scripted transport ---------------------------------------------------
class FakeTransport:
    def __init__(self, script):
        self.script, self.calls = script, []

    def get(self, ip, host, path, headers, timeout, max_bytes, deadline):
        self.calls.append((ip, host, path, headers))
        return self.script[(host, path)]


def html(body=b"<p>ok</p>", ctype="text/html; charset=utf-8"):
    return Response(200, {"content-type": ctype}, body)


def fetcher(script, answers=None, **kw):
    answers = answers or {"example.org": ["93.184.216.34"], "feeds.example.org": ["93.184.216.35"]}
    transport = FakeTransport(script)
    return SafeFetcher(ALLOWED, resolver=lambda h: answers[h], transport=transport, **kw), transport


def test_successful_fetch_connects_to_the_validated_address_with_the_original_host():
    f, t = fetcher({("example.org", "/r"): html()})
    result = f.fetch("https://example.org/r")
    assert result.body == b"<p>ok</p>" and result.content_type == "text/html"
    ip, host, _path, headers = t.calls[0]
    assert (ip, host) == ("93.184.216.34", "example.org")
    assert headers["Accept-Encoding"] == "identity" and "Cookie" not in headers


def test_dns_rebinding_cannot_change_the_connection_address():
    answers = iter([["93.184.216.34"], ["127.0.0.1"], ["127.0.0.1"]])
    t = FakeTransport({("example.org", "/r"): html()})
    f = SafeFetcher(ALLOWED, resolver=lambda h: next(answers), transport=t)
    f.fetch("https://example.org/r")
    assert [c[0] for c in t.calls] == ["93.184.216.34"]   # resolved once, then pinned


def test_private_resolution_is_blocked_before_any_request():
    f, t = fetcher({}, answers={"example.org": ["169.254.169.254"]})
    with pytest.raises(FetchError) as err:
        f.fetch("https://example.org/latest/meta-data")
    assert err.value.code is FetchCode.ADDRESS_NOT_PUBLIC and t.calls == []


def test_disallowed_host_never_reaches_dns():
    called = []
    f = SafeFetcher(ALLOWED, resolver=lambda h: called.append(h) or ["93.184.216.34"],
                    transport=FakeTransport({}))
    with pytest.raises(FetchError):
        f.fetch("https://evil.test/")
    assert called == []


def redirect(location, status=302):
    return Response(status, {"location": location})


def test_redirects_are_followed_and_revalidated():
    f, t = fetcher({("example.org", "/a"): redirect("https://feeds.example.org/b"),
                    ("feeds.example.org", "/b"): html()})
    r = f.fetch("https://example.org/a")
    assert r.url == "https://feeds.example.org/b" and r.redirects == ["https://example.org/a"]
    assert [c[0] for c in t.calls] == ["93.184.216.34", "93.184.216.35"]


def test_relative_redirects_resolve_against_the_current_url():
    f, _ = fetcher({("example.org", "/a/b"): redirect("../c"), ("example.org", "/c"): html()})
    assert f.fetch("https://example.org/a/b").url == "https://example.org/c"


@pytest.mark.parametrize("location,code", [
    ("https://evil.test/x", FetchCode.HOST_NOT_ALLOWED),
    ("http://example.org/x", FetchCode.URL_SCHEME),
    ("https://127.0.0.1/x", FetchCode.HOST_NOT_ALLOWED),
    ("file:///etc/passwd", FetchCode.URL_SCHEME),
])
def test_redirect_targets_obey_the_same_policy(location, code):
    f, _ = fetcher({("example.org", "/a"): redirect(location)})
    with pytest.raises(FetchError) as err:
        f.fetch("https://example.org/a")
    assert err.value.code is code


def test_redirect_to_an_allowed_host_that_resolves_privately_is_blocked():
    answers = {"example.org": ["93.184.216.34"], "feeds.example.org": ["10.1.2.3"]}
    f, _ = fetcher({("example.org", "/a"): redirect("https://feeds.example.org/b")}, answers=answers)
    with pytest.raises(FetchError) as err:
        f.fetch("https://example.org/a")
    assert err.value.code is FetchCode.ADDRESS_NOT_PUBLIC


def test_redirect_loop_is_cut_off():
    f, _ = fetcher({("example.org", "/a"): redirect("/a")}, max_redirects=3)
    with pytest.raises(FetchError) as err:
        f.fetch("https://example.org/a")
    assert err.value.code is FetchCode.TOO_MANY_REDIRECTS


def test_content_type_allowlist():
    f, _ = fetcher({("example.org", "/x"): html(b"MZ", "application/octet-stream")})
    with pytest.raises(FetchError) as err:
        f.fetch("https://example.org/x")
    assert err.value.code is FetchCode.CONTENT_TYPE
    f2, _ = fetcher({("example.org", "/x"): html(b"%PDF-", "Application/PDF; x=y")})
    assert f2.fetch("https://example.org/x").content_type == "application/pdf"


def test_size_limit_and_status_handling():
    f, _ = fetcher({("example.org", "/big"): html(b"x" * 101)}, max_bytes=100)
    with pytest.raises(FetchError) as err:
        f.fetch("https://example.org/big")
    assert err.value.code is FetchCode.TOO_LARGE
    f2, _ = fetcher({("example.org", "/nf"): Response(404, {})})
    with pytest.raises(FetchError) as err2:
        f2.fetch("https://example.org/nf")
    assert err2.value.code is FetchCode.HTTP_STATUS


# ---- the real pinned transport against a local TLS server --------------------------------
@pytest.fixture(scope="module")
def tls_server(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("tls")
    key, crt = d / "k.pem", d / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(crt), "-days", "2", "-subj", "/CN=allowed.example",
                    "-addext", "subjectAltName=DNS:allowed.example"], check=True,
                   capture_output=True)
    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen["host"] = self.headers.get("Host")
            body = b"x" * 5000 if self.path == "/big" else b"hello"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = ssl.create_default_context(cafile=str(crt))
    yield server.server_address[1], client, seen
    server.shutdown()


def test_pinned_transport_connects_to_the_given_address_and_verifies_the_hostname(tls_server):
    port, client_ctx, seen = tls_server
    t = PinnedTransport(client_ctx, port=port)
    import time
    resp = t.get("127.0.0.1", "allowed.example", "/", {}, 5, 1000, time.monotonic() + 5)
    assert resp.status == 200 and resp.body == b"hello"
    assert seen["host"] == "allowed.example"      # name sent, address pinned


def test_pinned_transport_rejects_a_certificate_for_another_name(tls_server):
    port, client_ctx, _ = tls_server
    t = PinnedTransport(client_ctx, port=port)
    import time
    with pytest.raises(FetchError) as err:
        t.get("127.0.0.1", "other.example", "/", {}, 5, 1000, time.monotonic() + 5)
    assert err.value.code is FetchCode.CONNECTION


def test_pinned_transport_enforces_the_size_limit_while_streaming(tls_server):
    port, client_ctx, _ = tls_server
    t = PinnedTransport(client_ctx, port=port)
    import time
    with pytest.raises(FetchError) as err:
        t.get("127.0.0.1", "allowed.example", "/big", {}, 5, 1000, time.monotonic() + 5)
    assert err.value.code is FetchCode.TOO_LARGE


def test_pinned_transport_enforces_the_deadline(tls_server):
    port, client_ctx, _ = tls_server
    t = PinnedTransport(client_ctx, port=port)
    import time
    with pytest.raises(FetchError) as err:
        t.get("127.0.0.1", "allowed.example", "/", {}, 5, 1000, time.monotonic() - 1)
    assert err.value.code is FetchCode.TIMEOUT


def test_unreachable_address_is_a_connection_error():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    import time
    with pytest.raises(FetchError) as err:
        PinnedTransport(port=port).get("127.0.0.1", "allowed.example", "/", {}, 2, 10, time.monotonic() + 5)
    assert err.value.code is FetchCode.CONNECTION
