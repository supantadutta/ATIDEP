import json
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

import pytest

from app.config import load_config
from components.c5_deployment.adapter import (
    AdapterError,
    NotAllowed,
    WazuhAdapter,
)

ALLOW = load_config().policies.deployment.wazuh_api_allowlist


def make_cert(directory, cn="localhost"):
    key, crt = directory / f"{cn}.key", directory / f"{cn}.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(crt), "-days", "2", "-subj", f"/CN={cn}",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)
    return str(crt), str(key)


class Stub:
    """A tiny stand-in for the Wazuh API that records every request."""

    def __init__(self, cert, key):
        self.calls = []
        self.files = {"rules": {}, "lists": {}}
        self.fail_uploads = False
        self.generation = 1                      # bumped by a restart; sessions die with it
        self.restarts = 0
        self.frozen = False
        self.missing_as_200 = False
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code, body, ctype="application/json"):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _handle(self, method):
                path = urlsplit(self.path).path
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                stub.calls.append((method, path, self.headers.get("Authorization", "")[:6]))
                if path == "/security/user/authenticate":
                    return self._send(200, b"TOKEN123", "text/plain")
                if self.headers.get("Authorization") != "Bearer TOKEN123":
                    return self._send(401, {"title": "Unauthorized"})
                parts = path.strip("/").split("/")
                if parts[0] in ("rules", "lists") and parts[1] == "files":
                    name, kind = parts[2], parts[0]
                    if method == "PUT":
                        if stub.fail_uploads:      # failure reported inside an HTTP 200 (F9)
                            return self._send(200, {"data": {"total_failed_items": 1,
                                                             "failed_items": [{"error": {
                                                                 "message": "XML syntax error"}}]},
                                                    "error": 1})
                        stub.files[kind][name] = body.decode()
                        return self._send(200, {"data": {"total_failed_items": 0}, "error": 0})
                    if name in stub.files[kind]:
                        return self._send(200, stub.files[kind][name].encode(), "text/plain")
                    if stub.missing_as_200:       # what the real manager does
                        return self._send(200, {"data": {"affected_items": [],
                                                         "total_failed_items": 1},
                                                "message": "No rule was returned", "error": 1})
                    return self._send(404, {"title": "Not found"})
                if path == "/logtest":
                    req = json.loads(body)
                    ev = json.loads(req["event"])
                    sent = req.get("token")
                    token = sent if sent == f"gen{stub.generation}" else f"gen{stub.generation}"
                    hit = "marker" in json.dumps(ev)
                    return self._send(200, {"error": 0, "data": {"token": token, "messages": ["ok"],
                                            "output": {"rule": {"id": "110001", "level": 8}}
                                            if hit else {}}})
                if path == "/manager/restart":
                    stub.restarts += 1
                    if not stub.frozen:
                        stub.generation += 1
                    return self._send(200, {"error": 0, "data": {"total_failed_items": 0}})
                return self._send(404, {"title": "Not found"})

            def do_GET(self):  # noqa: N802
                self._handle("GET")

            def do_PUT(self):  # noqa: N802
                self._handle("PUT")

            def do_POST(self):  # noqa: N802
                self._handle("POST")

            def do_DELETE(self):  # noqa: N802
                self._handle("DELETE")

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"https://127.0.0.1:{self.server.server_port}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture()
def stub(tmp_path):
    cert, key = make_cert(tmp_path)
    s = Stub(cert, key)
    s.cert = cert
    yield s
    s.stop()


def adapter(stub, **kw):
    return WazuhAdapter(stub.url, "atidep", "pw", ca_file=stub.cert, allowlist=ALLOW,
                        sleep=lambda s: None, **kw)


def test_files_are_written_and_read_back_through_the_api(stub):
    a = adapter(stub)
    a.put_rule_file("0910-atidep_rule_2026_0001.xml", "<group/>")
    a.put_list("atidep-domains", "bad.example.net:\n")
    assert a.get_rule_file("0910-atidep_rule_2026_0001.xml") == "<group/>"
    assert a.get_list("atidep-domains") == "bad.example.net:\n"
    assert a.get_rule_file("0911-atidep_missing.xml") is None
    assert all(c[0] in ("GET", "PUT", "POST") for c in stub.calls)


@pytest.mark.parametrize("as_200", [False, True])
def test_a_missing_file_is_none_never_an_error_document(stub, as_200):
    stub.missing_as_200 = as_200
    a = adapter(stub)
    assert a.get_rule_file("0911-atidep_missing.xml") is None
    assert a.get_list("atidep-missing") is None


def test_file_text_detection():
    ft = WazuhAdapter._file_text
    assert ft(200, "<group/>") == "<group/>" and ft(200, "a.example.net:\n") == "a.example.net:\n"
    assert ft(404, "<group/>") is None
    assert ft(200, '{"error": 1, "data": {}}') is None and ft(200, '{"title": "x"}') is None
    assert ft(200, "{not json but text") == "{not json but text"


@pytest.mark.parametrize("name", ["local_rules.xml", "0910-wazuh_rule.xml", "../0910-atidep_x.xml",
                                  "0910-atidep_X.xml", "10-atidep_x.xml", "0910-atidep_.xml"])
def test_rule_file_names_outside_the_atidep_pattern_never_reach_the_network(stub, name):
    a = adapter(stub)
    with pytest.raises(NotAllowed):
        a.put_rule_file(name, "<group/>")
    with pytest.raises(NotAllowed):
        a.get_rule_file(name)
    assert stub.calls == []


@pytest.mark.parametrize("name", ["malicious-ioc", "audit-keys", "atidep_x", "atidep-", "ATIDEP-x",
                                  "atidep-../x"])
def test_list_names_outside_the_atidep_pattern_are_refused(stub, name):
    with pytest.raises(NotAllowed):
        adapter(stub).put_list(name, "k:\n")
    assert stub.calls == []


def test_methods_and_paths_outside_the_allowlist_are_refused(stub):
    a = adapter(stub)
    for method, path in [("DELETE", "/rules/files/0910-atidep_x.xml"),
                         ("DELETE", "/lists/files/atidep-domains"),
                         ("PUT", "/manager/configuration"), ("GET", "/agents"),
                         ("PUT", "/active-response"), ("GET", "/security/users"),
                         ("PUT", "/rules/files/../../etc/x")]:
        with pytest.raises(NotAllowed):
            a._raw(method, path)
    assert stub.calls == []


def test_an_upload_that_fails_inside_http_200_is_an_error(stub):
    stub.fail_uploads = True
    with pytest.raises(AdapterError, match="XML syntax error"):
        adapter(stub).put_rule_file("0910-atidep_x.xml", "<broken")
    with pytest.raises(AdapterError, match="list atidep-domains failed"):
        adapter(stub).put_list("atidep-domains", "x:\n")


def test_restart_is_confirmed_by_the_engine_dropping_its_sessions_not_by_a_timer(stub):
    a = adapter(stub)
    seconds = a.restart(timeout=30)
    assert stub.restarts == 1 and seconds >= 0
    a.restart(timeout=30)
    assert stub.restarts == 2


def test_a_restart_that_never_resets_the_engine_times_out(stub):
    stub.frozen = True                       # the request is accepted but nothing restarts
    with pytest.raises(AdapterError, match="did not confirm"):
        adapter(stub).restart(timeout=0.2)


def test_logtest_reports_the_rule_that_fired(stub):
    a = adapter(stub)
    hit = a.logtest(json.dumps({"win": {"eventdata": {"commandLine": "marker"}}}))
    assert hit.fired_rule == 110001 and hit.level == 8
    miss = a.logtest(json.dumps({"win": {"eventdata": {"commandLine": "other"}}}))
    assert miss.fired_rule is None


def test_a_server_with_a_different_certificate_is_refused(stub, tmp_path):
    other, _ = make_cert(tmp_path, "other")
    a = WazuhAdapter(stub.url, "atidep", "pw", ca_file=other, allowlist=ALLOW)
    with pytest.raises(AdapterError, match="unreachable"):
        a.put_list("atidep-domains", "x:\n")
    assert stub.calls == []


def test_plain_http_urls_and_missing_credentials_are_refused(stub):
    with pytest.raises(AdapterError, match="https"):
        WazuhAdapter("http://127.0.0.1:55000", "u", "p", ca_file=stub.cert, allowlist=ALLOW)
    with pytest.raises(AdapterError, match="credentials"):
        WazuhAdapter(stub.url, "", "", ca_file=stub.cert, allowlist=ALLOW)


def test_an_expired_token_triggers_one_re_login(stub):
    a = adapter(stub)
    a.put_list("atidep-domains", "a:\n")
    a._token = "STALE"                      # the stub answers 401 for a stale token
    a.put_list("atidep-ips", "1.2.3.4:\n")
    logins = [c for c in stub.calls if c[1] == "/security/user/authenticate"]
    assert len(logins) == 2 and stub.files["lists"]["atidep-ips"] == "1.2.3.4:\n"


@pytest.mark.parametrize("path", [
    "/rules/files/../../etc/passwd", "/rules/files/%2e%2e/x", "/rules/files//x",
    "/rules/files/./0910-atidep_x.xml", "/lists/files/..%2fx", "/rules/files/a\\b",
    "/rules/files/x/y", "/rules/files", "rules/files/x", "/manager/restart/extra",
])
def test_path_tricks_do_not_slip_past_the_allowlist(stub, path):
    with pytest.raises(NotAllowed):
        adapter(stub)._raw("PUT", path)
    assert stub.calls == []


def test_a_wildcard_stands_for_one_segment_only(stub):
    a = adapter(stub)
    a._check("PUT", "/rules/files/0910-atidep_x.xml")                # one segment: allowed
    with pytest.raises(NotAllowed):
        a._check("PUT", "/rules/files/sub/0910-atidep_x.xml")        # two segments
