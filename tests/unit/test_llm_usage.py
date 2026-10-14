"""Usage and compute capture (blueprint §22.2): what a model call reports, how it is recorded,
and the cloud client that lets the same pipeline run on a paid backend."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.db import models as m
from app.db.session import init_db, make_engine, session_scope
from app.services.model_runs import log_calls
from components.llm.client import (
    CloudChatClient,
    LLMError,
    LLMRequest,
    OllamaClient,
    ReplayClient,
    ScriptedClient,
    estimate_tokens,
    is_cloud_provider,
    request_key,
)
from components.llm.prompts import load_prompt
from components.llm.structured import CallRecord
from research.metrics import cost_metrics, time_kinds
from tests.unit.test_c5_adapter import make_cert


def req(**kw):
    base = dict(agent="extraction", system="sys", user="hello", prompt_version="extraction_v1",
                seed=1)
    return LLMRequest(**{**base, **kw})


class Stub:
    """A one-route HTTP server that returns a prepared reply and records what it was sent."""

    def __init__(self, reply, status=200, tls=None, redirect_to=None):
        self.seen, outer = [], self
        self.reply, self.status, self.redirect_to = reply, status, redirect_to

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server API
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.seen.append({"path": self.path, "body": body,
                                   "headers": {k.lower(): v for k, v in self.headers.items()}})
                if outer.redirect_to:
                    self.send_response(307)
                    self.send_header("Location", outer.redirect_to)
                    self.end_headers()
                    return
                out = json.dumps(outer.reply).encode()
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.scheme = "http"
        if tls:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls)
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
            self.scheme = "https"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"{self.scheme}://127.0.0.1:{self.server.server_port}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture()
def stub_factory():
    made = []

    def make(*a, **kw):
        s = Stub(*a, **kw)
        made.append(s)
        return s
    yield make
    for s in made:
        s.stop()


OPENAI = {"choices": [{"message": {"content": '{"ok": true}'}}],
          "usage": {"prompt_tokens": 120, "completion_tokens": 30}}
ANTHROPIC = {"content": [{"type": "text", "text": '{"ok": '}, {"type": "text", "text": "true}"}],
             "usage": {"input_tokens": 200, "output_tokens": 40}}


# ---- local model ------------------------------------------------------------------------------
def test_ollama_reports_provider_usage_and_compute_time(stub_factory):
    s = stub_factory({"message": {"content": "{}"}, "prompt_eval_count": 11, "eval_count": 5,
                      "total_duration": 2_500_000_000, "load_duration": 400_000_000})
    r = OllamaClient("q", s.url, timeout=5).complete(req())
    assert (r.input_tokens, r.output_tokens) == (11, 5)
    assert r.usage_source == "provider" and r.compute_ms == 2500
    assert not is_cloud_provider(r.provider)


def test_a_missing_prompt_count_is_marked_partial_not_complete(stub_factory):
    """A local server may omit the prompt count for a cached prompt; the counts are then low."""
    s = stub_factory({"message": {"content": "{}"}, "eval_count": 5})
    r = OllamaClient("q", s.url, timeout=5).complete(req())
    assert r.usage_source == "provider_partial" and r.input_tokens == 0 and r.compute_ms is None


def test_no_usage_at_all_is_unknown(stub_factory):
    s = stub_factory({"message": {"content": "{}"}})
    r = OllamaClient("q", s.url, timeout=5).complete(req())
    assert r.usage_source == "unknown" and r.compute_ms is None


def test_scripted_usage_is_marked_as_an_estimate():
    assert ScriptedClient(["a b"]).complete(req()).usage_source == "estimated"


def test_old_recordings_without_the_new_fields_still_replay(tmp_path):
    path = tmp_path / "calls.jsonl"
    old = {"key": request_key(req(), "ollama", "q"), "agent": "extraction",
           "prompt_version": "v", "provider": "ollama", "model": "q",
           "recorded_at": "2026-01-01T00:00:00+00:00",
           "response": {"text": "x", "provider": "ollama", "model": "q", "input_tokens": 3,
                        "output_tokens": 2, "latency_ms": 9, "cost": 0.0, "replayed": False}}
    path.write_text(json.dumps(old) + "\n")
    resp = ReplayClient(path, mode="replay").complete(req())
    assert resp.replayed and resp.input_tokens == 3
    assert resp.usage_source == "unknown" and resp.compute_ms is None


# ---- cloud client -----------------------------------------------------------------------------
def test_openai_style_request_has_no_tools_and_carries_the_key_in_a_header(stub_factory):
    s = stub_factory(OPENAI)
    c = CloudChatClient("openai", s.url + "/v1", "m-1", "sk-secret", timeout=5)
    r = c.complete(req(seed=7, temperature=0.0, max_tokens=99))
    seen = s.seen[0]
    assert seen["path"] == "/v1/chat/completions"
    assert seen["headers"]["authorization"] == "Bearer sk-secret"
    b = seen["body"]
    assert b["model"] == "m-1" and b["seed"] == 7 and b["max_tokens"] == 99
    assert b["response_format"] == {"type": "json_object"}
    assert [x["role"] for x in b["messages"]] == ["system", "user"]
    assert "tools" not in b and "functions" not in b and "tool_choice" not in b
    assert (r.text, r.input_tokens, r.output_tokens) == ('{"ok": true}', 120, 30)
    assert r.usage_source == "provider" and r.provider == "cloud-openai"
    assert is_cloud_provider(r.provider) and r.compute_ms is None


def test_anthropic_style_request_and_usage(stub_factory):
    s = stub_factory(ANTHROPIC)
    c = CloudChatClient("anthropic", s.url, "m-2", "key-xyz", timeout=5)
    r = c.complete(req())
    seen = s.seen[0]
    assert seen["path"] == "/v1/messages"
    assert seen["headers"]["x-api-key"] == "key-xyz" and "authorization" not in seen["headers"]
    assert seen["body"]["system"] == "sys" and seen["body"]["messages"][0]["role"] == "user"
    assert "tools" not in seen["body"]
    assert r.text == '{"ok": true}' and (r.input_tokens, r.output_tokens) == (200, 40)
    assert r.usage_source == "provider" and r.provider == "cloud-anthropic"


def test_missing_usage_falls_back_to_a_marked_estimate(stub_factory):
    s = stub_factory({"choices": [{"message": {"content": "abcdefgh"}}]})
    r = CloudChatClient("openai", s.url, "m", "k", timeout=5).complete(req(user="x" * 40))
    assert r.usage_source == "estimated" and r.output_tokens == 2 and r.input_tokens >= 10


def test_the_key_never_appears_in_repr_or_errors(stub_factory):
    s = stub_factory({"error": "denied sk-secret"}, status=401)
    c = CloudChatClient("openai", s.url, "m", "sk-secret", timeout=5)
    assert "sk-secret" not in repr(c)
    with pytest.raises(LLMError, match="HTTP 401") as exc:
        c.complete(req())
    assert "sk-secret" not in str(exc.value)


def test_a_redirect_is_not_followed_so_the_key_cannot_travel(stub_factory):
    target = stub_factory(OPENAI)
    s = stub_factory(OPENAI, redirect_to=target.url + "/elsewhere")
    with pytest.raises(LLMError, match="HTTP 307"):
        CloudChatClient("openai", s.url, "m", "k", timeout=5).complete(req())
    assert target.seen == []


@pytest.mark.parametrize("reply", [{}, {"choices": []}, {"content": "text"}, ["x"]])
def test_an_unexpected_reply_is_an_error_not_a_guess(stub_factory, reply):
    s = stub_factory(reply)
    style = "anthropic" if "content" in reply else "openai"
    with pytest.raises(LLMError, match="unexpected reply"):
        CloudChatClient(style, s.url, "m", "k", timeout=5).complete(req())


def test_endpoint_rules():
    with pytest.raises(LLMError, match="https"):
        CloudChatClient("openai", "http://api.example.com/v1", "m", "k")
    with pytest.raises(LLMError, match="api_style"):
        CloudChatClient("grpc", "https://api.example.com", "m", "k")  # type: ignore[arg-type]
    with pytest.raises(LLMError, match="key"):
        CloudChatClient("openai", "https://api.example.com/v1", "m", "")
    assert CloudChatClient("openai", "http://127.0.0.1:1/v1", "m", "k").model == "m"


def test_https_with_a_pinned_certificate(stub_factory, tmp_path):
    crt, key = make_cert(tmp_path)
    s = stub_factory(OPENAI, tls=(crt, key))
    ok = CloudChatClient("openai", s.url + "/v1", "m", "k", timeout=5, ca_file=crt)
    assert ok.complete(req()).input_tokens == 120
    with pytest.raises(LLMError, match="unreachable"):         # system CAs do not know this cert
        CloudChatClient("openai", s.url + "/v1", "m", "k", timeout=5).complete(req())


def test_estimate_tokens():
    assert estimate_tokens("") == 0 and estimate_tokens("abcd") == 1 and estimate_tokens("abcde") == 2


# ---- recording and aggregation ------------------------------------------------------------------
def _calls(client, n=2):
    return [CallRecord(req(), client.complete(req()), i, True) for i in range(n)]


def test_calls_are_logged_with_their_provenance_and_summed_without_inventing_compute(stub_factory):
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    prompt = load_prompt("extraction_v1")
    local = stub_factory({"message": {"content": "{}"}, "prompt_eval_count": 10, "eval_count": 4,
                          "total_duration": 1_000_000_000})
    cloud = stub_factory(OPENAI)
    with session_scope(engine) as s:
        log_calls(s, run_id="r", agent="extraction", intel_id=None, prompt=prompt,
                  calls=_calls(OllamaClient("q", local.url, timeout=5)))
        log_calls(s, run_id="r", agent="rule", intel_id=None, prompt=prompt,
                  calls=_calls(CloudChatClient("openai", cloud.url + "/v1", "m", "k", timeout=5)))
        rows = s.query(m.ModelRun).order_by(m.ModelRun.id).all()
        assert [r.usage_source for r in rows] == ["provider"] * 4
        assert [r.compute_ms for r in rows] == [1000, 1000, None, None]
        c = cost_metrics(s)
    assert c["model_calls"] == 4 and c["input_tokens"] == 2 * 10 + 2 * 120
    assert c["model_compute_ms"] == 2000 and c["calls_with_compute_time"] == 2
    assert c["usage_sources"] == {"provider": 4}
    assert c["providers"] == ["cloud-openai", "ollama"]


def test_compute_time_is_none_when_no_call_reported_it():
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    prompt = load_prompt("extraction_v1")
    with session_scope(engine) as s:
        log_calls(s, run_id="r", agent="extraction", intel_id=None, prompt=prompt,
                  calls=_calls(ScriptedClient(["a", "b"])))
        c = cost_metrics(s)
    assert c["model_compute_ms"] is None and c["usage_sources"] == {"estimated": 2}


def test_replayed_calls_are_flagged_so_cash_spent_can_exclude_them(tmp_path):
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    prompt = load_prompt("extraction_v1")
    rc = ReplayClient(tmp_path / "c.jsonl", ScriptedClient(["x"]), mode="record")
    with session_scope(engine) as s:
        log_calls(s, run_id="r", agent="extraction", intel_id=None, prompt=prompt,
                  calls=[CallRecord(req(), rc.complete(req()), 0, True),
                         CallRecord(req(), rc.complete(req()), 1, True)])
        assert [r.replayed for r in s.query(m.ModelRun).order_by(m.ModelRun.id)] == [False, True]
        assert cost_metrics(s)["replayed_calls"] == 1


def test_time_kinds_keep_model_waiting_apart_from_automated_work():
    t = time_kinds({"processing": 4.0, "rules": 6.0}, model_latency_ms=7500, wall_seconds=11.2)
    assert t == {"wall_seconds": 11.2, "stage_seconds": 10.0, "model_wait_seconds": 7.5,
                 "automated_seconds": 2.5}
    assert time_kinds({"x": 1.0}, 5000, 1.5)["automated_seconds"] == 0.0     # never negative
