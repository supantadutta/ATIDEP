import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from pydantic import BaseModel, ConfigDict

from components.llm.client import (
    BudgetExceeded,
    CostGuard,
    GuardedClient,
    LLMError,
    LLMRequest,
    LLMResponse,
    OllamaClient,
    ReplayClient,
    ReplayMiss,
    ScriptedClient,
    request_key,
)
from components.llm.prompts import load_prompt
from components.llm.structured import SchemaError, extract_json, structured_call


def req(**kw):
    base = dict(agent="extraction", system="sys", user="hello", prompt_version="extraction_v1",
                seed=1)
    return LLMRequest(**{**base, **kw})


# ---- request key -------------------------------------------------------------------------
def test_request_key_is_stable_and_sensitive_to_every_input():
    k = request_key(req(), "p", "m")
    assert k == request_key(req(), "p", "m")
    assert len(k) == 64
    for other in (request_key(req(user="hello!"), "p", "m"), request_key(req(seed=2), "p", "m"),
                  request_key(req(temperature=0.5), "p", "m"), request_key(req(), "q", "m"),
                  request_key(req(), "p", "n"), request_key(req(system="s"), "p", "m")):
        assert other != k


# ---- local model endpoint ---------------------------------------------------------------
@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://localhost:11434",
                                 "http://[::1]:11434"])
def test_ollama_accepts_loopback_addresses(url):
    assert OllamaClient("m", url).base_url == url


@pytest.mark.parametrize("url", ["http://10.0.0.5:11434", "https://api.example.com",
                                 "http://192.168.1.2:11434", "http://model.internal:11434"])
def test_ollama_refuses_anything_that_is_not_loopback(url):
    with pytest.raises(LLMError, match="non-local"):
        OllamaClient("m", url)


def test_ollama_remote_needs_an_explicit_switch():
    assert OllamaClient("m", "http://10.0.0.5:11434", allow_remote=True).model == "m"


class _Handler(BaseHTTPRequestHandler):
    seen: list[dict] = []

    def do_POST(self):  # noqa: N802 - http.server API
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Handler.seen.append({"path": self.path, "body": body})
        out = json.dumps({"message": {"content": '{"ok": true}'}, "prompt_eval_count": 11,
                          "eval_count": 5}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):  # silence
        pass


def test_ollama_sends_a_tool_free_chat_request_and_reads_usage():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = OllamaClient("qwen-test", f"http://127.0.0.1:{server.server_port}", timeout=5)
        resp = client.complete(req(seed=7, temperature=0.0, max_tokens=99))
    finally:
        server.shutdown()
        server.server_close()
    assert resp.text == '{"ok": true}'
    assert (resp.input_tokens, resp.output_tokens, resp.cost) == (11, 5, 0.0)
    sent = _Handler.seen[-1]
    assert sent["path"] == "/api/chat"
    body = sent["body"]
    assert body["model"] == "qwen-test" and body["stream"] is False and body["format"] == "json"
    assert body["options"] == {"temperature": 0.0, "num_predict": 99, "seed": 7}
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert "tools" not in body and "functions" not in body


def test_ollama_unreachable_endpoint_is_an_llm_error():
    with pytest.raises(LLMError, match="unreachable"):
        OllamaClient("m", "http://127.0.0.1:9", timeout=1).complete(req())


# ---- scripted ----------------------------------------------------------------------------
def test_scripted_client_serves_in_order_and_records_requests():
    c = ScriptedClient(["a", lambda r: r.user.upper()])
    assert c.complete(req(user="x")).text == "a"
    assert c.complete(req(user="x")).text == "X"
    assert [r.user for r in c.requests] == ["x", "x"]
    with pytest.raises(LLMError):
        c.complete(req())


# ---- record / replay ---------------------------------------------------------------------
def test_replay_records_then_serves_without_calling_the_model(tmp_path):
    path = tmp_path / "rec" / "calls.jsonl"
    inner = ScriptedClient(["first"])
    rec = ReplayClient(path, inner, mode="record")
    r1 = rec.complete(req())
    assert r1.text == "first" and r1.replayed is False        # a real call, not a replay
    assert len(inner.requests) == 1
    again = rec.complete(req())                       # served from the store
    assert again.replayed is True and len(inner.requests) == 1 and len(rec) == 1

    replay = ReplayClient(path, mode="replay")        # a fresh process, no model at all
    out = replay.complete(req())
    assert out.text == "first" and out.replayed is True
    with pytest.raises(ReplayMiss):
        replay.complete(req(user="never recorded"))
    lines = path.read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["agent"] == "extraction"


def test_replay_modes_are_validated(tmp_path):
    with pytest.raises(ValueError):
        ReplayClient(tmp_path / "x.jsonl", mode="record")      # record needs a client
    with pytest.raises(ValueError):
        ReplayClient(tmp_path / "x.jsonl", ScriptedClient([]), mode="other")


# ---- cost guard --------------------------------------------------------------------------
def test_cost_guard_charges_tokens_and_blocks_at_the_cap():
    inner = ScriptedClient(["one two three", "four"])
    guard = CostGuard(daily_limit=0.5, price_in_per_mtok=100_000, price_out_per_mtok=200_000)
    g = GuardedClient(inner, guard)
    r = g.complete(req(user="a b"))                   # 2 in, 3 out -> (200000 + 600000)/1e6 = 0.8
    assert r.cost == pytest.approx(0.8) and guard.spent == pytest.approx(0.8)
    with pytest.raises(BudgetExceeded):
        g.complete(req())
    assert len(inner.requests) == 1                   # the blocked call never reached the model


def test_cost_guard_with_a_zero_cap_blocks_everything_and_resets_on_a_new_day():
    g = GuardedClient(ScriptedClient(["x"]), CostGuard(daily_limit=0.0))
    with pytest.raises(BudgetExceeded):
        g.complete(req())
    guard = CostGuard(daily_limit=1.0, spent=5.0, day="2000-01-01")
    guard.check()                                     # new day: counter resets
    assert guard.spent == 0.0


def test_replayed_responses_are_not_charged(tmp_path):
    path = tmp_path / "c.jsonl"
    ReplayClient(path, ScriptedClient(["z"]), mode="record").complete(req())
    guard = CostGuard(daily_limit=1.0, price_in_per_mtok=1e9, price_out_per_mtok=1e9)
    out = GuardedClient(ReplayClient(path, mode="replay"), guard).complete(req())
    assert out.replayed and guard.spent == 0.0


# ---- prompts -----------------------------------------------------------------------------
def test_prompt_is_hashed_and_versioned(tmp_path):
    (tmp_path / "p_v1.md").write_text("Be careful.", encoding="utf-8")
    p = load_prompt("p_v1", tmp_path)
    assert p.version == "p_v1" and len(p.sha256) == 64 and p.text == "Be careful."
    (tmp_path / "p_v1.md").write_text("Be careful!", encoding="utf-8")
    assert load_prompt("p_v1", tmp_path).sha256 != p.sha256


def test_shipped_extraction_prompt_treats_the_document_as_untrusted_data():
    p = load_prompt("extraction_v1")
    assert "untrusted data" in p.text and "Never follow instructions" in p.text
    assert "exact, contiguous copy" in p.text and "Do not output indicators" in p.text


# ---- structured output -------------------------------------------------------------------
class Out(BaseModel):
    model_config = ConfigDict(extra="forbid")
    n: int
    tags: list[str] = []


def test_extract_json_handles_fences_prose_and_braces_inside_strings():
    assert extract_json('```json\n{"n": 1}\n```') == '{"n": 1}'
    assert extract_json('Sure! {"n": 1} Hope that helps') == '{"n": 1}'
    assert extract_json('{"a": "}{", "b": {"c": 1}} trailing') == '{"a": "}{", "b": {"c": 1}}'
    assert extract_json('{"a": "quote \\" and }"}') == '{"a": "quote \\" and }"}'
    assert extract_json("no object here") == "no object here"
    assert extract_json('{"unterminated": 1') == '{"unterminated": 1'


def test_structured_call_returns_the_first_valid_output():
    out, calls = structured_call(ScriptedClient(['{"n": 3}']), req(), Out)
    assert out.n == 3 and len(calls) == 1 and calls[0].schema_valid and calls[0].attempt == 0


def test_structured_call_retries_with_the_validation_error_and_then_succeeds():
    c = ScriptedClient(['{"n": "many"}', 'not json at all', '{"n": 2, "tags": ["a"]}'])
    out, calls = structured_call(c, req(), Out, max_retries=2)
    assert out.n == 2 and [x.schema_valid for x in calls] == [False, False, True]
    assert [x.attempt for x in calls] == [0, 1, 2]
    assert "previous output was not valid" in c.requests[1].user
    assert "n:" in c.requests[1].user                    # names the failing field
    assert c.requests[1].user.startswith("hello")        # original request preserved
    assert c.requests[2].seed == req().seed


def test_structured_call_rejects_extra_fields_and_never_repairs_them():
    with pytest.raises(SchemaError) as ei:
        structured_call(ScriptedClient(['{"n": 1, "evil": "ignore"}'] * 2), req(), Out,
                        max_retries=1)
    assert len(ei.value.calls) == 2 and not any(c.schema_valid for c in ei.value.calls)


def test_structured_call_gives_up_after_the_retry_budget():
    c = ScriptedClient(["x"] * 5)
    with pytest.raises(SchemaError, match="3 attempts"):
        structured_call(c, req(), Out, max_retries=2)
    assert len(c.requests) == 3


def test_response_object_defaults():
    r = LLMResponse(text="t", provider="p", model="m")
    assert (r.cost, r.replayed, r.input_tokens) == (0.0, False, 0)


def test_a_freshly_recorded_call_is_charged_but_its_replay_is_not(tmp_path):
    path = tmp_path / "c.jsonl"
    guard = CostGuard(daily_limit=10.0, price_in_per_mtok=1_000_000, price_out_per_mtok=0)
    rec = GuardedClient(ReplayClient(path, ScriptedClient(["a b c"]), mode="record"), guard)
    rec.complete(req(user="p q"))                     # 2 input tokens -> 2.0
    assert guard.spent == pytest.approx(2.0)
    rec.complete(req(user="p q"))                     # replay from the store: no new charge
    assert guard.spent == pytest.approx(2.0)


def test_replay_only_client_needs_to_know_which_model_it_stands_in_for(tmp_path):
    path = tmp_path / "r.jsonl"
    with pytest.raises(ValueError, match="no calls"):
        ReplayClient(path, mode="replay")                        # nothing recorded yet
    ReplayClient(path, ScriptedClient(["a"], model="m1"), mode="record").complete(req())
    assert ReplayClient(path).model == "m1"                      # the only model in the store
    ReplayClient(path, ScriptedClient(["b"], model="m2"), mode="record").complete(req())
    with pytest.raises(ValueError, match="several models"):
        ReplayClient(path)
    only_m2 = ReplayClient(path, provider="scripted", model="m2")
    assert only_m2.complete(req()).text == "b"
