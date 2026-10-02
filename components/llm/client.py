"""Provider-neutral LLM client interface and implementations (blueprint §13, §18, §22.7).

* ``OllamaClient``: a local model. Refuses any non-loopback address, so inference stays local.
* ``ReplayClient``: records every call and replays it later, so an experiment is deterministic,
  never paid for twice, and can be re-run without a model.
* ``ScriptedClient``: returns prepared outputs, for tests.
* ``GuardedClient``: wraps another client with a daily cost cap.

No client exposes tools, function calling or browsing; a request is a system prompt, a user
message and sampling settings.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit


class LLMError(Exception):
    pass


class BudgetExceeded(LLMError):
    pass


class ReplayMiss(LLMError):
    pass


@dataclass(frozen=True)
class LLMRequest:
    agent: str
    system: str
    user: str
    prompt_version: str
    temperature: float = 0.0
    seed: int | None = None
    max_tokens: int = 2048
    json_mode: bool = True


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    cost: float = 0.0
    replayed: bool = False


class LLMClient(Protocol):
    provider: str
    model: str

    def complete(self, request: LLMRequest) -> LLMResponse: ...


def request_key(request: LLMRequest, provider: str, model: str) -> str:
    payload = json.dumps({**asdict(request), "provider": provider, "model": model},
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---- local model --------------------------------------------------------------------------
class OllamaClient:
    provider = "ollama"

    def __init__(self, model: str, base_url: str = "http://127.0.0.1:11434",
                 timeout: float = 300.0, allow_remote: bool = False) -> None:
        host = urlsplit(base_url).hostname or ""
        if not allow_remote and not _is_loopback(host):
            raise LLMError(f"refusing non-local model endpoint {host!r}: inference is local-first")
        self.model, self.base_url, self.timeout = model, base_url.rstrip("/"), timeout

    def complete(self, request: LLMRequest) -> LLMResponse:
        import urllib.request

        options: dict = {"temperature": request.temperature, "num_predict": request.max_tokens}
        if request.seed is not None:
            options["seed"] = request.seed
        body = {"model": self.model, "stream": False, "options": options,
                "messages": [{"role": "system", "content": request.system},
                             {"role": "user", "content": request.user}]}
        if request.json_mode:
            body["format"] = "json"
        req = urllib.request.Request(self.base_url + "/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except OSError as exc:
            raise LLMError(f"model endpoint unreachable: {exc}") from exc
        return LLMResponse(
            text=data.get("message", {}).get("content", ""), provider=self.provider,
            model=self.model, input_tokens=int(data.get("prompt_eval_count", 0)),
            output_tokens=int(data.get("eval_count", 0)),
            latency_ms=int((time.monotonic() - t0) * 1000), cost=0.0)


def _is_loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# ---- scripted (tests) ---------------------------------------------------------------------
class ScriptedClient:
    provider = "scripted"

    def __init__(self, outputs: list[str | Callable[[LLMRequest], str]],
                 model: str = "scripted-1") -> None:
        self.model = model
        self._outputs = list(outputs)
        self.requests: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        if not self._outputs:
            raise LLMError("scripted client has no more outputs")
        out = self._outputs.pop(0)
        text = out(request) if callable(out) else out
        return LLMResponse(text=text, provider=self.provider, model=self.model,
                           input_tokens=len(request.user.split()),
                           output_tokens=len(text.split()))


# ---- record / replay ----------------------------------------------------------------------
class ReplayClient:
    """``replay``: only serve recorded calls. ``record``: call the inner client and store the
    result (serving from the store first). The store is an append-only JSONL file."""

    def __init__(self, path: Path | str, inner: LLMClient | None = None,
                 mode: str = "replay", *, provider: str | None = None,
                 model: str | None = None) -> None:
        if mode not in ("replay", "record"):
            raise ValueError("mode must be 'replay' or 'record'")
        if mode == "record" and inner is None:
            raise ValueError("record mode needs an inner client")
        self.path, self.inner, self.mode = Path(path), inner, mode
        self._store: dict[str, dict] = {}
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rec = json.loads(line)
                    self._store[rec["key"]] = rec
        # Recorded keys include the model identity, so a replay must know which model it stands
        # in for: the inner client's, an explicit one, or the only one in the store.
        if inner is not None:
            self.provider, self.model = inner.provider, inner.model
        else:
            seen = {(r["provider"], r["model"]) for r in self._store.values()}
            if provider and model:
                self.provider, self.model = provider, model
            elif len(seen) == 1:
                self.provider, self.model = next(iter(seen))
            else:
                raise ValueError("the recording holds "
                                 + ("no calls" if not seen else "several models")
                                 + "; pass provider= and model=")

    def complete(self, request: LLMRequest) -> LLMResponse:
        key = request_key(request, self.provider, self.model)
        rec = self._store.get(key)
        fresh = rec is None
        if rec is None and self.mode == "replay":
            raise ReplayMiss(f"no recorded response for request {key[:12]} ({request.agent})")
        if rec is None:
            assert self.inner is not None
            resp = self.inner.complete(request)
            rec = {"key": key, "agent": request.agent, "prompt_version": request.prompt_version,
                   "provider": self.provider, "model": self.model,
                   "recorded_at": datetime.now(UTC).isoformat(), "response": asdict(resp)}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._store[key] = rec
        # A call made just now is a real call (and is charged); only stored ones are replays.
        return LLMResponse(**{**rec["response"], "replayed": not fresh})

    def __len__(self) -> int:
        return len(self._store)


# ---- budget ------------------------------------------------------------------------------
@dataclass
class CostGuard:
    """Daily spend cap. Prices are per million tokens in the currency of the cap."""

    daily_limit: float
    price_in_per_mtok: float = 0.0
    price_out_per_mtok: float = 0.0
    spent: float = 0.0
    day: str = field(default_factory=lambda: datetime.now(UTC).date().isoformat())

    def _roll(self) -> None:
        today = datetime.now(UTC).date().isoformat()
        if today != self.day:
            self.day, self.spent = today, 0.0

    def check(self) -> None:
        self._roll()
        if self.spent >= self.daily_limit:
            raise BudgetExceeded(f"daily cost limit {self.daily_limit} reached")

    def charge(self, response: LLMResponse) -> float:
        cost = (response.input_tokens * self.price_in_per_mtok
                + response.output_tokens * self.price_out_per_mtok) / 1_000_000
        self.spent += cost
        return cost


class GuardedClient:
    def __init__(self, inner: LLMClient, guard: CostGuard) -> None:
        self.inner, self.guard = inner, guard
        self.provider, self.model = inner.provider, inner.model

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.guard.check()
        resp = self.inner.complete(request)
        if not resp.replayed:
            resp.cost = self.guard.charge(resp)
        return resp
