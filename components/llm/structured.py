"""Strict structured output (blueprint §18). Output that does not validate is rejected and the
model is asked again with the validation error; it is never repaired or "fixed up" here."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from components.llm.client import LLMClient, LLMRequest, LLMResponse

T = TypeVar("T", bound=BaseModel)


class SchemaError(Exception):
    def __init__(self, message: str, calls: list[CallRecord]) -> None:
        super().__init__(message)
        self.calls = calls


@dataclass
class CallRecord:
    request: LLMRequest
    response: LLMResponse
    attempt: int
    schema_valid: bool
    error: str | None = None


def extract_json(text: str) -> str:
    """The first balanced top-level JSON object in the text (models sometimes wrap it in a
    code fence or add a sentence). Returns the text unchanged if no object is found."""
    start = text.find("{")
    if start < 0:
        return text
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text


def structured_call(client: LLMClient, request: LLMRequest, model: type[T], *,
                    max_retries: int = 2) -> tuple[T, list[CallRecord]]:
    calls: list[CallRecord] = []
    req = request
    for attempt in range(max_retries + 1):
        resp = client.complete(req)
        try:
            parsed = model.model_validate_json(extract_json(resp.text))
        except (ValidationError, ValueError) as exc:
            msg = _short(exc)
            calls.append(CallRecord(req, resp, attempt, False, msg))
            req = LLMRequest(
                agent=request.agent, system=request.system, prompt_version=request.prompt_version,
                temperature=request.temperature, seed=request.seed, max_tokens=request.max_tokens,
                json_mode=request.json_mode,
                user=request.user + "\n\nYour previous output was not valid: " + msg +
                "\nReturn only one JSON object that matches the schema.")
            continue
        calls.append(CallRecord(req, resp, attempt, True))
        return parsed, calls
    raise SchemaError(f"no valid output after {max_retries + 1} attempts", calls)


def _short(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        errs = exc.errors()[:3]
        return "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in errs)
    return str(exc)[:200] if not isinstance(exc, json.JSONDecodeError) else "not valid JSON"
