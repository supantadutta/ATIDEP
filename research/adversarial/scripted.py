"""A model stand-in for the adversarial evaluation: it answers by agent, from functions that the
evaluation supplies, and never calls anything. It reports no real token usage."""

from __future__ import annotations

from collections.abc import Callable

from components.llm.client import LLMError, LLMRequest, LLMResponse

Answer = str | Callable[[LLMRequest], str]


class AgentRouter:
    provider = "scripted"
    model = "adversarial-stand-in"

    def __init__(self, **by_agent: Answer) -> None:
        self.by_agent = by_agent
        self.requests: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        answer = self.by_agent.get(request.agent)
        if answer is None:
            raise LLMError(f"no scripted answer for agent {request.agent}")
        text = answer(request) if callable(answer) else answer
        return LLMResponse(text=text, provider=self.provider, model=self.model,
                           input_tokens=len(request.user.split()),
                           output_tokens=len(text.split()), usage_source="estimated")
