"""Versioned prompts. The version string and SHA-256 of each prompt file are recorded with
every model call (blueprint §18)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

PROMPT_DIR = Path(__file__).resolve().parents[2] / "prompts"


@dataclass(frozen=True)
class Prompt:
    name: str
    text: str
    sha256: str

    @property
    def version(self) -> str:
        return self.name


def load_prompt(name: str, directory: Path = PROMPT_DIR) -> Prompt:
    text = (directory / f"{name}.md").read_text(encoding="utf-8")
    return Prompt(name=name, text=text, sha256=hashlib.sha256(text.encode("utf-8")).hexdigest())


@dataclass(frozen=True)
class PromptSet:
    """Every prompt a run uses, frozen together. ``sha256`` identifies the set in the results."""

    extraction: Prompt
    opportunity: Prompt
    rule: Prompt
    improvement: Prompt
    baseline: Prompt

    @property
    def sha256(self) -> str:
        parts = [p.sha256 for p in (self.extraction, self.opportunity, self.rule,
                                    self.improvement, self.baseline)]
        return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def load_prompt_set(directory: Path = PROMPT_DIR) -> PromptSet:
    return PromptSet(
        extraction=load_prompt("extraction_v1", directory),
        opportunity=load_prompt("opportunity_v1", directory),
        rule=compose_prompt("rule_v1", ["rule_v1", "sigma_subset_v0"], directory),
        improvement=load_prompt("improvement_v1", directory),
        baseline=compose_prompt("single_prompt_baseline_v1",
                                ["single_prompt_baseline_v1", "sigma_subset_v0"], directory))


def compose_prompt(name: str, parts: list[str], directory: Path = PROMPT_DIR) -> Prompt:
    """One prompt made of several files (for example instructions plus the Sigma subset
    specification). The hash covers the combined text, so changing any part changes it."""
    text = "\n\n".join((directory / f"{p}.md").read_text(encoding="utf-8").strip()
                       for p in parts) + "\n"
    return Prompt(name=name, text=text, sha256=hashlib.sha256(text.encode("utf-8")).hexdigest())
