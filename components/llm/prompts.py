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
