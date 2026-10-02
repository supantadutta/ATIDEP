"""Content-addressed evidence store and near-duplicate fingerprints (blueprint §17.1).

Raw bytes are stored exactly as received under their SHA-256, so the evidence can always be
re-verified. The sanitised text is stored beside it. Nothing is ever overwritten with
different content.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path

_WORD = re.compile(r"\w+", re.UNICODE)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class EvidenceIntegrityError(Exception):
    pass


class EvidenceStore:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    def _path(self, sha: str, suffix: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError("not a SHA-256 digest")
        return self.root / sha[:2] / f"{sha}{suffix}"

    def _write(self, path: Path, data: bytes) -> None:
        if path.exists():
            if path.read_bytes() != data:
                raise EvidenceIntegrityError(f"{path.name} already exists with different content")
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def save_raw(self, data: bytes) -> str:
        sha = sha256_hex(data)
        self._write(self._path(sha, ".raw"), data)
        return sha

    def save_text(self, raw_sha: str, text: str) -> str:
        """Store sanitised text next to its raw evidence; returns the text's own SHA-256."""
        data = text.encode("utf-8")
        self._write(self._path(raw_sha, ".txt"), data)
        return sha256_hex(data)

    def load_raw(self, sha: str) -> bytes:
        data = self._path(sha, ".raw").read_bytes()
        if sha256_hex(data) != sha:
            raise EvidenceIntegrityError(f"{sha} no longer matches its content")
        return data

    def load_text(self, raw_sha: str) -> str:
        return self._path(raw_sha, ".txt").read_text(encoding="utf-8")


# ---- near-duplicate detection: bottom-k sketch over word shingles --------------------------
def fingerprint(text: str, *, k: int = 64, shingle: int = 5) -> list[int]:
    words = [w.lower() for w in _WORD.findall(text)]
    if len(words) < shingle:
        grams = [" ".join(words)] if words else []
    else:
        grams = [" ".join(words[i:i + shingle]) for i in range(len(words) - shingle + 1)]
    hashes = {int.from_bytes(hashlib.blake2b(g.encode(), digest_size=8).digest(), "big")
              for g in grams}
    return sorted(hashes)[:k]


def similarity(a: list[int], b: list[int], k: int = 64) -> float:
    """Estimated Jaccard similarity of the two shingle sets from their bottom-k sketches."""
    if not a or not b:
        return 0.0
    union_sketch = sorted(set(a) | set(b))[:k]
    shared = set(a) & set(b)
    return sum(1 for h in union_sketch if h in shared) / len(union_sketch)
