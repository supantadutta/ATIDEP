"""Deployment package: files, a manifest of their SHA-256 hashes, one package checksum
(blueprint §17.5.1).

The package holds no timestamps, so the same inputs always give the same checksum, and a
reviewer can recompute it. ``verify`` re-reads a package from disk and reports every file that
is missing, extra or changed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST = "manifest.json"


class PackageError(Exception):
    pass


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe(path: str) -> str:
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts or not p.parts or "\\" in path or path == MANIFEST:
        raise PackageError(f"unsafe package path {path!r}")
    return str(p)


@dataclass(frozen=True)
class Package:
    name: str
    files: dict[str, bytes]
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def manifest(self) -> dict[str, Any]:
        return {"name": self.name, "meta": self.meta,
                "files": {p: _sha(b) for p, b in sorted(self.files.items())}}

    @property
    def sha256(self) -> str:
        return _sha(_canonical(self.manifest))

    def with_files(self, extra: dict[str, bytes]) -> Package:
        return Package(self.name, {**self.files, **{_safe(k): v for k, v in extra.items()}},
                       self.meta)


def build_package(name: str, files: dict[str, bytes | str], meta: dict[str, Any]) -> Package:
    clean = {_safe(p): (b.encode("utf-8") if isinstance(b, str) else b)
             for p, b in files.items()}
    if not clean:
        raise PackageError("a package needs at least one file")
    return Package(name, clean, meta)


def write_package(pkg: Package, root: Path | str) -> Path:
    target = Path(root) / pkg.name
    if target.exists():
        raise PackageError(f"{target} already exists; packages are never overwritten")
    for path, data in pkg.files.items():
        out = target / path
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
    (target / MANIFEST).write_bytes(json.dumps(
        {**pkg.manifest, "package_sha256": pkg.sha256}, indent=2, sort_keys=True,
        ensure_ascii=False).encode() + b"\n")
    return target


def load_package(path: Path | str) -> Package:
    root = Path(path)
    doc = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    files = {p: (root / p).read_bytes() for p in doc["files"] if (root / p).is_file()}
    return Package(doc["name"], files, doc.get("meta", {}))


def verify_package(path: Path | str) -> list[str]:
    """Problems found in a package on disk; an empty list means it is intact."""
    root = Path(path)
    try:
        doc = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["the manifest is missing or unreadable"]
    problems: list[str] = []
    expected = doc.get("files", {})
    for rel, digest in expected.items():
        f = root / rel
        if not f.is_file():
            problems.append(f"missing: {rel}")
        elif _sha(f.read_bytes()) != digest:
            problems.append(f"changed: {rel}")
    on_disk = {str(p.relative_to(root)).replace("\\", "/") for p in root.rglob("*")
               if p.is_file() and p.name != MANIFEST}
    problems += [f"unlisted: {rel}" for rel in sorted(on_disk - set(expected))]
    body = {"name": doc.get("name"), "meta": doc.get("meta", {}), "files": expected}
    if doc.get("package_sha256") != _sha(_canonical(body)):
        problems.append("the package checksum does not match the manifest")
    return problems
