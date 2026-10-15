"""Turn the independent authors' raw outputs into case files, without judging them.

    python -m research.adversarial.authored import JOURNAL [--raw DIR] [--cases DIR]

``JOURNAL`` is the workflow journal (one JSON line per finished author, the return value under
``result``). Two things happen, in this order:

1. every author's raw return value is written, unedited, to ``--raw`` (default
   ``research/adversarial/authored/``), one file per author, named after the case-id prefix;
2. each case is validated against the case models and written as YAML under ``--cases``
   (default ``research/adversarial/cases/``): ``defects/``, ``controls/`` or ``injection/``.

A case that does not validate is **not repaired and not dropped silently**: it is listed with its
error in ``import_log.json`` next to the raw files, and the exit status is non-zero. Nothing here
runs a case against the system or inspects how the system treats it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from research.adversarial.cases import InjectionCase, RuleCase, dump_case

HERE = Path(__file__).resolve().parent


def read_journal(path: Path | str) -> list[dict[str, Any]]:
    """The authors' return values, the last one per journal key, empty ones left out (and
    reported by the caller as authors that returned nothing)."""
    latest: dict[str, dict[str, Any]] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("type") == "result" and isinstance(rec.get("result"), dict):
            latest[rec["key"]] = rec["result"]
    return list(latest.values())


def _items(result: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    if "cases" in result:
        return "cases", result["cases"]
    if "reports" in result:
        return "reports", result["reports"]
    return "", []


def import_journal(journal: Path | str, raw_dir: Path | str = HERE / "authored",
                   cases_dir: Path | str = HERE / "cases") -> dict[str, Any]:
    raw, cases = Path(raw_dir), Path(cases_dir)
    raw.mkdir(parents=True, exist_ok=True)
    log: dict[str, Any] = {"journal": str(journal), "authors": [], "written": [], "invalid": [],
                           "empty_authors": 0}
    for result in read_journal(journal):
        kind, items = _items(result)
        if not items:
            log["empty_authors"] += 1
            continue
        prefix = str(items[0].get("id", "")).split("-")[0] or "unknown"
        (raw / f"{prefix}.json").write_text(
            json.dumps(result, indent=1, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        log["authors"].append({"file": f"{prefix}.json", "kind": kind, "items": len(items)})
        for item in items:
            try:
                if kind == "cases":
                    case = RuleCase.model_validate(item)
                    sub = "defects" if case.role == "defective" else "controls"
                else:
                    case = InjectionCase.model_validate(item)
                    sub = "injection"
            except ValidationError as exc:
                log["invalid"].append({"id": item.get("id"), "error": str(exc)[:600]})
                continue
            path = cases / sub / f"{case.id}.yaml"
            dump_case(case, path)
            log["written"].append(str(path.relative_to(cases)))
    (raw / "import_log.json").write_text(json.dumps(log, indent=1, sort_keys=True),
                                         encoding="utf-8")
    return log


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m research.adversarial.authored")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("import")
    i.add_argument("journal")
    i.add_argument("--raw", default=str(HERE / "authored"))
    i.add_argument("--cases", default=str(HERE / "cases"))
    a = ap.parse_args(argv)
    log = import_journal(a.journal, a.raw, a.cases)
    print(f"{len(log['written'])} case file(s) written, {len(log['invalid'])} invalid, "
          f"{log['empty_authors']} author(s) returned nothing")
    for bad in log["invalid"]:
        print(f"  INVALID {bad['id']}: {bad['error'][:200]}")
    return 1 if log["invalid"] else 0


if __name__ == "__main__":
    sys.exit(main())
