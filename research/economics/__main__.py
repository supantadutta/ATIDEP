"""``python -m research.economics check`` lists what the cost inputs still lack and who has to
supply it; ``python -m research.economics report`` regenerates the economic tables from an export
folder (``research.export.export_results``)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.config import DEFAULT_CONFIG_DIR
from research.economics.inputs import load_cost_inputs, readiness
from research.economics.report import run_report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m research.economics")
    sub = ap.add_subparsers(dest="cmd", required=True)
    chk = sub.add_parser("check", help="what the cost inputs still lack")
    chk.add_argument("--config", default=str(DEFAULT_CONFIG_DIR))
    rep = sub.add_parser("report", help="regenerate the economic tables")
    rep.add_argument("--config", default=str(DEFAULT_CONFIG_DIR))
    rep.add_argument("--export", required=True, help="folder written by export_results")
    rep.add_argument("--out", required=True)
    rep.add_argument("--dataset", help="dataset folder (for item categories)")
    rep.add_argument("--technical", help="JSON file {h2, h3, h4: true|false|null}")
    rep.add_argument("--resamples", type=int)
    a = ap.parse_args(argv)
    if a.cmd == "check":
        gaps = readiness(load_cost_inputs(a.config))
        if not gaps:
            print("The cost inputs are complete.")
            return 0
        print(f"{len(gaps)} input(s) still missing:\n")
        for g in gaps:
            print(f"- {g.what}  [{g.supplied_by}]  needed for {g.needed_for}\n    {g.how}")
        return 1
    categories = None
    if a.dataset:
        from research.dataset.model import load_dataset
        categories = {i.id: i.category for i in load_dataset(a.dataset).items}
    technical = json.loads(Path(a.technical).read_text()) if a.technical else None
    run_report(a.config, a.export, a.out, categories=categories, technical=technical,
               resamples=a.resamples)
    print(f"written to {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
