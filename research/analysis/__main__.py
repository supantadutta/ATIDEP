"""``python -m research.analysis run --export DIR --out DIR [--adversarial summary.json]``."""

from __future__ import annotations

import argparse
import sys

from app.config import DEFAULT_CONFIG_DIR
from research.analysis.run import run_analysis


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m research.analysis")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--export", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--config", default=str(DEFAULT_CONFIG_DIR))
    r.add_argument("--adversarial", help="summary.json from research.adversarial")
    a = ap.parse_args(argv)
    res = run_analysis(a.export, a.out, config_dir=a.config, adversarial_summary=a.adversarial)
    for k in ("H1", "H4", "H2", "H3"):
        print(k, "->", res[k].get("not_evaluable", "computed"))
    print(f"written to {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
