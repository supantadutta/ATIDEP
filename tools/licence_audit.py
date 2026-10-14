"""Bill of materials with licences (blueprint §22.7, check E1).

    python tools/licence_audit.py [--out DIR]

Lists every package in the dependency closure of ``requirements.in`` with the licence its own
metadata states and whether it is recognised as OSI-approved, then the non-Python components
from ``tools/external_components.yaml``, which are unverified until someone has read their licence
text. The exit code is 1 if any Python package states no licence at all; packages whose licence
this tool does not recognise are listed for a manual check, which is not a finding that they are
not open source. So the claim "an open-source software stack" is checked, not asserted. An
open-weight model is not "open-source AI" under the OSI definition unless training data and code
are also disclosed; the model's row is therefore a classification to be filled in, not a
licence to be assumed.
"""

from __future__ import annotations

import csv
import sys
from importlib.metadata import distribution
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_lock import ROOT, closure, direct  # noqa: E402

# SPDX identifiers (and the plain names packages use for them) that OSI has approved. Anything
# else is "needs manual check", which is not a finding that it is not open source.
OSI_IDS = {
    "0bsd", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "bsd-2-clause-patent", "isc", "mit",
    "mit-0", "mpl-2.0", "psf-2.0", "python-2.0", "zlib", "unlicense", "hpnd",
    "gpl-2.0-only", "gpl-2.0-or-later", "gpl-3.0-only", "gpl-3.0-or-later", "lgpl-2.1-only",
    "lgpl-2.1-or-later", "lgpl-3.0-only", "lgpl-3.0-or-later", "gpl-2.0", "gpl-3.0", "lgpl-2.1",
}
PLAIN = {"mit license": "mit", "3-clause bsd license": "bsd-3-clause",
         "apache license 2.0": "apache-2.0", "apache license, version 2.0": "apache-2.0",
         "apache software license": "apache-2.0", "mozilla public license 2.0 (mpl 2.0)": "mpl-2.0",
         "python software foundation license": "psf-2.0", "bsd-3-clause license": "bsd-3-clause"}


def recognised(expression: str) -> bool:
    """True if the licence expression is made only of OSI-approved identifiers (for AND), or
    offers at least one (for OR)."""
    import re
    text = expression.strip().lower()
    if not text:
        return False
    text = PLAIN.get(text, text)
    for part in re.split(r"\s*;\s*", text):                 # classifier lists
        if part and part not in OSI_IDS and PLAIN.get(part) not in OSI_IDS:
            break
    else:
        return True
    ok = []
    for clause in re.split(r"\bor\b", text):
        ids = [i.strip(" ()") for i in re.split(r"\band\b", clause)]
        ok.append(all(i in OSI_IDS or PLAIN.get(i) in OSI_IDS for i in ids if i))
    return any(ok)


def licence_of(name: str) -> tuple[str, str, str]:
    """(licence text, status, where it came from). Status is 'recognised' (OSI-approved by the
    identifiers above, or marked with an OSI classifier), 'needs manual check', or 'none'."""
    md = distribution(name).metadata
    classifiers = md.get_all("Classifier") or []
    osi = [c.split("::")[-1].strip() for c in classifiers
           if c.startswith("License :: OSI Approved")]
    expr = (md.get("License-Expression") or "").strip()
    lic = (md.get("License") or "").strip()
    if expr:
        ok = "recognised" if recognised(expr) else "needs manual check"
        return expr, ok, "License-Expression"
    if osi:
        return "; ".join(osi), "recognised", "OSI classifier"
    if lic and len(lic) < 120 and "\n" not in lic:
        return lic, "recognised" if recognised(lic) else "needs manual check", "License field"
    return ((lic[:80] + "...") if lic else ""), "none" if not lic else "needs manual check", \
        "License field" if lic else "none"


def audit() -> list[dict[str, object]]:
    pins, _ = closure(direct(ROOT / "requirements.in"))
    rows = []
    for name, version in sorted(pins.items()):
        text, status, source = licence_of(name)
        rows.append({"package": name, "version": version, "licence": text,
                     "osi_status": status, "evidence": source})
    return rows


def externals() -> list[dict[str, object]]:
    data = yaml.safe_load((ROOT / "tools" / "external_components.yaml").read_text())
    return data["components"]


def main(argv: list[str]) -> int:
    rows, ext = audit(), externals()
    unstated = [r for r in rows if not r["licence"]]
    check = [r for r in rows if r["osi_status"] == "needs manual check"]
    out = Path(argv[argv.index("--out") + 1]) if "--out" in argv else None
    lines = ["# Bill of materials", "", "## Python packages", "",
             "| package | version | licence (as stated in its metadata) | OSI status | evidence |",
             "|---|---|---|---|---|"]
    lines += [f"| {r['package']} | {r['version']} | {r['licence'] or 'NOT STATED'} | "
              f"{r['osi_status']} | {r['evidence']} |" for r in rows]
    lines += ["", "## Other components (unverified until the licence text has been read)", "",
              "| component | kind | licence as stated upstream | verified |", "|---|---|---|---|"]
    lines += [f"| {c['name']} {c.get('version') or ''} | {c['kind']} | "
              f"{c.get('licence_as_stated') or 'NOT SET'} | "
              f"{'yes' if c['verified'] else 'NO'} |" for c in ext]
    text = "\n".join(lines) + "\n"
    if out:
        out.mkdir(parents=True, exist_ok=True)
        (out / "bill_of_materials.md").write_text(text)
        with (out / "python_packages.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    else:
        print(text)
    if check:
        print(f"\n{len(check)} package(s) need a manual licence check (not a finding that they "
              "are not open source): " + ", ".join(str(r["package"]) for r in check),
              file=sys.stderr)
    if unstated:
        print("no licence stated: " + ", ".join(str(r["package"]) for r in unstated),
              file=sys.stderr)
    return 1 if unstated else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
