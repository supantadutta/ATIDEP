# ATIDEP

**Agentic Threat Intelligence and Detection Engineering Platform.** A governed, open-source pipeline that turns selected threat intelligence into validated, human-approved detection content for a laboratory Wazuh target. Master's final project, PMICS, University of Dhaka.

The full design, hypotheses, experiment protocol and schedule are in [`docs/ATIDEP_Blueprint_v3.md`](docs/ATIDEP_Blueprint_v3.md). The earlier version is kept at [`docs/archive/ATIDEP_Blueprint_v2.md`](docs/archive/ATIDEP_Blueprint_v2.md).

## Status

Scaffold only (blueprint week 0, before spikes S1–S4). Implemented so far:

| Area | Where |
|---|---|
| Pydantic schemas: claims with verified evidence, intelligence record, priority bands, IOC bundle, detection opportunity, Sigma draft metadata, hard-gate validation, effort records, approval state machine | `schemas/` |
| SQLite schema: the 16 tables of blueprint §39, enum-backed `CHECK` constraints, foreign keys on | `app/db/` |
| Hash-chained audit trail with verification | `app/db/audit.py` |
| Config loading that **refuses to start** if a safety policy is weakened | `app/config.py`, `config/` |
| Component packages for the build | `components/c1_ingest` … `c5_deploy_feedback` |
| Early drafts of Chapters 1-2 and a 54-entry bibliography with per-entry verification status. **The paper is written after the build and experiments**, from the results (blueprint §34.4). | `paper/` (build with `paper/build.sh`, needs pandoc 3) |

Not built yet: collectors, extraction, agents, converter, validators, Wazuh adapter, UI. Build order is in blueprint §25.

## Design rules enforced in code

These come from the blueprint and are covered by tests, so they cannot be loosened by accident:

- Every confidence, reliability and score value is an integer or decimal on a **0–100** scale.
- Priority bands are **half-open** (`[0,40) [40,60) [60,80) [80,100]`) on the score rounded half-up to one decimal.
- A claim whose evidence quote did not verify is **never usable**.
- **Hard gates G1–G11 are pass/fail.** A quality score is rejected for any rule that has not passed every gate; a G6 (telemetry) failure is *blocked*, not repairable.
- A rule cannot skip validation or approval in the state machine; a lab deployment row must reference an approval.
- Loading `config/policies.yaml` fails if LLM tools, command generation, automatic production deployment, plain-HTTP ingest, or a non-dry-run default are enabled.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
ruff check .
python -m pytest
```

Python 3.11 or newer. Copy `.env.example` to `.env` before running anything that needs credentials (none yet).

## Layout

```text
config/       YAML configuration (scoring, policies, telemetry catalog, experiment pre-registration, …)
schemas/      Pydantic models
app/          configuration loader and database layer (API and UI come later)
components/   the five pipeline components
docs/         blueprint v3, archive of v2
tests/unit/   unit tests
```

`config/experiment.yaml` holds the pre-registered parameters; its `TBD` and "provisional" values are fixed after the pilot and frozen under the `prereg-v1` tag (blueprint §9, §29).
