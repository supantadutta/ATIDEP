# ATIDEP

**Agentic Threat Intelligence and Detection Engineering Platform.** A governed, open-source pipeline that turns selected threat intelligence into validated, human-approved detection content for a laboratory Wazuh target. Master's final project, PMICS, University of Dhaka.

ATIDEP is an open-source-oriented, LLM-assisted threat-intelligence-to-detection-engineering pipeline: it ingests threat reports, extracts security-relevant information, generates detection content, validates it through deterministic security and quality gates, supports human approval and controlled deployment, and records feedback, analyst effort and resource use from which operational cost is evaluated. A short overview for the supervisor (definition, problem, challenges, state of the art, research gap) is [`docs/supervisor_brief.md`](docs/supervisor_brief.md).

The full design, hypotheses, experiment protocol and schedule are in [`docs/ATIDEP_Blueprint_v3.md`](docs/ATIDEP_Blueprint_v3.md) (version 3.2). The earlier version is kept at [`docs/archive/ATIDEP_Blueprint_v2.md`](docs/archive/ATIDEP_Blueprint_v2.md).

The thesis evaluates ATIDEP on **two dimensions**: technical effectiveness (analyst effort, rule validity and quality, safety under attack) and economic cost-effectiveness (the cost of the workflow in physical and monetary units, compared with a manual workflow and a modelled paid configuration of the same functions). Neither conclusion is assumed: both are computed from measurements and sourced inputs.

## Status

The software and the evaluation tooling are built and tested. **No result on real data exists yet**, and nothing in the repository is a price, a labour rate or a result that someone invented.

| Area | Where |
|---|---|
| Schemas, SQLite schema, hash-chained audit, fail-closed configuration | `schemas/`, `app/db/`, `app/config.py`, `config/` |
| C1 ingest, C2 processing and agents, C3 detection engineering, C4 validation and governance (gates G1-G11, Sigma-subset converter, Tier-1 matcher, approval bound to content hash), C5 deployment and feedback | `components/` |
| Pipeline service, internal REST API, Streamlit UI (3 pages), analyst timer with heartbeat and idle accounting | `app/`, `ui/` |
| Usage measurement: provider-reported versus estimated token counts, local compute time, a hosted-model client behind a spend cap and a replay store | `components/llm/` |
| Experiment harness: dataset with ground truth, conditions A/B/C/B-V/B-R, metrics, CSV exports | `research/` |
| Statistics: paired and non-inferiority tests, BCa bootstrap, Holm, mixed model, proportions, agreement, rater reliability, power | `research/analysis/` |
| Economic evaluation: sourced inputs, price register, comparable scenarios, ledger, unit costs, the H7 decision rule, sensitivity, tipping points | `research/economics/`, `config/cost_*.yaml`, `config/price_register.yaml` |
| Adversarial evaluation: 70 seeded defective rules, 24 clean controls and 16 prompt-injection reports written by independent agents, mechanical integrity checks, reviewer tooling, runner and summary | `research/adversarial/` |
| Reproducibility: pinned lock, licence audit, freeze manifests, model probe, reference checklist | `requirements.txt`, `tools/`, `research/freeze.py`, `paper/verification_checklist.md` |
| Real-data readiness: dataset checker, pre-registration pack, ethics drafts | `research/dataset/check.py`, `research/preregistration/`, `docs/ethics/` |
| Early drafts of Chapters 1-2 (definition, problem, challenges, themed state of the art, comparison matrix, research gap); a 69-entry bibliography with a verification record per source (no paper read in full: every paper is "Full-text verification pending"). **The rest of the paper is written after the experiments**, from the results (blueprint §34.4). | `paper/`, `tools/related_work_matrix.py` |

## What only a person can supply

Everything below is listed with its status in `research/preregistration/checklist.md`.

* The language model (spike S3): `tools/model_probe.py` gathers evidence and selects nothing.
* The real dataset (30 reports plus a pilot set), ground truth, a second labeller, blinded raters, event corpora (spike S4).
* Commercial price candidates and prices from the vendors' own pages or written quotes; analyst and engineer rates; host price, power draw and tariff; δ_c and the primary workload. Until they are supplied, `python -m research.economics check` lists them and the paid side is reported as `Vendor quote required / public price unavailable`.
* Ethics and data-handling approval, supervisor sign-off (`docs/ethics/`, all marked PENDING), publisher-side verification of every reference.

## Commands

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
ruff check . && python -m pytest

python -m research.economics check --config config            # what cost inputs are still missing
python -m research.dataset check DATASET_DIR --cutoff YYYY-MM-DD --second-labels FILE
python -m research.freeze make --label prereg-v1 --out research/preregistration/prereg-v1.json
python -m research.adversarial run --out research/adversarial/results/v0 --freeze research/adversarial/FREEZE.json
python -m research.analysis run --export EXPORT_DIR --out OUT_DIR --adversarial research/adversarial/results/v0/summary.json
python tools/model_probe.py --provider ollama --model NAME --items PILOT_DIR
python tools/licence_audit.py
```

Python 3.11 or newer. Copy `.env.example` to `.env` before running anything that needs credentials.

## Design rules enforced in code

These come from the blueprint and are covered by tests, so they cannot be loosened by accident:

- Every confidence, reliability and score value is on a **0-100** scale; priority bands are half-open.
- A claim whose evidence quote did not verify is **never usable**.
- **Hard gates G1-G11 are pass/fail**; a G6 (telemetry) failure is *blocked*, not repairable. Approval is bound to the SHA-256 of the exact rule content.
- Loading `config/policies.yaml` fails if LLM tools, command generation, automatic production deployment, plain-HTTP ingest, or a non-dry-run default are enabled, or if cloud inference is enabled without a positive spend cap.
- **No invented numbers in the cost files**: every value in `config/cost_rates.yaml` is `null` or carries a basis, a source and (if supplied) a date checked; the loader refuses otherwise. A total with a missing input is a lower bound, never completed with zero.
- The adversarial runner refuses to start unless the freeze manifest matches the files on disk, and never overwrites a raw result.

## Layout

```text
config/       YAML configuration (policies, scoring, telemetry, experiment pre-registration, cost inputs)
schemas/      Pydantic models
app/ ui/      configuration loader, database, services, REST API, Streamlit pages
components/   the five pipeline components and the LLM clients
research/     dataset, experiment runner, metrics, statistics, economics, adversarial evaluation, pre-registration
tools/        licence audit, dependency lock, model probe, reference checklist, related-work matrix
docs/         blueprint v3.2, supervisor brief, ADR-001 (Wazuh findings), model selection, ethics drafts, archive of v2
paper/        chapters 1-2 (drafts), bibliography, verification records and checklist, related-work matrix
tests/unit/   unit tests
```

`config/experiment.yaml` holds the pre-registered parameters; its `TBD`, `null` and "provisional" values are fixed after the pilot and frozen under the `prereg-v1` tag (blueprint §9, §29).
