# Pre-registration checklist

Status values: `pending` (nobody has done it), `drafted` (a draft exists, not approved), `done`.
Only the coordinator, or the person named, can change a status to `done`. Nothing here has been
decided on the coordinator's behalf.

## Decisions only the coordinator can take

| # | Decision | Recorded in | Status |
|---|---|---|---|
| 1 | The language model, its exact version or digest, its licence classification and its training cutoff (spike S3). Evidence: `tools/model_probe.py`. | `config/experiment.yaml` `model` | pending |
| 2 | Whether the optional paid-API arm (S-OSS-API) is run, and if so which paid model, with its own cutoff | `config/experiment.yaml` `paid_model` | pending |
| 3 | δ_t (relative reduction of analyst minutes that counts as meaningful), Δ_q (rubric non-inferiority margin), H6 thresholds, fixed from the pilot | `config/experiment.yaml` | pending (provisional values in the file are placeholders from the blueprint) |
| 4 | δ_c, the margin for "substantially cheaper", with a written rationale that does not depend on the result | `config/experiment.yaml` `economics.delta_c_pct`, `delta_c_rationale` | pending (null) |
| 5 | The one primary workload (id from `config/cost_scenarios.yaml`) | `config/experiment.yaml` `economics.primary_workload` | pending (null) |
| 6 | Engineer and analyst hourly rates, each with basis, source and date. No default exists. | `config/cost_rates.yaml` | pending (null) |
| 7 | Host hardware price, useful life, measured power draw, electricity tariff, storage price, each with source and date | `config/cost_rates.yaml` | pending (null) |
| 8 | The list of commercial candidates for the paid reference scenario, written down **before** any price is looked up, and the adequacy test they must meet | `config/price_register.yaml` | pending (four placeholders marked `Vendor quote required / public price unavailable`) |
| 9 | Prices for those candidates, from the vendor's own published page or a written quote, with URL and date checked | `config/price_register.yaml` | pending |
| 10 | The random seed for set assignment and the stratified draw, committed before use | `config/experiment.yaml` `set_assignment_seed`; `selection_protocol.md` | pending |
| 11 | Whether the optional independent-analyst subset is run (only if departmental rules allow) | `docs/ethics/` | pending |

## Documents and artefacts

| # | Artefact | Owner | Status |
|---|---|---|---|
| 12 | `selection_protocol.md` completed and committed **before** any candidate report is looked at | coordinator | pending |
| 13 | Pilot set (about 10 reports) selected, kept separate from the test set | coordinator | pending |
| 14 | Test set (30 reports: 10 IOC, 10 behaviour, 5 mixed, 5 unsuitable), all published after the model's cutoff | coordinator | pending |
| 15 | `labelling_guide.md` approved by the supervisor, then fixed | coordinator and supervisor | drafted |
| 16 | Ground truth written by the coordinator **before** viewing any system output for the item | coordinator | pending |
| 17 | Second labeller labels at least a third of the items (minimum 10), stratified; agreement computed with `research.dataset check` | supervisor or qualified peer | pending |
| 18 | Event corpora (spike S4): at least 3 techniques with at least 10 positive events each, a benign baseline, licences checked | coordinator | pending (a synthetic 400-event baseline exists for development only) |
| 19 | Lab VM baseline of benign events (Sysmon) | coordinator | pending |
| 20 | `rater_instructions.md` calibrated on pilot rules; at least two raters who are not the coordinator identified | supervisor | drafted |
| 21 | Adversarial case set frozen with its hash **before** it is run | coordinator (done by the harness workflow) | in progress |
| 22 | Dependency lock and licence audit committed | coordinator | done (`requirements.txt`, `tools/licence_audit.py`) |
| 23 | Reference verification (`paper/verification_checklist.md`): every cited work checked against the publisher or the paper itself | coordinator | pending |
| 24 | Ethics: supervisor sign-off, data-management plan, departmental view on the independent-analyst subset | coordinator and supervisor, then the university | pending (see `docs/ethics/`) |
| 25 | `config/experiment.yaml` committed; `python -m research.freeze make --label prereg-v1`; git tag `prereg-v1` created by a human on a clean tree | coordinator | pending |
| 26 | `freeze-v1` (code, prompts, prompts' hashes, event sets) tagged | coordinator | pending |

## Rules that stay in force after the freeze

* No change to prompts, thresholds, margins, exclusion rules, seeds or the analysis plan after
  `freeze-v1`. A change after that point is a deviation: write it in `deviations.md` with its date
  and reason, and report it in the paper.
* A negative or unexpected result is reported as it is. A run is excluded only for a reason written
  in advance (a mechanical failure of the harness, a stopped spend cap) and every exclusion is
  listed with its reason.
* The coordinator does not rate rules and does not label the second-labeller subset.
