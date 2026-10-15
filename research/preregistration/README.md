# Pre-registration folder

Nothing in this folder has been frozen. The tag `prereg-v1` does not exist yet. This folder holds
the documents that must be completed, and the decisions that must be taken by the coordinator,
**before** the main run (blueprint §27.2, §27.3, §27.5, §29). Files marked TEMPLATE are layouts
with the required fields; they contain no values that the coordinator has not chosen.

| File | What it is | Status |
|---|---|---|
| `checklist.md` | Every decision and artefact that must exist before `prereg-v1`, with its status | all pending except the items marked done |
| `selection_protocol.md` | TEMPLATE: source list, time window, inclusion and exclusion criteria, stratified draw, seed | not written; must precede any item selection |
| `labelling_guide.md` | How ground truth is labelled (draft for the coordinator and supervisor to approve) | draft, not approved; must be fixed before labelling |
| `rater_instructions.md` | Blind rubric (five dimensions, anchored 1 to 5) and the rating procedure | draft; anchors to be calibrated on pilot rules |
| `inclusion_log.csv` | One row per candidate report considered, included or not, with the reason | header only |

How freezing works: `python -m research.freeze make --label prereg-v1 --out
research/preregistration/prereg-v1.json` hashes the configuration (including the economics inputs
and the price register), prompts, knowledge files, dataset manifests, the adversarial protocol and
case set, these files, the lock file and the blueprint. `python -m research.freeze verify` lists
every file changed since. The git tag is created by a human, after the working tree is clean.

What the tooling can already check for you:

* `python -m research.dataset check DIR --cutoff YYYY-MM-DD --pilot DIR --second-labels FILE`:
  composition (10 IOC, 10 behaviour, 5 mixed, 5 unsuitable), ground truth on every item, event
  sets, publication after the model's training cutoff, no duplicate or pilot-overlapping reports,
  second-labeller coverage (a third of the items, at least 10, every category) and the agreement
  between the two labellers. It exits non-zero while any blocker remains.
* `python -m research.economics check`: which cost inputs are still missing.
* `python tools/model_probe.py ...`: evidence for the model decision; it does not choose.
