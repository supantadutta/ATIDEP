# Selection protocol (TEMPLATE)

**Status: not written.** This file must be completed, committed and frozen before the coordinator
looks at any candidate report for the study (blueprint §27.2). Fields marked `<decide>` are
decisions of the coordinator; nothing has been filled in on their behalf. A protocol that is
written after seeing candidates is not a protocol.

## 1. What is being sampled

* Population: threat-intelligence reports that describe adversary activity relevant to the
  synthetic organisation in `config/org_profile.yaml`, published openly and licensed or otherwise
  permitted for research use.
* Test set: 30 reports. Pilot set: about 10 reports, selected the same way, kept entirely
  separate and never reported as evidence.
* Strata of the test set: 10 IOC-focused, 10 behaviour-focused, 5 mixed, 5 unsuitable (vague,
  duplicate, expired or irrelevant). The stratum is proposed from the title and abstract at
  screening, and the final category is the one in the frozen ground truth.

## 2. Frame (to be decided before selection)

| Field | Value |
|---|---|
| Source list (names and URLs; only sources whose terms permit research use and storage of the text) | `<decide>` |
| Reason each source is in the list (independent of what it publishes about any particular technique) | `<decide>` |
| Time window for publication dates | `<decide>`; it must start **after** the pinned model's training cutoff (§27.9), so it cannot be fixed before spike S3 |
| Languages | `<decide>` |
| Report types accepted (HTML page, PDF) | `<decide>` |
| Maximum length (characters) | `<decide>` |
| Number of candidates screened per stratum | `<decide>` |

## 3. Inclusion and exclusion criteria (to be decided before selection)

Write each criterion so that a second person applying it to the same candidate would reach the same
decision, and give each a reason code used in `inclusion_log.csv`.

| Code | Criterion | Applies to |
|---|---|---|
| `IN-1` | `<decide>` | all |
| `EX-1` | `<decide>` (for example: content cannot be stored under the source's terms) | all |
| `EX-2` | `<decide>` (for example: the same report mirrored under a second URL, other than in the deliberate duplicate stratum) | all |
| `EX-3` | `<decide>` (for example: not text-extractable) | all |

## 4. Draw

1. Every candidate that passes screening is written to `inclusion_log.csv` (included or not), with
   the SHA-256 of the retrieved content and the reason code. Excluded candidates stay in the log.
2. Candidates are ordered by the SHA-256 of their content (not by date, source or title), and the
   stratified draw takes the first *k* per stratum from the list shuffled with the committed seed
   (`random.Random(seed)`, the same generator `assign_order_sets` uses). The exact procedure is
   `<decide>` and is written here before the seed is chosen.
3. Seed: `<decide>`; committed in `config/experiment.yaml` **before** the draw.
4. The draw is run once. A re-draw is a deviation and is logged in `deviations.md`.

## 5. After selection

* The reports are stored with their hashes; `python -m research.dataset check` must report no
  blocker for composition, dates, duplicates and pilot separation.
* Order sets X and Y are assigned by `assign_order_sets` from the committed seed.
* Ground truth is written under `labelling_guide.md`, before any system output is seen.
