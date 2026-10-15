# Dataset folders

A dataset is a folder with a `manifest.yaml` and the files it names. Two datasets exist in the
repository, neither of which is evidence:

* `research/dataset/` (id `demo-v1`) holds seven **fictional** reports for demonstrations and tests.
  It is marked `synthetic: true`, so `python -m research.dataset check` always reports it as not
  ready, which is correct.
* The real **pilot set** (about 10 reports) and **test set** (30 reports: 10 IOC, 10 behaviour,
  5 mixed, 5 unsuitable) do not exist yet. They are selected under
  `research/preregistration/selection_protocol.md`, which must be written first. Nothing in this
  repository supplies, generates or imitates them.

## Layout of a real dataset

```text
DATASET/
  manifest.yaml            # see below
  items/<file>             # one report per item: .html, .txt or .pdf, exactly as retrieved
  sets/<item>/positive/    # *.json Sysmon events the rule must match
  sets/<item>/negative/    # *.json unrelated events the rule must not match
  sets/<item>/benign_lookalike/   # *.json benign activity that resembles the behaviour
  second_labels.yaml       # the second labeller's labels (kept apart from the manifest)
```

`manifest.yaml` (schema: `research/dataset/model.py`):

```yaml
dataset_id: <your id>
synthetic: false
seed: <the committed seed>
items:
- id: <A-Z0-9-, 3-20 characters>
  file: items/<file>
  category: ioc | behaviour | mixed | unsuitable
  source: {name: <publisher>, reliability: A-F, credibility: 1-6, url: <where it was retrieved>}
  published: 'YYYY-MM-DD'        # must be after the pinned model's training cutoff
  test_events: sets/<item>      # for behavioural items
  ground_truth:                  # written before any system output is seen
    detectable: true|false
    decisions: [ioc_based | behavioral | correlation | hunting_only | additional_telemetry_required | insufficient_evidence | not_relevant | expired_or_low_value]
    indicators: [{type: domain, value: example.invalid}]     # refanged; only indicators of the activity
    techniques: [T1059.001]
    required_log_source: windows_process_creation            # name as in config/telemetry_catalog.yaml
    notes: ''
```

`second_labels.yaml` maps item id to `{detectable: bool, techniques: [..]}` for at least a third of
the items (minimum 10), covering every category. See `research/preregistration/labelling_guide.md`.

Events are Sysmon JSON of the shape used by `tests/events/` (`{"win": {"system": {...},
"eventdata": {...}}}`) with a unique `eventRecordID` across everything replayed together. Public
attack datasets are converted to this form and replayed as inert logs only; their licences are
checked before they are stored or redistributed (spike S4, blueprint §27.7).

## Checking readiness

```bash
python -m research.dataset check DATASET --cutoff YYYY-MM-DD --pilot PILOT_DIR --second-labels DATASET/second_labels.yaml
```

The command reports blockers (composition, missing ground truth, missing or incomplete event sets,
publication not after the cutoff, duplicate or pilot-overlapping reports, missing or unstratified
second labeller, synthetic flag) and computes the agreement between the two labellers. It never
modifies anything. `dataset_sha256` in its output is the hash that run records quote.
