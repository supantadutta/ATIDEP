# Ground-truth labelling guide (DRAFT for approval)

**Status: drafted, not approved.** The supervisor approves this guide, and it is then fixed and
hashed before the first label is written (blueprint §27.3). Changes after labelling begins are
deviations. The labeller writes the labels for an item **before** seeing any ATIDEP, baseline or
ablation output for that item. The second labeller works from the report and this guide only, not
from the first labeller's labels.

The labels are stored in the dataset manifest (`research/dataset/model.py`, `GroundTruth`).

## What a label means

The ground truth is *what a careful analyst would extract and decide from this report alone, given
the synthetic organisation's profile and telemetry catalogue*. It is not what the report's author
wishes were detectable, and it is not what the model produced.

## Fields

**`detectable`** (true or false). True if the report contains information that supports a
detection rule or indicator list that could be written for the organisation's available telemetry
(`config/telemetry_catalog.yaml`) and justified by quotations from the report. False otherwise.
It must agree with `decisions`: it is true exactly when a generating or correlation decision is
acceptable.

**`decisions`** (one or more acceptable opportunity decisions): `ioc_based`, `behavioral`,
`correlation`, `hunting_only`, `additional_telemetry_required`, `insufficient_evidence`,
`not_relevant`, `expired_or_low_value`. List every decision a careful analyst would accept; do not
list a decision merely because it is conceivable.

* `ioc_based`: the report gives indicators of compromise that are specific, current and not
  benign infrastructure.
* `behavioral`: the report describes an observable behaviour (for example a command line or a
  process relationship) specific enough to separate it from routine administration.
* `correlation`: detection needs several events over time; recorded, not generated in the MVP.
* `hunting_only`: the behaviour is real but too common to alert on.
* `additional_telemetry_required`: the behaviour is detectable only with telemetry the
  organisation does not collect (the catalogue says which).
* `insufficient_evidence`, `not_relevant`, `expired_or_low_value`: as named. Expired means the
  indicators are stale by the rule written in the selection protocol.

**`indicators`** (type and value). Only indicators the report presents as belonging to the
activity. Not included: the report publisher's own domains and links, example or documentation
addresses, well-known benign services named as context, defanged placeholders that are not real
values. Defanged values are written in their refanged form (`hxxp` to `http`, `[.]` to `.`) and
indicator types follow the schema. Hashes are the hash the report states, in lower case.

**`techniques`** (ATT&CK technique or sub-technique IDs). A technique is labelled when the report
describes the behaviour in text, not when it is merely typical for the actor. Use the most specific
level the text supports (a sub-technique only if the text supports the sub-technique). The ATT&CK
release is the one pinned in `knowledge/attack_release/`. Techniques the report mentions as a
label (for example a table of "associated techniques" with no description) are not labelled unless
the text also describes the behaviour.

**`required_log_source`**. The telemetry source needed for the generating decision, named as in
`config/telemetry_catalog.yaml`. Required whenever a generating decision is acceptable.

**`notes`**. Known benign look-alikes, ambiguities and reasons for borderline calls. Notes are
read by humans; no metric uses them.

## Procedure

1. Read the whole report once without labelling.
2. Fill the fields. When unsure between a generating decision and a non-generating one, record
   the reason in `notes` and list both decisions only if a careful analyst could defend both.
3. Record the time at which labelling of the item was finished (in the inclusion log); labels are
   not edited after the system has seen the item.
4. The second labeller labels at least a third of the items (minimum 10), stratified by category,
   writing only `detectable` and `techniques` in `second_labels.yaml`.
5. Agreement is computed by `python -m research.dataset check ... --second-labels FILE` (Cohen's
   kappa on `detectable`, Jaccard on technique sets). Disagreements are adjudicated by the second
   labeller or the supervisor and the adjudication is logged with the reason; the adjudicated
   label becomes the ground truth. Both sets of pre-adjudication labels are kept.
6. The labels and events are hashed (`dataset_sha256`) at `prereg-v1`.

## Labelling effort

Labelling is scheduled from week 3 and is timed (hours per item) so that the paper can report it;
labelling hours are not part of the analyst-minutes endpoint.
