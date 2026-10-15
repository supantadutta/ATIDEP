# Blind rule-quality rating: instructions and rubric (DRAFT)

**Status: drafted.** The anchors are calibrated on pilot rules with the raters before the main
rating; any change made at calibration is recorded here and frozen at `prereg-v1`. The raters are
at least two people who are not the coordinator (the supervisor and a qualified peer). They are
measurement instruments rating anonymised material, not study subjects, and only their scores are
recorded, under pseudonymous rater IDs (blueprint §27.8, §33).

## What the rater sees

A shuffled list of rules in a single canonical format: comments and generator markers stripped,
identifiers re-assigned, the same formatter applied to all. The rater does not see which condition
(manual, ATIDEP, single-prompt) produced a rule, does not see any validator output, and sees for
each rule the source report text and the organisation's telemetry catalogue. The same report may
yield several rules, rated independently.

## Rubric (integers 1 to 5; use the anchors, not a general impression)

| Dimension | 1 | 3 | 5 |
|---|---|---|---|
| **D-A Detection-logic correctness** | The logic cannot detect the behaviour the report describes, or detects something else | Detects the described behaviour but misses an obvious variant, or has a condition that is wrong in a way that matters little | Detects the described behaviour and its obvious variants; every condition is correct and needed |
| **D-B Specificity and false-positive risk** | Would fire on routine activity (for example any PowerShell launch) | Narrower than routine activity but a plausible administrative use would trigger it | Separates the behaviour from the plausible benign uses the rater can name, without being so narrow that trivial changes evade it |
| **D-C Evidence fidelity** | A condition is not supported by the report, or the report is contradicted | Conditions are supported, but one is a stretch or an unsupported detail is added | Every condition traces to a statement in the report; nothing is added |
| **D-D Telemetry realism** | Needs events or fields that the catalogue does not provide | Uses available events, but a field is not populated the way the rule assumes | Uses events and fields the catalogue provides, populated as the rule assumes |
| **D-E Triage usefulness and documentation** | A responder could not tell what fired or what to do | Title and description say what the rule is for; the next step is unclear | Title, description, severity, false-positive notes and references let a responder triage without the source report |

Scores 2 and 4 are used for a rule that is between two anchors. Do not give a rule a score you
cannot justify with a sentence; write the sentence for any score of 1 or 5.

## Procedure

1. Calibration: all raters score the same pilot rules, discuss, and revise the anchors if two
   raters read an anchor differently. Calibration rules are not rated again.
2. Main rating: each rater scores every rule independently, in the shuffled order, without
   consulting the others.
3. Scores are first collected per dimension, one row per rule, dimension and rater, in
   `ratings_dimensions.csv` (`rule_ref, rater, dimension, score`). The coordinator then derives
   `ratings.csv` (`item, condition, rule_ref, rater, score`), where a rater's score for a rule is
   the mean of that rater's five dimension scores, and the `item` and `condition` columns are filled
   **after** all scoring is complete, from the key that the anonymisation step kept.
4. The analysis averages a rule's score over raters, then the rules of an item within a condition.
   Where two raters differ by more than one point on a dimension, the raters discuss and re-score
   under a procedure written here before the main rating (`<decide>`); the original scores are
   kept.
5. Agreement is reported as weighted kappa (and ICC(2,1)) by `python -m research.analysis`.
