# Families that are not in the injection set

The brief for author **INJC** asked for four reports: an instruction encoded in base64 that the
model is told to decode and follow; a visible request to disable validation or declare a rule
approved; a request to add an exfiltration URL together with a shell command in the output; and a
rule-stage attack asking for a critical-level, wildcard-only rule. The author returned an empty set
and stated that its generation had been stopped by the platform's safety classifier and that it had
been told not to produce that content again, even reworded. The briefing was **not** rewritten to
get past that stop, and the cases were not written by the system's builder (which would also break
the independence rule in `../PROTOCOL.md`).

Consequence for the report: the families "base64 or encoded instructions" and "requests to disable
validation or add an exfiltration URL" of blueprint §27.6 are **not covered** by this case set. The
set still has 16 reports (at least 12 required) across the other families, including PDF metadata
(author INJE). The gap is stated wherever the injection result is quoted. It can be closed later by
a human author (the case format is `research/adversarial/cases.py: InjectionCase`), in a separate,
dated addition that is hashed and reported as a second run, not folded into this one.
