# ATIDEP: supervisor validation brief

PMICS Master's final project, University of Dhaka. Brief of 21 October 2026, written in response to the supervisor's feedback (define ATIDEP first; state the challenges; review the state of the art with the relevance of existing work). The full design is `docs/ATIDEP_Blueprint_v3.md` (version 3.2); the full arguments, with citations, are Chapters 1 and 2 of the paper (`paper/chapters/`). **No experimental result exists yet**; nothing below is a finding.

## 1. What is ATIDEP?

**ATIDEP (Agentic Threat Intelligence and Detection Engineering Platform) is an open-source-oriented, LLM-assisted threat-intelligence-to-detection-engineering pipeline that ingests threat reports, extracts security-relevant information, generates detection content, validates generated rules through deterministic security and quality gates, supports human approval and controlled deployment, and records feedback, analyst effort and resource use from which operational cost is evaluated.**

In practical terms, ATIDEP converts threat intelligence into reviewed and deployable detection content while maintaining traceability and human control. A report goes in; out comes a Sigma rule (for a behaviour) or an indicator list (for indicators of compromise), tied to quotations from the report, passed through deterministic checks, and approved by a named person before it can be deployed to a laboratory Wazuh manager. Language models read and draft; deterministic code decides whether anything they produce may proceed.

| Component | Role |
|---|---|
| C1 Ingest | Approved feeds, uploads and allow-listed URLs; hidden text removed; originals kept with checksums |
| C2 Intelligence processing | Indicators extracted deterministically; behaviours by an Extraction Agent, each with a quotation verified verbatim against the report; ATT&CK mapping; priority score |
| C3 Detection engineering | Whether and what to detect, checked against the telemetry actually collected; Sigma rules with at most two validator-driven repairs; Wazuh CDB lists for indicators |
| C4 Validation and governance | Eleven hard gates G1-G11; a refusing Sigma-to-Wazuh converter; approval bound to the SHA-256 of the exact content; hash-chained audit |
| C5 Deployment and feedback | Export, dry-run or laboratory deployment with rollback; alert feedback; improvements re-enter validation and approval |

ATIDEP is not a SIEM, not an autonomous response system and not a production deployment.

## 2. Problem being addressed

Turning a report into a working detection is a chain of judgement-heavy steps: review reports of uneven quality; pick out the relevant behaviours and indicators; decide what is observable in the organisation's logs; write the detection logic; validate its syntax, meaning and platform compatibility; assess false-positive risk; obtain an accountable approval; deploy safely; monitor and improve. Done by hand it is slow and depends on experienced people. A language model can draft a rule from a report in one prompt, but nothing in that arrangement checks that each condition is supported by the report, that the fields exist, that the rule detects the right thing on the target platform without matching normal activity, that the report's own text has not steered the output, or that anyone accountable approved it.

**Research problem.** Can a controlled, auditable workflow, with deterministic validation around bounded LLM steps, turn threat intelligence into deployable detection content with less analyst effort and without loss of quality or safety; are the controls, rather than the model alone, responsible for that safety; and what does such a workflow cost compared with manual work and with a comparable paid configuration?

## 3. Key challenges

Each is matched in Chapter 1 (and Blueprint §5.4) to the part of ATIDEP designed to address it and to how the experiment evaluates the response.

1. Unstructured, heterogeneous reports.
2. Incomplete, ambiguous or conflicting evidence.
3. Turning narrative into observable detection logic (telemetry the report does not describe).
4. Hallucination and unsupported output.
5. Syntactic correctness is not semantic correctness.
6. Event schemas, field mapping and platform compatibility (Sigma to Wazuh).
7. False positives, over-broad rules and noise.
8. Prompt injection through untrusted report text.
9. Validation that cannot be bypassed before approval and deployment.
10. Human governance and accountability (and over-reliance on automation).
11. Provenance, auditability and reproducibility.
12. Safe deployment, rollback and the rule lifecycle.
13. Model variability and training-data contamination.
14. Ground truth and a fair evaluation when the builder also labels and approves.
15. Comparing open-source and paid cost fairly.
16. Open source is not free: compute, energy, storage, inference, labour and maintenance remain.

## 4. State of the art and research relevance

Chapter 2 reviews the literature by theme, with a per-source table (problem, approach, findings, relevance, limitation) in each. The groups that matter most:

- **Extraction** (TTPDrill, rcATT, LADDER, EXTRACTOR, aCTIon, TTPrint): reports can be turned into structured ATT&CK knowledge; TTPrint ties each technique to located source text, the nearest precedent for ATIDEP's quotation verification.
- **Generation** (SIGMERGE, AutoSigma, LLMCloudHunter, FALCON, Tseng et al., GenTI, RulePilot) and **benchmarks** (CTI-REALM): LLM generation of detection rules from intelligence is established and often strong. ATIDEP does not claim a better generator.
- **Validation, conversion and quality** (Sigma linting with seeded defects; a nine-year study of SigmaHQ exclusions; the Tyrian and sigma_to_wazuh converters): deterministic checks and refusing converters have precedents.
- **Wazuh as a target**: the one LLM study found (Schafhauzer et al.) reports a negative result; a positive outcome cannot be presumed.
- **Governance and SOC automation** (TRACE-CTI; an end-to-end LLM SOC framework): controls around extracted claims, and LLM triage with reported time savings.
- **Reliability and attack surface**: hallucination, validator-driven repair and indirect prompt injection are documented.
- **Economics**: cost is framed generally or optimised for inference alone; vendor cost claims are excluded as evidence.

**Verification status.** 69 sources are recorded in `paper/verification_records.yaml`: 58 confirmed at abstract level and 6 at metadata level through search extracts, and 5 (software READMEs, the Sigma specification, a practitioner framework, the Wazuh documentation) read directly. The environment's network policy blocks publisher sites, DOI resolution and arXiv, so **no paper has been read in full; every paper is marked "Full-text verification pending"** (`paper/verification_checklist.md`).

## 5. Preliminary comparison with the closest works

Marked only where the source, as read, says so; "–" is "not reported", not "absent". The ATIDEP row is the design, not a result. Evidence and source for every marked cell: `paper/related_work_matrix.md`; all 25 works: Table 2.10 in Chapter 2. Bracketed keys refer to `paper/references.bib`. Columns M1-M13 are capabilities, not ATIDEP components.

<!-- MATRIX:BEGIN (generated by tools/related_work_matrix.py) -->
| Work | Year | M1 | M2 | M3 | M4 | M5 | M6 | M7 | M8 | M9 | M10 | M11 | M12 | M13 | Read |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SIGMERGE [@cai2026sigmerge] | 2026 | Y | Y | – | Y | Y | – | – | – | P | – | – | – | – | A |
| AutoSigma [@ghaffarzadegan2026autosigma] | 2026 | Y | P | – | P | Y | – | – | – | N | – | – | – | – | A |
| LLMCloudHunter [@schwartz2024llmcloudhunter] | 2024 | Y | Y | Y | Y | Y | P | – | – | – | – | – | – | – | A |
| CTI-REALM [@chakraborty2026ctirealm] | 2026 | Y | – | – | P | Y | P | – | – | – | – | – | – | – | A |
| Static quality assessment of Sigma rules [@tyagi2026sigmalint] | 2026 | – | – | – | – | – | Y | – | – | – | – | – | – | – | A |
| Tyrian Detection Pack [@zshguy2026tyrian] | 2026 | – | – | – | – | P | Y | – | – | P | – | – | – | Y | R |
| FALCON [@mitra2025falcon] | 2025 | Y | – | – | – | Y | P | – | – | – | – | – | – | – | A |
| Context-aware SIEM rule generation [@schafhauzer2026context] | 2026 | – | – | – | – | Y | P | – | – | – | – | – | – | Y | A |
| TTPrint [@cheng2026ttprint] | 2026 | Y | Y | – | – | – | – | – | – | – | – | – | – | – | A |
| TRACE-CTI [@valletta2026tracecti] | 2026 | – | P | – | – | – | P | – | P | – | – | – | – | Y | A |
| **ATIDEP (design, not a result)** | 2026 | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | P | – |

: Preliminary comparison with the closest works (a subset of Table 2.10 of the paper).

Columns: M1 CTI ingestion; M2 Structured extraction; M3 IOC generation; M4 Behavioural detection; M5 Sigma / rule generation; M6 Deterministic validation; M7 Adversarial / prompt-injection evaluation; M8 Human approval / governance; M9 Deployment / rollback; M10 Feedback / improvement; M11 Analyst-effort measurement; M12 Economic / cost analysis; M13 Open-source availability. Y = yes, P = partial, N = no (the source says so), – = not reported in the source as read. Read: A = abstract-level search extracts, M = metadata only, R = software README read directly, F = full text. No row has been checked against a full text. Evidence for every marked cell: `paper/related_work_matrix.md`.
<!-- MATRIX:END -->

## 6. Research gap

The reviewed literature indicates limited evidence of an integrated approach that jointly evaluates the technical and the economic side of LLM-assisted detection engineering. Existing studies commonly address individual stages (extraction, generation, conversion, quality, triage, claim governance), and several address two or three strongly. The gap is not that no system generates rules from threat intelligence; several do. It is the absence, in the evidence found, of a governed, fail-closed, end-to-end workflow for an open-source target that is evaluated as a workflow: on analyst effort against manual work, on independently judged quality, on resistance to attacks on its own controls, and on cost against a defined, comparable paid configuration.

## 7. How ATIDEP differs from or extends existing work

- It integrates ideas that have precedents (evidence-located extraction, claim governance, validity gates, refusing converters, validator-driven repair) into one workflow, rather than claiming any new component.
- Its deterministic gates are fail-closed and sit before human approval and deployment; a score can never override them, and approval is bound to the exact content.
- It targets an open-source SIEM (Wazuh) end to end, with a documented Sigma subset, a converter that refuses what it cannot translate, and a measured conversion fidelity.
- It attacks its own controls: seeded defective rules in ten classes and injected reports, under the full pipeline (B), validators logged but not enforced (B-V) and a single prompt (C).
- It measures the workflow on two dimensions: analyst active time and blinded, non-inferiority-tested quality against a manual workflow (A) and a single prompt (C); and cost against manual work and a modelled paid configuration of the same nine functions, with every price sourced or reported as missing.

If the pending full-text reading shows that a close work already covers one of these points, the contribution is narrowed.

## 8. Evaluation design in one paragraph

Thirty test items (10 indicator, 10 behaviour, 5 mixed, 5 unsuitable) published after the pinned model's training cutoff, plus a separate pilot set. Conditions: A manual, B full ATIDEP, C single prompt, with ablations B-V and B-R. Primary hypotheses: H1 (analyst active time reduced by at least a pilot-fixed margin) and H4 (quality non-inferior to manual by a pilot-fixed margin, blinded raters); secondary H2 (structural validity), H3 (gates against seeded defects and injection), H5 (pipeline versus single prompt), H6 (feedback tuning); economic H7 (a pre-registered decision rule on "substantially cheaper") with descriptive analyses E1-E3. Counterbalanced crossover with washout, second labeller, pre-registration and freeze manifests. Full protocol: Blueprint §27-§29.

## 9. Status and decisions that need the supervisor

The software and the evaluation tooling are built and unit-tested on synthetic data. The adversarial set has been reviewed (two independent reviewers per case; 2 of 70 defective rules excluded), frozen and run once (v0, 22 October 2026; `research/adversarial/results/v0/REPORT.md`). On synthetic cases and with a worst-case obedient model stand-in, under B: 0 of 68 defective rules reached approval, 2 of 24 clean controls were rejected, and 3 of 16 prompt-injection attacks succeeded (one without any model compliance), so H3 is not met. Those findings are reported, not fixed; any fix will be a second run beside v0. The adversarial set was run before your sign-off of it (item 10), which is still pending. Awaiting human decisions (listed with their documents in `docs/ethics/supervisor_signoff.md`, all PENDING): the research questions and hypotheses; the selection protocol and labelling guide; the second labeller and the rater panel; the pilot-fixed margins; the economic decision rule, the workload and the labour rates with sources; the commercial candidate list; the language model to pin; the adversarial set and protocol; the data-management plan; whether ethics review is required; and the pre-registration freeze.
