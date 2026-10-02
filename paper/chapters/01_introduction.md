# Introduction

## Background and motivation

Cyber threat intelligence (CTI) is information about adversaries, their infrastructure and their methods that defenders can use to anticipate and respond to attacks. Guidance such as the NIST guide to cyber threat information sharing describes how organisations establish sharing relationships, the benefits and difficulties of sharing, and the automated exchange of threat information [@johnson2016nist]. Surveys of the field document how technical threat intelligence and its sharing have grown into an established topic of research and practice [@tounsi2018survey; @wagner2019sharing].

The supply of intelligence is large, but it is not uniform in quality or in agreement. Comparative analyses of threat intelligence data sources have examined how the sources relate to one another [@li2019tea]. An empirical assessment of two leading commercial providers found almost no overlap between their indicators, or with four large open feeds; for 22 threat actors tracked by both vendors, the average overlap was only 2.5% to 4.0% [@bouwman2020cup]. A separate evaluation of 24 open-source feeds over several months found significant variation in their quality [@griffioen2020quality]. The same commercial-intelligence study reports a finding that frames the motivation for this thesis: in 14 interviews with practitioners, customers were found to optimise for analyst time rather than for threat detection as such [@bouwman2020cup]. The practical value of intelligence therefore depends not only on what it contains but on how cheaply a team can turn it into protection.

Turning intelligence into protection is the work of detection engineering. Intelligence arrives in two broad forms. *Indicators of compromise* (IP addresses, domains, file hashes) are easy to match but, as the Pyramid of Pain argues, also easy for an adversary to change, while *tactics, techniques and procedures* (TTPs) are the hardest for an adversary to change and so cause the most disruption when detected [@bianco2013pyramid]. MITRE ATT&CK provides a common taxonomy of adversary behaviour that is used to convey threat intelligence, to test defences, and to improve them [@strom2018attack]. Behaviour-based detections are usually written as rules for a security information and event management (SIEM) or extended detection and response (XDR) platform. Sigma is a generic, open, YAML-based rule format that is compiled to the query language of a particular SIEM, which lets one rule serve many platforms [@sigmahq2024spec]. Practitioner frameworks such as Palantir's Alerting and Detection Strategy framework prescribe what a detection should document, including its goal, technical context, blind spots and assumptions, false positives, and validation [@palantir2017ads].

Doing this well by hand is slow. An analyst must read a report, extract indicators and behaviours, decide whether the intelligence is relevant, map behaviours to ATT&CK, determine which telemetry would reveal them, write a rule, test it against positive and benign events, convert it to the target platform's format, deploy it, and tune it afterwards. The downstream cost of poorly engineered rules is well documented. In a qualitative study of security operations centre (SOC) analysts, practitioners confirmed that the tools they use produce high rates of false-positive alarms that require manual validation, although most of these were attributed to benign triggers, that is, true alarms explained by legitimate behaviour in the organisation's environment [@alahmadi2022false]. Detection content that is hard to explain, hard to validate and noisy adds to the burden it is meant to reduce.

Cost is the other side of the problem. Security spending competes with other uses of an organisation's money [@gordon2002economics], and incentives and economics shape security outcomes as much as technology does [@anderson2001hard]. For a small team or an academic laboratory, the question is therefore not only whether automating detection engineering works, but whether it can be done without significant spending, with a free and open-source stack and hardware already at hand. This thesis treats that as a testable claim and not a slogan: it defines what "cost-effective" means before the experiment, measures the inputs, and reports where the conclusion holds and where it does not.

## Problem statement

Large language models (LLMs) promise to automate parts of this workflow, from extracting behaviours out of prose to drafting rules. They also introduce failure modes that matter for security content. Language models can *hallucinate*, producing fluent output that is not supported by the source [@ji2023hallucination]; for a detection rule this can mean an invented field name, a condition the report never described, or a technique mapping that does not hold. Models that read external text can also be manipulated by instructions embedded in that text. Attack techniques such as goal hijacking and prompt leaking were described early [@perez2022ignore], and *indirect* prompt injection extended the threat model to any content that an LLM-integrated application retrieves and reads [@greshake2023indirect]. Threat reports are exactly such content: they are collected from the open internet, so their text cannot be assumed to be trustworthy. Guidance for LLM applications consequently recommends restricting a model's access to what is necessary, requiring human approval for privileged operations, and limiting the influence of untrusted content [@owasp2023llmtop10].

A growing body of work now generates detection rules from threat reports with LLMs. Recent systems produce Sigma rules from report text [@cai2026sigmerge; @ghaffarzadegan2026autosigma], extract detection-rule candidates from cloud-focused intelligence [@schwartz2024llmcloudhunter], and a recent benchmark measures whether AI agents can complete the whole task of reading intelligence and producing validated detections in a controlled environment [@chakraborty2026ctirealm]. These works advance the quality of generated rules. As reported in their abstracts and project descriptions, they focus on measures such as rule validity, relevance, ATT&CK coverage, compilation to a query language, or scoring against ground-truth detections. The questions that matter to a team deciding whether to adopt such a workflow are partly different: whether the workflow can be made to *fail closed*, so that a rule that is invalid, unsupported by evidence or incompatible with available telemetry cannot reach deployment; how much analyst effort it saves compared with doing the work by hand and compared with simply prompting a model; and whether its controls hold when they are attacked. Chapter 2 examines the literature on these points and the extent to which they have been addressed.

<!-- VERIFY(full-text): the statement about what the cited systems report is based on abstracts, publisher pages and project descriptions. Re-check against the full texts of Cai et al. 2026, Ghaffarzadegan et al. 2026, Schwartz et al. 2024 and Chakraborty et al. 2026 before submission. -->

The research problem of this thesis is therefore not whether an LLM can draft a detection rule. It is whether a controlled and auditable workflow, with deterministic validation around bounded LLM steps, can turn heterogeneous threat intelligence into useful, deployable detection content with less analyst effort and without loss of rule quality or operational safety, and whether the controls, rather than the language model alone, account for that safety.

## Aim and objectives

**Aim.** To design, implement, and experimentally evaluate an open-source platform, ATIDEP (Agentic Threat Intelligence and Detection Engineering Platform), that transforms heterogeneous cyber threat intelligence into prioritised, explainable, validated and human-approved detection content, and to determine the effect of its workflow and controls on analyst effort, rule quality and safety relative to manual and single-prompt baselines.

The aim is pursued through the following objectives.

1. Ingest intelligence from a small set of approved sources (feeds, uploaded files and allowlisted URLs) safely, preserving the original evidence.
2. Extract indicators, behaviours and entities, each linked to a verbatim quotation that is verified against the source text.
3. Prioritise intelligence with a transparent, reproducible scoring model and decide, with deterministic telemetry checks, whether it supports a defensible detection.
4. Generate Sigma rules for behaviours and Wazuh constant-database (CDB) lists for indicators.
5. Validate generated content through hard pass/fail gates and positive, negative and benign look-alike tests, with a bounded automated repair loop.
6. Convert a documented subset of Sigma to Wazuh rules, refusing constructs that cannot be translated faithfully, and test the result at two tiers.
7. Record human approval bound to the exact rule content, with versioning, rollback and a tamper-evident audit trail.
8. Evaluate the workflow against a manual workflow and a single-prompt LLM baseline in a pre-registered, bias-controlled experiment, including seeded-defect and prompt-injection tests of the controls.

## Research questions

The main research question is:

> To what extent does a governed, open-source agentic workflow reduce the analyst effort needed to turn cyber threat intelligence into validated, deployable detection content, without reducing independently judged rule quality or operational safety, and how much of the result is attributable to the pipeline's structure and validators rather than to the language model alone?

It is supported by the following questions.

- **RQ1.** How accurately does the platform extract indicators, behaviours and context, and how often does it produce unsupported claims?
- **RQ2.** Can the platform correctly identify intelligence that is, or is not, suitable for detection engineering?
- **RQ3.** What proportion of generated rules are structurally valid on the first attempt and after bounded automated repair?
- **RQ4.** How accurately does the platform map behaviours to MITRE ATT&CK techniques?
- **RQ5.** Do the hard gates prevent seeded defective rules and prompt-injection attempts from reaching approval or deployment?
- **RQ6.** How does rule quality, judged blind by independent raters and measured on held-out events, compare between manual, ATIDEP and single-prompt conditions?
- **RQ7.** Does feedback-based tuning reduce false positives on benign events while retaining true-positive detections?

A secondary, descriptive question concerns economics.

- **RQ8.** Is the open-source workflow cost-effective under three pre-registered checks (an open-source stack with a measured cash outlay, a lower cost per accepted rule than the manual workflow, and a reported break-even volume), and how sensitive is that conclusion to its assumptions?

## Research approach

The thesis follows a design-science approach: it builds an artefact, ATIDEP, to address an identified problem, and evaluates the artefact rigorously [@hevner2004design]. The process follows the usual sequence of problem identification, definition of objectives, design and development, demonstration, evaluation and communication [@peffers2007dsrm].

The evaluation is a pre-registered experiment on 30 intelligence items, plus a separate pilot set used only for tuning. Three conditions are compared: a manual workflow, the full ATIDEP workflow with human review, and a single-prompt LLM baseline that receives the same information but no pipeline; ablations remove the validators and the repair loop. Two primary hypotheses concern efficiency (H1: analyst active time per item is reduced by at least a pilot-fixed margin) and quality (H4: rules approved through ATIDEP are not worse than manual rules by more than a pilot-fixed margin). Quality is tested as *non-inferiority*, since a non-significant difference does not demonstrate equivalence [@schuirmann1987tost; @lakens2017equivalence]. Secondary hypotheses concern structural validity (H2), the effectiveness of the gates against seeded defects and injected instructions (H3), the contribution of the pipeline relative to a single prompt (H5) and the effect of feedback-based tuning (H6). The design counters learning and carry-over effects by counterbalancing the order of conditions with a washout period, estimates the effect of order explicitly, uses blinded raters other than the researcher, and controls for training-data contamination by using reports published after the model's training cutoff, since benchmark exposure during training can inflate results [@sainz2023contamination]. Cost-effectiveness is assessed separately, through three pre-registered descriptive checks that are derived from the efficiency data and from recorded resource use, with sensitivity analysis (Chapter 8). The full protocol, hypotheses and statistical plan are given in Chapter 3.

## Scope and delimitations

The study is deliberately bounded. ATIDEP is a laboratory prototype, not a production system, and it is not a SIEM or an autonomous response platform: it connects intelligence sources to portable detection content and a controlled target. The target is a manager-only instance of the stable Wazuh 4.14 line, a free and open-source platform that unifies XDR and SIEM capabilities [@wazuh2026overview]. The input types are limited to feeds, uploaded files and allowlisted URLs. The converter handles a documented subset of Sigma, and constructs outside the subset are rejected. The organisation is synthetic, a single language model is pinned for the experiment, and the dataset has 30 test items. Production deployment, real malware execution, customer data, STIX/TAXII ingestion, and MISP or OpenCTI integration are out of scope. Cost-effectiveness is assessed through three pre-registered, descriptive checks (Chapter 8) and does not include a commercial-platform price comparison, because no commercial baseline is measured.

## Contributions

The thesis makes the following contributions. It does not claim to advance the state of the art in the raw quality of LLM-generated Sigma rules, which is the focus of the systems discussed in Chapter 2; its contributions are in governance, conversion and evaluation.

1. A reference design for CTI-to-detection automation in which deterministic gates and tests surround bounded LLM steps, with every consequential action fail-closed and gated by a hash-bound human approval.
2. An evidence-verification method in which every extracted claim carries a verbatim quotation that is checked by substring match against the sanitised source.
3. A documented Wazuh-compatible subset of Sigma and a conservative converter that refuses what it cannot translate faithfully, with a measurement of conversion fidelity between a Sigma-level matcher and Wazuh's own rule tester.
4. A bounded repair loop driven by deterministic validators, with first-pass and post-repair validity reported separately.
5. A pre-registered, bias-controlled comparison of manual, governed-pipeline and single-prompt workflows, using a blinded rubric, held-out events, and non-inferiority testing.
6. Seeded-defect and prompt-injection test sets for evaluating the controls of a detection-engineering pipeline.
7. A pre-registered cost-effectiveness analysis of an open-source stack, with break-even projections, a hidden-cost register and an audit of the open-source claim, including the status of the language model.

## Terminology

| Term | Meaning in this thesis |
|---|---|
| Indicator of compromise (IOC) | A concrete observable such as an IP address, domain, URL or file hash. |
| Tactics, techniques and procedures (TTP) | Adversary behaviour, expressed using the MITRE ATT&CK taxonomy [@strom2018attack]. |
| Detection engineering | The practice of turning intelligence and behaviour descriptions into tested, documented, maintainable detection content. |
| Sigma rule | A YAML detection rule in the open Sigma format, independent of any one SIEM's query language [@sigmahq2024spec]. |
| CDB list | A Wazuh constant-database list of keys matched exactly by rules, used here for indicator detections [@wazuh2026docs]. |
| Workflow versus agent | Following Schluntz and Zhang [-@schluntz2024effective], a *workflow* orchestrates LLMs and tools through predefined code paths, whereas an *agent* lets the LLM direct its own process. In this thesis, "stage" denotes deterministic code, and "agent" is reserved for an LLM-backed component making a bounded decision inside a loop whose exit is decided by deterministic validators. |
| Hard gate | A pass/fail check that must succeed before a rule can proceed; a score can never override it. |
| Repair loop | A bounded loop in which an LLM revises a rule using only structured defect reports from deterministic validators. |
| Active time | The time an analyst is actually working on an item, measured by an explicit timer with inactivity auto-pause. |
| Cost-effectiveness | Satisfaction of three pre-registered checks: an open-source stack with a measured cash outlay, a lower cost per accepted rule than the manual workflow, and a reported break-even volume. |
| Open-source stack | A software stack whose components carry licences that meet the Open Source Definition [@osi2007osd]. A language model released only as open weights is not thereby "open-source AI" [@osi2024osaid]. |

## Structure of the thesis

Chapter 2 reviews the literature on threat intelligence operationalisation, detection engineering, extraction of attack behaviour from reports, LLM-based rule generation, the reliability and security of LLM components, human oversight, and the economics of automation and the meaning of "open source", and derives the research gap. Chapter 3 presents the methodology, including hypotheses, experimental design, metrics and statistical analysis. Chapter 4 sets out requirements and architecture, and Chapter 5 describes the implementation. Chapter 6 describes the experimental setup, and Chapter 7 reports results. Chapter 8 presents the cost analysis and the verdict on cost-effectiveness. Chapter 9 discusses the findings, Chapter 10 examines threats to validity, and Chapter 11 concludes with answers to the research questions, limitations and future work.
