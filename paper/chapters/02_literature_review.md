# Literature Review and State of the Art

## Introduction and review method

This chapter reviews the state of the art against which ATIDEP must be positioned, and derives the research gap from it. It is organised by research theme, following the chain of activities described in Chapter 1: how threat intelligence is produced and how good it is (Section 2.2); how it is extracted and structured (Section 2.3); how it is turned into detection rules (Section 2.4); how portable rules reach a platform such as Wazuh (Section 2.5); how detection content is validated and its quality judged (Section 2.6); how language models are used in security operations more broadly (Section 2.7); how reliable and how attackable language-model components are (Sections 2.8 and 2.9); how humans govern automated security work (Section 2.10); how detection content is deployed and maintained (Section 2.11); what "open source" means for a pipeline that contains a model (Section 2.12); and how the economics of such automation has been, or has not been, evaluated (Section 2.13). Section 2.14 compares the closest works in a matrix, Section 2.15 states the limitations of existing approaches, Section 2.16 states the research gap, and Section 2.17 traces each challenge of Chapter 1 to existing approaches, their remaining limitation, the ATIDEP component that responds to it, and the experimental condition and metric that evaluate the response.

For each important source or group of sources the review states the research problem, the approach, the main findings or contribution, the relevance to ATIDEP, and the limitation relative to ATIDEP's research problem; each theme ends with the gap that remains.

**Method.** The review is a structured narrative review, not a systematic review conforming to a protocol such as PRISMA. Searches were first run on 2 October 2026 and repeated on 20 and 21 October 2026 with a general web-search service, which returns publisher pages, preprint servers, proceedings and code repositories. They were organised by theme (Table 2.1). Central papers were then searched by title and author to confirm bibliographic details, and citation chasing from the closest works identified further sources. The October 2026 repetition was deliberately aimed at finding work that overlaps with ATIDEP, so that no closely related system is omitted; it added fifteen sources, several of which narrow the novelty claim (Section 2.16). Peer-reviewed venues and credible preprints from 2017 to 2026 were included where they bore directly on one of the themes; practitioner sources were included only where they define widely used frameworks or formats, or document a system that is otherwise undocumented, and are labelled as such. Marketing material, vendor blogs without a method, and sources that could not be matched to an identifiable author or publisher were excluded.

| Theme | Representative search |
|---|---|
| LLM-generated detection rules | "LLM generate Sigma detection rules from cyber threat intelligence reports"; "LLM generate SIEM detection rules from threat intelligence validation human-in-the-loop deployment"; system names (SIGMERGE, AutoSigma, LLMCloudHunter, RulePilot, FALCON, GenTI) |
| CTI benchmarks for LLMs | "CTIBench benchmark large language models cyber threat intelligence"; "CTI-REALM" |
| Extraction of ATT&CK techniques from reports | "automatic extraction of ATT&CK techniques from threat reports" with system names (TTPDrill, LADDER, rcATT, EXTRACTOR, aCTIon, TTPrint) |
| Quality, testing and lifecycle of rules | "Sigma rules empirical study quality SIEM detection rules ATT&CK coverage false positives"; "SOC workflows management of NIDS rules" |
| LLMs in cyber security and SOCs (surveys, frameworks) | "survey large language models for cyber security systematic literature review"; "end-to-end LLM framework SOC" |
| Prompt injection against security pipelines | "prompt injection attack on LLM cyber threat intelligence extraction pipeline"; "prompt injection LLM-augmented security operations log content" |
| Hallucination, refinement, judging, contamination | title and author searches for the foundational papers |
| Economics of security, TCO, cost-aware LLM use, open-source definitions | title searches for the foundational papers; "cost-effectiveness evaluation LLM security operations automation analyst time"; "open source SIEM total cost of ownership" (results were vendor and blog material and were excluded) |
| Automation bias and design-science method | title and author searches |

: Table 2.1. Search themes and representative queries.

**Verification.** Every source was re-checked in October 2026 and the result is recorded per source in `paper/verification_records.yaml`: the title, authors, year, venue and identifier found, any discrepancy with the bibliography, which sentences of this thesis the source supports, and the URLs of the extracts. The network policy of the authoring environment blocks publisher sites, DOI resolution and arXiv, so papers could be checked only through search-engine extracts: for 58 sources the extracts showed abstract-level content, for 6 only metadata. Five sources (two software repositories, a format specification, a practitioner framework and the Wazuh documentation) were read directly from their repositories. **No paper has been checked against its full text, and full-text verification is pending for every paper cited in this chapter.** Statements about what a work does *not* report are therefore bounded by what its abstract-level extracts show, and are phrased accordingly ("not reported in the extracts"). The comparison matrix (Section 2.14) was compiled by one reader from the same extracts; a second, independent reading against the full texts is pending.

<!-- VERIFY(full-text): read the closest works in full (Section 2.14 rows marked A) and confirm every "not reported" statement in Sections 2.4, 2.14, 2.15 and 2.16; repeat the search shortly before submission. -->

## Threat-intelligence sources, sharing and quality

**Concepts and standards.** Threat intelligence is exchanged in structured forms, of which STIX is the OASIS standard [@oasis2021stix], and under organisational guidance on how to share it responsibly [@johnson2016nist]. Surveys of technical threat intelligence and of CTI sharing review the benefits of sharing, its technical and non-technical obstacles, and directions for research [@tounsi2018survey; @wagner2019sharing]. This body of work concerns *how* intelligence is represented and exchanged; in the abstracts reviewed, it says little about how much effort is needed to act on it.

| Work | Research problem | Approach | Main findings | Relevance to ATIDEP | Limitation relative to ATIDEP |
|---|---|---|---|---|---|
| Li et al. [@li2019tea] | How do threat-intelligence sources compare? | Metrics for characterising feeds, applied to public and commercial sources | Most sources do not overlap; coverage is limited | Feeds cannot be treated as complete or as ground truth | Characterises sources; does not address turning them into detections |
| Bouwman et al. [@bouwman2020cup] | What is the added value of commercial threat intelligence? | Analysis of two leading vendors' indicators against each other and four open feeds; 14 practitioner interviews | Almost no overlap (2.5% to 4.0% average for 22 shared actors); overlapping indicators appear in the other feed about a month later; customers appeared to optimise for analyst time rather than detection coverage | Motivates analyst effort as an outcome, and validation and expiry of indicators | Does not study the detection-engineering step |
| Griffioen et al. [@griffioen2020quality] | How good are open-source CTI feeds? | Multi-month evaluation of open-source feeds (24, per secondary extracts) | Significant variation in quality (secondary extracts only) | Supports filtering, expiry and source reliability scoring | Feed-level; no detection content |

: Table 2.2. Threat-intelligence quality.

**Indicators versus behaviour.** The Pyramid of Pain ranks indicator types by how much it hurts an adversary to have them detected: hash values and similar low-level indicators are trivial to change, whereas detecting TTPs forces the adversary to change behaviour [@bianco2013pyramid]. ATT&CK supplies a shared vocabulary for that behaviour [@strom2018attack]. Indicator detections and behaviour detections are therefore different artefacts with different lifetimes and false-positive profiles; ATIDEP's indicator lists and Sigma rules follow this distinction. The half-lives used in ATIDEP's recency score are design parameters, not findings from the literature, and are subject to sensitivity analysis.

**Remaining gap.** The literature shows that intelligence is plentiful, uneven and overlapping little across sources, and, in one interview study, that customers appeared to optimise for analyst time [@bouwman2020cup]. In the works reviewed, it does not measure how much analyst time is needed to turn intelligence into detections, nor how much of that time automation saves.

## Threat-intelligence extraction and structuring

A long line of work extracts structured knowledge from threat-report text, first with classical NLP and, since 2023, with language models.

| Work | Research problem | Approach | Main findings | Relevance to ATIDEP | Limitation relative to ATIDEP |
|---|---|---|---|---|---|
| TTPDrill [@husari2017ttpdrill] | Manual analysis of unstructured CTI is slow | Threat-action ontology; NLP and information retrieval; mapping to techniques, tactics and kill-chain phases; STIX output | More than 82% precision and recall on vendor reports | Shows behaviours can be extracted and mapped to ATT&CK | Stops at structured knowledge |
| rcATT [@legoy2020rcatt] | Retrieve ATT&CK tactics and techniques from reports | Comparison of classifiers; released tool | A practical released classifier with STIX output | Baseline for ATT&CK mapping | No detection content |
| EXTRACTOR [@satvat2021extractor] | Extract attack behaviour from reports without strong assumptions on the text | Provenance graphs from unstructured text | Concise graphs from real incident and DARPA engagement reports, usable for threat hunting | Behaviour-centred extraction | Output is for hunting, not deployable rules |
| LADDER [@alam2023ladder] | Look beyond IoCs to durable attack patterns | Extraction of text-based attack patterns at scale, mapped to ATT&CK; released dataset | Attack-phase models for Android and enterprise networks | Supports behaviour-based detection | No detection content |
| aCTIon [@siracusano2023action] | Automate structured CTI analysis with LLMs | Two GPT-3.5 extraction pipelines; dataset of 204 reports with STIX annotations | F1 gains of roughly 10 to 50 points over ten earlier approaches | LLM extraction is effective but imperfect | No detection content; no defences against injected instructions reported |
| CTIBench [@alam2024ctibench] | Are LLMs reliable on CTI tasks? | Benchmark (multiple-choice knowledge, mapping vulnerabilities to weaknesses, severity prediction, further tasks) | Motivated by reliability and hallucination concerns; code and data released | Grounds the concern that model output must be checked | Measures models, not workflows |
| TTPrint [@cheng2026ttprint] | Get both precision and recall in ATT&CK extraction | Broad candidate proposal, deterministic span localisation tying each candidate to source text, convergent filtering against evidence and ATT&CK definitions | Macro-F1 of 76.48% and 87.39% on two benchmarks | Closest in spirit to ATIDEP's verbatim-quotation check: evidence is located deterministically | Extraction only |
| TRACE-CTI [@valletta2026tracecti] | Extracted TTP mappings are fallible and stored without evidence or validation history | Per-run predictions aggregated into assertions exposed only when backed by policy-compliant validation, with provenance, versioned trust decisions and revocation | Requiring unanimity across six setups raised precision from 25.3% to 90.6% but cut recall from 88.2% to 16.3% | Governance and audit of claims, like ATIDEP's evidence store and audit chain | Governs extraction output, not rules or deployment |
| Meng et al. [@meng2025ctivuln] | Why do LLMs fail at CTI? | Large-scale evaluation on benchmarks and real reports with human inspection | Three failure modes: spurious correlations, contradictory knowledge, constrained generalisation | Explains why extraction errors must be tolerated downstream | Diagnoses failures; does not build a pipeline |

: Table 2.3. Extraction and structuring of threat intelligence.

**Remaining gap.** This line of work produces structured *knowledge* (techniques, patterns, graphs, assertions), and the most recent work grounds it in located evidence [@cheng2026ttprint] and governs it with provenance [@valletta2026tracecti]. As described in the extracts, none of these systems produces a tested, deployable detection rule, so the steps from telemetry to approval remain outside their scope. Extraction errors remain even for the best systems, so a downstream pipeline must tolerate them: in ATIDEP every claim must be a quotation found verbatim in the sanitised report, and claims that fail are excluded and counted.

## From threat intelligence to detection rules

The closest works generate detection content from intelligence or from descriptions of attacks.

| Work | Research problem | Approach | Main findings | Relevance to ATIDEP | Limitation relative to ATIDEP (as reported in the extracts) |
|---|---|---|---|---|---|
| LLMCloudHunter [@schwartz2024llmcloudhunter] | Cloud CTI is ignored by earlier automated tools | LLMs produce Sigma rule candidates from text and images in open-source cloud CTI | 92% precision and 98% recall for actor API calls; 99% and 98% for IoCs; 99.18% of candidates compile to Splunk queries | Closest early generator from CTI; compilation is checked | Approval, deployment, adversarial robustness, analyst effort and cost not reported |
| SIGMERGE [@cai2026sigmerge] | Bridge report text and Sigma rules | Semantic intermediate layer: extraction of ATT&CK TTPs and commands, attack-description generation, Sigma generation | Evaluated with 23 metrics against 16 baselines and 13 LLMs; 10 case studies integrated with real security systems | The strongest generator in the literature; ATIDEP does not claim to generate better rules | No deterministic gates, approval, adversarial testing, effort or cost reported |
| AutoSigma [@ghaffarzadegan2026autosigma] | Turn unstructured CTI into Sigma rules | Knowledge-base enrichment; retrieval of existing Sigma rules as templates; LLM-as-a-judge validation loop | Gains in validity, relevancy and ATT&CK coverage over baselines; operational validation with live alerts left to future work | Validate-and-revise loop; template grounding | Validation by a model judging a model; deployment is future work; no approval, adversarial testing, effort or cost reported |
| FALCON [@mitra2025falcon] | Generate deployable IDS rules from CTI in real time | Agentic framework with built-in multi-phased validators; Snort and YARA rules | 95% average accuracy; qualitative evaluation by analysts with 84% inter-rater agreement | CTI-to-rule with validators and analyst assessment, the closest to ATIDEP's chain outside SIEM rules | Network and file signatures, not SIEM rules; nature of the validators, human approval, deployment and rollback, effort and cost not reported |
| RulePilot [@wang2025rulepilot] | Rule languages demand scarce expertise | LLM agent creates and converts rules from analysts' natural-language descriptions through an intermediate representation | Up to 107.4% better textual similarity to ground truth than baselines; execution success evaluated | Intermediate representation; conversion between rule languages | Starts from analyst descriptions, not reports; governance not reported |
| Tseng et al. [@tseng2024ctiagent] | Automate CTI analysis in SOCs | GPT-4 agent extracts IoCs and generates regular expressions for SIEM use; consensus across model instances and retrieval checks reduce errors | Large numbers of IoCs and expressions generated from CTI reports | Indicator path with explicit hallucination controls | Indicator-level matching only; approval and deployment not reported |
| GenTI [@hadi2026genti] | Signature rules adapt poorly to unseen attacks | Benchmark and fine-tuned generator for IDPS and YARA rules | Higher unseen-attack detection and fewer false positives than general models (figures seen in secondary listings only) | Measures detection and false positives, not only syntax | Network and file signatures; governance and cost not reported |
| Schafhauzer et al. [@schafhauzer2026context] | Can an LLM tailor SIEM rules to an organisation? | An LLM given an organisation profile and Wazuh's native rule catalogue writes local Wazuh rules; evaluated on 1,000 production SSH events | **Negative result:** accuracy fell 4.4 points and weighted F1 3.1 points against the native rules | The only work found that generates rules for Wazuh with an LLM; shows that plausible LLM rules can make a real SIEM worse | Not CTI-driven; no gates or approval workflow reported |
| Maiorano [@maiorano2026probe] | Analysts still write rules for attack-simulation findings by hand | Deterministic template mapping from findings to starter Sigma rules, with traceability to finding and technique | 17/17 rules parse and convert, yet on replay they fire on 30% and 14% of two held-out attack sets at 7.7% false positives | Determinism and traceability; shows validity is not effectiveness | Input is simulation findings, not reports; no LLM |
| CTI-REALM [@chakraborty2026ctirealm] | Can agents do the analyst's whole task? | Benchmark environment: agents read CTI, explore schemas, run queries and write detections, scored against ground truth with trajectory rewards | 16 models evaluated; best overall reward 0.637; CTI-specific tools help | Realistic end-to-end evaluation of generation | Measures agents, not a governed workflow; no approval, deployment or cost |
| SigmaGen (practitioner talk) [@pham2025sigmagen] | Scale Sigma rule writing | Attack patterns from security blogs, ATT&CK mapping, fine-tuned LLMs | No paper or benchmark found | Shows practitioner interest | Weak evidence; not a research result |

: Table 2.4. Generation of detection content from intelligence or attack descriptions.

These works are significant. Together they show that LLM-based generation of detection content from intelligence is feasible and is improving quickly; that intermediate representations, retrieval of existing rules and validate-and-revise loops help; that realistic evaluation environments now exist; and that baseline comparisons are standard. They are strong on the dimensions they chose to measure: validity, relevance, coverage, compilation, similarity to reference rules and, in CTI-REALM and GenTI, behaviour against data. Two results temper the picture: a rule that parses and converts can still detect little [@maiorano2026probe], and LLM-written rules for a real Wazuh deployment can be worse than the platform's own [@schafhauzer2026context].

**Remaining gap.** As reported in the extracts, none of these works combines generation from threat reports with deterministic pass/fail gates that block deployment independently of any score, an approval bound to the exact content of the rule, deployment with rollback to an open-source SIEM, an adversarial test of its own controls, a measurement of analyst effort against a manual workflow, and an analysis of cost. Individual works cover one or two of these.

## Sigma, platform-independent rules and conversion to Wazuh

**Practice and formats.** Detection engineering is documented largely through practitioner frameworks rather than academic theory. The Alerting and Detection Strategy framework asks authors to record a detection's goal, categorisation, strategy abstract, technical context, blind spots and assumptions, false positives, validation, priority and response [@palantir2017ads]. Sigma provides the portable rule format, a generic signature format for SIEM systems [@sigmahq2024spec]. Both inform ATIDEP's data model: the use-case fields it requires, the declaration of engineering assumptions, and the mandatory false-positive hypotheses.

| Work | Research problem | Approach | Main findings or contribution | Relevance to ATIDEP | Limitation relative to ATIDEP |
|---|---|---|---|---|---|
| Tyrian Detection Pack [@zshguy2026tyrian] (software) | Sigma rules need faithful translation to Wazuh | A compiler that rewrites disjunctions into sibling rules, refuses to emit a rule that can never fire, and reports every refusal | Of 3,144 SigmaHQ rules, 3,007 translated and 137 declined (96%), producing 3,609 Wazuh rules; MIT licence | The closest prior art for ATIDEP's converter, and the same refuse-rather-than-approximate principle | A compiler and rule pack, not a CTI-to-detection workflow |
| sigma_to_wazuh [@theflakes2024sigmatowazuh] (software) | Convert Sigma rules to Wazuh | Script producing one or more Wazuh rules per Sigma rule | Some OR-logic conversion still broken; `near` and timeframe rules skipped; Python version no longer maintained | Documents the constraints a converter must respect | Not maintained; partial |
| Wazuh documentation [@wazuh2026docs] | (platform documentation) | Rules as XML elements combined conjunctively; constant-database lists for exact lookups; rule-testing and API facilities | Platform behaviour measured in this project's spikes (ADR-001) | Defines the target | — |

: Table 2.5. Conversion of portable rules to Wazuh.

Wazuh describes itself as a free and open-source XDR and SIEM platform [@wazuh2026overview]. **Remaining gap.** Conversion is treated by the generation literature mostly as compilation into a commercial query language (Splunk, KQL). The open-source converters establish the engineering constraints for Wazuh, but, in the sources found, no work combines such a converter with an LLM generation pipeline, a Sigma-level matcher, and a measured fidelity check against Wazuh's own rule tester.

## Validation, testing and quality of detection content

| Work | Research problem | Approach | Main findings | Relevance to ATIDEP | Limitation relative to ATIDEP |
|---|---|---|---|---|---|
| Tyagi [@tyagi2026sigmalint] | How to assess the quality of Sigma rules statically | Separates a binary validity gate from a weighted quality score; corpus study of SigmaHQ; seeded-defect tests of the checks | The validity/quality separation is workable at corpus scale | Same separation as ATIDEP's hard gates and ranking score; same seeded-defect idea | Assesses existing rules; governing generation is not reported in the extracts |
| Dhananjeyan and Kumaran [@dhananjeyan2026exclusion] | How does false-positive suppression evolve in a rule repository? | Nine years of SigmaHQ history; deterministic semantic suppression test; survival analysis | Exclusions are added about 5.4 times per withdrawal; 86.7% remain three years later; structural diffs miss about 31% of narrowing | Warns that automated tuning ratchets rules narrower; motivates true-positive retention in H6 | Empirical study, not a system |
| Alahmadi et al. [@alahmadi2022false] | How do SOC analysts experience alarms? | Survey of 20 and interviews with 21 practitioners from seven SOCs | High false-positive rates needing manual validation, mostly from benign triggers; five properties of good alarms (reliable, explainable, analytical, contextual, transferable) | Design requirements for ATIDEP's outputs; distinction between false positives and benign true positives | Does not study generated rules |
| Vermeer et al. [@vermeer2023alchemy] | How are network detection rules created and managed in SOCs? | Seventeen interviews with professionals at managed security providers and in-house teams | Specificity and alert volume drive rule management; recommends more specific rules, explicit feedback loops from detection to rule development, and transfer of tacit knowledge | Supports ATIDEP's feedback loop and documentation fields | Network rules; no automation studied |
| Teuwen et al. [@teuwen2025unruly] | What makes intrusion-detection rules low-noise? | Rules from a commercial managed SOC; six design principles tested for their effect on specificity | Some design choices add unnecessary analyst workload; specificity trades off against coverage | Supports breadth limits and look-alike tests | Network rules; no generation |

: Table 2.6. Validation, testing and quality of detection content.

**Remaining gap.** The quality literature establishes that validity must be separated from quality [@tyagi2026sigmalint], that conformance is not effectiveness [@maiorano2026probe], and that noise is the operational cost of poor rules [@alahmadi2022false; @teuwen2025unruly]. Seeded-defect testing exists for a linter, but in the sources found it has not been applied to the gates of a generation pipeline, together with tests on positive, negative and benign look-alike events and a breadth limit on a benign baseline.

## LLMs in cyber security and SOC automation

A systematic literature review of LLMs in cyber security analysed 127 papers from leading security and software-engineering venues (in the version described by the extracts) and shows how broad the application area has become [@xu2024llmsecurity]; a survey of LLMs for security operations centres covers the same ground for SOCs [@habibzadeh2025socsurvey]. An end-to-end framework for SOC operations combines ensemble detection on SIEM logs, syntax-constrained query generation and retrieval-augmented resolution, and reports executable queries for 88% of inputs and triage time falling from about four hours to under ten minutes [@saju2026autonomoussoc]. Industry guidance distinguishes *workflows*, in which LLMs and tools are orchestrated through predefined code paths, from *agents*, in which the model directs its own process, and advises adding agency only when its flexibility is needed [@schluntz2024effective]. ATIDEP is predominantly a workflow with bounded agentic components; the term "agent" is reserved for those.

**Remaining gap.** The SOC-automation literature reports time savings and accuracy for triage and query generation, but in the sources found it does not address detection engineering from intelligence with fail-closed governance, and its time-saving figures are the authors' own measurements without a controlled comparison against manual work.

## Reliability of LLM components

| Work | Research problem | Approach | Main findings | Relevance to ATIDEP | Limitation relative to ATIDEP |
|---|---|---|---|---|---|
| Ji et al. [@ji2023hallucination] | Generated text that is fluent but unsupported | Survey of metrics and mitigation across generation tasks and LLMs | Hallucination is pervasive and task-specific | In rules: invented fields, unsupported conditions, wrong mappings | General; not security-specific |
| Self-Refine [@madaan2023selfrefine] | Can a model improve its own output? | One model generates, critiques and refines | Improvements across seven tasks | A refinement loop can help | Feedback is the model's own opinion |
| Self-Debugging [@chen2024selfdebug] | Can models fix code from execution feedback? | Few-shot debugging with execution results and explanations | Up to 12% gains where unit tests exist; 2-3% on Spider and 9% on its hardest problems | Closest to ATIDEP's repair loop: feedback from an external check | Code, not detection rules |
| Zheng et al. [@zheng2023judge] | Can LLMs judge LLM output? | MT-Bench and Chatbot Arena | Strong judges agree with humans about as often as humans agree with each other, but show position, verbosity and self-enhancement biases | A judge can be biased, so a safety gate should not be a judge | Not about security gates |
| Sainz et al. [@sainz2023contamination] | Benchmark contamination | Position paper with levels of contamination | Training on test data inflates results and can produce wrong conclusions | Motivates post-cutoff reports and a similarity check against SigmaHQ | General |

: Table 2.7. Reliability of LLM components.

**Remaining gap.** Refinement loops work best when the feedback comes from an external check [@chen2024selfdebug], and LLM judges carry known biases [@zheng2023judge]. Generation systems for detection rules use model-driven validation [@ghaffarzadegan2026autosigma] or report compilation; in the sources found, none drives its repair loop with deterministic validators whose structured defect reports are the only feedback the model receives, and none reports the effect of removing the validators or the repair loop on the same pipeline.

## Prompt injection and adversarial risks in LLM pipelines

| Work | Research problem | Approach | Main findings | Relevance to ATIDEP | Limitation relative to ATIDEP |
|---|---|---|---|---|---|
| Perez and Ribeiro [@perez2022ignore] | Can instructions in the input hijack a model? | PromptInject framework against GPT-3 | Goal hijacking and prompt leaking with simple handcrafted inputs | Reports can carry such inputs | Direct injection only |
| Greshake et al. [@greshake2023indirect] | Can retrieved content compromise LLM-integrated applications? | Indirect injection into data likely to be retrieved; real and synthetic applications | Remote compromise including data theft and contamination of the information ecosystem | A CTI pipeline ingests exactly such untrusted content | General applications |
| OWASP Top 10 for LLM applications [@owasp2023llmtop10] | (practitioner guidance) | Ranked list of risks | Prompt injection first; excessive agency addressed by least privilege | Informs tool-less agents and limited privileges | Guidance, not evidence |
| Pandey and Bhujang [@pandey2026watchtower] | Can attackers inject instructions through the logs an LLM analyses? | Taxonomy of four attack classes in attacker-controlled log fields; 48 strategy-defence-task combinations | Log content is an injection channel inherent to SOC pipelines | Security pipelines are a concrete injection target | Log analysis, not CTI-to-rule generation |

: Table 2.8. Prompt injection and adversarial risks.

**Remaining gap.** Injection is well characterised for general applications and, recently, for SOC log analysis. The October 2026 search did not find a study that applies a set of injected threat reports to a CTI-to-rule pipeline and measures which defences stop which attacks, nor one that applies seeded defective rules to such a pipeline's gates and reports the escape rate with an exact confidence bound.

## Human-in-the-loop automation and governance

Approval by a human is ATIDEP's final control, and the literature on automation bias says it cannot be assumed to be effective. A review of empirical studies found that complacency and automation bias are overlapping phenomena in which attention plays a central role, that they occur in experts as well as novices, and that they are not removed by simple practice or by training and instructions [@parasuraman2010complacency]. A systematic review of 74 studies of automation bias, framed around clinical decision support, found that user factors such as experience and trust, and environmental factors such as workload and time pressure, mediate over-reliance [@goddard2012automation]. An anthropological study of a corporate SOC described analyst burnout as a human-capital management problem arising from the interaction of human, technical and managerial factors [@sundaramurthy2015burnout]. TRACE-CTI shows how governance of automated output can be made explicit, with provenance, versioned trust decisions and revocation, for extracted claims [@valletta2026tracecti].

**Remaining gap.** These findings argue against treating the reviewer as a guarantee. In the sources found, generation systems do not report an approval step that is bound to the exact content and its validation report, nor a test of what happens when an approved rule is changed afterwards. ATIDEP makes the reviewer's task explicit (verified quotations, every gate result, declared assumptions), binds approval to content hashes, measures the effect of tampering (seeded class D10) and re-reviews a sample of approvals. The researcher being both author and approver in the laboratory remains a stated limitation.

## Deployment and detection lifecycle management

Rule management in practice is a lifecycle: rules are created, tuned, narrowed and occasionally withdrawn. Interview evidence recommends explicit feedback loops from detection back to rule development [@vermeer2023alchemy]; repository evidence shows that suppression accumulates and rarely relaxes [@dhananjeyan2026exclusion]; and an LLM-aided recommender identifies redundant or overlapping rules in existing SIEM rule sets, with a local open-source model reaching over 80% recall and 75% precision [@shukla2025rulegenie]. On the deployment side, the Wazuh documentation defines how rules and lists are loaded and tested [@wazuh2026docs], and the open-source rule pack installs detections on a Wazuh manager in one command [@zshguy2026tyrian].

**Remaining gap.** In the sources found, no CTI-to-detection system deploys through a least-privilege interface with rollback and returns tuning proposals to the same validation and approval gates as new rules, with a measured trade-off between false-positive reduction and true-positive retention.

## Open-source security automation and the meaning of "open source"

The Open Source Definition sets criteria for open-source software licences, including free redistribution, availability of source code, derived works, and no discrimination against persons, groups or fields of endeavour [@osi2007osd]. For AI systems, the Open Source AI Definition 1.0 requires, in addition to code and parameters under approved terms, sufficiently detailed information about the training data that a skilled person could build a substantially equivalent system [@osi2024osaid]. A model released only as open weights does not meet that definition. Several of the works reviewed release code or data [@legoy2020rcatt; @alam2024ctibench; @dhananjeyan2026exclusion; @schafhauzer2026context; @valletta2026tracecti], and RuleGenie compares a local open-source model with a proprietary one, noting the privacy and cost advantage of the former without analysing cost [@shukla2025rulegenie].

**Remaining gap.** "Open source" is usually stated as an availability property. In the sources found, it is not treated as a claim to be audited (licences of every component, classification of the model) nor connected to a measured cost.

## Economic and cost-effectiveness evaluation

| Work | Research problem | Approach | Main findings | Relevance to ATIDEP | Limitation relative to ATIDEP |
|---|---|---|---|---|---|
| Anderson [@anderson2001hard] | Why is security hard? | Economic analysis | Insecurity is at least as much due to perverse incentives as to technical design | Frames cost as a first-class design dimension | Framing, not a costing method |
| Gordon and Loeb [@gordon2002economics] | How much should be invested in information security? | Economic model of investment against breach probability | For the two classes of breach function analysed, the optimal investment does not exceed about 37% (1/e) of the expected loss | Frames security spending as an optimisation | Investment-level, not workflow-level; later work shows the bound is not general |
| Ellram and Siferd; Ferrin and Plank [@ellram1998tco; @ferrin2002tco] | How to compare alternatives beyond purchase price | Total cost of ownership; exploratory study of TCO models in purchasing | Organisations use TCO models with identifiable cost drivers | The reason ATIDEP separates licence, infrastructure, hardware, energy, storage, inference, labour, maintenance, development and onboarding, with build and adopt views | Not security-specific |
| FrugalGPT [@chen2024frugalgpt] | LLM API fees differ by two orders of magnitude | Prompt adaptation, model approximation, cascades | Matches the best single model with up to 98% lower cost, or 4% higher accuracy at the same cost | Model cost is a design variable | Inference cost only; not security |
| RouteLLM [@ong2025routellm] | Route queries between strong and weak models | Routers trained on preference data | More than a twofold cost reduction without loss of response quality on public benchmarks | Local versus hosted model choice | Inference cost only |
| Bouwman et al. [@bouwman2020cup] | (see Table 2.2) | Interviews | Customers appeared to optimise for analyst time | Analyst labour is the expected principal cost driver | Not a costing |

: Table 2.9. Economic and cost-effectiveness evaluation.

Vendor and practitioner material asserts large total-cost differences between open-source and commercial SIEMs, and repeats the caution that "free" software still incurs infrastructure, storage, support and skilled-labour costs; some vendors report a cost per alert for their own automated triage. These sources were excluded under the criteria in Section 2.1: they are vendor or blog material without a stated method, and some are published by sellers of the products concerned. The thesis therefore uses no such estimate as evidence. It measures its own workflow, takes every price and rate from a cited primary source (a vendor's own published price page, or a written quotation) or leaves it explicitly missing, and states its assumptions. The same caution applies in the other direction: that open-source tooling avoids licence fees is not evidence that it is cheaper overall.

**Remaining gap.** The October 2026 search found no peer-reviewed study that measures, together, the analyst time saved and the cost per unit of detection content for LLM-based detection engineering, against both a manual workflow and a comparable paid configuration, with sourced prices and a decision rule fixed in advance. The generation works report quality and compilation measures but, in the extracts, no unit cost per accepted rule and no break-even analysis.

## Comparison matrix

Table 2.10 compares the works that build, benchmark, validate or govern part of the path from intelligence to deployed detection content, on the capabilities that matter to ATIDEP's problem. A capability is marked only where the source, as read, states it; everything else is "not reported", which is not a claim that the full text lacks it. The evidence for every marked cell, with its source, is in `paper/related_work_matrix.md`.

<!-- MATRIX:BEGIN (generated by tools/related_work_matrix.py) -->
| Work | Year | M1 | M2 | M3 | M4 | M5 | M6 | M7 | M8 | M9 | M10 | M11 | M12 | M13 | Read |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SIGMERGE [@cai2026sigmerge] | 2026 | Y | Y | – | Y | Y | – | – | – | P | – | – | – | – | A |
| AutoSigma [@ghaffarzadegan2026autosigma] | 2026 | Y | P | – | P | Y | – | – | – | N | – | – | – | – | A |
| LLMCloudHunter [@schwartz2024llmcloudhunter] | 2024 | Y | Y | Y | Y | Y | P | – | – | – | – | – | – | – | A |
| CTI-REALM [@chakraborty2026ctirealm] | 2026 | Y | – | – | P | Y | P | – | – | – | – | – | – | – | A |
| Detection-as-code from attack simulation [@maiorano2026probe] | 2026 | N | – | – | P | Y | P | – | – | P | – | – | – | – | A |
| Static quality assessment of Sigma rules [@tyagi2026sigmalint] | 2026 | – | – | – | – | – | Y | – | – | – | – | – | – | – | A |
| The Exclusion Ratchet [@dhananjeyan2026exclusion] | 2026 | – | – | – | – | – | – | – | – | – | P | – | – | Y | A |
| Tyrian Detection Pack [@zshguy2026tyrian] | 2026 | – | – | – | – | P | Y | – | – | P | – | – | – | Y | R |
| sigma_to_wazuh [@theflakes2024sigmatowazuh] | 2021 | – | – | – | – | P | P | – | – | – | – | – | – | Y | R |
| TTPDrill [@husari2017ttpdrill] | 2017 | Y | Y | – | – | – | – | – | – | – | – | – | – | – | A |
| rcATT [@legoy2020rcatt] | 2020 | Y | Y | – | – | – | – | – | – | – | – | – | – | Y | A |
| LADDER [@alam2023ladder] | 2023 | Y | Y | – | – | – | – | – | – | – | – | – | – | P | A |
| EXTRACTOR [@satvat2021extractor] | 2021 | Y | Y | – | – | – | – | – | – | – | – | – | – | – | A |
| aCTIon [@siracusano2023action] | 2023 | Y | Y | – | – | – | – | – | – | – | – | – | – | – | A |
| CTIBench [@alam2024ctibench] | 2024 | P | P | – | – | – | – | – | – | – | – | – | – | Y | A |
| RulePilot [@wang2025rulepilot] | 2025 | – | – | – | – | Y | P | – | – | – | – | – | – | – | A |
| FALCON [@mitra2025falcon] | 2025 | Y | – | – | – | Y | P | – | – | – | – | – | – | – | A |
| RuleGenie [@shukla2025rulegenie] | 2025 | – | – | – | – | – | – | – | – | – | P | – | – | – | A |
| CTI analysis agent for SOCs [@tseng2024ctiagent] | 2024 | Y | Y | Y | – | P | P | – | – | – | – | – | – | – | A |
| Context-aware SIEM rule generation [@schafhauzer2026context] | 2026 | – | – | – | – | Y | P | – | – | – | – | – | – | Y | A |
| GenTI [@hadi2026genti] | 2026 | P | – | – | – | Y | – | – | – | – | – | – | – | – | A |
| TTPrint [@cheng2026ttprint] | 2026 | Y | Y | – | – | – | – | – | – | – | – | – | – | – | A |
| TRACE-CTI [@valletta2026tracecti] | 2026 | – | P | – | – | – | P | – | P | – | – | – | – | Y | A |
| End-to-end LLM SOC framework [@saju2026autonomoussoc] | 2026 | – | – | – | – | P | P | – | – | – | – | P | – | – | A |
| SigmaGen (practitioner talk) [@pham2025sigmagen] | 2025 | Y | P | – | – | Y | – | – | – | – | – | – | – | – | A |
| **ATIDEP (design, not a result)** | 2026 | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | Y | P | – |

: Table 2.10. Related-work comparison matrix (capabilities stated in the sources as read).

Columns: M1 CTI ingestion; M2 Structured extraction; M3 IOC generation; M4 Behavioural detection; M5 Sigma / rule generation; M6 Deterministic validation; M7 Adversarial / prompt-injection evaluation; M8 Human approval / governance; M9 Deployment / rollback; M10 Feedback / improvement; M11 Analyst-effort measurement; M12 Economic / cost analysis; M13 Open-source availability. Y = yes, P = partial, N = no (the source says so), – = not reported in the source as read. Read: A = abstract-level search extracts, M = metadata only, R = software README read directly, F = full text. No row has been checked against a full text. Evidence for every marked cell: `paper/related_work_matrix.md`.
<!-- MATRIX:END -->

## Limitations of existing approaches

Read across Tables 2.2 to 2.9 and the matrix (Table 2.10), the limitations of existing approaches relative to ATIDEP's research problem are the following. Each is bounded by the verification limits of Section 2.1.

1. **Stages are addressed separately.** Extraction systems stop at structured knowledge; generation systems stop at a rule that compiles, scores well against references or passes an LLM judge; converters translate rules that already exist; quality studies examine repositories; SOC frameworks address triage and queries. The extracts show no work that carries one item from report to an approved, deployed and tuned rule under one set of controls.
2. **Validation is mostly not fail-closed.** Validation is reported as compilation, similarity, an LLM judge or validators of unstated nature [@schwartz2024llmcloudhunter; @ghaffarzadegan2026autosigma; @mitra2025falcon]. Deterministic gates appear in a linter [@tyagi2026sigmalint], a converter [@zshguy2026tyrian] and a governance layer for extracted claims [@valletta2026tracecti], but not, in the extracts, as hard gates that block a generated rule from approval and deployment regardless of any score.
3. **Effectiveness is measured on rules, not on work.** Rule quality is measured by automatic metrics, reference similarity, compilation or, in a few cases, behaviour on data [@chakraborty2026ctirealm; @maiorano2026probe; @hadi2026genti; @schafhauzer2026context]. Analyst effort is reported only as authors' time-saving figures for triage [@saju2026autonomoussoc]; no work in the extracts compares analyst active time against manual detection engineering under a design that controls order and learning, or judges quality by blinded raters with a non-inferiority margin.
4. **The controls themselves are not attacked.** Prompt injection is studied for general applications and SOC log analysis [@greshake2023indirect; @pandey2026watchtower], and seeded defects for a linter [@tyagi2026sigmalint], but the extracts show no seeded-defect or injected-report evaluation of a CTI-to-rule pipeline's gates.
5. **Open-source SIEM targets are rare and difficult.** Generation targets Sigma, Splunk, KQL, Snort or YARA; the only LLM work found that generates Wazuh rules reports a negative result [@schafhauzer2026context], and the converters document the constraints [@zshguy2026tyrian; @theflakes2024sigmatowazuh].
6. **Cost is asserted rather than evaluated.** Cost appears as inference-cost optimisation [@chen2024frugalgpt; @ong2025routellm], as a remark on local models [@shukla2025rulegenie] or in vendor claims that cannot serve as evidence; no work in the extracts evaluates the full cost of a detection-engineering workflow against a comparable paid configuration.

## Research gap

The reviewed literature indicates limited evidence of an integrated approach that jointly evaluates the technical and the economic side of LLM-assisted detection engineering. Existing studies commonly address individual stages (extraction, generation, conversion, quality assessment, triage, governance of extracted claims), and several address two or three of them strongly; evidence concerning the integrated workflow remains limited. Specifically, in the sources found and as their abstract-level extracts describe them, no study combines, for one pipeline:

- threat-intelligence ingestion and structured, evidence-linked extraction;
- identification of whether a defensible detection opportunity exists, given the telemetry actually collected;
- generation of both indicator lists and behavioural rules;
- deterministic security and quality gates that block a rule regardless of any score;
- a bounded repair loop driven only by those gates' defect reports;
- a human approval bound to the exact content and validation report;
- controlled deployment to an open-source SIEM with rollback;
- feedback-driven improvement that re-enters the same gates;
- adversarial testing of the controls with seeded defective rules and injected reports;
- a bias-controlled measurement of analyst effort against a manual workflow and of quality against a non-inferiority margin; and
- a technical-versus-economic evaluation against a defined, comparable paid scenario.

The gap is therefore **not** that no system generates detection rules from threat intelligence: several do, and some do so well [@cai2026sigmerge; @ghaffarzadegan2026autosigma; @schwartz2024llmcloudhunter; @mitra2025falcon]. It is the absence, in the evidence found, of a governed, fail-closed, end-to-end workflow for an open-source target that is evaluated as a workflow (on analyst effort, independently judged quality, resistance to attack on its own controls, and cost) rather than as a generator.

**How ATIDEP differs from or extends existing work.** ATIDEP does not claim a more accurate generator than SIGMERGE, AutoSigma, LLMCloudHunter or FALCON, nor that any of its components is individually new: evidence-located extraction [@cheng2026ttprint], governance of claims [@valletta2026tracecti], validity gates [@tyagi2026sigmalint], refusing converters [@zshguy2026tyrian] and validator-driven repair [@chen2024selfdebug] all have precedents. Its intended contribution is the integration of these ideas into one governed workflow, the fail-closed placement of deterministic gates before human approval and deployment, and an evaluation design that measures the workflow on both dimensions, including attacks on its own controls. If the full-text reading of the works in Table 2.10 shows that one of them already covers a point of the list above, the corresponding contribution in Chapter 1 will be narrowed accordingly.

## From challenges to design and evaluation

Table 2.11 traces each challenge of Chapter 1 to the existing approaches reviewed, the limitation that remains, the ATIDEP component designed to respond, the experimental condition that tests the response, and the metric. Conditions: A manual; B ATIDEP full; B-V validators logged but not enforced; B-R no repair loop; C single prompt with the same model and information. Scenarios: S-MANUAL, S-OSS-LOCAL (ATIDEP as built), S-PAID (modelled paid configuration).

| # | Challenge | Existing approaches | Remaining limitation | ATIDEP component | Condition | Metric |
|---|---|---|---|---|---|---|
| 1 | Unstructured, heterogeneous reports | Classical and LLM extraction [@husari2017ttpdrill; @siracusano2023action] | Extraction stops at knowledge; errors remain | C1 sanitiser and collectors; C2 extraction | B (and C) on 30 labelled items | Precision, recall, F1 (RQ1) |
| 2 | Incomplete, ambiguous or conflicting evidence | Evidence-located extraction and claim governance [@cheng2026ttprint; @valletta2026tracecti] | Not connected to whether a rule may be built | C2 verbatim-quote verification; C3 non-generating decisions | B on items incl. 5 unsuitable | Opportunity accuracy, macro-F1 (RQ2); unsupported-extraction rate |
| 3 | Narrative to observable logic | Generators and agent benchmarks [@cai2026sigmerge; @chakraborty2026ctirealm] | Telemetry actually collected is not a hard constraint | C3 Opportunity Agent with telemetry catalogue and override; G5, G6 | B versus C | Telemetry-requirement accuracy; held-out detection rate (RQ6) |
| 4 | Hallucination and unsupported output | Model-judged validation; compilation [@ghaffarzadegan2026autosigma; @schwartz2024llmcloudhunter] | Unsupported conditions can pass a model judge | C2 quote check; G4, G5, G7 | B versus C (H5); B versus B-V | Invented-field rate; seeded D3, D4, D8 escape and gate-miss rates |
| 5 | Syntactic versus semantic correctness | Compilation and similarity metrics; replay [@maiorano2026probe] | Valid rules can detect little | G1-G3; G8-G10; blinded rubric | B, B-R; B versus A | Structural validity before and after repair (H2); rubric non-inferiority (H4) |
| 6 | Schema, field mapping and platform compatibility | Refusing converters [@zshguy2026tyrian; @theflakes2024sigmatowazuh]; LLM Wazuh rules [@schafhauzer2026context] | Not joined to generation; LLM rules can harm | Wazuh-compatible subset; refusing converter; measured field map | B (Tier 1 versus Tier 2) | Conversion fidelity; seeded D3, D6 |
| 7 | False positives and noise | Quality studies and rule-set optimisation [@alahmadi2022false; @teuwen2025unruly; @shukla2025rulegenie] | Not enforced before deployment | G10, G11; Improvement Agent with revalidation | B; feedback experiment | Benign false-positive rate; seeded D7, D9; H6 |
| 8 | Prompt injection, untrusted content | Injection studies [@greshake2023indirect; @pandey2026watchtower] | Not tested on a CTI-to-rule pipeline | C1 sanitiser; tool-less agents; schema output; quote check; allow-list; gates | B versus B-V versus C | Injection success per family (H3) |
| 9 | Validation before approval and deployment | Linters and validators [@tyagi2026sigmalint; @mitra2025falcon] | Not fail-closed before approval | C4 gates and state machine | B versus B-V versus C | Defective-rule escape rate with exact bound; rejection and gate-miss rates (H3) |
| 10 | Human governance and accountability | Automation-bias evidence [@parasuraman2010complacency; @goddard2012automation] | Approval not bound to content in generation systems | Hash-bound approval; audit chain | B, B-V (D10) | Tamper detection per route; approval re-review agreement; analyst minutes (H1) |
| 11 | Provenance, auditability, reproducibility | Claim governance [@valletta2026tracecti] | Not end to end | Evidence store; model-call log; replay store; freeze manifests | All | Audit verification; regenerated tables |
| 12 | Safe deployment, rollback, lifecycle | Feedback-loop recommendations [@vermeer2023alchemy]; exclusion ratchet [@dhananjeyan2026exclusion] | Tuning not returned to the gates | C5 least-privilege adapter, rollback, revalidation | B; feedback experiment | Acceptance criteria; true-positive retention with false-positive reduction (H6) |
| 13 | Model variability and reproducibility | Contamination warnings [@sainz2023contamination] | Single runs; possible memorisation | Pinned model; three runs; post-cutoff reports; replay | B, C (three runs) | Run-to-run variance; SigmaHQ similarity |
| 14 | Ground truth and fair evaluation | Benchmarks with ground truth [@chakraborty2026ctirealm; @alam2024ctibench] | Builder bias and learning effects not controlled | Labelling guide; second labeller; blinded raters; counterbalanced crossover; pre-registration | A versus B | κ, ICC; order and first-exposure analyses |
| 15 | Comparing open-source and paid cost | Inference-cost optimisation [@chen2024frugalgpt; @ong2025routellm]; vendor claims (excluded) | No comparable paid scenario with sourced prices | FN1-FN9 scenarios; sourced price register; H7 | S-OSS-LOCAL versus S-PAID; S-MANUAL | H7 at the primary cell; cost per valid, approved and deployed detection |
| 16 | Open source is not free | TCO concepts [@ellram1998tco; @ferrin2002tco] | Licence-free is equated with free | Twelve ledger categories; provenance of every quantity | S-OSS-LOCAL | Cost composition and evidence shares (E1); unit costs (E2) |

: Table 2.11. From challenges to design and evaluation.

## Summary

The literature shows that threat intelligence is abundant, uneven and costly to act on; that extraction of attack behaviour is established and increasingly grounded in located evidence; that LLM-based generation of detection content from intelligence is feasible, improving quickly and well benchmarked; that valid rules can still detect little, and LLM rules for a real Wazuh deployment can be worse than the native ones; that LLM components bring specific risks (hallucination, injection, judge bias, contamination); that human approval is vulnerable to automation bias; and that cost claims for open-source security tooling rest largely on vendor material. What it does not yet show, in the sources found, is how a fail-closed, human-approved, end-to-end workflow for an open-source SIEM performs when it is evaluated as a workflow, on analyst effort, independently judged quality, resistance to attack on its own controls, and cost against a comparable paid configuration. The next chapter sets out the methodology designed to answer that question.
