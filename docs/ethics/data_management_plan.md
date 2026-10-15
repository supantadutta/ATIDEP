# Data management plan (DRAFT, PENDING supervisor review)

## 1. Data created or used

| Data | Origin | Personal data? | Sensitivity | Where held | Published? |
|---|---|---|---|---|---|
| Threat-intelligence reports (test set about 30, pilot about 10) | Public vendor or government reports chosen under `research/preregistration/selection_protocol.md` | No (authors' names appear only as publisher metadata) | Public, but redistribution is limited by each source's terms | The research repository's dataset folder and the evidence store | Hashes and identifiers only, unless the source's licence permits redistribution; this is checked per source and logged |
| Ground-truth labels, second-labeller labels, adjudication log | Written by the coordinator, the supervisor or a qualified peer | Labeller pseudonyms only (`L1`, `L2`) | Low | Repository | Yes, de-identified |
| Rule-quality ratings | Raters (supervisor, qualified peer) scoring anonymised, shuffled rules | Rater pseudonyms (`R1`, `R2`); no names in the data | Low | Repository, with the key to condition labels kept separately until scoring ends | Yes, de-identified |
| Event corpora: public attack datasets (inert event logs), lab-VM benign baseline, hand-built look-alikes | Public datasets (licences to be checked per dataset), a lab VM, the coordinator | No (lab usernames and hosts are synthetic) | Low; no executable samples | Repository (converted JSON events) | Subject to each dataset's licence; the lab baseline is the coordinator's own and can be published |
| Seeded adversarial rules and prompt-injection reports | Written by independent authors for this study | No | Contains deliberately hostile text and indicator-like strings; no working malware | `research/adversarial/cases/` | Yes. The injection reports contain no real credentials or live infrastructure |
| Model outputs, run logs, token counts, timings, costs | The experiment harness | No | Low | Results database and CSV exports | Yes |
| Analyst timer records | The coordinator (and, only if the optional subset runs, the participating analysts) | Pseudonymous analyst ID only | Low to moderate for participants | Application database | The coordinator's timings: yes. Other people's timings: only with their consent and de-identified |
| Cost inputs and the price register | Vendor price pages or written quotes, vendor and product named | No | Quotes may be under confidentiality terms: check before publishing | Configuration files | Published prices yes; a confidential quote only with the vendor's permission |

## 2. Principles

* No personal data is collected. Synthetic organisation, hosts, users and events are used
  throughout. No production credentials, logs or telemetry from any real organisation.
* No real malware is executed or stored. Public attack datasets are replayed as inert event logs.
* All Wazuh testing happens in an isolated laboratory network; deployment stays human-controlled.
* Raters and second labellers act as expert reviewers of anonymised public or synthetic material.
  Only their scores and labels are recorded, under pseudonymous IDs, never names.
* Cloud inference (only if the paid-API arm is run): fields sent are limited to the report text and
  the schema-conformant prompt; sensitive fields are redacted first; the provider, model, date and
  fields transmitted are recorded in the call log. No data is sent to any cloud provider unless the
  coordinator has set a key and chosen the arm.

## 3. Storage, backup and access

* The repository (private until the supervisor agrees to publication) is the single store of
  record. A second copy of the results database and exports is kept on a storage device the
  coordinator controls (`PENDING: coordinator to name it`).
* Access: the coordinator and the supervisor. Raters receive only the shuffled, anonymised rules
  they score.
* Secrets (API keys, the application's API key) are held in environment variables and never in the
  repository; `git` history is checked for secrets before any publication.

## 4. Retention and deletion

* Research data is retained for the period the university requires (`PENDING: confirm the period`)
  and then deleted or archived as the university directs.
* Cloud provider retention and logging terms are recorded when an arm is run, and the coordinator
  checks that no data is retained beyond them.

## 5. Sharing and publication

* Published: code, configuration with sourced values, prompts, hashes, de-identified results,
  analysis scripts and the freeze manifests.
* Not published without further checks: report texts whose licences do not allow redistribution
  (identifiers and hashes are published instead), confidential vendor quotes.
* Negative and unexpected results are published with the rest.

## 6. Open points (all PENDING)

1. The retention period and the university's required storage location.
2. Whether the department requires ethics review for expert raters scoring anonymised rules.
3. Each report source's terms and each public attack dataset's licence, recorded per source.
4. Whether the optional independent-analyst subset is allowed (see the consent template).
