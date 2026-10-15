# Ethics statement (DRAFT, PENDING supervisor and university)

*This is the researcher's description of the project. It is not an approval, and it does not
decide whether the university's rules require a formal review.*

## The project

ATIDEP is a defensive security tool and its evaluation. It turns public threat-intelligence reports
into reviewed detection rules and indicator lists for a laboratory Wazuh installation, with a human
approving every rule, and it compares this with manual work and with a single-prompt language model.
It also compares the cost of the workflow with a modelled commercial alternative.

## People involved

| Role | Who | What they do | What is recorded |
|---|---|---|---|
| Researcher and coordinator | The student | Builds the system; performs the manual and ATIDEP workflows; writes ground truth | Own timings, decisions, labels |
| Supervisor | Named in `supervisor_signoff.md` | Approves protocols; second labeller; rater; samples approvals | Labels and scores under a pseudonym |
| Qualified peer(s) | `PENDING: to be named` | Second labeller and rater | Labels and scores under pseudonyms |
| Independent analysts (optional) | `PENDING`, only if allowed | Complete the manual condition on at least 8 items with the timer | Pseudonymous timings and rules; consent required |

The core design needs no recruited participants. The supervisor and peers act as expert reviewers
of anonymised public or synthetic material. The optional independent-analyst subset is the only
part in which other people's performance is timed; it is run only if departmental rules allow it,
with informed consent, and the paper reports it as a limitation if it is not run.

## Risks and how they are handled

| Risk | Handling |
|---|---|
| Handling hostile content (prompt-injection reports, attack datasets) | Text only; no execution; isolated lab network; inert event logs |
| Misuse of generated detection content or of the adversarial set | The adversarial material contains no working malware, credentials or live infrastructure; deployment is human-controlled and lab-only |
| Third-party content (reports, datasets) used beyond its terms | Terms and licences checked per source; hashes published instead of text where redistribution is not permitted |
| Disclosure of sensitive information to a cloud model | Local-first inference; a cloud arm only with a key the coordinator sets; redaction before transmission; call logs |
| Pressure or stress on participants in the timed subset | Participation voluntary; may stop at any time; times are not used to assess individuals |
| Bias from the researcher's dual role | Pre-registration, blinded ratings by others, second labeller, sampled re-review of approvals; limitations reported |

## Declarations (to be completed by the coordinator and the supervisor)

* Conflicts of interest: `PENDING`
* Funding: `PENDING`
* Ethics review reference or exemption statement: `PENDING (university)`
