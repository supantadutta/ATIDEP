# Model selection (spike S3): support, not a decision

**Status: no model has been selected.** `config/experiment.yaml` still reads `TBD` for `model` and
`paid_model`, and nothing in the repository, the tests or the documents claims a model, a version
or a training cutoff. The decision belongs to the coordinator; this page says how to take it and
how to record it.

## What the decision must rest on

| Criterion | Evidence and where it comes from |
|---|---|
| Schema-valid output on the pilot items (S3 pass criterion: at least 90%) | `tools/model_probe.py` runs the real extraction prompt on pilot items and reports first-attempt and post-retry rates |
| Quotations that are verbatim in the report | the same probe reports the verbatim share |
| Fits the 12 GB host with the Wazuh VM stopped (blueprint §24) | `ollama ps` during the probe; the probe cannot measure memory portably |
| Training cutoff earlier than the start of the selection window | the model card; the probe records `training_cutoff: null` because it cannot know it |
| Licence, and its classification against the OSI Open Source AI Definition 1.0 | the licence text the server reports (excerpt in the probe) and the model card; an open-weight model is not "open-source AI" unless data information and code are disclosed too |
| Usage reporting | the probe sends one request twice and compares the reported input-token counts; a caching server may under-report, in which case input tokens are a lower bound |
| Reproducibility | seed and temperature supported; the digest or version is recorded |

## Rules

1. Name the candidates **before** measuring any of them, and record every one that was tried,
   including those that failed, so the choice cannot be a selection of the best-looking run.
2. Use the pilot items only; the test set is never used for model choice.
3. For the optional hosted-model arm (S-OSS-API), a model counts as an adequate candidate for the
   paid reference scenario only if the pipeline has actually been run on it; its training cutoff
   must also precede the item window.
4. Record the decision as an ADR (`docs/adr/0002-model-selection.md`, template below), pin the
   identifier and version in `config/experiment.yaml`, and freeze with `prereg-v1`.

## ADR template (copy to `docs/adr/0002-model-selection.md` when deciding)

```text
# ADR-002: Model selection
Status: PENDING coordinator decision (not decided by this repository)
Date: <date>
Candidates tried (all of them): <name, version or digest, size, quantisation, licence>
Evidence: <paths to tools/model_probe.py outputs and ollama ps readings>
Decision: <model, exact version or digest, training cutoff from the model card, licence and OSAID classification>
Reasons and rejected alternatives: <...>
Pinned in: config/experiment.yaml (model, paid_model if the hosted arm is run)
```

Running the probe: `python tools/model_probe.py --provider ollama --model NAME --items PILOT_DIR
--out probe-NAME.json` (`--smoke` checks the wiring on the fictional demo items; its numbers are not
evidence). For a hosted model set `ATIDEP_CLOUD_KEY` and pass `--provider cloud --url ... --api-style
...`; a hosted run is a paid call, so it is made only deliberately.
