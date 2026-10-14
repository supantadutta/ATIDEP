"""Evidence for the model decision (spike S3). It selects nothing.

    python tools/model_probe.py --provider ollama --model NAME --items DIR [--url URL] [--out FILE]
    python tools/model_probe.py --provider ollama --model NAME --smoke        # wiring check only

For a local model (Ollama, loopback only) or a hosted one (set ATIDEP_CLOUD_KEY and pass --url and
--api-style) it records: the model's identity as the server reports it (digest, quantisation, the
licence text the model ships with, which is the starting point for classifying it against the
OSI Open Source AI Definition), whether the provider reports token usage and whether a repeated
identical request reports the same input count (a caching server may not), the first-attempt and
post-retry schema-valid rates of the real extraction prompt on the supplied pilot items (the S3
criterion is at least 90% schema-valid), the share of extracted quotations that are verbatim in the
report, and latency and tokens per second. It cannot know the training cutoff, which comes from
the model card, and it cannot measure peak memory portably (run ``ollama ps`` during the probe).

The result says "decision: pending". The coordinator picks the model and pins it in
``config/experiment.yaml``. ``--smoke`` uses the synthetic demo items and is for checking that the
tool and the endpoint work; its numbers are not evidence for choosing a model.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from components.c1_ingest.collect import collect_bytes  # noqa: E402
from components.c2_processing.evidence import check_quote  # noqa: E402
from components.c2_processing.extraction_agent import (  # noqa: E402
    ExtractionOutput,
    chunk_text,
    run_extraction,  # noqa: F401 - the same entry point the pipeline uses
)
from components.llm.client import (  # noqa: E402
    CloudChatClient,
    LLMClient,
    LLMRequest,
    OllamaClient,
    probe_usage_stability,
)
from components.llm.prompts import load_prompt_set  # noqa: E402
from components.llm.structured import SchemaError, structured_call  # noqa: E402

CRITERION = 0.90      # blueprint §21, S3: at least 90% schema-valid on the pilot items


def ollama_show(base_url: str, model: str, timeout: float = 30.0) -> dict[str, Any]:
    req = urllib.request.Request(base_url.rstrip("/") + "/api/show", method="POST",
                                 data=json.dumps({"model": model}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:    # loopback checked by the caller
        data = json.loads(resp.read())
    details = data.get("details", {})
    return {"family": details.get("family"), "parameter_size": details.get("parameter_size"),
            "quantization": details.get("quantization_level"), "format": details.get("format"),
            "model_info_keys": sorted(data.get("model_info", {}))[:8],
            "licence_text_excerpt": (data.get("license") or "")[:1500],
            "licence_text_present": bool(data.get("license"))}


def probe(client: LLMClient, texts: dict[str, str]) -> dict[str, Any]:
    prompts = load_prompt_set()
    first_ok = final_ok = chunks = 0
    quotes = verbatim = 0
    tokens_out, seconds = 0, 0.0
    usage_sources: dict[str, int] = {}
    for text in texts.values():
        for chunk in chunk_text(text):
            chunks += 1
            req = LLMRequest(agent="extraction", system=prompts.extraction.text,
                             user=f"<<<DATA>>>\n{chunk}\n<<<END DATA>>>",
                             prompt_version=prompts.extraction.version, seed=1)
            t0 = time.monotonic()
            try:
                out, calls = structured_call(client, req, ExtractionOutput, max_retries=2)
                first_ok += calls[0].schema_valid
                final_ok += 1
                for b in out.behaviors:
                    quotes += 1
                    verbatim += check_quote(b.quote, text).ok
                for e in out.entities:
                    quotes += 1
                    verbatim += check_quote(e.quote, text).ok
            except SchemaError as exc:
                calls = exc.calls
            seconds += time.monotonic() - t0
            for c in calls:
                tokens_out += c.response.output_tokens
                usage_sources[c.response.usage_source] = usage_sources.get(
                    c.response.usage_source, 0) + 1
    rate = (final_ok / chunks) if chunks else None
    return {"items": len(texts), "chunks": chunks,
            "first_attempt_schema_valid": first_ok / chunks if chunks else None,
            "post_retry_schema_valid": rate, "criterion": CRITERION,
            "meets_s3_schema_criterion": None if rate is None else rate >= CRITERION,
            "quote_verbatim_rate": verbatim / quotes if quotes else None,
            "output_tokens_per_second": tokens_out / seconds if seconds else None,
            "usage_sources": usage_sources}


def load_texts(folder: Path) -> dict[str, str]:
    out = {}
    for p in sorted(folder.iterdir()):
        if p.is_file() and p.suffix.lower() in (".html", ".htm", ".txt", ".pdf"):
            out[p.name] = collect_bytes(p.read_bytes(), source_name="pilot", title=p.name).text
    if not out:
        raise SystemExit(f"no pilot items (.html, .txt, .pdf) in {folder}")
    return out


def build_client(a: argparse.Namespace) -> LLMClient:
    if a.provider == "ollama":
        return OllamaClient(a.model, a.url or "http://127.0.0.1:11434", timeout=600)
    key = os.environ.get("ATIDEP_CLOUD_KEY", "")
    return CloudChatClient(a.api_style, a.url, a.model, key, timeout=300)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--provider", choices=["ollama", "cloud"], required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--url")
    ap.add_argument("--api-style", choices=["openai", "anthropic"], default="openai")
    ap.add_argument("--items", help="folder of pilot items")
    ap.add_argument("--smoke", action="store_true", help="use the synthetic demo items (wiring "
                    "check only)")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    if not a.items and not a.smoke:
        ap.error("give --items DIR (pilot items), or --smoke for a wiring check")
    folder = (Path(__file__).resolve().parents[1] / "research" / "dataset" / "items"
              if a.smoke else Path(a.items))
    texts = load_texts(folder)
    client = build_client(a)
    report: dict[str, Any] = {"decision": "pending: taken by the coordinator, not by this tool",
                              "model_pinned": False, "provider": a.provider, "model": a.model,
                              "smoke_only": bool(a.smoke), "training_cutoff": None,
                              "training_cutoff_note": "take it from the model card; this tool "
                              "cannot know it", "peak_memory": "run `ollama ps` while this runs"}
    if a.provider == "ollama":
        report["identity"] = ollama_show(a.url or "http://127.0.0.1:11434", a.model)
    probe_req = LLMRequest(agent="extraction", system="Reply with {}.", user="x" * 2000,
                           prompt_version="probe", seed=1)
    first, second, stable = probe_usage_stability(client, probe_req)
    report["usage_probe"] = {"first_input_tokens": first, "second_input_tokens": second,
                             "stable": stable,
                             "note": "if not stable, input tokens from this server are a lower "
                                     "bound and must be recounted before they are priced"}
    report["pilot"] = probe(client, texts)
    text = json.dumps(report, indent=1)
    if a.out:
        Path(a.out).write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
