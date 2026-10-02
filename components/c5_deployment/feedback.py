"""Deterministic feedback statistics (blueprint §17.5.2).

The Improvement Agent never sees raw alerts. It sees these aggregates: volume per rule, and
false-positive clusters by command line, parent process, image, user and host. Exact clusters
group identical raw values and can be turned into an exclusion; pattern clusters group command
lines after numbers, GUIDs and long encoded blobs are replaced, and only describe the shape.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

# alert feature key -> Sigma field (None: informative only, nothing to exclude on)
FEATURE_FIELDS = {"commandLine": "CommandLine", "parentImage": "ParentImage", "image": "Image",
                  "user": "User", "host": None}
DISPOSITIONS = ("true_positive", "false_positive", "benign_true_positive", "unknown")
_B64 = re.compile(r"[A-Za-z0-9+/=]{24,}")
_GUID = re.compile(r"\{?[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?")
_NUM = re.compile(r"\d+")


def alert_features(alert: dict[str, Any]) -> dict[str, Any]:
    """The few fields kept from a Wazuh alert (``alerts.json`` line), and nothing else."""
    win = alert.get("data", {}).get("win", {})
    data, system = win.get("eventdata", {}), win.get("system", {})
    return {"rule_id": int(alert["rule"]["id"]), "level": int(alert["rule"].get("level", 0)),
            "timestamp": alert.get("timestamp"), "alert_id": alert.get("id"),
            "host": system.get("computer") or alert.get("agent", {}).get("name"),
            "commandLine": data.get("commandLine"), "image": data.get("image"),
            "parentImage": data.get("parentImage"), "user": data.get("user")}


def normalise(text: str) -> str:
    t = _GUID.sub("<guid>", text)
    t = _B64.sub("<blob>", t)
    t = _NUM.sub("<n>", t)
    return re.sub(r"\s+", " ", t.strip().casefold())


@dataclass
class Cluster:
    cluster_id: str
    kind: str                      # exact | pattern
    feature: str
    field: str | None              # Sigma field, None if nothing can be excluded on it
    value: str
    count: int
    false_positives: int
    true_positives: int
    excludable: bool

    def as_dict(self) -> dict[str, Any]:
        return {"cluster_id": self.cluster_id, "kind": self.kind, "field": self.field,
                "feature": self.feature, "value": self.value[:300], "alerts": self.count,
                "false_positives": self.false_positives, "true_positives": self.true_positives,
                "excludable": self.excludable}


@dataclass
class RuleStats:
    alerts: int = 0
    by_disposition: dict[str, int] = field(default_factory=dict)
    per_day: dict[str, int] = field(default_factory=dict)
    false_positive_rate: float | None = None      # of dispositioned alerts
    clusters: list[Cluster] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"alerts": self.alerts, "by_disposition": self.by_disposition,
                "per_day": self.per_day, "false_positive_rate": self.false_positive_rate,
                "clusters": [c.as_dict() for c in self.clusters]}

    def cluster(self, cluster_id: str) -> Cluster | None:
        return next((c for c in self.clusters if c.cluster_id == cluster_id), None)


def compute_stats(rows: list[dict[str, Any]], *, min_cluster: int = 2, max_clusters: int = 12
                  ) -> RuleStats:
    """``rows``: dicts with ``disposition`` and the alert features."""
    stats = RuleStats(alerts=len(rows))
    disp = Counter(r["disposition"] for r in rows)
    stats.by_disposition = {d: disp[d] for d in DISPOSITIONS if disp[d]}
    stats.per_day = dict(sorted(Counter(
        str(r.get("timestamp") or "")[:10] or "unknown" for r in rows).items()))
    decided = disp["true_positive"] + disp["false_positive"] + disp["benign_true_positive"]
    benign = disp["false_positive"] + disp["benign_true_positive"]
    stats.false_positive_rate = round(benign / decided, 3) if decided else None

    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        for feat in FEATURE_FIELDS:
            value = r.get(feat)
            if not value:
                continue
            groups[("exact", feat, str(value).casefold())].append(r)
            if feat == "commandLine":
                groups[("pattern", feat, normalise(str(value)))].append(r)
    clusters = []
    for (kind, feat, value), members in groups.items():
        fp = sum(m["disposition"] in ("false_positive", "benign_true_positive") for m in members)
        tp = sum(m["disposition"] == "true_positive" for m in members)
        if fp < min_cluster or fp <= tp:
            continue                                  # not a benign pattern
        sigma_field = FEATURE_FIELDS[feat]
        clusters.append((fp, len(members), kind, feat, value, sigma_field, tp))
    clusters.sort(key=lambda c: (-c[0], -c[1], c[2], c[3], c[4]))
    for i, (fp, n, kind, feat, value, sigma_field, tp) in enumerate(clusters[:max_clusters], 1):
        stats.clusters.append(Cluster(f"c{i}", kind, feat, sigma_field, value, n, fp, tp,
                                      excludable=kind == "exact" and sigma_field is not None))
    return stats
