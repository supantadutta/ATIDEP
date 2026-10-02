"""Intermediate representation of the Wazuh-compatible Sigma subset (blueprint §20.2).

``parse_rule`` accepts only what the v0 subset allows and refuses everything else with a
stable reason code (``UnsupportedReason``) instead of approximating it. The result holds the
boolean expression (used by the Tier 1 matcher) and its disjunctive normal form (used by the
converter: one Wazuh rule per clause, because a Wazuh rule is a conjunction).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from itertools import product
from typing import Any

import yaml

from schemas.sigma_subset import UnsupportedReason

SUPPORTED_CATEGORIES = ("process_creation", "network_connection", "dns_query")
KIND_MODIFIERS = ("contains", "startswith", "endswith", "re")
SUPPORTED_MODIFIERS = frozenset({*KIND_MODIFIERS, "all", "windash"})
MAX_VALUES_PER_FIELD = 200
MAX_DNF_CLAUSES = 2000


class SubsetError(Exception):
    def __init__(self, code: UnsupportedReason, path: str, message: str) -> None:
        super().__init__(f"{code.value} at {path}: {message}")
        self.code, self.path, self.message = code, path, message


@dataclass(frozen=True)
class Matcher:
    """One field test. ``values`` are alternatives (OR); ``kind`` is how each is compared."""

    field: str
    kind: str                      # exact | contains | startswith | endswith | re
    values: tuple[str, ...]
    windash: bool = False


@dataclass(frozen=True)
class Lit:
    matcher: Matcher


@dataclass(frozen=True)
class And:
    items: tuple[Expr, ...]


@dataclass(frozen=True)
class Or:
    items: tuple[Expr, ...]


@dataclass(frozen=True)
class Not:
    item: Expr


Expr = Lit | And | Or | Not
Clause = frozenset[tuple[Matcher, bool]]        # conjunction of (matcher, negated)


@dataclass
class RuleIR:
    sigma_id: str
    title: str
    level: str
    tags: list[str]
    category: str
    expr: Expr
    clauses: list[Clause] = field(default_factory=list)

    def fields_used(self) -> list[str]:
        out: list[str] = []

        def walk(e: Expr) -> None:
            if isinstance(e, Lit):
                if e.matcher.field not in out:
                    out.append(e.matcher.field)
            elif isinstance(e, Not):
                walk(e.item)
            else:
                for i in e.items:
                    walk(i)
        walk(self.expr)
        return out

    def matchers(self) -> list[Matcher]:
        out: list[Matcher] = []

        def walk(e: Expr) -> None:
            if isinstance(e, Lit):
                out.append(e.matcher)
            elif isinstance(e, Not):
                walk(e.item)
            else:
                for i in e.items:
                    walk(i)
        walk(self.expr)
        return out


# ---- selections ---------------------------------------------------------------------------
def _scalar(value: Any, path: str) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    raise SubsetError(UnsupportedReason.UNSUPPORTED_SELECTION, path,
                      "only text, number and boolean values are supported (no null or maps)")


def _entry(key: str, value: Any, path: str) -> Expr:
    field_name, *mods = key.split("|")
    if not field_name:
        raise SubsetError(UnsupportedReason.UNSUPPORTED_SELECTION, path,
                          "keyword searches without a field are not supported")
    for m in mods:
        if m not in SUPPORTED_MODIFIERS:
            raise SubsetError(UnsupportedReason.UNSUPPORTED_MODIFIER, path,
                              f"modifier {m!r} is not in the v0 subset")
    kinds = [m for m in mods if m in KIND_MODIFIERS]
    if len(kinds) > 1 or len(set(mods)) != len(mods):
        raise SubsetError(UnsupportedReason.UNSUPPORTED_MODIFIER, path,
                          "conflicting or repeated modifiers")
    kind = kinds[0] if kinds else "exact"
    windash = "windash" in mods
    if windash and kind == "re":
        raise SubsetError(UnsupportedReason.UNSUPPORTED_MODIFIER, path,
                          "windash cannot be combined with re")
    raw = value if isinstance(value, list) else [value]
    if not raw:
        raise SubsetError(UnsupportedReason.UNSUPPORTED_SELECTION, path, "empty value list")
    if len(raw) > MAX_VALUES_PER_FIELD:
        raise SubsetError(UnsupportedReason.EXPANSION_TOO_LARGE, path,
                          f"more than {MAX_VALUES_PER_FIELD} values; use a CDB list")
    values = tuple(_scalar(v, f"{path}[{i}]") for i, v in enumerate(raw))
    if kind == "re":
        for v in values:
            try:
                re.compile(v)
            except re.error as exc:
                raise SubsetError(UnsupportedReason.INVALID_REGEX, path, str(exc)) from exc
    if "all" in mods and len(values) > 1:
        return And(tuple(Lit(Matcher(field_name, kind, (v,), windash)) for v in values))
    return Lit(Matcher(field_name, kind, values, windash))


def _selection(name: str, body: Any) -> Expr:
    path = f"detection.{name}"
    if isinstance(body, dict):
        if not body:
            raise SubsetError(UnsupportedReason.UNSUPPORTED_SELECTION, path, "empty selection")
        items = tuple(_entry(str(k), v, f"{path}.{k}") for k, v in body.items())
        return items[0] if len(items) == 1 else And(items)
    if isinstance(body, list) and body and all(isinstance(b, dict) for b in body):
        alts = [_selection(f"{name}[{i}]", b) for i, b in enumerate(body)]
        return alts[0] if len(alts) == 1 else Or(tuple(alts))
    raise SubsetError(UnsupportedReason.UNSUPPORTED_SELECTION, path,
                      "a selection must be a map or a list of maps (keyword lists are not "
                      "supported)")


# ---- condition ----------------------------------------------------------------------------
_TOKEN = re.compile(r"\(|\)|[^\s()]+")
_AGGREGATION_WORDS = frozenset({"count", "near", "min", "max", "sum", "avg", "by", "timeframe"})


def _tokens(text: str, path: str) -> list[str]:
    toks = _TOKEN.findall(text)
    for t in toks:
        if t in ("|", "<", ">", "<=", ">=", "=") or t.startswith("|") \
                or t.lower() in _AGGREGATION_WORDS:
            raise SubsetError(UnsupportedReason.UNSUPPORTED_AGGREGATION, path,
                              f"{t!r}: aggregation and temporal conditions are not supported")
    return toks


class _Parser:
    def __init__(self, toks: list[str], selections: dict[str, Expr], path: str) -> None:
        self.t, self.i, self.sel, self.path = toks, 0, selections, path

    def _peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def _next(self) -> str:
        tok = self._peek()
        if tok is None:
            raise self._err("unexpected end of condition")
        self.i += 1
        return tok

    def _err(self, msg: str) -> SubsetError:
        return SubsetError(UnsupportedReason.INVALID_CONDITION, self.path, msg)

    def parse(self) -> Expr:
        if not self.t:
            raise self._err("empty condition")
        e = self._or()
        if self._peek() is not None:
            raise self._err(f"unexpected {self._peek()!r}")
        return e

    def _or(self) -> Expr:
        items = [self._and()]
        while (self._peek() or "").lower() == "or":
            self._next()
            items.append(self._and())
        return items[0] if len(items) == 1 else Or(tuple(items))

    def _and(self) -> Expr:
        items = [self._not()]
        while (self._peek() or "").lower() == "and":
            self._next()
            items.append(self._not())
        return items[0] if len(items) == 1 else And(tuple(items))

    def _not(self) -> Expr:
        if (self._peek() or "").lower() == "not":
            self._next()
            return Not(self._not())
        return self._atom()

    def _atom(self) -> Expr:
        tok = self._next()
        if tok == "(":
            e = self._or()
            if self._next() != ")":
                raise self._err("missing closing parenthesis")
            return e
        if tok == ")":
            raise self._err("unexpected closing parenthesis")
        if tok.lower() in ("and", "or", "not", "of"):
            raise self._err(f"unexpected {tok!r}")
        if tok == "1" or tok.lower() == "all":
            if (self._peek() or "").lower() != "of":
                raise self._err(f"expected 'of' after {tok!r}")
            self._next()
            pattern = self._next()
            names = list(self.sel) if pattern.lower() == "them" else \
                [n for n in self.sel if fnmatch.fnmatchcase(n, pattern)]
            if not names:
                raise self._err(f"no selection matches {pattern!r}")
            exprs = tuple(self.sel[n] for n in names)
            if len(exprs) == 1:
                return exprs[0]
            return And(exprs) if tok.lower() == "all" else Or(exprs)
        if tok not in self.sel:
            raise self._err(f"unknown selection {tok!r}")
        return self.sel[tok]


def _condition(detection: dict[str, Any], selections: dict[str, Expr]) -> Expr:
    cond = detection.get("condition")
    path = "detection.condition"
    if cond is None:
        raise SubsetError(UnsupportedReason.INVALID_CONDITION, path, "missing condition")
    texts = cond if isinstance(cond, list) else [cond]
    exprs = []
    for i, t in enumerate(texts):
        if not isinstance(t, str):
            raise SubsetError(UnsupportedReason.INVALID_CONDITION, path, "condition must be text")
        p = f"{path}[{i}]" if isinstance(cond, list) else path
        exprs.append(_Parser(_tokens(t, p), selections, p).parse())
    return exprs[0] if len(exprs) == 1 else Or(tuple(exprs))


# ---- normal form --------------------------------------------------------------------------
def _nnf(e: Expr, negated: bool = False) -> Expr | tuple[Matcher, bool]:
    """Negation normal form; leaves are returned as (matcher, negated) pairs."""
    if isinstance(e, Lit):
        return (e.matcher, negated)
    if isinstance(e, Not):
        return _nnf(e.item, not negated)
    kids = tuple(_nnf(i, negated) for i in e.items)
    both_and = isinstance(e, And)
    return And(kids) if both_and != negated else Or(kids)    # De Morgan  # type: ignore[arg-type]


def _dnf(e: Any) -> list[Clause]:
    if isinstance(e, tuple):
        return [frozenset({e})]
    if isinstance(e, Or):
        out: list[Clause] = []
        for i in e.items:
            out.extend(_dnf(i))
            if len(out) > MAX_DNF_CLAUSES:
                raise SubsetError(UnsupportedReason.EXPANSION_TOO_LARGE, "detection.condition",
                                  "the condition expands to too many alternatives")
        return out
    parts = [_dnf(i) for i in e.items]
    size = 1
    for p in parts:
        size *= max(len(p), 1)
        if size > MAX_DNF_CLAUSES:
            raise SubsetError(UnsupportedReason.EXPANSION_TOO_LARGE, "detection.condition",
                              "the condition expands to too many alternatives")
    return [frozenset().union(*combo) for combo in product(*parts)]


def to_clauses(expr: Expr) -> list[Clause]:
    """Disjunctive normal form: contradictory clauses are dropped, duplicates and clauses that
    another clause already covers (absorption) are removed. Order is deterministic."""
    clauses = []
    for c in _dnf(_nnf(expr)):
        if any((m, not neg) in c for m, neg in c):
            continue                                   # contains a term and its negation
        clauses.append(c)
    unique = list(dict.fromkeys(clauses))
    keep = [c for c in unique if not any(o < c for o in unique)]
    return sorted(keep, key=lambda c: sorted((m.field, m.kind, m.values, n) for m, n in c))


# ---- rule ---------------------------------------------------------------------------------
def parse_rule(sigma_yaml: str) -> RuleIR:
    try:
        doc = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError as exc:
        raise SubsetError(UnsupportedReason.INVALID_CONDITION, "(rule)",
                          f"not valid YAML: {str(exc)[:100]}") from exc
    if not isinstance(doc, dict):
        raise SubsetError(UnsupportedReason.INVALID_CONDITION, "(rule)",
                          "a Sigma rule is a YAML mapping")
    if "correlation" in doc:
        raise SubsetError(UnsupportedReason.UNSUPPORTED_CORRELATION, "correlation",
                          "Sigma correlation rules are not supported")
    ls = doc.get("logsource")
    if not isinstance(ls, dict) or ls.get("category") not in SUPPORTED_CATEGORIES \
            or ls.get("product") not in (None, "windows") \
            or ls.get("service") not in (None, "sysmon"):
        raise SubsetError(UnsupportedReason.UNSUPPORTED_LOGSOURCE, "logsource",
                          f"supported: category in {list(SUPPORTED_CATEGORIES)}, product windows")
    det = doc.get("detection")
    if not isinstance(det, dict):
        raise SubsetError(UnsupportedReason.INVALID_CONDITION, "detection", "missing detection")
    if "timeframe" in det:
        raise SubsetError(UnsupportedReason.UNSUPPORTED_AGGREGATION, "detection.timeframe",
                          "timeframe is not supported")
    selections = {str(k): _selection(str(k), v) for k, v in det.items()
                  if k not in ("condition", "timeframe")}
    if not selections:
        raise SubsetError(UnsupportedReason.INVALID_CONDITION, "detection", "no selections")
    expr = _condition(det, selections)
    clauses = to_clauses(expr)
    if not clauses:
        raise SubsetError(UnsupportedReason.UNSUPPORTED_SELECTION, "detection.condition",
                          "the condition can never be true")
    if any(all(neg for _, neg in c) for c in clauses):
        raise SubsetError(UnsupportedReason.UNSUPPORTED_SELECTION, "detection.condition",
                          "an alternative has only negative terms; add a positive condition")
    return RuleIR(sigma_id=str(doc.get("id", "")), title=str(doc.get("title", "")),
                  level=str(doc.get("level", "")),
                  tags=[str(t) for t in doc.get("tags", [])], category=ls["category"],
                  expr=expr, clauses=clauses)
