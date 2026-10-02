"""Wazuh rule-ID allocator (blueprint §20.5, ADR-001 decision 4).

IDs come from the ATIDEP block. The mapping owner key -> ID is stored, so regenerating a rule
or list gives the same ID, and an ID is never reused after a rule is retired. IDs already
present on the manager (read through the API by the caller) can be passed as ``reserved``.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import models as m


class RuleIdExhausted(Exception):
    pass


def allocate_rule_id(session: Session, owner_key: str, *, id_range: tuple[int, int],
                     reserved: Iterable[int] = ()) -> int:
    lo, hi = id_range
    existing = session.scalars(select(m.RuleIdAllocation).where(
        m.RuleIdAllocation.owner_key == owner_key)).first()
    if existing:
        return existing.wazuh_id
    taken = set(session.scalars(select(m.RuleIdAllocation.wazuh_id)
                                .where(m.RuleIdAllocation.wazuh_id >= lo,
                                       m.RuleIdAllocation.wazuh_id < hi))) | set(reserved)
    for candidate in range(lo, hi):
        if candidate not in taken:
            session.add(m.RuleIdAllocation(wazuh_id=candidate, owner_key=owner_key))
            session.flush()
            return candidate
    raise RuleIdExhausted(f"no free rule ID in {lo}-{hi - 1}")


def allocations(session: Session) -> dict[str, int]:
    return {a.owner_key: a.wazuh_id for a in session.scalars(select(m.RuleIdAllocation))}
