"""Convert between event representations used for testing (blueprint §20.6, spike S1).

Wazuh's logtest cannot run the built-in ``windows_eventchannel`` decoder (it is invoked only
for messages on the analysis engine's Windows queue, marker ``f``), so two forms are needed:

* the *structured* form, ``{"win": {"system": {...}, "eventdata": {...}}}``, which is what the
  decoder produces and what rules match against; Tier 1 and logtest use this;
* the *raw agent* form, ``{"Message": ..., "Event": "<Event>...xml...</Event>"}``, which is what
  a Windows agent sends and what the real pipeline decodes; the pipeline replay uses this.
"""

from __future__ import annotations

import json
from typing import Any
from xml.sax.saxutils import escape

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
WIN_EVT_QUEUE = "f"  # WIN_EVT_MQ in src/headers/mq_op.h of the Wazuh source (v4.14.8)

_SYSTEM_REQUIRED = ("providerName", "providerGuid", "eventID", "version", "level", "task",
                    "opcode", "keywords", "systemTime", "eventRecordID", "processID",
                    "threadID", "channel", "computer")


def _cap(name: str) -> str:
    return name[:1].upper() + name[1:]


def _attr(value: object) -> str:
    """Single-quoted XML attribute, as Windows renders event XML. Double quotes would be
    escaped inside the JSON ``Event`` string and break the manager's XML parser."""
    return "'" + escape(str(value), {"'": "&apos;"}) + "'"


def to_raw_eventchannel(event: dict[str, Any]) -> str:
    """Rebuild the raw agent JSON (``Message`` + ``Event`` XML) from the structured form."""
    win = event["win"]
    system, data = win["system"], win.get("eventdata", {})
    missing = [k for k in _SYSTEM_REQUIRED if k not in system]
    if missing:
        raise ValueError(f"win.system is missing {missing}")
    fields = "".join(
        f"<Data Name={_attr(_cap(k))}>{escape(str(v))}</Data>" for k, v in data.items()
    )
    xml = (
        f"<Event xmlns='{EVENT_NS}'><System>"
        f"<Provider Name={_attr(system['providerName'])} Guid={_attr(system['providerGuid'])}/>"
        f"<EventID>{system['eventID']}</EventID><Version>{system['version']}</Version>"
        f"<Level>{system['level']}</Level><Task>{system['task']}</Task>"
        f"<Opcode>{system['opcode']}</Opcode><Keywords>{system['keywords']}</Keywords>"
        f"<TimeCreated SystemTime={_attr(system['systemTime'])}/>"
        f"<EventRecordID>{system['eventRecordID']}</EventRecordID><Correlation/>"
        f"<Execution ProcessID={_attr(system['processID'])} "
        f"ThreadID={_attr(system['threadID'])}/>"
        f"<Channel>{escape(system['channel'])}</Channel>"
        f"<Computer>{escape(system['computer'])}</Computer>"
        f"<Security UserID='S-1-5-18'/></System><EventData>{fields}</EventData></Event>"
    )
    return json.dumps({"Message": system.get("message", ""), "Event": xml}, separators=(",", ":"))


def to_queue_message(event: dict[str, Any], location: str = "EventChannel") -> str:
    """The datagram the analysis engine's queue socket accepts for a Windows event."""
    return f"{WIN_EVT_QUEUE}:{location}:{to_raw_eventchannel(event)}"
