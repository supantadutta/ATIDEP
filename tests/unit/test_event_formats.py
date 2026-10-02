import json
import xml.etree.ElementTree as ET

import pytest

from components.c4_validation.event_formats import (
    WIN_EVT_QUEUE,
    to_queue_message,
    to_raw_eventchannel,
)
from tests.events import sysmon_factory as f

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parsed(event):
    raw = json.loads(to_raw_eventchannel(event))
    return raw, ET.fromstring(raw["Event"])


def test_raw_form_is_valid_xml_with_all_fields():
    ev = f.process_create(1, f.PS, "powershell.exe -enc AAAA", "C:\\Windows\\explorer.exe")
    raw, root = parsed(ev)
    assert raw["Message"] == "Sysmon event"
    assert root.find("e:System/e:EventID", NS).text == "1"
    assert root.find("e:System/e:Provider", NS).attrib["Name"] == "Microsoft-Windows-Sysmon"
    data = {d.attrib["Name"]: d.text for d in root.findall("e:EventData/e:Data", NS)}
    assert data["Image"] == f.PS and data["CommandLine"] == "powershell.exe -enc AAAA"


def test_attributes_are_single_quoted_so_json_escaping_cannot_break_the_xml():
    """Spike S1: double-quoted attributes become \\" inside the JSON string and the manager's
    XML parser rejects them ('Could not read XML string')."""
    raw = json.loads(to_raw_eventchannel(f.dns_query(2, "a.example.invalid")))
    assert '"' not in raw["Event"]
    assert "Name='Microsoft-Windows-Sysmon'" in raw["Event"]


def test_special_characters_are_escaped():
    ev = f.process_create(3, f.PS, "powershell.exe -c \"a<b&c' d\"", "C:\\x.exe")
    _, root = parsed(ev)
    data = {d.attrib["Name"]: d.text for d in root.findall("e:EventData/e:Data", NS)}
    assert data["CommandLine"] == "powershell.exe -c \"a<b&c' d\""


def test_queue_message_uses_the_windows_queue_marker():
    msg = to_queue_message(f.network_connect(4, "203.0.113.10"))
    assert msg.startswith(f"{WIN_EVT_QUEUE}:EventChannel:{{")
    assert json.loads(msg.split(":", 2)[2])["Event"].startswith("<Event")


def test_missing_system_fields_are_rejected():
    ev = f.dns_query(5, "a.example.invalid")
    del ev["win"]["system"]["channel"]
    with pytest.raises(ValueError):
        to_raw_eventchannel(ev)
