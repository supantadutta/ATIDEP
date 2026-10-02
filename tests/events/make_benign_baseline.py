"""Writes tests/events/benign_baseline/baseline.jsonl: a SYNTHETIC benign baseline.

It is deterministic (fixed seed) and inert (documentation address ranges, ordinary vendor
domains). It stands in for the lab-VM baseline that spike S4 produces and is good enough to
exercise the breadth guard (G11); results measured against it must be reported as synthetic.

Run:  python -m tests.events.make_benign_baseline
"""
from __future__ import annotations

import json
import random
from pathlib import Path

from tests.events import sysmon_factory as f

OUT = Path(__file__).parent / "benign_baseline" / "baseline.jsonl"
SEED = 20261002
WIN = "C:\\Windows\\System32\\"
PF = "C:\\Program Files\\"
EXPLORER = "C:\\Windows\\explorer.exe"

PROCESSES = [
    (PF + "Google\\Chrome\\Application\\chrome.exe", '"{img}" --profile-directory=Default', EXPLORER),
    (PF + "Microsoft\\Edge\\Application\\msedge.exe", '"{img}" --no-startup-window', EXPLORER),
    (PF + "Microsoft Office\\root\\Office16\\OUTLOOK.EXE", '"{img}"', EXPLORER),
    (PF + "Microsoft Office\\root\\Office16\\WINWORD.EXE", '"{img}" /n "C:\\Users\\alice\\Documents\\report.docx"', EXPLORER),
    ("C:\\Windows\\notepad.exe", "notepad.exe C:\\Users\\alice\\notes.txt", EXPLORER),
    (WIN + "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p", WIN + "services.exe"),
    (WIN + "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p", WIN + "services.exe"),
    (WIN + "taskhostw.exe", "taskhostw.exe", WIN + "svchost.exe"),
    (WIN + "conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1", WIN + "cmd.exe"),
    (WIN + "cmd.exe", "cmd.exe /c ipconfig /all", EXPLORER),
    (WIN + "cmd.exe", "cmd.exe /c dir C:\\Users\\alice\\Downloads", EXPLORER),
    (WIN + "cmd.exe", "cmd.exe /c whoami", WIN + "svchost.exe"),
    (WIN + "ipconfig.exe", "ipconfig /all", WIN + "cmd.exe"),
    (WIN + "whoami.exe", "whoami", WIN + "cmd.exe"),
    (WIN + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1", WIN + "taskeng.exe"),
    (WIN + "WindowsPowerShell\\v1.0\\powershell.exe", 'powershell.exe -Command "Get-Service | Where-Object Status -eq Running"', EXPLORER),
    (WIN + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoLogo", EXPLORER),
    (WIN + "msiexec.exe", "msiexec.exe /i C:\\Temp\\app.msi /qn", WIN + "svchost.exe"),
    ("C:\\Windows\\servicing\\TrustedInstaller.exe", "C:\\Windows\\servicing\\TrustedInstaller.exe", WIN + "services.exe"),
    (WIN + "wuauclt.exe", "wuauclt.exe /detectnow", WIN + "svchost.exe"),
    (PF + "Microsoft OneDrive\\OneDrive.exe", '"{img}" /background', EXPLORER),
    (PF + "Microsoft\\Teams\\current\\Teams.exe", '"{img}"', EXPLORER),
    (WIN + "tasklist.exe", "tasklist /v", WIN + "cmd.exe"),
    (WIN + "net.exe", "net use Z: \\\\fileserver\\share", WIN + "cmd.exe"),
    (WIN + "schtasks.exe", "schtasks /query /fo LIST", WIN + "cmd.exe"),
]
NETWORK_IMAGES = [f.BROWSER, PF + "Microsoft\\Edge\\Application\\msedge.exe",
                  PF + "Microsoft\\Teams\\current\\Teams.exe", WIN + "svchost.exe",
                  PF + "Microsoft OneDrive\\OneDrive.exe"]
NETWORK_IPS = [f"198.51.100.{i}" for i in range(10, 40)] + [f"192.0.2.{i}" for i in range(10, 30)]
DOMAINS = ["www.microsoft.com", "login.microsoftonline.com", "windowsupdate.microsoft.com",
           "www.google.com", "mail.google.com", "outlook.office365.com", "teams.microsoft.com",
           "onedrive.live.com", "www.bing.com", "update.googleapis.com", "ocsp.digicert.com",
           "crl.microsoft.com", "time.windows.com", "www.wikipedia.org", "cdn.jsdelivr.net"]
DNS_IMAGES = [f.BROWSER, WIN + "svchost.exe", PF + "Microsoft\\Teams\\current\\Teams.exe"]


def build(n_proc: int = 260, n_net: int = 80, n_dns: int = 60) -> list[dict]:
    rng = random.Random(SEED)
    events, rec = [], 20000
    for _ in range(n_proc):
        image, cmd, parent = rng.choice(PROCESSES)
        user = rng.choice(["LAB\\alice", "LAB\\bob", "NT AUTHORITY\\SYSTEM"])
        events.append(f.process_create(rec, image, cmd.format(img=image), parent, user=user,
                                       sha256=f"{rng.getrandbits(256):064x}"))
        rec += 1
    for _ in range(n_net):
        events.append(f.network_connect(rec, rng.choice(NETWORK_IPS), rng.choice(["443", "443", "80"]),
                                        rng.choice(NETWORK_IMAGES)))
        rec += 1
    for _ in range(n_dns):
        events.append(f.dns_query(rec, rng.choice(DOMAINS), rng.choice(DNS_IMAGES)))
        rec += 1
    return events


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in build()), encoding="utf-8")
    print(f"wrote {OUT} ({len(build())} events)")


if __name__ == "__main__":
    main()
