# ADR-001: Wazuh lab target and the test strategy for generated rules

**Status:** accepted · **Date:** 2026-10-02 · **Spikes:** S1, S2 (blueprint §21) · **Supersedes:** the assumptions marked `[verify: S1/S2]` in blueprint v3

## Context

Blueprint v3 listed several Wazuh behaviours as unverified: whether `wazuh-logtest` can simulate Windows Event Channel events, how CDB lists behave, how rule files reach the manager, what a least-privilege API user can do, and how much memory a manager-only install needs. They were tested on a real manager (`wazuh/wazuh-manager:4.14.8`, Docker, no indexer or dashboard) and checked against the Wazuh v4.14.8 source (`src/analysisd`). The scripts that produced the results are in `spikes/` and are repeatable against any running container named `wazuh`.

## Findings

| # | Finding | Evidence |
|---|---|---|
| F1 | **logtest cannot run the `windows_eventchannel` decoder.** Events sent to `PUT /logtest` are decoded by the generic `json` decoder, so Wazuh's own Windows and Sysmon rules (60000 … 61603) never fire. | `logtest.c` calls only `OS_CleanMSG` and `DecodeEvent`; `DecodeWinevt` is called from `analysisd.c` only for messages on the Windows queue (marker `f`). Probe: five `log_format`/`location` variants, all decoded as `json`, no rule matched. |
| F2 | **The real pipeline can be driven without a Windows agent.** Writing `f:EventChannel:<raw agent JSON>` datagrams to `/var/ossec/queue/sockets/queue` inside the manager runs the real decoder and rule chain; alerts appear in `alerts.json`. | `spikes/s1_pipeline_replay.py`. Positives fire, negatives do not. |
| F3 | The raw agent format needs **single-quoted XML attributes** inside the JSON `Event` string; double quotes are escaped and the manager logs `Could not read XML string`. | Reproduced and fixed; `components/c4_validation/event_formats.py` and its tests. |
| F4 | **Parent rules and field names.** Sysmon Event 1 → `61603`, Event 3 → `61605`, Event 22 → `61650`. Decoded fields are `win.eventdata.image`, `.commandLine`, `.parentImage`, `.destinationIp`, `.queryName`, `.hashes`. | Shipped `0595-win-sysmon_rules.xml`; replay. Recorded in `knowledge/wazuh_parent_sids.json`. |
| F5 | **Decoded Windows paths contain doubled backslashes** in the real pipeline (`C:\\Windows\\System32\\…`); logtest on pre-decoded JSON keeps single ones. Shipped rules write `\\\\`. | Alert output; shipped `0915-win-powershell_rules.xml`. |
| F6 | **Sibling shadowing.** When several rules share a parent, the first that matches wins and later siblings are never evaluated. A shipped level-0 rule (`92101`, "PowerShell over TCP") silently shadowed my Event 3 rules for PowerShell events. | IP rules produced no alerts until the test process was changed from PowerShell; rule structure read in `0810-sysmon_id_3.xml`. |
| F7 | `local_rules.xml` ships **rule IDs 100001 and 100002**; a duplicate ID is ignored with only a warning. | `Rule ID '100001' is duplicated. Only the first occurrence will be considered.` |
| F8 | **CDB lists.** Domain keys are exact and **case-sensitive** (a subdomain or upper-case form does not match). `address_match_key` matches exact IPs and prefix keys (`198.51.100.:`). A CDB key cannot match Sysmon's combined `hashes` string (`SHA256=…`); a PCRE2 alternation on that field works. A **list change takes effect only after a manager restart**. Lists must be declared in `ossec.conf` before `</ruleset>`. | `spikes/s1_cdb.py`: 9 of 9 behavioural cases as expected; the change-without-restart case did not match. |
| F9 | **API behaviour.** An upload of invalid XML returns **HTTP 200** with `total_failed_items: 1` and error code 1113 (the file is not stored). A restart takes 11-14 s. Tokens issued in the same second as an RBAC change are invalidated (401). | `spikes/wazuh_probe.py`, `s2_rbac.py`. |
| F10 | **Least-privilege role works.** With `logtest:run`, `rules:read/update`, `lists:read/update`, `manager:restart`: the allowed calls succeed; `manager/configuration`, `DELETE /rules/files`, `DELETE /lists/files` return 403; agent, user and active-response endpoints return 200 with **zero items**. As the 4.14 RBAC reference states, the PUT file actions have resource `*:*`, so the role can write any file name. Listing rules needs a `rule:file` resource. | `spikes/s2_rbac.py`. |
| F11 | **Footprint.** The manager-only container used about 464 MiB right after start and 816 MiB at steady state (including the unused Filebeat), against the 4 GB budget. | `docker stats`. |

## Decisions

1. **Lab target.** Pin **Wazuh 4.14.8** (image `wazuh/wazuh-manager:4.14.8`). Wazuh 5.x is out of scope.
2. **Tiers.** Tier 1 (Sigma-level matcher) is unchanged. **Tier 2 is the real-pipeline replay (F2)**, which runs the production rule with its real `if_sid` parent and is authoritative for G8-G10. **Tier 2a** is logtest on pre-decoded JSON with a test-only stand-in parent; it checks the rule body only, is cheap, and cannot detect parent-chain or shadowing problems. Tier 3 (live Windows agent) is not needed.
3. **The replay harness is a test tool, not the deployment adapter.** It needs host-level access to the lab manager (`docker exec` or equivalent) to write to the queue socket and read `alerts.json`. It has its own fixed allowlist and is never used with production systems. The deployment adapter stays API-only (§20.5).
4. **Rule IDs.** ATIDEP uses the block **110000-119999**. The allocator also reads the existing IDs in `etc/rules` through the API before assigning.
5. **Converter requirements.** (a) Emit `\\{1,2}` for each backslash in a Sigma value so a rule matches both the doubled and the single form (F5). (b) Take the parent from `knowledge/wazuh_parent_sids.json`, never from memory. (c) Report **shadow risk** from the table of known shadowing siblings and add them as extra parents (`<if_sid>61605, 92101</if_sid>`); the Tier 2 positive test is the authoritative check and a failed positive is diagnosed as possible shadowing. (d) Lower-case domain keys and say in the conversion report that matching is exact and case-sensitive.
6. **IOC path.** Pre-declare `atidep-domains`, `atidep-ips` at provisioning; ATIDEP replaces file content and restarts the manager. IPs use `address_match_key` (prefix keys allowed). Hashes use one PCRE2 alternation per rule with a size cap, not a CDB list.
7. **Adapter requirements.** Treat an upload as failed when the **response body** reports `total_failed_items > 0`, whatever the HTTP status. Wait a few seconds after any RBAC change before authenticating. Restart after every rule or list change and re-run Tier 2 afterwards. Grant `rule:file:*` and `list:file:*` resources in addition to `*:*`, and enforce file-name patterns in the adapter itself (F10).

## Consequences

- The Windows scenarios keep their Windows telemetry; no re-scoping to Linux is needed (fallback 4 of §20.6 is not used).
- Tier 2 depends on a container or host the experimenter controls. The experiment protocol must run on a lab manager, not a shared one.
- Part of what Tier 2 verifies (parent scoping, shadowing) is specific to Wazuh 4.14.8's shipped ruleset and must be re-checked on any other version.
- A repeat of the spikes is cheap: start the container, run `spikes/s1_pipeline_replay.py`, `s1_cdb.py` and `s2_rbac.py`.
