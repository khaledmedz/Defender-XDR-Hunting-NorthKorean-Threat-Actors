# Defender XDR Hunting North Korean Threat Actors

**Uncovering Nation-State Attacks with Microsoft Defender XDR**

Full-scale investigation and attribution of **Moonstone Sleet** (North Korea-linked) and **Crimson Sandstorm** using Microsoft Defender XDR Advanced Hunting.

> **Platform:** KC7 Cyber (Microsoft-sponsored)  
> **Tools used:** Microsoft Defender XDR · Advanced Hunting (KQL) · Defender Threat Intelligence · Passive DNS  
> **Threat actors identified:** Moonstone Sleet · Crimson Sandstorm (Curium)  
> **Status:** Investigation complete

---

## Overview

TitanShield is a defense contractor running a classified program called **Project Omega**. This case documents a full investigation into a multi-stage intrusion — from LinkedIn reconnaissance through phishing delivery, malware execution, lateral spread across 15 hosts, and confirmed data exfiltration.


---

## Attack Summary

| Stage              | What happened |
|--------------------|---------------|
| Reconnaissance     | Threat actor IPs scanned the company from Jul 5 — targeting employees via LinkedIn |
| Initial access     | Phishing email with malicious Excel file delivered to Defense Engineers |
| Execution          | Macro dropped malicious DLLs |
| Discovery          | 39 recon commands logging system info |
| Lateral movement   | Same pattern found across **15 distinct hosts** |
| Collection         | Project Omega files staged and compressed |
| Exfiltration       | Data sent via FTP to external server |
| Second vector      | Separate Moonstone Sleet campaign via fake tank game |

---

## Key KQL Techniques Demonstrated
- `join kind=inner` across `Email` and `Employees` tables to map phishing targets to job roles
- `let` variable + `in` operator for domain → IP pivoting using Passive DNS
- `has_all()` to fingerprint specific attacker command patterns
- `parse_url().Host` for domain extraction and threat intelligence lookup
- Timeline reconstruction using `order by timestamp`

---

## Threat Actor Attribution

**Moonstone Sleet**  
- Linked to: `detankwar[.]com`, malicious DLLs (`NVUnityPlugin.dll`)
- Vector: Fake tank game distributed via phishing
- Attribution confirmed via Defender XDR Threat Intelligence


**Crimson Sandstorm (Curium)**  
- Used phishing emails from `marcella_flores[.]gmail[.]com`
- Infrastructure: IPs `208.199.30.154` and `202.241.233.180`
- Exfiltrated data sent to: `exfilbucket93[.]gmail[.]com`
- Attribution confirmed via Passive DNS + Defender Threat Intelligence

  ## Investigation Walkthrough

**00. Moonstone Sleet Actor Profile**  
![Moonstone Sleet Actor Profile](Screenshots/Moonstone_actor_profile.png)

**1. Moonstone Sleet Threat Intelligence Attribution**  
![Moonstone Sleet Threat Intelligence](Screenshots/01_moonstone_sleet_ti_attribution.png)

**2. FTP Exfiltration Command – The Smoking Gun**  
![FTP Exfiltration Command](Screenshots/02_ftp_exfiltration_command.png) 

**3. Lateral Movement Across 15 Hosts**  
![15 Hosts Compromised](Screenshots/03_15_hosts_compromised.png)

**4. Precision Targeting of Defense Engineers**  
![Defense Engineer Targeting](Screenshots/04_defense_engineer_targeting.png)

**5. Passive DNS Pivot – Resolving Attacker IPs**  
![Passive DNS Actor IPs](Screenshots/05_passive_dns_actor_ips.png)

**6. Full Kill Chain Timeline Reconstruction**  
![Kill Chain Timeline](Screenshots/06_kill_chain_timeline.png)

**7. Inbound Reconnaissance & LinkedIn Activity**  
![Inbound Recon & LinkedIn Activity](Screenshots/07_inbound_recon_linkedin.png)

**8. C2 Domains Used by the Actor**  
![C2 Domains](Screenshots/C2_domains.png)

---

## Skills Demonstrated
`KQL Advanced Hunting` · `Microsoft Defender XDR` · `Threat Intelligence` · `Passive DNS` · `Kill Chain Analysis` · `Threat Actor Attribution` · `Incident Investigation`

---

## Platform
[KC7 Cyber](https://kc7cyber[.]com) — Titan Shield module (Microsoft-sponsored)

*This investigation was conducted in a simulated environment on the KC7 Cyber platform. No real systems were accessed.*

---

**Author**: Mohamed Khaled 
**Date**: Feb 2026
